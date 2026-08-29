//! Real TUN backend (Linux + macOS) behind the `TunDevice` trait.
//!
//! Blocking reads and writes run on two dedicated OS threads and talk to
//! the async engine over bounded channels (DESIGN.md §9). That is what
//! keeps platform quirks — macOS `utun`'s 4-byte address-family prefix,
//! non-blocking flakiness — in one place instead of in the data path.

use anyhow::{Context, Result};
use ipnet::IpNet;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::tun::TunDevice;

/// macOS `utun` frames carry a 4-byte address-family prefix on the wire,
/// but `tun-rs` strips and adds it for us (`packet_information` defaults
/// to false, which sets `ignore_packet_info`). Doing it again here
/// corrupted every packet on macOS — the engine saw an IP header shifted
/// by four bytes, so the version nibble was garbage and everything was
/// dropped as malformed. The device hands us bare IP packets on every
/// platform, so there is nothing to strip.
const AF_PREFIX: usize = 0;

pub struct RealTun {
    rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    write_tx: mpsc::Sender<Vec<u8>>,
    mtu: u16,
    pub name: String,
    dev: Arc<tun_rs::SyncDevice>,
    addrs: Mutex<Vec<IpNet>>,
}

impl RealTun {
    /// Create the device, assign addresses, and start the I/O threads.
    ///
    /// `name` requests a specific device name. The kernel has the final
    /// say and the rules differ sharply by platform, so the *actual*
    /// name is read back from the device afterwards and used everywhere
    /// (route programming in particular) rather than the requested one:
    ///
    ///   * Linux takes an arbitrary name up to 15 characters.
    ///   * macOS only accepts `utunN`; anything else fails to create.
    pub fn create(addrs: &[IpNet], mtu: u16, name: Option<&str>) -> Result<Arc<RealTun>> {
        let mut cfg = tun_rs::DeviceBuilder::new();
        cfg = cfg.mtu(mtu);
        if let Some(n) = name {
            cfg = cfg.name(n);
        }
        // A device with no address is legal on Linux (headless gateways);
        // macOS and Windows need one, which the caller supplies.
        for a in addrs {
            match a {
                IpNet::V4(v4) => {
                    cfg = cfg.ipv4(v4.addr(), v4.netmask(), None);
                }
                IpNet::V6(v6) => {
                    cfg = cfg.ipv6(v6.addr(), v6.netmask());
                }
            }
        }
        let dev = cfg.build_sync().with_context(|| match name {
            // The overwhelmingly common cause of a named-device failure.
            Some(n) if cfg!(target_os = "macos") && !n.starts_with("utun") => format!(
                "creating TUN device {n:?} — macOS only allows names of the form \"utunN\"; \
                 either use utun<number> or leave tun_name unset"
            ),
            Some(n) => format!("creating TUN device {n:?} (already in use, or name not allowed)"),
            None => "creating TUN device".to_string(),
        })?;
        // Read back what we actually got: the kernel may hand us a
        // different unit than requested, and routes must name the real one.
        let name = dev.name().unwrap_or_else(|_| "tun".into());
        let dev = Arc::new(dev);

        let (tx, rx) = mpsc::channel::<Vec<u8>>(512);
        let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(512);

        // Reader thread: device -> engine.
        let rdev = dev.clone();
        std::thread::Builder::new()
            .name("tun-read".into())
            .spawn(move || {
                let mut buf = vec![0u8; 65536];
                loop {
                    match rdev.recv(&mut buf) {
                        Ok(0) => continue,
                        Ok(n) => {
                            // AF_PREFIX is 0 on every platform: tun-rs
                            // already strips the utun address-family
                            // header for us, and handling it a second
                            // time here shifted every packet by four
                            // bytes. The constant is kept so the intent
                            // stays visible, but the length guard is
                            // just the empty-read case above.
                            let pkt = buf[AF_PREFIX..n].to_vec();
                            // Bounded: a stalled engine drops packets
                            // rather than growing memory.
                            if tx.blocking_send(pkt).is_err() {
                                return;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("TUN read failed: {e}");
                            return;
                        }
                    }
                }
            })
            .context("spawning TUN reader")?;

        // Writer thread: engine -> device.
        let wdev = dev.clone();
        std::thread::Builder::new()
            .name("tun-write".into())
            .spawn(move || {
                while let Some(pkt) = write_rx.blocking_recv() {
                    let framed = frame_for_device(&pkt);
                    if let Err(e) = wdev.send(&framed) {
                        tracing::warn!("TUN write failed: {e}");
                    }
                }
            })
            .context("spawning TUN writer")?;

        Ok(Arc::new(RealTun { rx: Mutex::new(Some(rx)), write_tx, mtu, name, dev, addrs: Mutex::new(addrs.to_vec()) }))
    }
}

fn add_addr(dev: &tun_rs::SyncDevice, a: &IpNet) -> Result<()> {
    match a {
        IpNet::V4(v4) => dev.add_address_v4(v4.addr(), v4.prefix_len()),
        IpNet::V6(v6) => dev.add_address_v6(v6.addr(), v6.prefix_len()),
    }
    .with_context(|| format!("adding {a} to the TUN"))
}

/// The device takes bare IP packets: `tun-rs` owns the platform framing.
fn frame_for_device(packet: &[u8]) -> Vec<u8> {
    packet.to_vec()
}

impl TunDevice for RealTun {
    fn reader(&self) -> mpsc::Receiver<Vec<u8>> {
        self.rx.lock().unwrap().take().expect("reader taken once")
    }

    fn write(&self, packet: Vec<u8>) -> bool {
        // try_send, never block: the TUN writer falling behind must not
        // stall the network-side pump.
        self.write_tx.try_send(packet).is_ok()
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    /// Diff against what the device carries: remove what is gone, add
    /// what is new. A re-join with the same addresses is a no-op.
    fn set_addresses(&self, wanted: &[IpNet]) -> Result<()> {
        let mut cur = self.addrs.lock().unwrap();
        for old in cur.iter() {
            if !wanted.contains(old) {
                self.dev.remove_address(old.addr()).with_context(|| format!("removing {old} from the TUN"))?;
            }
        }
        for new in wanted {
            if !cur.contains(new) {
                add_addr(&self.dev, new)?;
            }
        }
        *cur = wanted.to_vec();
        Ok(())
    }

    fn addresses(&self) -> Vec<IpNet> {
        self.addrs.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: we used to add/strip the utun address-family prefix
    /// on macOS, which `tun-rs` already handles. The double-handling
    /// shifted every packet by four bytes and silently broke the macOS
    /// client while Linux worked fine.
    #[test]
    fn the_device_sees_bare_ip_packets_on_every_platform() {
        assert_eq!(frame_for_device(&[0x45, 1, 2]), vec![0x45, 1, 2]);
        assert_eq!(AF_PREFIX, 0, "tun-rs owns the platform framing");
    }
}
