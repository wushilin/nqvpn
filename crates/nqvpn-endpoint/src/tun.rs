//! TUN abstraction (DESIGN.md §10 dependency rule): a trait with
//! platform backends behind it, so the engine and CI run against a fake
//! device and the real ones land per-platform in Phase 4.

use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// A packet source/sink. Real backends run blocking reads and writes on
/// dedicated OS threads (§9); the trait hides that from the engine.
pub trait TunDevice: Send + Sync + 'static {
    /// Channel of packets read from the device (device -> engine).
    fn reader(&self) -> mpsc::Receiver<Vec<u8>>;
    /// Send a packet to the device (engine -> device).
    fn write(&self, packet: Vec<u8>) -> bool;
    fn mtu(&self) -> u16;
    /// Kernel-assigned interface name — route programming needs the real
    /// one, not a guess (the kernel picks `utunN` on macOS and may
    /// rename on Linux).
    fn name(&self) -> String;
    /// Make the device carry exactly these addresses (a re-join brought
    /// new ones). Backends without address management accept silently.
    fn set_addresses(&self, _addrs: &[ipnet::IpNet]) -> anyhow::Result<()> {
        Ok(())
    }
    /// Addresses the device currently carries, where known.
    fn addresses(&self) -> Vec<ipnet::IpNet> {
        Vec::new()
    }
}

/// A TUN handle whose underlying device can be replaced underneath every
/// holder (DESIGN.md §8).
///
/// Deleting the device is the only *reliable* way to drop the routes that
/// point at it. Tracking them in userspace and diffing against a cached
/// set assumes we are the sole writer of the routing table, and we are
/// demonstrably not: a second endpoint on the same host claims the same
/// prefixes, an admin can delete one, and a vanishing interface takes its
/// routes with it. The kernel already knows the truth; recreating the
/// device makes it authoritative instead of something we try to mirror.
///
/// Everything holds this wrapper rather than a concrete device, so a
/// replacement is invisible to the engine, the pumps, and the route
/// programmer.
pub struct SwappableTun {
    inner: std::sync::RwLock<Swap>,
}

struct Swap {
    dev: std::sync::Arc<dyn TunDevice>,
    /// A device hands out its reader exactly once. Tracked here so a pump
    /// that re-subscribes after a swap gets the *new* device's reader,
    /// and asking twice for the same one yields a closed channel instead
    /// of panicking.
    reader_taken: bool,
}

impl SwappableTun {
    pub fn new(dev: std::sync::Arc<dyn TunDevice>) -> std::sync::Arc<SwappableTun> {
        std::sync::Arc::new(SwappableTun {
            inner: std::sync::RwLock::new(Swap { dev, reader_taken: false }),
        })
    }

    /// Install a new device. The old one is dropped, which closes it and
    /// makes the kernel discard every route that pointed at it.
    pub fn replace(&self, dev: std::sync::Arc<dyn TunDevice>) {
        let mut g = self.inner.write().unwrap();
        g.dev = dev;
        g.reader_taken = false;
    }

    /// The current device's reader, if it has not been handed out yet.
    ///
    /// Pumps call this in a loop: when the device is replaced the old
    /// reader ends, and the next call returns the new one.
    pub fn take_reader(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        let mut g = self.inner.write().unwrap();
        if g.reader_taken {
            return None;
        }
        g.reader_taken = true;
        Some(g.dev.reader())
    }

    pub fn device(&self) -> std::sync::Arc<dyn TunDevice> {
        self.inner.read().unwrap().dev.clone()
    }
}

impl TunDevice for SwappableTun {
    fn reader(&self) -> mpsc::Receiver<Vec<u8>> {
        match self.take_reader() {
            Some(r) => r,
            // Already handed out: a closed channel, so a caller loops and
            // retries rather than panicking on a double take.
            None => {
                let (_tx, rx) = mpsc::channel(1);
                rx
            }
        }
    }
    fn write(&self, packet: Vec<u8>) -> bool {
        self.inner.read().unwrap().dev.write(packet)
    }
    fn mtu(&self) -> u16 {
        self.inner.read().unwrap().dev.mtu()
    }
    fn name(&self) -> String {
        // Read live: the kernel picks the name, so a replacement may land
        // on a different unit and route programming must follow it.
        self.inner.read().unwrap().dev.name()
    }
}

/// An in-memory device for tests and CI: what goes in `inject` comes out
/// of the engine's outbound pump, and what the engine delivers lands in
/// `written`.
pub struct FakeTun {
    tx: mpsc::Sender<Vec<u8>>,
    rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    written: Arc<Mutex<Vec<Vec<u8>>>>,
    write_tx: mpsc::Sender<Vec<u8>>,
    write_rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    mtu: u16,
    name: String,
    addrs: Mutex<Vec<ipnet::IpNet>>,
}

impl FakeTun {
    pub fn new(mtu: u16) -> Arc<FakeTun> {
        FakeTun::named("tun-test", mtu)
    }

    /// A device with a chosen name, so tests can assert that route
    /// programming follows a replacement onto a different interface.
    pub fn named(name: &str, mtu: u16) -> Arc<FakeTun> {
        let (tx, rx) = mpsc::channel(512);
        let (write_tx, write_rx) = mpsc::channel(512);
        Arc::new(FakeTun {
            tx,
            rx: Mutex::new(Some(rx)),
            written: Arc::new(Mutex::new(Vec::new())),
            write_tx,
            write_rx: Mutex::new(Some(write_rx)),
            mtu,
            name: name.to_string(),
            addrs: Mutex::new(Vec::new()),
        })
    }

    /// Pretend an application sent this packet into the tunnel.
    pub async fn inject(&self, packet: Vec<u8>) {
        let _ = self.tx.send(packet).await;
    }

    /// Everything the engine has delivered to this device so far.
    pub fn written(&self) -> Vec<Vec<u8>> {
        self.written.lock().unwrap().clone()
    }

    /// Wait for the next delivered packet.
    pub fn take_writes(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.write_rx.lock().unwrap().take()
    }
}

impl TunDevice for FakeTun {
    fn reader(&self) -> mpsc::Receiver<Vec<u8>> {
        self.rx.lock().unwrap().take().expect("reader taken once")
    }

    fn write(&self, packet: Vec<u8>) -> bool {
        self.written.lock().unwrap().push(packet.clone());
        self.write_tx.try_send(packet).is_ok()
    }

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn name(&self) -> String {
        self.name.clone()
    }

    fn set_addresses(&self, addrs: &[ipnet::IpNet]) -> anyhow::Result<()> {
        *self.addrs.lock().unwrap() = addrs.to_vec();
        Ok(())
    }

    fn addresses(&self) -> Vec<ipnet::IpNet> {
        self.addrs.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_tun_roundtrips() {
        let tun = FakeTun::new(1350);
        let mut reader = tun.reader();
        tun.inject(vec![1, 2, 3]).await;
        assert_eq!(reader.recv().await.unwrap(), vec![1, 2, 3]);
        assert!(tun.write(vec![4, 5, 6]));
        assert_eq!(tun.written(), vec![vec![4, 5, 6]]);
        assert_eq!(tun.mtu(), 1350);
    }

    #[tokio::test]
    async fn a_replacement_is_invisible_to_everyone_holding_the_handle() {
        // The engine, the pumps and the route programmer all hold this
        // wrapper, so a swap must not require handing them anything new.
        let a = FakeTun::new(1400);
        let sw = SwappableTun::new(a.clone());
        let holder = sw.clone();

        assert_eq!(holder.mtu(), 1400);
        let b = FakeTun::new(1280);
        sw.replace(b.clone());
        assert_eq!(holder.mtu(), 1280, "an existing holder must see the new device");
        assert!(holder.write(vec![1, 2, 3]));
        assert_eq!(b.written().len(), 1, "writes must land on the new device");
        assert!(a.written().is_empty(), "and not on the old one");
    }

    #[tokio::test]
    async fn the_device_name_is_read_live_not_captured() {
        // Route programming must follow the device: the kernel picks the
        // name, so a replacement can land on a different unit. Capturing
        // it once is how routes end up aimed at an interface that no
        // longer exists.
        let sw = SwappableTun::new(FakeTun::named("utun10", 1400));
        assert_eq!(sw.name(), "utun10");
        sw.replace(FakeTun::named("utun11", 1400));
        assert_eq!(sw.name(), "utun11");
    }

    #[tokio::test]
    async fn a_pump_re_subscribes_to_the_new_device_after_a_swap() {
        // A device hands out its reader once. After a swap the pump loops
        // and asks again; it must get the *new* device's reader.
        let a = FakeTun::new(1400);
        let sw = SwappableTun::new(a.clone());
        let first = sw.take_reader();
        assert!(first.is_some());
        assert!(sw.take_reader().is_none(), "one reader per device");

        let b = FakeTun::new(1400);
        sw.replace(b.clone());
        let mut second = sw.take_reader().expect("the new device has its own reader");

        b.inject(vec![9, 9, 9]).await;
        let got = tokio::time::timeout(std::time::Duration::from_secs(2), second.recv())
            .await
            .expect("no timeout");
        assert_eq!(got, Some(vec![9, 9, 9]));
    }

    #[tokio::test]
    async fn asking_twice_yields_a_closed_channel_rather_than_panicking() {
        // Via the trait, a double take must degrade to "nothing to read"
        // so the pump loops instead of bringing the process down.
        let sw = SwappableTun::new(FakeTun::new(1400));
        let _first = sw.reader();
        let mut second = sw.reader();
        assert_eq!(second.recv().await, None);
    }
}
