//! Lane behaviour over a real QUIC connection.
//!
//! The unit tests cover lane *selection* (a pure hash). What they cannot
//! cover is the property the relay depends on: that a lane label survives
//! the wire, so a frame can be forwarded on the lane it arrived on.

use nqvpn_proto::identity::TlsIdentity;
use nqvpn_proto::quic::{client_config, server_config};
use nqvpn_proto::transport::{Mode, PacketChannel};
use std::sync::Arc;
use std::time::Duration;

/// A connected pair of packet channels over loopback.
async fn pair(mode: Mode, lanes: u8) -> (Arc<PacketChannel>, Arc<PacketChannel>) {
    let server_id = TlsIdentity::generate("server").expect("server identity");
    let client_id = TlsIdentity::generate("client").expect("client identity");
    let fp = server_id.fingerprint();

    let endpoint = quinn::Endpoint::server(
        server_config(&server_id, 30).expect("server config"),
        "127.0.0.1:0".parse().unwrap(),
    )
    .expect("bind");
    let addr = endpoint.local_addr().expect("local addr");

    let accept = tokio::spawn(async move {
        let incoming = endpoint.accept().await.expect("incoming");
        let conn = incoming.await.expect("accepted");
        // Hold the endpoint open for the connection's life.
        let held = endpoint;
        let chan = PacketChannel::start_lanes(conn.clone(), mode, lanes);
        tokio::spawn(async move {
            conn.closed().await;
            drop(held);
        });
        chan
    });

    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).expect("client bind");
    ep.set_default_client_config(client_config(&client_id, Some(fp), 30).expect("client config"));
    let conn = ep.connect(addr, "server").expect("connect").await.expect("handshake");
    let client_chan = PacketChannel::start_lanes(conn.clone(), mode, lanes);
    std::mem::forget(ep); // test-lifetime endpoint

    (accept.await.expect("accept task"), client_chan)
}

#[tokio::test]
async fn a_lane_label_survives_the_wire() {
    let (server, client) = pair(Mode::Stream, 4).await;

    // Send one distinctly-tagged packet per lane.
    for lane in 0..4u8 {
        assert!(client.send_on(vec![lane, 0xAA].into(), lane), "send on lane {lane}");
    }

    // Every packet must arrive carrying the lane it was sent on —
    // otherwise a relay would forward frames onto the wrong lane and
    // silently reorder flows.
    let mut seen = std::collections::HashMap::new();
    for _ in 0..4 {
        let (pkt, lane) = tokio::time::timeout(Duration::from_secs(5), server.recv())
            .await
            .expect("no timeout")
            .expect("packet");
        seen.insert(pkt[0], lane);
    }
    for lane in 0..4u8 {
        assert_eq!(seen.get(&lane), Some(&lane), "packet tagged {lane} arrived on a different lane");
    }
}

#[tokio::test]
async fn order_is_preserved_within_a_lane() {
    let (server, client) = pair(Mode::Stream, 4).await;

    // A flow is sticky to one lane, so that lane must never reorder it —
    // this is the guarantee that makes lane-splitting safe for TCP.
    for i in 0..200u8 {
        assert!(client.send_on(vec![i].into(), 2));
    }
    for expected in 0..200u8 {
        let (pkt, lane) = tokio::time::timeout(Duration::from_secs(5), server.recv())
            .await
            .expect("no timeout")
            .expect("packet");
        assert_eq!(lane, 2);
        assert_eq!(pkt[0], expected, "lane 2 reordered its packets");
    }
}

#[tokio::test]
async fn a_sender_with_more_lanes_than_the_receiver_still_gets_through() {
    // The rolling-upgrade case, and the reason lane count needs no
    // negotiation: the receiver accepts however many streams arrive.
    let server_id = TlsIdentity::generate("server").unwrap();
    let client_id = TlsIdentity::generate("client").unwrap();
    let fp = server_id.fingerprint();
    let endpoint = quinn::Endpoint::server(
        server_config(&server_id, 30).unwrap(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();

    let accept = tokio::spawn(async move {
        let conn = endpoint.accept().await.unwrap().await.unwrap();
        let held = endpoint;
        // Receiver configured for a single lane.
        let chan = PacketChannel::start_lanes(conn.clone(), Mode::Stream, 1);
        tokio::spawn(async move {
            conn.closed().await;
            drop(held);
        });
        chan
    });

    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(client_config(&client_id, Some(fp), 30).unwrap());
    let conn = ep.connect(addr, "server").unwrap().await.unwrap();
    // Sender uses eight.
    let client = PacketChannel::start_lanes(conn, Mode::Stream, 8);
    std::mem::forget(ep);
    let server = accept.await.unwrap();

    for lane in 0..8u8 {
        assert!(client.send_on(vec![lane].into(), lane));
    }
    let mut got = std::collections::HashSet::new();
    for _ in 0..8 {
        let (pkt, _) = tokio::time::timeout(Duration::from_secs(5), server.recv())
            .await
            .expect("no timeout")
            .expect("packet");
        got.insert(pkt[0]);
    }
    assert_eq!(got.len(), 8, "a one-lane receiver dropped packets from an eight-lane sender");
}

#[tokio::test]
async fn datagram_mode_has_no_lanes_and_ignores_the_label() {
    let (server, client) = pair(Mode::Datagram, 4).await;
    assert_eq!(client.lane_count(), 0, "datagram mode must not open streams");

    // A lane label on a datagram is meaningless but must not be an error:
    // the relay hands one along without knowing the mode.
    assert!(client.send_on(vec![7u8, 7].into(), 3));
    let (pkt, lane) = tokio::time::timeout(Duration::from_secs(5), server.recv())
        .await
        .expect("no timeout")
        .expect("packet");
    assert_eq!(pkt[0], 7);
    assert_eq!(lane, 0, "datagrams always report the default lane");
}
