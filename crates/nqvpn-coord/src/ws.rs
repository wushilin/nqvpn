//! The UI's live feed: one WebSocket per open page. The server pushes
//! the full status of every network whenever a generation is published
//! or configuration changes, and every two seconds regardless (traffic
//! counters move without a generation). The page never polls.

use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;

use crate::state::AppState;

pub async fn serve(state: Arc<AppState>, socket: WebSocket) {
    let (mut tx, mut rx) = socket.split();
    let mut events = state.events.subscribe();
    let mut tick = tokio::time::interval(Duration::from_secs(2));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Every wake-up sends one frame; a burst of publishes is coalesced
    // into one by draining the channel after a short pause.
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            ev = events.recv() => {
                if matches!(ev, Err(tokio::sync::broadcast::error::RecvError::Closed)) {
                    return;
                }
                // Let the rest of a burst land before rendering.
                tokio::time::sleep(Duration::from_millis(50)).await;
                while events.try_recv().is_ok() {}
            }
            msg = rx.next() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                    _ => continue, // pings, or anything the page sends: ignored
                }
            }
        }
        let frame = match crate::api::live_frame(&state) {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!("live frame: {}", e.message);
                continue;
            }
        };
        if tx.send(Message::Text(frame.into())).await.is_err() {
            return;
        }
    }
}
