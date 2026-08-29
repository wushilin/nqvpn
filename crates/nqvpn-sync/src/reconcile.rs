//! The reconciler driver: desired state arrives whole; the node diffs it
//! against what it actually has and acts only on the difference.
//!
//! The driver knows nothing about what is being reconciled. It calls
//! `reconcile` whenever the view changes and on a timer — the timer is
//! what heals drift the view did not cause (a route an admin deleted, a
//! dialer that died). Implementations must therefore be idempotent and
//! diff against *observed* state (open sessions, dialer handles, the
//! kernel), never against the previous view.

use nqvpn_proto::control::Snapshot;
use std::sync::Arc;
use std::time::Duration;

use crate::link::View;

pub trait Reconcile: Send + Sync {
    fn reconcile(&self, view: &Snapshot);
}

/// Run `r` on every view change and every `interval`.
pub fn spawn_reconciler(view: Arc<View>, r: Arc<dyn Reconcile>, interval: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut rx = view.subscribe();
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_err() {
                        return;
                    }
                }
                _ = tick.tick() => {}
            }
            let snap = view.get();
            r.reconcile(&snap);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counter(AtomicUsize);
    impl Reconcile for Counter {
        fn reconcile(&self, _: &Snapshot) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn runs_on_change_and_on_timer() {
        let view = Arc::new(View::new());
        let c = Arc::new(Counter(AtomicUsize::new(0)));
        let _h = spawn_reconciler(view.clone(), c.clone(), Duration::from_millis(200));
        tokio::time::sleep(Duration::from_millis(50)).await;
        let first = c.0.load(Ordering::Relaxed);
        view.poke();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(c.0.load(Ordering::Relaxed) > first, "a change runs it");
        let n = c.0.load(Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(c.0.load(Ordering::Relaxed) > n, "the timer runs it too");
    }
}
