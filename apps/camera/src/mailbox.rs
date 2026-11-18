//! A bounded queue from camera threads to the app where the newest wins: a full queue drops its
//! oldest item, so a slow reader never blocks or slows the camera, and memory stays bounded.
//!
//! The receiver can be awaited (on NSH's engine thread) or drained (tests). When the receiver is
//! dropped, senders see [`Sender::is_open`] turn false and their sends are discarded.

#![forbid(unsafe_code)]

use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context, Poll, Waker},
};

struct State<T> {
    items: VecDeque<T>,
    capacity: usize,
    waker: Option<Waker>,
    senders: usize,
    receiver: bool,
    dropped: u64,
}

struct Shared<T>(Mutex<State<T>>);

impl<T> Shared<T> {
    fn lock(&self) -> MutexGuard<'_, State<T>> {
        // A panic while holding the lock leaves a queue that is still consistent.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Sends into a [`channel`]; cheap to clone, usable from any thread.
pub struct Sender<T>(Arc<Shared<T>>);

/// Reads a [`channel`].
pub struct Receiver<T>(Arc<Shared<T>>);

/// A queue holding at most `capacity` (at least 1) items.
#[must_use]
pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
    let shared = Arc::new(Shared(Mutex::new(State {
        items: VecDeque::with_capacity(capacity.max(1)),
        capacity: capacity.max(1),
        waker: None,
        senders: 1,
        receiver: true,
        dropped: 0,
    })));
    (Sender(shared.clone()), Receiver(shared))
}

impl<T> Sender<T> {
    /// Queues `item`, dropping the oldest one when full; discarded once the receiver is gone.
    /// Never blocks beyond the short lock.
    pub fn send(&self, item: T) {
        let waker = {
            let mut s = self.0.lock();
            if !s.receiver {
                return;
            }
            if s.items.len() == s.capacity {
                s.items.pop_front();
                s.dropped += 1;
            }
            s.items.push_back(item);
            s.waker.take()
        };
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Whether the receiver still exists.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.0.lock().receiver
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        self.0.lock().senders += 1;
        Sender(self.0.clone())
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        let waker = {
            let mut s = self.0.lock();
            s.senders -= 1;
            if s.senders == 0 { s.waker.take() } else { None }
        };
        if let Some(w) = waker {
            w.wake();
        }
    }
}

impl<T> Receiver<T> {
    /// The next item, waiting for one; `None` once every sender is gone and the queue is empty.
    #[must_use]
    pub fn recv(&self) -> Recv<'_, T> {
        Recv(self)
    }

    /// The next item if one is waiting.
    #[must_use]
    pub fn try_recv(&self) -> Option<T> {
        self.0.lock().items.pop_front()
    }

    /// Everything waiting, oldest first.
    #[must_use]
    pub fn drain(&self) -> Vec<T> {
        self.0.lock().items.drain(..).collect()
    }

    /// How many items were dropped because the queue was full.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.0.lock().dropped
    }

    /// The next item, parking this thread until one comes; `None` once every sender is gone.
    /// For worker threads (a scanner), never the engine thread.
    #[must_use]
    pub fn recv_blocking(&self) -> Option<T> {
        struct Unpark(std::thread::Thread);
        impl std::task::Wake for Unpark {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        loop {
            let mut fut = self.recv();
            if let Poll::Ready(item) = Pin::new(&mut fut).poll(&mut cx) {
                return item;
            }
            std::thread::park();
        }
    }

    /// Whether any sender is left.
    #[must_use]
    pub fn has_senders(&self) -> bool {
        self.0.lock().senders > 0
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        let mut s = self.0.lock();
        s.receiver = false;
        s.items.clear();
        s.waker = None;
    }
}

/// [`Receiver::recv`]'s future.
pub struct Recv<'a, T>(&'a Receiver<T>);

impl<T> Future for Recv<'_, T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<T>> {
        let mut s = self.0.0.lock();
        if let Some(item) = s.items.pop_front() {
            return Poll::Ready(Some(item));
        }
        if s.senders == 0 {
            return Poll::Ready(None);
        }
        s.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::Wake,
        time::{Duration, Instant},
    };

    use super::*;

    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn poll<T>(rx: &Receiver<T>, waker: &Waker) -> Poll<Option<T>> {
        let mut fut = rx.recv();
        Pin::new(&mut fut).poll(&mut Context::from_waker(waker))
    }

    #[test]
    fn a_full_queue_drops_the_oldest() {
        let (tx, rx) = channel(2);
        for i in 0..5 {
            tx.send(i);
        }
        assert_eq!(rx.drain(), vec![3, 4]);
        assert_eq!(rx.dropped(), 3);
    }

    #[test]
    fn a_stalled_reader_never_blocks_the_sender() {
        // A camera producing 10,000 frames while nobody reads: bounded, and quick.
        let (tx, rx) = channel(2);
        let start = Instant::now();
        let producer = std::thread::spawn(move || {
            for i in 0..10_000u32 {
                tx.send(
                    vec![0u8; 64]
                        .into_iter()
                        .chain(i.to_le_bytes())
                        .collect::<Vec<_>>(),
                );
            }
        });
        producer.join().unwrap();
        assert!(start.elapsed() < Duration::from_secs(5));
        let left = rx.drain();
        assert_eq!(left.len(), 2);
        assert_eq!(rx.dropped(), 9_998);
        assert_eq!(left[1][64..], 9_999u32.to_le_bytes());
    }

    #[test]
    fn a_waiting_reader_is_woken_and_ends_with_the_senders() {
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let (tx, rx) = channel::<u8>(4);
        assert_eq!(poll(&rx, &waker), Poll::Pending);
        tx.send(7);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert_eq!(poll(&rx, &waker), Poll::Ready(Some(7)));
        let tx2 = tx.clone();
        drop(tx);
        assert_eq!(poll(&rx, &waker), Poll::Pending);
        drop(tx2);
        assert_eq!(count.0.load(Ordering::SeqCst), 2);
        assert_eq!(poll(&rx, &waker), Poll::Ready(None));
    }

    #[test]
    fn sends_after_the_reader_is_gone_are_discarded() {
        let (tx, rx) = channel(2);
        assert!(tx.is_open());
        drop(rx);
        assert!(!tx.is_open());
        tx.send(1); // nothing to keep it: no growth
    }
}
