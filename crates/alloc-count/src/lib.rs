//! A counting global allocator for tests (M3: "steady-state delivery must not allocate per
//! message", proved by measurement and kept in CI).
//!
//! [`Counting`] delegates every call to the system allocator unchanged and counts allocations
//! (and reallocations) made on threads that opted in with [`count_this_thread`]; [`snapshot`]
//! reads the totals. Counting per thread lets a test run a server and its clients in one process
//! and count only the server's thread.
//!
//! This is the workspace's one `unsafe` exception (D-0033): implementing `GlobalAlloc` requires
//! it. Every unsafe operation is a forwarding call to `std::alloc::System` with the caller's own
//! arguments, so the safety contract is the caller's; the counter is a thread-local `Cell<bool>`
//! with a const initializer (no allocation, no destructor) and two relaxed atomics. Test-only:
//! no service depends on this crate. The tests run under Miri in the deep CI tier.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicU64, Ordering};

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

thread_local! {
    static COUNT_HERE: Cell<bool> = const { Cell::new(false) };
}

/// Starts (`true`) or stops counting the calling thread's allocations.
pub fn count_this_thread(on: bool) {
    COUNT_HERE.with(|c| c.set(on));
}

/// Allocations and bytes requested so far on counted threads.
#[must_use]
pub fn snapshot() -> (u64, u64) {
    (
        ALLOCS.load(Ordering::Relaxed),
        BYTES.load(Ordering::Relaxed),
    )
}

fn note(size: usize) {
    // `try_with`: during thread teardown the flag may be gone; nothing is counted then.
    if COUNT_HERE.try_with(Cell::get).unwrap_or(false) {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        BYTES.fetch_add(u64::try_from(size).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}

/// The counting allocator. Install it in a test binary with
/// `#[global_allocator] static A: songbird_alloc_count::Counting = songbird_alloc_count::Counting;`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Counting;

#[allow(
    unsafe_code,
    reason = "D-0033: GlobalAlloc can only be implemented with unsafe"
)]
// SAFETY: every method forwards to `System` with exactly the arguments it received, so it upholds
// `GlobalAlloc`'s contract exactly as `System` does; counting touches no allocator state.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: the caller upholds `alloc`'s contract for `layout`; forwarded unchanged.
        unsafe { System.alloc(layout) } // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(layout.size());
        // SAFETY: as `alloc`.
        unsafe { System.alloc_zeroed(layout) } // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note(new_size);
        // SAFETY: the caller guarantees `ptr` came from this allocator (that is, from `System`)
        // with `layout`, and that `new_size` is valid; forwarded unchanged.
        unsafe { System.realloc(ptr, layout, new_size) } // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: the caller guarantees `ptr` came from this allocator with `layout`.
        unsafe { System.dealloc(ptr, layout) } // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[global_allocator]
    static A: Counting = Counting;

    #[test]
    fn counts_only_threads_that_opted_in() {
        // Other test threads may allocate meanwhile: nothing they do is counted.
        let (a0, _) = snapshot();
        count_this_thread(true);
        let v: Vec<u64> = Vec::with_capacity(16);
        let b = Box::new(7u8);
        count_this_thread(false);
        let (a1, _) = snapshot();
        assert_eq!(a1 - a0, 2);
        drop((v, b));
        let other = std::thread::spawn(|| Vec::<u8>::with_capacity(64).capacity());
        assert_eq!(other.join().ok(), Some(64));
        assert_eq!(snapshot().0, a1, "an uncounted thread added nothing");
    }
}
