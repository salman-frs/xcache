use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::thread;

/// Locks a mutex whose data stays usable if a thread panicked while holding it.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn available_cpus() -> usize {
    thread::available_parallelism().map_or(1, NonZeroUsize::get)
}

/// Applies `work` to every item on all CPUs and returns the results in the
/// order of the items.
pub fn on_all_cpus<T: Sync, R: Send>(items: &[T], work: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let mut results: Vec<(usize, R)> = thread::scope(|scope| {
        let workers: Vec<_> = (0..available_cpus().min(items.len()))
            .map(|_| {
                scope.spawn(|| {
                    let mut results = Vec::new();
                    loop {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(index) else {
                            break results;
                        };
                        results.push((index, work(item)));
                    }
                })
            })
            .collect();
        workers.into_iter().flat_map(|worker| worker.join().expect("a worker panicked")).collect()
    });
    results.sort_unstable_by_key(|(index, _)| *index);
    results.into_iter().map(|(_, result)| result).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_keep_the_order_of_the_items() {
        let items: Vec<u32> = (0..1000).collect();
        assert_eq!(on_all_cpus(&items, |item| item * 2), items.iter().map(|item| item * 2).collect::<Vec<_>>());
        assert!(on_all_cpus(&[] as &[u32], |item| *item).is_empty());
    }
}
