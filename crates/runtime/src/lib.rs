//! Thread-per-core runtime (master prompt §4, D-0032).
//!
//! [`start`] runs one OS thread per worker core, each pinned to its own CPU (when pinning is on)
//! and running its own **current-thread** Tokio runtime: a core's tasks never migrate, so what a
//! core owns (its connections, sessions, timers, buffers) needs no locks and stays in that core's
//! caches. Each worker gets a [`Core`] telling it who it is.
//!
//! [`reuseport_listeners`] binds one listener per worker on the same address with `SO_REUSEPORT`:
//! the kernel spreads new connections across them by a hash of the connection, so there is no
//! shared accept queue and no thundering herd.
//!
//! Pinning uses the CPUs this process may run on (`sched_getaffinity`, which honours `taskset`
//! and cgroup cpusets), so workers can be confined to a subset and leave the rest for the
//! stores on a single server.
#![forbid(unsafe_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread::JoinHandle;

/// Why the runtime could not start.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// Fewer CPUs are available to this process than pinned workers were asked for.
    #[error("{workers} pinned workers requested but only {cpus} CPUs are available")]
    NotEnoughCpus {
        /// Workers requested.
        workers: usize,
        /// CPUs available to the process.
        cpus: usize,
    },
    /// Zero workers requested.
    #[error("at least one worker is required")]
    NoWorkers,
    /// A thread could not be spawned.
    #[error("cannot spawn worker thread: {0}")]
    Spawn(std::io::Error),
}

/// How many workers to run and whether to pin them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config {
    /// Worker threads (one per core).
    pub workers: usize,
    /// Pin worker `i` to the `i`-th CPU this process may use.
    pub pin: bool,
}

/// What a worker knows about itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Core {
    /// This worker's index, `0..count`.
    pub index: usize,
    /// How many workers run.
    pub count: usize,
    /// The CPU it is pinned to, if pinned.
    pub cpu: Option<usize>,
}

/// The CPUs this process may run on, in ascending order.
#[must_use]
pub fn allowed_cpus() -> Vec<usize> {
    #[cfg(target_os = "linux")]
    {
        if let Ok(set) = rustix::thread::sched_getaffinity(None) {
            return (0..rustix::thread::CpuSet::MAX_CPU)
                .filter(|c| set.is_set(*c))
                .collect();
        }
    }
    let n = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    (0..n).collect()
}

/// Pins the calling thread to `cpu`.
fn pin(cpu: usize) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut set = rustix::thread::CpuSet::new();
        set.set(cpu);
        rustix::thread::sched_setaffinity(None, &set).map_err(std::io::Error::from)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = cpu;
        Ok(())
    }
}

/// Running workers.
#[derive(Debug)]
pub struct Workers {
    handles: Vec<JoinHandle<()>>,
}

impl Workers {
    /// How many workers run.
    #[must_use]
    pub fn len(&self) -> usize {
        self.handles.len()
    }

    /// Whether no worker runs (never true for a started runtime).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty()
    }

    /// Waits until every worker's future has completed (blocking: call from a blocking context).
    /// Returns how many workers panicked.
    pub fn join(self) -> usize {
        self.handles
            .into_iter()
            .map(JoinHandle::join)
            .filter(Result::is_err)
            .count()
    }
}

/// Starts `cfg.workers` threads; worker `i` runs `f(Core { index: i, .. })` to completion on its
/// own current-thread Tokio runtime (I/O and timers enabled). The future need not be `Send`:
/// per-core state can use `Rc` and `RefCell`.
///
/// # Errors
/// [`RuntimeError`]: no workers, too few CPUs to pin, or a thread could not be spawned (workers
/// already started keep running and are detached).
pub fn start<F, Fut>(cfg: Config, f: F) -> Result<Workers, RuntimeError>
where
    F: Fn(Core) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + 'static,
{
    if cfg.workers == 0 {
        return Err(RuntimeError::NoWorkers);
    }
    let cpus = allowed_cpus();
    if cfg.pin && cpus.len() < cfg.workers {
        return Err(RuntimeError::NotEnoughCpus {
            workers: cfg.workers,
            cpus: cpus.len(),
        });
    }
    let f = Arc::new(f);
    let mut handles = Vec::with_capacity(cfg.workers);
    for index in 0..cfg.workers {
        let cpu = if cfg.pin {
            cpus.get(index).copied()
        } else {
            None
        };
        let core = Core {
            index,
            count: cfg.workers,
            cpu,
        };
        let f = Arc::clone(&f);
        let handle = std::thread::Builder::new()
            .name(format!("core-{index}"))
            .spawn(move || run_worker(core, &*f))
            .map_err(RuntimeError::Spawn)?;
        handles.push(handle);
    }
    Ok(Workers { handles })
}

fn run_worker<F, Fut>(core: Core, f: &F)
where
    F: Fn(Core) -> Fut,
    Fut: Future<Output = ()>,
{
    if let Some(cpu) = core.cpu
        && let Err(e) = pin(cpu)
    {
        // Unpinned still works, only slower: say so and continue.
        tracing::warn!(core = core.index, cpu, error = %e, "cannot pin worker");
    }
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            tracing::error!(core = core.index, error = %e, "cannot build worker runtime");
            return;
        }
    };
    rt.block_on(f(core));
}

/// Binds `n` listeners on `addr` with `SO_REUSEPORT` (and `SO_REUSEADDR`), non-blocking, each
/// listening with `backlog`. With port 0, all share the port the first one got. Bound here, on
/// the calling thread, so a bind error surfaces before any worker starts; each worker converts
/// its own with `tokio::net::TcpListener::from_std`.
///
/// # Errors
/// Socket creation, an option, bind or listen failed.
pub fn reuseport_listeners(
    addr: SocketAddr,
    n: usize,
    backlog: i32,
) -> std::io::Result<Vec<std::net::TcpListener>> {
    use socket2::{Domain, Protocol, Socket, Type};
    let mut out = Vec::with_capacity(n);
    let mut at = addr;
    for _ in 0..n {
        let socket = Socket::new(Domain::for_address(at), Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
        socket.set_reuse_port(true)?;
        socket.set_nonblocking(true)?;
        socket.bind(&at.into())?;
        socket.listen(backlog)?;
        let listener: std::net::TcpListener = socket.into();
        if at.port() == 0 {
            at = listener.local_addr()?;
        }
        out.push(listener);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        reason = "tests"
    )]
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn every_worker_runs_once_on_its_own_thread() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = Arc::clone(&seen);
        let workers = start(
            Config {
                workers: 3,
                pin: false,
            },
            move |core| {
                let s = Arc::clone(&s);
                async move {
                    // Not Send: per-core state may use Rc.
                    let local = std::rc::Rc::new(core.index);
                    tokio::task::yield_now().await;
                    let name = std::thread::current().name().unwrap().to_owned();
                    s.lock().unwrap().push((*local, core.count, name));
                }
            },
        )
        .unwrap();
        assert_eq!(workers.join(), 0);
        let mut seen = seen.lock().unwrap().clone();
        seen.sort();
        assert_eq!(
            seen,
            vec![
                (0, 3, "core-0".to_owned()),
                (1, 3, "core-1".to_owned()),
                (2, 3, "core-2".to_owned())
            ]
        );
    }

    #[test]
    fn pinned_workers_run_on_their_cpu() {
        let cpus = allowed_cpus();
        let n = cpus.len().min(2);
        let ok = Arc::new(AtomicUsize::new(0));
        let o = Arc::clone(&ok);
        let workers = start(
            Config {
                workers: n,
                pin: true,
            },
            move |core| {
                let o = Arc::clone(&o);
                async move {
                    if core.cpu.is_some_and(|c| allowed_cpus() == vec![c]) {
                        o.fetch_add(1, Ordering::Relaxed);
                    }
                }
            },
        )
        .unwrap();
        assert_eq!(workers.join(), 0);
        if cfg!(target_os = "linux") {
            assert_eq!(ok.load(Ordering::Relaxed), n);
        }
    }

    #[test]
    fn refuses_more_pinned_workers_than_cpus() {
        let n = allowed_cpus().len() + 1;
        let err = start(
            Config {
                workers: n,
                pin: true,
            },
            |_| async {},
        )
        .unwrap_err();
        assert!(matches!(err, RuntimeError::NotEnoughCpus { .. }));
        assert!(matches!(
            start(
                Config {
                    workers: 0,
                    pin: false
                },
                |_| async {}
            ),
            Err(RuntimeError::NoWorkers)
        ));
    }

    #[test]
    fn reuseport_listeners_share_the_port_and_the_connections() {
        let listeners = reuseport_listeners("127.0.0.1:0".parse().unwrap(), 4, 1024).unwrap();
        let addr = listeners[0].local_addr().unwrap();
        assert!(listeners.iter().all(|l| l.local_addr().unwrap() == addr));
        let accepted: Arc<Vec<AtomicUsize>> =
            Arc::new((0..4).map(|_| AtomicUsize::new(0)).collect());
        let total = 128;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut tasks = Vec::new();
            for (i, l) in listeners.into_iter().enumerate() {
                let l = tokio::net::TcpListener::from_std(l).unwrap();
                let a = Arc::clone(&accepted);
                tasks.push(tokio::spawn(async move {
                    while let Ok(Ok((_s, _))) =
                        tokio::time::timeout(std::time::Duration::from_millis(500), l.accept())
                            .await
                    {
                        a[i].fetch_add(1, Ordering::Relaxed);
                    }
                }));
            }
            let mut conns = Vec::new();
            for _ in 0..total {
                conns.push(tokio::net::TcpStream::connect(addr).await.unwrap());
            }
            for t in tasks {
                t.await.unwrap();
            }
        });
        let counts: Vec<usize> = accepted.iter().map(|a| a.load(Ordering::Relaxed)).collect();
        assert_eq!(counts.iter().sum::<usize>(), total, "{counts:?}");
        // The kernel spread them: more than one listener accepted (all on one would be a
        // probability of 4^-127 with a uniform hash).
        assert!(counts.iter().filter(|c| **c > 0).count() > 1, "{counts:?}");
    }
}
