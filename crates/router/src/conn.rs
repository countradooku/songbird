//! A Valkey command connection that heals itself (M4 chaos run: after a Valkey restart a
//! multiplexed connection stays broken forever, so leases stopped renewing and publishes stopped
//! reaching anyone).
//!
//! Commands go through one multiplexed connection; when a command fails because the connection
//! dropped, timed out or hit an I/O error, the connection is discarded and the next command
//! connects again. The failing command is not retried here: callers decide (a publish is best
//! effort, a lease renewal runs again next round).

use std::time::Duration;

use redis::aio::MultiplexedConnection;
use redis::{FromRedisValue, RedisResult};

/// How long connecting may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

/// A self-healing command connection.
pub struct ValkeyConn {
    client: redis::Client,
    current: tokio::sync::Mutex<Option<MultiplexedConnection>>,
}

impl std::fmt::Debug for ValkeyConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValkeyConn").finish_non_exhaustive()
    }
}

fn io_failure(e: &redis::RedisError) -> bool {
    e.is_io_error() || e.is_connection_dropped() || e.is_timeout() || e.is_connection_refusal()
}

impl ValkeyConn {
    /// Connects now (so a bad address or password fails at start-up).
    ///
    /// # Errors
    /// Connecting failed.
    pub async fn connect(client: redis::Client) -> RedisResult<Self> {
        let c = Self::open(&client).await?;
        Ok(Self {
            client,
            current: tokio::sync::Mutex::new(Some(c)),
        })
    }

    async fn open(client: &redis::Client) -> RedisResult<MultiplexedConnection> {
        match tokio::time::timeout(CONNECT_TIMEOUT, client.get_multiplexed_async_connection()).await
        {
            Ok(r) => r,
            Err(_) => Err(redis::RedisError::from(std::io::Error::from(
                std::io::ErrorKind::TimedOut,
            ))),
        }
    }

    async fn get(&self) -> RedisResult<MultiplexedConnection> {
        let mut cur = self.current.lock().await;
        if let Some(c) = cur.as_ref() {
            return Ok(c.clone());
        }
        let c = Self::open(&self.client).await?;
        *cur = Some(c.clone());
        Ok(c)
    }

    async fn forget(&self) {
        *self.current.lock().await = None;
    }

    /// Runs a command; a connection failure discards the connection for the next one.
    ///
    /// # Errors
    /// The command or the connection failed.
    pub async fn query<T: FromRedisValue>(&self, cmd: &redis::Cmd) -> RedisResult<T> {
        let mut c = self.get().await?;
        let r = cmd.query_async(&mut c).await;
        if let Err(e) = &r
            && io_failure(e)
        {
            self.forget().await;
        }
        r
    }

    /// Runs a pipeline; as [`ValkeyConn::query`].
    ///
    /// # Errors
    /// The pipeline or the connection failed.
    pub async fn query_pipe<T: FromRedisValue>(&self, pipe: &redis::Pipeline) -> RedisResult<T> {
        let mut c = self.get().await?;
        let r = pipe.query_async(&mut c).await;
        if let Err(e) = &r
            && io_failure(e)
        {
            self.forget().await;
        }
        r
    }
}
