//! Data Access Layer: owns the SQLite connection pool, row structs, and all SQL queries/transactions.

pub mod adapters;
pub mod audit;
pub mod config;
pub mod locks;
pub mod users;

pub use adapters::{AdapterFilter, AdapterRow};
pub use audit::{AuditLogFilter, AuditLogRow};
pub use locks::{BindLockOutcome, LockRow};
pub use users::{LoginDeviceParams, UserDeviceRow, UserRow};

use crate::error::AppResult;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;
use std::str::FromStr;
use std::time::Duration;

#[derive(Clone)]
pub struct Db {
    pub pool: SqlitePool,
}

impl Db {
    /// Connects to SQLite with WAL mode and runs embedded migrations.
    pub async fn connect(database_url: &str) -> anyhow::Result<Self> {
        let opts = SqliteConnectOptions::from_str(database_url)?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
            .foreign_keys(true)
            .busy_timeout(Duration::from_millis(5000));

        let max_conns = if database_url.contains(":memory:") {
            1
        } else {
            8
        };

        let pool = SqlitePoolOptions::new()
            .max_connections(max_conns)
            .connect_with(opts)
            .await?;

        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }

    /// Lightweight database liveness probe.
    pub async fn ping(&self) -> AppResult<()> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }
}

pub(crate) fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(err, sqlx::Error::Database(db_err) if db_err.is_unique_violation())
}
