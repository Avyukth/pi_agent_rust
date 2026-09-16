//! Atomic memory mutations across the primary row, FTS index, and audit log.
//!
//! Take the writer reservation before reading for deduplication or checking a
//! superseded row. A deferred transaction would allow concurrent callers to
//! make decisions from the same stale snapshot.

use crate::error::{Error, Result};
use crate::session_sqlite::SqliteConnection;

struct PendingTransaction<'a> {
    conn: &'a SqliteConnection,
    committed: bool,
}

impl Drop for PendingTransaction<'_> {
    fn drop(&mut self) {
        if !self.committed && self.conn.execute_raw("ROLLBACK").is_err() {
            // Do not log SQL or retained content from an engine diagnostic.
            tracing::warn!("memory transaction rollback failed; connection will be discarded");
        }
    }
}

/// Publish a mutation only after all its statements have committed. The guard
/// also rolls back an early return, a failed commit, or a panic in the action.
pub(super) fn run<T>(
    conn: &SqliteConnection,
    action: impl FnOnce(&SqliteConnection) -> Result<T>,
) -> Result<T> {
    conn.execute_raw("BEGIN IMMEDIATE")
        .map_err(|error| Error::tool("memory", format!("begin transaction failed: {error}")))?;
    let mut pending = PendingTransaction {
        conn,
        committed: false,
    };
    let result = action(conn)?;
    conn.execute_raw("COMMIT")
        .map_err(|error| Error::tool("memory", format!("commit transaction failed: {error}")))?;
    pending.committed = true;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_sqlite::run_on_sqlite_thread;

    fn count(conn: &SqliteConnection) -> i64 {
        let rows = conn.query_sync("SELECT COUNT(*) FROM facts", &[]).unwrap();
        match &rows[0].values()[0] {
            fsqlite::SqliteValue::Integer(count) => *count,
            value => panic!("expected count, got {value:?}"),
        }
    }

    #[test]
    fn committed_mutation_survives_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bank.sqlite");
        run_on_sqlite_thread(|| {
            let conn = SqliteConnection::open_read_write(&path).unwrap();
            conn.execute_raw("CREATE TABLE facts (id INTEGER PRIMARY KEY, content TEXT)")
                .unwrap();
            let result = run(&conn, |conn| {
                conn.execute_raw("INSERT INTO facts VALUES (1, 'durable')")
                    .unwrap();
                Ok(17)
            })?;
            assert_eq!(result, 17);
            conn.close().unwrap();
            let reopened = SqliteConnection::open_read_write(&path).unwrap();
            assert_eq!(count(&reopened), 1);
            reopened.close().unwrap();
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn late_statement_failure_rolls_back_earlier_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bank.sqlite");
        run_on_sqlite_thread(|| {
            let conn = SqliteConnection::open_read_write(&path).unwrap();
            conn.execute_raw("CREATE TABLE facts (id INTEGER PRIMARY KEY, content TEXT)")
                .unwrap();
            let result: Result<()> = run(&conn, |conn| {
                conn.execute_raw("INSERT INTO facts VALUES (1, 'must roll back')")
                    .unwrap();
                conn.execute_raw("INSERT INTO missing_audit_table VALUES (1)")
                    .map_err(|error| Error::tool("memory", format!("audit failed: {error}")))?;
                Ok(())
            });
            assert!(result.unwrap_err().to_string().contains("audit failed"));
            assert_eq!(count(&conn), 0);
            // Failure releases the transaction; the next mutation can commit.
            run(&conn, |conn| {
                conn.execute_raw("INSERT INTO facts VALUES (2, 'retry')")
                    .unwrap();
                Ok(())
            })?;
            conn.close().unwrap();
            let reopened = SqliteConnection::open_read_write(&path).unwrap();
            assert_eq!(count(&reopened), 1);
            reopened.close().unwrap();
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn unwinding_a_mutation_rolls_back_and_releases_the_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bank.sqlite");
        run_on_sqlite_thread(|| {
            let conn = SqliteConnection::open_read_write(&path).unwrap();
            conn.execute_raw("CREATE TABLE facts (id INTEGER PRIMARY KEY, content TEXT)")
                .unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _panic_guard = crate::crash::SuppressPanicHook::new();
                let _: Result<()> = run(&conn, |conn| {
                    conn.execute_raw("INSERT INTO facts VALUES (1, 'uncommitted')")
                        .unwrap();
                    panic!("intentional memory mutation failure");
                });
            }));
            assert!(result.is_err());
            assert_eq!(count(&conn), 0);
            run(&conn, |_| Ok(()))?;
            conn.close().unwrap();
            Ok(())
        })
        .unwrap();
    }
}
