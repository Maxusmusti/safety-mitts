use std::path::Path;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::entry::AuditEntry;
use crate::writer::AuditWriter;

/// Channel buffer size used between producers and the background writer task.
const CHANNEL_BUFFER: usize = 1024;

/// Flush the writer at most every this many seconds when the channel is idle.
const FLUSH_INTERVAL_SECS: u64 = 1;

/// A cheap, cloneable handle used to submit [`AuditEntry`] values into the
/// background audit-log writer.
///
/// `AuditSink` is `Clone + Send + Sync` so it can be shared freely across
/// tasks, request handlers, and components.
#[derive(Clone)]
pub struct AuditSink {
    tx: mpsc::Sender<AuditEntry>,
}

impl AuditSink {
    /// Spawn the background writer task and return a `(sink, join_handle)` pair.
    ///
    /// The writer opens (or creates) the file at `path` in append mode and
    /// begins draining entries from the internal channel. The background task
    /// will:
    ///
    /// * Write each entry as a JSON line via [`AuditWriter`].
    /// * Flush periodically (every ~1 second of channel inactivity).
    /// * Flush once more when the last `AuditSink` clone is dropped and the
    ///   channel closes, then exit cleanly.
    ///
    /// # Panics
    ///
    /// The background task will **not** panic. I/O errors are logged via
    /// `tracing::error` and the entry is skipped.
    pub async fn start(
        path: impl AsRef<Path>,
    ) -> Result<(Self, JoinHandle<()>), crate::writer::AuditWriteError> {
        let (tx, rx) = mpsc::channel::<AuditEntry>(CHANNEL_BUFFER);

        let mut writer = AuditWriter::new(path).await?;

        let handle = tokio::spawn(async move {
            run_writer_loop(&mut writer, rx).await;
        });

        Ok((Self { tx }, handle))
    }

    /// Send an audit entry to the background writer.
    ///
    /// If the channel is full this will wait asynchronously until space is
    /// available. If the background task has already exited (e.g. after a
    /// fatal I/O error) the entry is silently dropped and a warning is logged.
    pub async fn log(&self, entry: AuditEntry) {
        if let Err(err) = self.tx.send(entry).await {
            tracing::warn!(
                event_type = ?err.0.event_type,
                "audit sink channel closed — entry dropped"
            );
        }
    }
}

/// Core loop executed inside the background task.
///
/// Reads entries from the channel and writes them to the audit log. When the
/// channel has no entries ready for [`FLUSH_INTERVAL_SECS`] the writer is
/// flushed. On channel close a final flush is performed.
async fn run_writer_loop(writer: &mut AuditWriter, mut rx: mpsc::Receiver<AuditEntry>) {
    let flush_interval = tokio::time::Duration::from_secs(FLUSH_INTERVAL_SECS);
    let mut dirty = false;

    loop {
        // Wait for the next entry, but time out so we can periodically flush.
        let maybe_entry = tokio::time::timeout(flush_interval, rx.recv()).await;

        match maybe_entry {
            // Received an entry before the timeout.
            Ok(Some(entry)) => {
                if let Err(err) = writer.write(&entry).await {
                    tracing::error!(%err, "failed to write audit entry");
                } else {
                    dirty = true;
                }
            }
            // Channel closed — perform final flush and exit.
            Ok(None) => {
                if dirty {
                    if let Err(err) = writer.flush().await {
                        tracing::error!(%err, "failed to flush audit log on shutdown");
                    }
                }
                tracing::debug!("audit writer background task shutting down");
                return;
            }
            // Timeout — flush if we have outstanding writes.
            Err(_) => {
                if dirty {
                    if let Err(err) = writer.flush().await {
                        tracing::error!(%err, "periodic audit log flush failed");
                    } else {
                        dirty = false;
                    }
                }
            }
        }
    }
}
