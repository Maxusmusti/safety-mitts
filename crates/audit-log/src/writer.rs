use std::path::Path;

use tokio::io::AsyncWriteExt;

use crate::entry::AuditEntry;

/// Errors that can occur during audit log I/O.
#[derive(Debug, thiserror::Error)]
pub enum AuditWriteError {
    #[error("failed to create parent directories: {0}")]
    CreateDir(std::io::Error),

    #[error("failed to open audit log file: {0}")]
    OpenFile(std::io::Error),

    #[error("failed to serialize audit entry: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("failed to write to audit log: {0}")]
    Write(std::io::Error),

    #[error("failed to flush audit log: {0}")]
    Flush(std::io::Error),
}

/// Append-only file writer that serialises [`AuditEntry`] values as JSON-lines.
///
/// Each call to [`write`](Self::write) produces exactly one newline-terminated
/// JSON object in the output file.
pub struct AuditWriter {
    file: tokio::fs::File,
}

impl AuditWriter {
    /// Open (or create) the audit log file at `path` in append mode.
    ///
    /// Parent directories are created automatically if they do not exist.
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, AuditWriteError> {
        let path = path.as_ref();

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(AuditWriteError::CreateDir)?;
        }

        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .map_err(AuditWriteError::OpenFile)?;

        Ok(Self { file })
    }

    /// Serialise `entry` as a single JSON line and append it to the file.
    pub async fn write(&mut self, entry: &AuditEntry) -> Result<(), AuditWriteError> {
        let mut line = serde_json::to_vec(entry)?;
        line.push(b'\n');

        self.file
            .write_all(&line)
            .await
            .map_err(AuditWriteError::Write)?;

        Ok(())
    }

    /// Flush the underlying file, ensuring all buffered data reaches disk.
    pub async fn flush(&mut self) -> Result<(), AuditWriteError> {
        self.file.flush().await.map_err(AuditWriteError::Flush)
    }
}
