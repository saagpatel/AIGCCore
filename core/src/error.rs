use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("input schema error: {0}")]
    InputSchemaError(String),

    #[error("artifact missing: {0}")]
    ArtifactMissingError(String),

    #[error("policy violation: {0}")]
    PolicyViolationError(String),

    #[error("determinism violation: {0}")]
    DeterminismViolationError(String),

    #[error("citation violation: {0}")]
    CitationViolationError(String),

    #[error("redaction violation: {0}")]
    RedactionViolationError(String),

    #[error("consent missing: {0}")]
    ConsentMissingError(String),

    #[error("workflow transition error: {0}")]
    WorkflowTransitionError(String),

    #[error("policy blocked: {0}")]
    PolicyBlocked(String),

    #[error("evidenceos validation failed: {0}")]
    EvidenceOsValidation(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("io error during {operation} at {path}: {source}")]
    IoAt {
        operation: &'static str,
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("zip error: {0}")]
    Zip(String),

    #[error("csv error: {0}")]
    Csv(#[from] csv::Error),
}

impl CoreError {
    /// An IO failure that records which operation and path failed.
    pub fn io(
        operation: &'static str,
        path: impl AsRef<std::path::Path>,
        source: std::io::Error,
    ) -> Self {
        Self::IoAt {
            operation,
            path: path.as_ref().display().to_string(),
            source,
        }
    }

    /// The underlying IO error kind, when this error wraps one.
    pub fn io_kind(&self) -> Option<std::io::ErrorKind> {
        match self {
            Self::Io(source) | Self::IoAt { source, .. } => Some(source.kind()),
            _ => None,
        }
    }
}

pub type CoreResult<T> = Result<T, CoreError>;
