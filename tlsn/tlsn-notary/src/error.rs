use std::error::Error;

use tlsn_tls_mpc::MpcTlsError;

#[derive(Debug, thiserror::Error)]
pub enum NotaryError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    MuxerError(#[from] utils_aio::mux::MuxerError),
    #[error(transparent)]
    CoreError(#[from] tlsn_core::Error),
    #[error("error occurred in MPC protocol: {0}")]
    MpcError(Box<dyn Error>),
}

impl From<MpcTlsError> for NotaryError {
    fn from(e: MpcTlsError) -> Self {
        Self::MpcError(Box::new(e))
    }
}

#[derive(Debug)]
pub struct OTShutdownError;

impl std::fmt::Display for OTShutdownError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ot shutdown prior to completion")
    }
}

impl Error for OTShutdownError {}

impl From<OTShutdownError> for NotaryError {
    fn from(e: OTShutdownError) -> Self {
        Self::MpcError(Box::new(e))
    }
}
