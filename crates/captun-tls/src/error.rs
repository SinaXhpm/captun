use std::{
    io,
    path::{Path, PathBuf},
};

/// What went wrong, in words the person using Captun can act on.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TlsError {
    /// Making or using the CA key needs the Captun service, which runs with
    /// administrator (Windows) or root (Linux, macOS) rights.
    #[error("{0}")]
    NeedsService(&'static str),
    /// The place the CA key is kept could not make, open, use or delete it.
    #[error("Captun could not use its HTTPS inspection key: {0}")]
    Key(String),
    /// A file or folder could not be read, written or deleted.
    #[error("Captun could not {action} {}: {source}", path.display())]
    File {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The folder for the CA is controlled by another account, which could
    /// swap what is kept in it.
    #[error("Captun will not keep its HTTPS inspection certificate in {}: {why}", path.display())]
    UnsafeFolder { path: PathBuf, why: &'static str },
    /// Not a website name or an IP address.
    #[error("Captun cannot make a certificate for {0:?}: it is not a website name or an IP address")]
    BadSiteName(String),
    /// Making or signing a certificate failed.
    #[error("Captun could not make a certificate: {0}")]
    Certificate(String),
    /// The CA has run out (or will within a day), so no site certificate can
    /// be made with it.
    #[error("Captun's HTTPS inspection certificate has run out. Make a new one, then install it again on each device.")]
    CaExpired,
}

/// Turns an I/O error about `path` into [`TlsError::File`].
pub(crate) fn file_error<'a>(action: &'static str, path: &'a Path) -> impl FnOnce(io::Error) -> TlsError + 'a {
    move |source| TlsError::File { action, path: path.to_path_buf(), source }
}
