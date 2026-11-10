use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
};

use rand::RngCore;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("cannot access IPC token file {path}: {source}")]
    Io { path: String, source: io::Error },
    #[error("IPC token file {0} is malformed")]
    Malformed(String),
}

/// Per-run shared secret proving the GUI may talk to the service. 256 bits,
/// stored as hex.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        Self(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Constant-time comparison, so response timing leaks nothing.
    pub fn verify(&self, candidate: &str) -> bool {
        let (a, b) = (self.0.as_bytes(), candidate.as_bytes());
        a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }

    pub fn read(path: &Path) -> Result<Self, TokenError> {
        let text = fs::read_to_string(path).map_err(|source| TokenError::Io { path: path.display().to_string(), source })?;
        let token = text.trim();
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(TokenError::Malformed(path.display().to_string()));
        }
        Ok(Self(token.to_owned()))
    }

    /// Writes the token as [`Token::write_for`] does with no reader, so on
    /// Windows only SYSTEM and Administrators can read it, and leaves the
    /// file in place.
    pub fn write(&self, path: &Path, owner_uid: Option<u32>) -> Result<(), TokenError> {
        self.write_for(path, owner_uid, None).map(TokenFile::keep)
    }

    /// Writes the token for the GUI to read and returns a guard that removes
    /// the file again, so no run (one that ends, fails to start or panics)
    /// leaves it behind. On Unix the file is mode 0600, handed to `owner_uid`
    /// (the service usually runs as root via sudo or pkexec). On Windows it
    /// gets a protected DACL of its own, whatever its folder allows: SYSTEM
    /// and Administrators, and `reader_sid` (`S-1-…`, the GUI's user) to read
    /// it, when given. Either way an existing file or link is replaced, never
    /// written through.
    pub fn write_for(
        &self,
        path: &Path,
        #[cfg_attr(not(unix), allow(unused_variables))] owner_uid: Option<u32>,
        #[cfg_attr(not(windows), allow(unused_variables))] reader_sid: Option<&str>,
    ) -> Result<TokenFile, TokenError> {
        let err = |source| TokenError::Io { path: path.display().to_string(), source };
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).map_err(err)?;
        }
        // Replace rather than overwrite, so a pre-planted file (or link)
        // with looser permissions never ends up holding the secret. Creating
        // fails if one is planted again in between.
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(err(e)),
        }
        #[cfg(windows)]
        let mut file = crate::transport::secret_file_sddl(reader_sid)
            .and_then(|sddl| crate::transport::create_file_with_sddl(path, &sddl))
            .map_err(err)?;
        #[cfg(not(windows))]
        let mut file = {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            options.open(path).map_err(err)?
        };
        // From here on, a failure takes the file away again.
        let written = TokenFile { path: path.to_owned(), keep: false };
        {
            use std::io::Write;
            file.write_all(self.0.as_bytes()).map_err(err)?;
        }
        drop(file);
        #[cfg(unix)]
        if let Some(uid) = owner_uid {
            std::os::unix::fs::chown(path, Some(uid), None).map_err(err)?;
        }
        Ok(written)
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(***)")
    }
}

/// A token file that is removed when this is dropped, however the run that
/// wrote it ends, short of being killed.
#[derive(Debug)]
#[must_use = "dropping it removes the token file"]
pub struct TokenFile {
    path: PathBuf,
    keep: bool,
}

impl TokenFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for TokenFile {
    fn drop(&mut self) {
        if self.keep {
            return;
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => tracing::warn!("cannot remove the token file {}: {e}", self.path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everyone, so the test can read back what it wrote. The service names
    /// the GUI's user.
    const READER: &str = "S-1-1-0";

    fn temp_file(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("captun-token-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir.join("ipc.token")
    }

    #[test]
    fn generate_verify_round_trip() {
        let token = Token::generate();
        assert_eq!(token.as_str().len(), 64);
        assert!(token.verify(token.as_str()));
        assert!(!token.verify(&token.as_str()[1..]));
        assert!(!token.verify(&"0".repeat(64)));
        assert_ne!(token, Token::generate());
    }

    #[test]
    fn a_planted_file_is_replaced_and_the_guard_removes_the_new_one() {
        let path = temp_file("guard");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "planted with the folder's permissions").unwrap();

        let token = Token::generate();
        let written = token.write_for(&path, None, Some(READER)).unwrap();
        assert_eq!(written.path(), path);
        assert_eq!(Token::read(&path).unwrap(), token);
        #[cfg(windows)]
        assert_eq!(crate::transport::file_dacl(&path).unwrap(), "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }

        drop(written);
        assert!(!path.exists(), "the guard removed the file");
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn what_cannot_be_replaced_is_left_alone_and_write_keeps_its_file() {
        // A folder where the file should be cannot be replaced.
        let path = temp_file("blocked");
        fs::create_dir_all(&path).unwrap();
        assert!(Token::generate().write_for(&path, None, Some(READER)).is_err());
        assert!(path.is_dir(), "what was there is left alone");
        fs::remove_dir(&path).unwrap();

        let token = Token::generate();
        token.write(&path, None).unwrap();
        token.write(&path, None).unwrap();
        assert!(path.is_file(), "write leaves the file for its caller");
        // Without a reader, only SYSTEM and Administrators may read it.
        #[cfg(windows)]
        assert_eq!(crate::transport::file_dacl(&path).unwrap(), "D:P(A;;FA;;;SY)(A;;FA;;;BA)");
        #[cfg(unix)]
        assert_eq!(Token::read(&path).unwrap(), token);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn a_reader_that_is_not_a_sid_is_refused() {
        let path = temp_file("injection");
        let err = Token::generate().write_for(&path, None, Some("S-1-5-21)(A;;FA;;;WD")).unwrap_err();
        assert!(matches!(err, TokenError::Io { ref source, .. } if source.kind() == io::ErrorKind::InvalidInput), "{err:?}");
        assert!(!path.exists());
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }
}
