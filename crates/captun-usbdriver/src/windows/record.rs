//! What Captun installed, noted under `HKLM\SOFTWARE\Captun` (which only
//! administrators may change), so that removing it takes exactly that: the
//! name Windows gave the INF in its driver store, and the certificate's
//! thumbprint.

use std::{io, ptr};

use windows_sys::{
    Win32::{
        Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR},
        System::Registry::{
            HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY, REG_OPTION_NON_VOLATILE, REG_SZ,
            RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegGetValueW, RegOpenKeyExW, RegSetValueExW,
        },
    },
    core::{PCWSTR, w},
};

use super::system::from_wide;

const KEY: PCWSTR = w!("SOFTWARE\\Captun");
const INF: PCWSTR = w!("UsbDriverInf");
const CERTIFICATE: PCWSTR = w!("UsbDriverCertificate");
const VERSION: PCWSTR = w!("UsbDriverVersion");

/// What was installed. Every part is optional: an install notes the
/// certificate before trusting it, and the INF's name once Windows gives it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Record {
    /// The name Windows gave the INF (`oemNN.inf`).
    pub(super) inf: Option<String>,
    /// The certificate's SHA-1 thumbprint, in hex.
    pub(super) thumbprint: Option<String>,
    /// The package's version.
    pub(super) version: Option<String>,
}

impl Record {
    pub(super) fn is_empty(&self) -> bool {
        self.inf.is_none() && self.thumbprint.is_none() && self.version.is_none()
    }
}

pub(super) fn read() -> io::Result<Record> {
    let Some(key) = Key::open()? else { return Ok(Record::default()) };
    Ok(Record { inf: key.get(INF)?, thumbprint: key.get(CERTIFICATE)?, version: key.get(VERSION)? })
}

/// Notes `record` as a whole: a part it leaves out is removed.
pub(super) fn write(record: &Record) -> io::Result<()> {
    let key = Key::create()?;
    key.set(INF, record.inf.as_deref())?;
    key.set(CERTIFICATE, record.thumbprint.as_deref())?;
    key.set(VERSION, record.version.as_deref())
}

/// Forgets it all. The key stays: other parts of Captun may note things
/// there too.
pub(super) fn clear() -> io::Result<()> {
    if Key::open()?.is_none() {
        return Ok(());
    }
    write(&Record::default())
}

/// The 64-bit view of the key, whichever build reads it.
struct Key(HKEY);

impl Key {
    /// The key if it is there.
    fn open() -> io::Result<Option<Self>> {
        let mut key: HKEY = ptr::null_mut();
        // SAFETY: `KEY` is a static NUL-terminated string; `key` is a valid
        // place for the handle written.
        let status = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, KEY, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &mut key) };
        match status {
            ERROR_SUCCESS => Ok(Some(Self(key))),
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(os_error(other)),
        }
    }

    /// The key, made if it is not there yet with the permissions it takes
    /// from `HKLM\SOFTWARE`.
    fn create() -> io::Result<Self> {
        let mut key: HKEY = ptr::null_mut();
        // SAFETY: `KEY` is a static NUL-terminated string; no class, default
        // security; `key` is a valid place for the handle written, and the
        // disposition is not wanted.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                KEY,
                0,
                ptr::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY,
                ptr::null(),
                &mut key,
                ptr::null_mut(),
            )
        };
        if status != ERROR_SUCCESS {
            return Err(os_error(status));
        }
        Ok(Self(key))
    }

    fn get(&self, name: PCWSTR) -> io::Result<Option<String>> {
        let mut size = 0u32;
        // SAFETY: `name` is a static NUL-terminated string; a null buffer
        // asks only for the size, written to `size`.
        let status = unsafe {
            RegGetValueW(self.0, ptr::null(), name, RRF_RT_REG_SZ, ptr::null_mut(), ptr::null_mut(), &mut size)
        };
        match status {
            ERROR_SUCCESS => {}
            ERROR_FILE_NOT_FOUND => return Ok(None),
            other => return Err(os_error(other)),
        }
        let mut buf = vec![0u16; (size as usize).div_ceil(2).max(1)];
        let mut size = u32::try_from(buf.len() * 2).map_err(io::Error::other)?;
        // SAFETY: `buf` has room for `size` bytes, as `size` says.
        let status = unsafe {
            RegGetValueW(self.0, ptr::null(), name, RRF_RT_REG_SZ, ptr::null_mut(), buf.as_mut_ptr().cast(), &mut size)
        };
        match status {
            ERROR_SUCCESS => Ok(Some(from_wide(&buf)).filter(|value| !value.is_empty())),
            ERROR_FILE_NOT_FOUND => Ok(None),
            other => Err(os_error(other)),
        }
    }

    /// Sets the value `name` to `value`, or removes it for `None`.
    fn set(&self, name: PCWSTR, value: Option<&str>) -> io::Result<()> {
        let status = match value {
            Some(value) => {
                let mut units: Vec<u16> = value.encode_utf16().collect();
                units.push(0);
                let bytes = u32::try_from(units.len() * 2).map_err(io::Error::other)?;
                // SAFETY: `name` is a static NUL-terminated string; `units`
                // holds `bytes` bytes of NUL-terminated UTF-16 for the call.
                unsafe { RegSetValueExW(self.0, name, 0, REG_SZ, units.as_ptr().cast(), bytes) }
            }
            None => {
                // SAFETY: `name` is a static NUL-terminated string.
                match unsafe { RegDeleteValueW(self.0, name) } {
                    ERROR_FILE_NOT_FOUND => ERROR_SUCCESS,
                    other => other,
                }
            }
        };
        if status == ERROR_SUCCESS { Ok(()) } else { Err(os_error(status)) }
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: the key was opened by this module and is closed once.
        unsafe { RegCloseKey(self.0) };
    }
}

fn os_error(status: WIN32_ERROR) -> io::Error {
    io::Error::from_raw_os_error(status.cast_signed())
}
