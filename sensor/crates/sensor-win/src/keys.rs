//! Vault master key. MVP: 32 random bytes protected with DPAPI (machine scope)
//! in the SYSTEM-only data dir. M4: sealed to the TPM via the NCrypt Platform
//! Crypto Provider so the key never exists in clear on disk.

use std::path::PathBuf;
use vault::{KeyProvider, VaultError};
use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
};

pub struct DpapiKey {
    path: PathBuf,
}

impl DpapiKey {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

fn io(e: impl std::fmt::Display) -> VaultError {
    VaultError::Io(std::io::Error::other(e.to_string()))
}

unsafe fn take(blob: CRYPT_INTEGER_BLOB) -> Vec<u8> {
    let v = unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) }.to_vec();
    unsafe { LocalFree(Some(HLOCAL(blob.pbData as _))) };
    v
}

impl KeyProvider for DpapiKey {
    fn master_key(&self) -> Result<[u8; 32], VaultError> {
        if let Ok(sealed) = std::fs::read(&self.path) {
            let input = CRYPT_INTEGER_BLOB { cbData: sealed.len() as u32, pbData: sealed.as_ptr() as *mut u8 };
            let mut out = CRYPT_INTEGER_BLOB::default();
            unsafe { CryptUnprotectData(&input, None, None, None, None, CRYPTPROTECT_LOCAL_MACHINE, &mut out) }.map_err(io)?;
            let key = unsafe { take(out) };
            return key.try_into().map_err(|_| VaultError::Crypto);
        }
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
        let input = CRYPT_INTEGER_BLOB { cbData: 32, pbData: key.as_mut_ptr() };
        let mut out = CRYPT_INTEGER_BLOB::default();
        unsafe { CryptProtectData(&input, None, None, None, None, CRYPTPROTECT_LOCAL_MACHINE, &mut out) }.map_err(io)?;
        std::fs::write(&self.path, unsafe { take(out) })?;
        Ok(key)
    }
}
