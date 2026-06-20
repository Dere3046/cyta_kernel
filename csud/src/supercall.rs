use crate::defs::*;
use sha2::{Digest, Sha256};

pub fn hello() -> i64 {
    unsafe { libc::syscall(CKSU_NR, b"\0".as_ptr(), CKSU_HELLO, 0i64, 0i64) }
}

pub fn get_challenge() -> anyhow::Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    let ret = unsafe {
        libc::syscall(
            CKSU_NR,
            b"\0".as_ptr(),
            CKSU_GET_CHALLENGE,
            nonce.as_mut_ptr() as i64,
            0i64,
        )
    };
    if ret != 0 {
        anyhow::bail!("get_challenge failed: {ret}");
    }
    Ok(nonce)
}

fn compute_response(key: &str, nonce: &[u8; NONCE_LEN]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(nonce);
    hasher.finalize().into()
}

pub fn auth_call(key: &str, cmd: i64, a1: i64, a2: i64) -> anyhow::Result<i64> {
    let nonce = get_challenge()?;
    let resp = compute_response(key, &nonce);
    let ret = unsafe { libc::syscall(CKSU_NR, resp.as_ptr(), cmd, a1, a2) };
    Ok(ret)
}

pub fn grant_root(key: &str) -> anyhow::Result<()> {
    let ret = auth_call(key, CKSU_GRANT_ROOT, 0, 0)?;
    if ret != 0 {
        anyhow::bail!("grant_root failed: {ret}");
    }
    Ok(())
}

pub fn add_uid(key: &str, uid: u32) -> anyhow::Result<()> {
    let ret = auth_call(key, CKSU_ADD_UID, uid as i64, 0)?;
    if ret != 0 {
        anyhow::bail!("add_uid failed: {ret}");
    }
    Ok(())
}

pub fn remove_uid(key: &str, uid: u32) -> anyhow::Result<()> {
    let ret = auth_call(key, CKSU_REMOVE_UID, uid as i64, 0)?;
    if ret != 0 {
        anyhow::bail!("remove_uid failed: {ret}");
    }
    Ok(())
}
