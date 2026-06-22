use crate::defs::*;
use sha2::{Digest, Sha256};

fn compute_magic(key: &str) -> u32 {
    u32::from_le_bytes(Sha256::digest(key.as_bytes())[0..4].try_into().unwrap())
}

fn encode_cmd(key: &str, cmd: i64) -> i64 {
    let magic = compute_magic(key) as i64;
    (magic << 32) | (CKSU_VERSION << 16) | (cmd & 0xFFFF)
}

pub fn hello(key: &str) -> anyhow::Result<i64> {
    let ver = unsafe {
        libc::syscall(
            CKSU_NR,
            b"\0".as_ptr(),
            encode_cmd(key, CKSU_HELLO),
            0i64,
            0i64,
        )
    };
    if ver < 0 {
        anyhow::bail!("hello failed: {ver}");
    }
    Ok(ver)
}

pub fn get_challenge(key: &str) -> anyhow::Result<[u8; NONCE_LEN]> {
    let mut nonce = [0u8; NONCE_LEN];
    let ret = unsafe {
        libc::syscall(
            CKSU_NR,
            b"\0".as_ptr(),
            encode_cmd(key, CKSU_GET_CHALLENGE),
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
    let nonce = get_challenge(key)?;
    let resp = compute_response(key, &nonce);
    let encoded = encode_cmd(key, cmd);
    let ret = unsafe { libc::syscall(CKSU_NR, resp.as_ptr(), encoded, a1, a2) };
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

pub fn get_list(key: &str) -> anyhow::Result<Vec<u32>> {
    let mut buf = [0u32; 256];
    let ret = auth_call(key, CKSU_GET_LIST, buf.as_mut_ptr() as i64, 256)?;
    if ret < 0 {
        anyhow::bail!("get_list failed: {ret}");
    }
    Ok(buf[..ret as usize].to_vec())
}

pub fn add_virt_type(key: &str, type_name: &str, context: &str) -> anyhow::Result<()> {
    #[repr(C)]
    struct VirtTypeData {
        type_name: [u8; 64],
        context: [u8; 128],
    }

    let mut data = VirtTypeData {
        type_name: [0u8; 64],
        context: [0u8; 128],
    };

    let name_bytes = type_name.as_bytes();
    let ctx_bytes = context.as_bytes();
    let name_len = name_bytes.len().min(63);
    let ctx_len = ctx_bytes.len().min(127);
    data.type_name[..name_len].copy_from_slice(&name_bytes[..name_len]);
    data.context[..ctx_len].copy_from_slice(&ctx_bytes[..ctx_len]);

    let ret = auth_call(key, CKSU_ADD_VIRT_TYPE, &data as *const _ as i64, 0)?;
    if ret != 0 {
        anyhow::bail!("add_virt_type failed: {ret}");
    }
    Ok(())
}

pub fn set_su_path(key: &str, path: &str) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let ret = auth_call(key, CKSU_SET_SU_PATH, c_path.as_ptr() as i64, 0)?;
    if ret != 0 {
        anyhow::bail!("set_su_path failed: {ret}");
    }
    Ok(())
}

pub fn get_su_path(key: &str) -> anyhow::Result<String> {
    let mut buf = [0u8; 64];
    let ret = auth_call(key, CKSU_GET_SU_PATH, buf.as_mut_ptr() as i64, buf.len() as i64)?;
    if ret < 0 {
        anyhow::bail!("get_su_path failed: {ret}");
    }
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Ok(String::from_utf8_lossy(&buf[..len]).to_string())
}

pub fn load_sepolicy_rule(key: &str, action: u8, source: u32, target: u32, tclass: u16, perms: u32) -> anyhow::Result<()> {
    #[repr(C)]
    struct SepolicyCmd {
        action: u8,
        _pad: [u8; 3],
        source: u32,
        target: u32,
        tclass: u16,
        _pad2: u16,
        perms: u32,
    }

    let cmd = SepolicyCmd {
        action,
        _pad: [0; 3],
        source,
        target,
        tclass,
        _pad2: 0,
        perms,
    };

    let ret = auth_call(key, CKSU_LOAD_SEPOLICY, &cmd as *const _ as i64, 1)?;
    if ret != 0 {
        anyhow::bail!("load_sepolicy_rule failed: {ret}");
    }
    Ok(())
}
