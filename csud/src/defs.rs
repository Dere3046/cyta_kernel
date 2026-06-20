pub const CKSU_DIR: &str = "/data/adb/cksu";
pub const BIN_DIR: &str = "/data/adb/cksu/bin";
pub const MODULE_DIR: &str = "/data/adb/cksu/modules";
pub const MODULE_UPDATE_DIR: &str = "/data/adb/cksu/modules_update";
pub const BUSYBOX_PATH: &str = "/data/adb/cksu/bin/busybox";
pub const CSUD_PATH: &str = "/data/adb/cksu/bin/csud";

pub const CKSU_NR: i64 = 45; // __NR_truncate
pub const CKSU_HELLO: i64 = 0x0001;
pub const CKSU_GET_CHALLENGE: i64 = 0x1000;
pub const CKSU_GRANT_ROOT: i64 = 0x1001;
pub const CKSU_ADD_UID: i64 = 0x1002;
pub const CKSU_REMOVE_UID: i64 = 0x1003;
pub const CKSU_GET_LIST: i64 = 0x1004;
pub const CKSU_LOAD_SEPOLICY: i64 = 0x1010;
pub const CKSU_CLEAR_SEPOLICY: i64 = 0x1011;
pub const CKSU_SET_VIRT_DOMAIN: i64 = 0x1012;
pub const CKSU_REPORT_EVENT: i64 = 0x1020;

pub const HASH_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;
