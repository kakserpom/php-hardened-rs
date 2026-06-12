//! Detects the PHP version and emits `php8x` cfg flags so that
//! version-gated `ext-php-rs` macro features (e.g. readonly classes,
//! PHP 8.2+) compile correctly.

use ext_php_rs_build::{ApiVersion, PHPInfo, emit_check_cfg, emit_rerun_if_env_changed, find_php};

fn main() {
    emit_check_cfg();
    emit_rerun_if_env_changed();

    let php = find_php().expect("could not find PHP executable");
    let info = PHPInfo::get(&php).expect("could not get PHP info");
    let zend_version = info.zend_version().expect("could not get PHP API version");
    let version = ApiVersion::try_from(zend_version).expect("unsupported PHP version");

    for supported_version in version.supported_apis() {
        println!("cargo:rustc-cfg={}", supported_version.cfg_name());
    }
}
