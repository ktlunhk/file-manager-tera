<?php
/**
 * TeraBox File Manager — settings.
 * The file-manager UI is the one from the MEGA version; storage is TeraBox (terabox:// via terabox_wrapper.php).
 */

/* ---- Sign-in (login.php) ---- */
const TB_TOKEN_LOGIN_ENABLED = false; // true shows the "sign in with ndus session token" form
const TB_DEBUG = false;               // true shows detailed upstream errors
const TB_LOG_ENABLED = true;          // private diagnostic log (terabox_log.php); set false once everything works
const TB_CAPTCHA_AUTO_SUBMIT = true;  // sign in once automatically after the slider check succeeds

const TB_LOGIN_THROTTLE = true;
// Conservative local safety limits; these are NOT published TeraBox limits.
const TB_MAX_LOGIN_FAILURES = 3;
const TB_LOGIN_LOCKOUT_SECONDS = 1800;
const TB_MAX_CAPTCHA_FAILURES = 3;
const TB_STOP_ON_SECURITY_ERROR = true;
const TB_REUSE_BROWSER_ID = true;
const TB_LOG_MAX = 1048576;

/* ---- Direct download links (direct.php) ---- */
// Days a direct link stays valid. 0 = never expires (until you stop it).
const TB_DIRECT_DAYS = 30;

/* ---- File manager ---- */
$storage_type = 'terabox';
$use_auth = false;                 // sign-in is handled by login.php, not by Tiny File Manager
$root_path = 'terabox://root';     // TeraBox "/" folder

// login.php, image.php and logout.php define TB_NO_AUTH_GATE; every other page requires a signed-in session.
if (!defined('TB_NO_AUTH_GATE')) {
    require_once __DIR__ . '/terabox_wrapper.php';
    tb_require_login();
}
