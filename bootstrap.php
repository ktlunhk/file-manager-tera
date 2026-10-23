<?php
declare(strict_types=1);
require_once __DIR__ . '/config.php';
if (!TB_DEBUG) ini_set('display_errors', '0');

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

ini_set('session.use_strict_mode', '1');
ini_set('session.use_cookies', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_trans_sid', '0');
// Isolate this application from PHPSESSID cookies used by other hosted apps.
session_name('TBSESSID_' . substr(hash('sha256', __DIR__), 0, 12));
$tbCookiePath = str_replace('\\', '/', dirname($_SERVER['SCRIPT_NAME'] ?? '/index.php'));
$tbCookiePath = rtrim($tbCookiePath, '/') . '/';
// Private session folder outside the web root: shared hosts often purge the default one after a few minutes.
$tbSessDir = sys_get_temp_dir() . '/tbfm_sessions_' . substr(hash('sha256', __DIR__), 0, 12);
if (!is_dir($tbSessDir)) { @mkdir($tbSessDir, 0700, true); }
if (is_dir($tbSessDir) && is_writable($tbSessDir)) {
    session_save_path($tbSessDir);
    ini_set('session.gc_maxlifetime', '604800');
}
session_set_cookie_params([
    'lifetime' => 0,
    'path'     => $tbCookiePath,
    'domain'   => '', // Do not inherit another application's session.cookie_domain.
    'secure'   => (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off'),
    'httponly' => true,
    'samesite' => 'Lax',
]);
if (!session_start()) {
    http_response_code(503);
    exit('Unable to start a secure session. Please contact the site administrator.');
}

require_once __DIR__ . '/TeraBoxAuth.php';

function e(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }

function csrf_token(): string
{
    $key = app_key();
    if ($key === null) {                                   // cannot store a key: fall back to the session
        if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(32)); }
        return $_SESSION['csrf'];
    }
    $body = time() . '.' . bin2hex(random_bytes(8));
    return $body . '.' . hash_hmac('sha256', 'csrf|' . session_id() . '|' . $body, $key);
}

function csrf_ok($t): bool
{
    $GLOBALS['tb_csrf_reason'] = '';
    if (!is_string($t) || $t === '') { $GLOBALS['tb_csrf_reason'] = 'token_missing'; return false; }
    $key = app_key();
    if ($key === null) {
        $ok = !empty($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $t);
        if (!$ok) $GLOBALS['tb_csrf_reason'] = empty($_SESSION['csrf']) ? 'session_lost' : 'session_mismatch';
        return $ok;
    }
    $parts = explode('.', $t);
    if (count($parts) !== 3) { $GLOBALS['tb_csrf_reason'] = 'bad_format'; return false; }
    [$ts, $rnd, $mac] = $parts;
    if (!ctype_digit($ts)) { $GLOBALS['tb_csrf_reason'] = 'bad_format'; return false; }
    if (time() - (int)$ts > 21600) { $GLOBALS['tb_csrf_reason'] = 'expired_' . (time() - (int)$ts) . 's'; return false; }
    if ((int)$ts > time() + 60) { $GLOBALS['tb_csrf_reason'] = 'from_future'; return false; }
    if (!hash_equals(hash_hmac('sha256', 'csrf|' . session_id() . '|' . $ts . '.' . $rnd, $key), $mac)) { $GLOBALS['tb_csrf_reason'] = 'bad_signature'; return false; }
    return true;
}

function csrf_error_message(): string
{
    return empty($_COOKIE[session_name()])
        ? 'Your session cookie was not received. Reload this page and allow cookies for this site before signing in.'
        : 'Your form session expired. Please try again. If verification was open, start a new challenge.';
}

/* ---------- server-side login throttle (per client IP; survives clearing browser data) ---------- */

function rl_file(): string
{
    return sys_get_temp_dir() . '/tbfm_rl_' . hash('sha256', $_SERVER['REMOTE_ADDR'] ?? 'unknown');
}

/** Seconds the client must still wait before another login attempt (0 = go ahead). */
function rl_wait(): int
{
    if (!TB_LOGIN_THROTTLE) return 0;
    $f = @fopen(rl_file(), 'c+');
    if (!$f) return 60; // fail closed when protection storage is unavailable
    try {
        if (!flock($f, LOCK_SH)) return 60;
        rewind($f);
        $d = json_decode((string)stream_get_contents($f), true);
        flock($f, LOCK_UN);
        return is_array($d) ? max(0, (int)($d['until'] ?? 0) - time()) : 0;
    } finally { fclose($f); }
}

/** Atomic, per-IP login failure tracking. Maximum failures require a cooldown. */
function rl_fail(): void
{
    if (!TB_LOGIN_THROTTLE) return;
    $f = @fopen(rl_file(), 'c+');
    if (!$f) return;
    try {
        if (!flock($f, LOCK_EX)) return;
        rewind($f);
        $d = json_decode((string)stream_get_contents($f), true);
        $now = time();
        $fails = (is_array($d) && $now - (int)($d['last'] ?? 0) < 1800) ? (int)($d['fails'] ?? 0) : 0;
        $fails++;
        $wait = $fails >= TB_MAX_LOGIN_FAILURES ? TB_LOGIN_LOCKOUT_SECONDS : min(600, 30 * (2 ** min(10, $fails - 1)));
        rewind($f); ftruncate($f, 0);
        fwrite($f, json_encode(['fails' => $fails, 'last' => $now, 'until' => $now + $wait]));
        fflush($f); flock($f, LOCK_UN);
    } finally { fclose($f); }
}

/** Temporary safety pause for security-related upstream errors. */
function rl_security_pause(): void
{
    if (!TB_LOGIN_THROTTLE || !TB_STOP_ON_SECURITY_ERROR) return;
    $f = @fopen(rl_file(), 'c+');
    if (!$f) return;
    try {
        if (!flock($f, LOCK_EX)) return;
        rewind($f); $d = json_decode((string)stream_get_contents($f), true);
        $now = time();
        $d = is_array($d) ? $d : [];
        $d['last'] = $now;
        $d['until'] = max((int)($d['until'] ?? 0), $now + TB_LOGIN_LOCKOUT_SECONDS);
        rewind($f); ftruncate($f, 0); fwrite($f, json_encode($d)); fflush($f);
        flock($f, LOCK_UN);
    } finally { fclose($f); }
}

function rl_reset(): void { @unlink(rl_file()); }

/** Shared browser identification cookie, never readable by JavaScript. */
function tb_set_browser_id(string $id): void
{
    if ($id === '') return;
    setcookie('tb_bid', $id, [
        'expires' => time() + 31536000, 'path' => '/',
        'secure' => (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off'),
        'httponly' => true, 'samesite' => 'Lax',
    ]);
}

/* ---------- "keep me signed in": encrypted cookie holding only the TeraBox session token ---------- */

function app_key(): ?string
{
    $f = __DIR__ . '/secret.key.php';
    if (is_file($f)) {
        $k = @include $f;
        if (is_string($k) && strlen($k) === 64 && ctype_xdigit($k)) return hex2bin($k);
    }
    $hex = bin2hex(random_bytes(32));
    if (@file_put_contents($f, "<?php return '$hex';\n", LOCK_EX) === false) return null;
    @chmod($f, 0600);
    return hex2bin($hex);
}

function remember_set(array $data): void
{
    $key = app_key();
    if ($key === null) return;                     // cannot store a key: silently skip the feature
    $data['exp'] = time() + 30 * 86400;
    $iv  = random_bytes(12);
    $ct  = openssl_encrypt(json_encode($data), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ct === false) return;
    setcookie('tb_remember', rtrim(strtr(base64_encode($iv . $tag . $ct), '+/', '-_'), '='), [
        'expires' => time() + 30 * 86400, 'path' => '/',
        'secure' => (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off'), 'httponly' => true, 'samesite' => 'Lax',
    ]);
}

function remember_get(): ?array
{
    $key = app_key();
    $c = (string)($_COOKIE['tb_remember'] ?? '');
    if ($key === null || $c === '') return null;
    $raw = base64_decode(strtr($c, '-_', '+/'), true);
    if ($raw === false || strlen($raw) < 30) return null;
    $pt = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
    $d  = $pt === false ? null : json_decode($pt, true);
    return (is_array($d) && ($d['exp'] ?? 0) > time() && !empty($d['ndus'])) ? $d : null;
}

function remember_clear(): void
{
    setcookie('tb_remember', '', ['expires' => time() - 3600, 'path' => '/', 'secure' => (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off'),
                                  'httponly' => true, 'samesite' => 'Lax']);
}


/* ---------- analysis log ----------
 * Appends one JSON object per line to terabox_log.php in this folder (the first line is a PHP guard,
 * so a browser request to the file returns 404; open it over FTP / the host's file manager).
 * Never logged: passwords, cookies, ndus tokens, response bodies. Emails are masked.
 * Set TB_LOG_ENABLED to false to switch it off.
 */

function tb_mask_email(string $e): string
{
    $p = explode('@', $e, 2);
    return ($p[0] !== '' ? $p[0][0] : '') . '***@' . ($p[1] ?? '');
}

function tb_clean($v)
{
    if (is_array($v)) return array_map('tb_clean', $v);
    if (is_string($v)) return substr(preg_replace('/[\r\n\t]+/', ' ', $v), 0, 300);
    return $v;
}

function tb_log(string $event, array $ctx = []): void
{
    if (!TB_LOG_ENABLED) return;
    try {
        $f = __DIR__ . '/terabox_log.php';
        $guard = "<?php http_response_code(404); exit; ?>\n";
        if (!is_file($f)) {
            @file_put_contents($f, $guard, LOCK_EX);
            @chmod($f, 0640);
        } elseif ((int)@filesize($f) > TB_LOG_MAX) {
            @rename($f, __DIR__ . '/terabox_log.1.php');
            @file_put_contents($f, $guard, LOCK_EX);
        }
        $row = ['t' => gmdate('c'), 'ev' => $event, 'ip_hash' => substr(hash('sha256', (string)($_SERVER['REMOTE_ADDR'] ?? '-')), 0, 12),
                'sid' => substr(hash('sha256', session_id()), 0, 8),          // same value on GET and POST = session survived
                'sess_cookie' => isset($_COOKIE[session_name()]) ? 1 : 0];    // did the browser send the session cookie?
        @file_put_contents($f, json_encode($row + tb_clean($ctx), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
    } catch (Throwable $e) {
        // logging must never break the page
    }
}

function tb_env(): array
{
    return ['php' => PHP_VERSION, 'https' => (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') ? 1 : 0,
            'xfp' => $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '', 'host' => $_SERVER['HTTP_HOST'] ?? '',
            'sess_path_ok' => is_writable(session_save_path() ?: sys_get_temp_dir()) ? 1 : 0,
            'key_ok' => app_key() !== null ? 1 : 0];
}

function tb_public_error(string $detail, string $message): string { return TB_DEBUG ? $detail : $message; }


/* ---------- sign-in audit (same record format as the MEGA version) ----------
 * One JSON object per line in user_login_YYYY-MM-DD.php (UTC day). The first line is a PHP guard, so a
 * browser request returns 404; read the files over FTP / the host's file manager.
 * Only this fixed schema is written. Never logged: passwords, cookies, ndus tokens, captcha data.
 * Controlled by $user_logging_* in config.php (off by default). Separate from the diagnostic tb_log().
 */
if (!function_exists('fm_log_user_login')) {
function fm_log_user_login($username, $success, $category = '') {
    if (($GLOBALS['user_logging_enabled'] ?? false) !== true) return;
    try {
        $zone = new DateTimeZone($GLOBALS['user_logging_timezone'] ?? 'UTC');
        $now = new DateTimeImmutable('now', $zone);
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) $ip = '';
        $clean = function($value, $limit) {
            if (!is_string($value)) return '';
            $value = substr($value, 0, $limit);
            // Drop malformed UTF-8 rather than allowing it to break the record.
            if (!preg_match('//u', $value)) $value = function_exists('iconv') ? @iconv('UTF-8', 'UTF-8//IGNORE', $value) : preg_replace('/[\x80-\xff]/', '', $value);
            return is_string($value) ? $value : '';
        };
        $categories = ['invalid_credentials', 'invalid_security_token', 'login_cooldown', 'verification_required', 'two_factor_required', 'invalid_two_factor', 'service_error', 'invalid_request'];
        if (!isset($GLOBALS['fm_login_request_id'])) $GLOBALS['fm_login_request_id'] = bin2hex(random_bytes(16));
        $id = $GLOBALS['fm_login_request_id'];
        $storage = $GLOBALS['storage_type'] ?? 'terabox';
        $entry = json_encode([
            'datetime' => $now->format('Y-m-d\TH:i:sP'),
            'timezone' => $zone->getName(),
            'username' => $clean($username, 512),
            'ip' => $ip,
            'status' => $success ? 'success' : 'failure',
            'failure_category' => $success ? null : (in_array($category, $categories, true) ? $category : 'service_error'),
            'storage' => in_array($storage, ['mega', 'terabox', 'local'], true) ? $storage : 'terabox',
            'browser' => $clean($_SERVER['HTTP_USER_AGENT'] ?? '', 1024),
            'request_id' => $id
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
        if ($entry === false) throw new RuntimeException('Invalid audit entry');
        // UTC filenames keep retention unambiguous if the display timezone changes.
        $path = __DIR__ . '/user_login_' . gmdate('Y-m-d') . '.php';
        if (is_link($path)) throw new RuntimeException('Unsafe audit file');
        $fh = @fopen($path, 'c+b');
        if (!$fh) throw new RuntimeException('Audit file unavailable');
        @chmod($path, 0600);
        $prefix = "<?php http_response_code(404); exit; ?>\n";
        try {
            if (!flock($fh, LOCK_EX)) throw new RuntimeException('Audit lock unavailable');
            rewind($fh); $current = fread($fh, strlen($prefix));
            if ($current !== '' && $current !== $prefix) throw new RuntimeException('Invalid audit file');
            fseek($fh, 0, SEEK_END);
            $bytes = ($current === '' ? $prefix : '') . $entry . "\n";
            while ($bytes !== '') {
                $written = fwrite($fh, $bytes);
                if (!$written) throw new RuntimeException('Audit write failed');
                $bytes = substr($bytes, $written);
            }
            if (!fflush($fh)) throw new RuntimeException('Audit flush failed');
        } finally { flock($fh, LOCK_UN); fclose($fh); }
        if (!headers_sent()) header('X-Request-ID: ' . $id);
        $days = $GLOBALS['user_logging_retention_days'] ?? 30;
        if (!is_int($days) || $days < 0 || $days > 3650) $days = 30;
        if ($days > 0) {
            $cutoff = (new DateTimeImmutable('today', new DateTimeZone('UTC')))->modify('-' . ($days - 1) . ' days')->format('Y-m-d');
            foreach (glob(__DIR__ . '/user_login_????-??-??.php') ?: [] as $old) {
                if (is_link($old) || !is_file($old) || !preg_match('/\Auser_login_(\d{4}-\d{2}-\d{2})\.php\z/', basename($old), $m) || $m[1] >= $cutoff) continue;
                $parts = explode('-', $m[1]);
                if (!checkdate((int)$parts[1], (int)$parts[2], (int)$parts[0])) continue;
                $candidate = @fopen($old, 'rb');
                if (!$candidate) continue;
                $protected = fread($candidate, strlen($prefix)) === $prefix;
                fclose($candidate);
                if ($protected) @unlink($old);
            }
        }
    } catch (Throwable $e) {
        // A logging failure never prevents login and never discloses credentials.
        error_log('[filemanager] Unable to write login audit. Check folder permissions and logging configuration.');
    }
}
}
