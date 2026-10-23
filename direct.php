<?php
declare(strict_types=1);
/**
 * Public direct-download endpoint: direct.php?t=<token>
 * Streams a file from the owner's TeraBox account, so visitors need no TeraBox sign-in.
 * No session is started here; the 64-hex token is the only credential.
 */
define('TB_NO_AUTH_GATE', true);
require __DIR__ . '/config.php';
require __DIR__ . '/TeraBoxAuth.php';
require __DIR__ . '/direct_lib.php';

function direct_fail(int $code, string $msg): void
{
    if (!headers_sent()) {
        http_response_code($code);
        header('Content-Type: text/plain; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Robots-Tag: noindex, nofollow');
    }
    echo $msg;
    exit;
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method !== 'GET' && $method !== 'HEAD') { header('Allow: GET, HEAD'); direct_fail(405, 'Method not allowed.'); }

$token = isset($_GET['t']) && is_string($_GET['t']) ? $_GET['t'] : '';
$rec = TeraDirect::load($token);
if (!$rec) direct_fail(404, 'This link does not exist or has expired.');

@set_time_limit(0);
ignore_user_abort(false);
while (ob_get_level() > 0) @ob_end_clean();

try {
    $api = new TeraBoxAuth((string)$rec['cookie'], (string)($rec['whost'] ?? '') ?: null);
    $dlink = $api->getDownloadLink((string)$rec['path'], (int)$rec['fs']);
} catch (Throwable $e) {
    error_log('[tbfm] direct link failed: ' . preg_replace('/[^\w .,:;()\/-]/', '', $e->getMessage()));
    direct_fail(502, 'The file is temporarily unavailable. Ask the owner to open the file manager and refresh the link.');
}

$name = (string)$rec['name'];
$ascii = preg_replace('/[^A-Za-z0-9._-]+/', '_', $name);
if ($ascii === '' || $ascii === null) $ascii = 'download';
$range = isset($_SERVER['HTTP_RANGE']) && is_string($_SERVER['HTTP_RANGE']) ? $_SERVER['HTTP_RANGE'] : '';

$sendHeaders = function (int $status, array $up) use ($ascii, $name): void {
    http_response_code($status);
    header('Content-Type: application/octet-stream');      // never let the browser render a file from this domain
    header('Content-Disposition: attachment; filename="' . $ascii . '"; filename*=UTF-8\'\'' . rawurlencode($name));
    header('X-Content-Type-Options: nosniff');
    header('Cache-Control: private, no-store');
    header('X-Robots-Tag: noindex, nofollow');
    header('Accept-Ranges: bytes');
    if (isset($up['content-length']) && ctype_digit($up['content-length'])) header('Content-Length: ' . $up['content-length']);
    if (isset($up['content-range']) && preg_match('#^bytes [\d*/\- ]+$#D', $up['content-range'])) header('Content-Range: ' . $up['content-range']);
};
$sendBody = function (string $chunk): bool {
    echo $chunk;
    flush();
    return !connection_aborted();
};

try {
    $api->streamUrl($dlink, $range, $method === 'HEAD', $sendHeaders, $sendBody);
} catch (Throwable $e) {
    error_log('[tbfm] direct stream failed: ' . preg_replace('/[^\w .,:;()\/-]/', '', $e->getMessage()));
    if (!headers_sent()) direct_fail(502, 'The file could not be downloaded right now. Please try again.');
}
