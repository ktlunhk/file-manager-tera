<?php
declare(strict_types=1);
define('TB_NO_AUTH_GATE', true);
require __DIR__ . '/bootstrap.php';

// Logging out changes authentication state: do not allow a link or cross-site GET to trigger it.
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: ' . (!empty($_SESSION['ndus']) ? 'index.php' : 'login.php'), true, 303);
    exit;
}
if (!csrf_ok($_POST['csrf'] ?? null)) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=UTF-8');
    echo 'Logout request expired or invalid. Return to the file manager and try again.';
    exit;
}

tb_log('logout', ['remember_cookie' => isset($_COOKIE['tb_remember']) ? 1 : 0]);
// Remove the encrypted persistent authentication cookie, including its in-request copy.
remember_clear();
unset($_COOKIE['tb_remember']);
// Clear the optional persistent browser identity as part of a full local logout.
setcookie('tb_bid', '', [
    'expires' => time() - 3600, 'path' => '/',
    'secure' => (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off'), 'httponly' => true, 'samesite' => 'Lax',
]);
unset($_COOKIE['tb_bid']);

// Clear all local session data and invalidate the session identifier.
$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $p = session_get_cookie_params();
    setcookie(session_name(), '', [
        'expires' => time() - 3600, 'path' => $p['path'] ?: '/',
        'domain' => $p['domain'] ?? '', 'secure' => (bool)$p['secure'],
        'httponly' => (bool)$p['httponly'], 'samesite' => $p['samesite'] ?? 'Lax',
    ]);
}
session_destroy();
header('Clear-Site-Data: "cache"');
header('Location: login.php', true, 303);
exit;
