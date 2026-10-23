<?php
declare(strict_types=1);
define('TB_NO_AUTH_GATE', true);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/captcha_support.php';
header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");

function captcha_reply(int $status, array $data): void
{
    if (!TB_DEBUG) unset($data['code']);
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    header('Allow: POST');
    captcha_reply(405, ['ok' => false, 'message' => 'Start from the login form. This endpoint accepts protected CAPTCHA requests only.']);
}
if ($_GET !== [] || (int)($_SERVER['CONTENT_LENGTH'] ?? 0) > 4096) {
    captcha_reply(400, ['ok' => false, 'message' => 'Invalid CAPTCHA request.']);
}
if (!csrf_ok(is_string($_POST['csrf'] ?? null) ? $_POST['csrf'] : null)) {
    captcha_reply(403, ['ok' => false, 'message' => csrf_error_message(), 'session_expired' => true, 'csrf' => csrf_token()]);
}
$action = $_POST['action'] ?? '';
if (!in_array($action, ['load', 'verify'], true)) {
    captcha_reply(400, ['ok' => false, 'message' => 'Unsupported CAPTCHA action.']);
}
$pending = &$_SESSION['tb_pending_captcha'];
if (!is_array($pending) || (int)($pending['expires'] ?? 0) <= time()
    || !preg_match('/^[0-9]{8,24}$/D', (string)($pending['request_id'] ?? ''))) {
    unset($_SESSION['tb_pending_captcha']);
    captcha_reply(410, ['ok' => false, 'message' => 'Challenge expired. Make one manual sign-in attempt to obtain a new challenge.']);
}
if ((int)($pending['verify_failures'] ?? 0) >= TB_MAX_CAPTCHA_FAILURES) {
    captcha_reply(429, ['ok' => false, 'message' => 'Challenge attempt limit reached.']);
}
$now = microtime(true);
if ($now - (float)($pending['last_api_call'] ?? 0) < 1) {
    captcha_reply(429, ['ok' => false, 'message' => 'Please wait a moment and try again.']);
}
if ((int)($pending['api_calls'] ?? 0) >= 20) {
    captcha_reply(429, ['ok' => false, 'message' => 'Challenge attempt limit reached. Wait for this challenge to expire.']);
}
$pending['last_api_call'] = $now;
$pending['api_calls'] = (int)($pending['api_calls'] ?? 0) + 1;
$api = new TeraBoxAuth((string)$pending['cookie'], (string)$pending['whost']);
try {
    if ($action === 'load') {
        unset($pending['capt_token'], $pending['ticket_expires'], $pending['challenge_id'], $pending['geometry']);
        $response = $api->getSlide($pending['request_id']);
        $pending['cookie'] = $api->getCookie();
        $code = (int)($response['errno'] ?? $response['code'] ?? -1);
        tb_log('captcha_load', ['code' => $code, 'trace' => $api->getTrace()]);
        if ($code !== 0 || !is_array($response['data'] ?? null)) {
            captcha_reply(502, ['ok' => false, 'message' => 'TeraBox did not return a drag-and-drop challenge.', 'code' => $code]);
        }
        $raw = $response['data'];
        $challengeId = $raw['challenge_id'] ?? null;
        if ((!is_string($challengeId) && !is_int($challengeId)) || (string)$challengeId === '' || strlen((string)$challengeId) > 512) {
            throw new RuntimeException('Unsupported challenge identifier.');
        }
        $render = captcha_render_data($raw);
        $pending['challenge_id'] = (string)$challengeId;
        $pending['geometry'] = array_diff_key($render, ['master_image' => true, 'tile_image' => true]);
        captcha_reply(200, ['ok' => true, 'challenge' => $render]);
    }
    if (empty($pending['challenge_id']) || empty($pending['geometry'])) {
        captcha_reply(409, ['ok' => false, 'message' => 'Load a fresh challenge before verifying.']);
    }
    $g = $pending['geometry'];
    foreach (['delta_x', 'delta_y'] as $field) {
        if (!is_string($_POST[$field] ?? null) || !preg_match('/^-?[0-9]{1,5}$/D', $_POST[$field])) {
            captcha_reply(400, ['ok' => false, 'message' => 'Invalid drag coordinates.']);
        }
    }
    $dx = (int)$_POST['delta_x']; $dy = (int)$_POST['delta_y'];
    if ($dx < -$g['tile_x'] || $dx > $g['master_width'] - $g['tile_width'] - $g['tile_x']
        || $dy < -$g['tile_y'] || $dy > $g['master_height'] - $g['tile_height'] - $g['tile_y']) {
        captcha_reply(400, ['ok' => false, 'message' => 'Drag coordinates are outside the challenge.']);
    }
    $id = $pending['challenge_id'];
    unset($pending['challenge_id'], $pending['geometry']); // one verification per fetched challenge
    $response = $api->checkSlide($pending['request_id'], $id, $dx, $dy);
    $pending['cookie'] = $api->getCookie();
    $code = (int)($response['errno'] ?? $response['code'] ?? -1);
    $token = $response['data']['capt_token'] ?? null;
    $deadline = captcha_ticket_deadline($response['data']['expire'] ?? null, time());
    $accepted = $code === 0 && is_string($token) && $token !== '' && strlen($token) <= 8192 && $deadline > time();
    tb_log('captcha_verify', ['code' => $code, 'ticket_received' => $accepted, 'trace' => $api->getTrace()]);
    if (!$accepted) {
        $pending['verify_failures'] = (int)($pending['verify_failures'] ?? 0) + 1;
        tb_log('captcha_fail', ['attempts' => $pending['verify_failures']]);
        if ($pending['verify_failures'] >= TB_MAX_CAPTCHA_FAILURES) {
            unset($_SESSION['tb_pending_captcha']);
            rl_security_pause();
            captcha_reply(429, ['ok' => false, 'message' => 'Too many verification attempts. Please wait before signing in again.']);
        }
        captcha_reply(200, ['ok' => false, 'message' => $code === 0
            ? 'Could not complete verification. Load another challenge.'
            : 'Verification was not accepted. Load another challenge and try again.', 'code' => $code]);
    }
    $pending['capt_token'] = $token;
    $pending['ticket_expires'] = min($deadline, (int)$pending['expires']);
    captcha_reply(200, ['ok' => true, 'verified' => true, 'message' => 'Verification accepted.']);
} catch (Throwable $exception) {
    $pending['cookie'] = $api->getCookie();
    tb_log('captcha_api_error', ['kind' => get_class($exception), 'trace' => $api->getTrace()]);
    captcha_reply(502, ['ok' => false, 'message' => 'Could not load or verify this challenge. Use the official-site link if it continues.']);
}
