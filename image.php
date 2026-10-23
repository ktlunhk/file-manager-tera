<?php
declare(strict_types=1);
/**
 * CAPTCHA endpoint used by captcha.js (actions: load, verify).
 *
 * Always answers JSON. The TeraBox cookie jar, the challenge id and the verified
 * ticket stay in the PHP session; the browser only receives rendering data.
 */
define('TB_NO_AUTH_GATE', true);

// Never let a PHP warning/notice or fatal turn into an HTML page: captcha.js parses JSON.
ini_set('display_errors', '0');
ob_start();

function image_out(array $payload, int $status = 200): void
{
    while (ob_get_level() > 0) { ob_end_clean(); }
    http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($payload, JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES);
    exit;
}

register_shutdown_function(function (): void {
    $e = error_get_last();
    if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        while (ob_get_level() > 0) { @ob_end_clean(); }
        if (!headers_sent()) {
            http_response_code(500);
            header('Content-Type: application/json; charset=UTF-8');
        }
        echo json_encode(['ok' => false, 'message' => 'The challenge service failed. Please try again.']);
    }
});

try {
    require __DIR__ . '/bootstrap.php';
    require __DIR__ . '/captcha_support.php';
} catch (Throwable $e) {
    image_out(['ok' => false, 'message' => 'The challenge service could not start.'], 500);
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    image_out(['ok' => false, 'message' => 'POST required.'], 405);
}
if (!csrf_ok($_POST['csrf'] ?? null)) {
    image_out(['ok' => false, 'session_expired' => true, 'csrf' => csrf_token(),
               'message' => csrf_error_message()], 403);
}

$action = (string)($_POST['action'] ?? '');
$now = time();
$pending = $_SESSION['tb_pending_captcha'] ?? null;
if (!is_array($pending) || (int)($pending['expires'] ?? 0) <= $now
    || !preg_match('/^[0-9]{8,24}$/D', (string)($pending['request_id'] ?? ''))) {
    unset($_SESSION['tb_pending_captcha']);
    image_out(['ok' => false, 'session_expired' => true, 'csrf' => csrf_token(),
               'message' => 'The verification expired. Enter your password and sign in again.'], 410);
}
$rid = (string)$pending['request_id'];

/** Upstream answers either flat or under "data"; return the first array holding any of $keys. */
function image_pick(array $r, array $keys): array
{
    foreach ([$r, $r['data'] ?? null, $r['data']['challenge'] ?? null, $r['challenge'] ?? null] as $c) {
        if (!is_array($c)) continue;
        foreach ($keys as $k) {
            if (array_key_exists($k, $c)) return $c;
        }
    }
    return [];
}
function image_code(array $r): int { return (int)($r['errno'] ?? $r['code'] ?? 0); }

try {
    $auth = new TeraBoxAuth((string)$pending['cookie'], (string)$pending['whost']);

    if ($action === 'load') {
        // Cap how many challenges one failed login may pull.
        $pending['loads'] = (int)($pending['loads'] ?? 0) + 1;
        if ($pending['loads'] > 20) {
            $_SESSION['tb_pending_captcha'] = $pending;
            image_out(['ok' => false, 'message' => 'Too many challenges. Sign in again to start over.'], 429);
        }
        unset($pending['challenge_id'], $pending['capt_token'], $pending['ticket_expires'], $pending['tile_x'], $pending['tile_y']);

        $r = $auth->getSlide($rid);
        $pending['cookie'] = $auth->getCookie();
        if (image_code($r) !== 0) {
            $_SESSION['tb_pending_captcha'] = $pending;
            tb_log('captcha_load_rejected', ['code' => image_code($r), 'keys' => array_keys($r)]);
            image_out(['ok' => false, 'message' => 'TeraBox did not provide a challenge. Load another challenge or sign in again.'], 502);
        }
        $d = image_pick($r, ['master_image']);
        $cid = $d['challenge_id'] ?? $r['challenge_id'] ?? ($r['data']['challenge_id'] ?? '');
        if (!is_string($cid) && !is_int($cid)) $cid = '';
        $cid = (string)$cid;
        if ($d === [] || $cid === '' || strlen($cid) > 512) {
            $_SESSION['tb_pending_captcha'] = $pending;
            tb_log('captcha_load_shape', ['keys' => array_keys($r), 'data_keys' => is_array($r['data'] ?? null) ? array_keys($r['data']) : []]);
            image_out(['ok' => false, 'message' => 'Unexpected challenge response from TeraBox.'], 502);
        }
        $challenge = captcha_render_data($d);
        $pending['challenge_id'] = $cid;
        $pending['tile_x'] = $challenge['tile_x'];
        $pending['tile_y'] = $challenge['tile_y'];
        $pending['challenge_at'] = $now;
        $_SESSION['tb_pending_captcha'] = $pending;
        image_out(['ok' => true, 'challenge' => $challenge]);
    }

    if ($action === 'verify') {
        $cid = (string)($pending['challenge_id'] ?? '');
        if ($cid === '' || $now - (int)($pending['challenge_at'] ?? 0) > 300) {
            image_out(['ok' => false, 'message' => 'Challenge expired. Load another challenge.'], 400);
        }
        $dx = $_POST['delta_x'] ?? '';
        $dy = $_POST['delta_y'] ?? '';
        if (!is_string($dx) || !is_string($dy) || !preg_match('/^-?[0-9]{1,5}$/D', $dx) || !preg_match('/^-?[0-9]{1,5}$/D', $dy)
            || abs((int)$dx) > 4096 || abs((int)$dy) > 4096) {
            image_out(['ok' => false, 'message' => 'Invalid position.'], 400);
        }
        // A challenge may be answered once; a miss needs a new one.
        unset($pending['challenge_id']);
        $r = $auth->checkSlide($rid, $cid, (int)$dx, (int)$dy);
        $pending['cookie'] = $auth->getCookie();

        $tokenHolder = image_pick($r, ['capt_token']);
        $token = $tokenHolder['capt_token'] ?? '';
        if (image_code($r) === 0 && is_string($token) && $token !== '' && strlen($token) <= 4096
            && !preg_match('/[\x00-\x1f\x7f]/', $token)) {
            $expire = $tokenHolder['expire'] ?? $tokenHolder['expires'] ?? $tokenHolder['expire_time']
                ?? $r['expire'] ?? $r['expires'] ?? null;
            $pending['capt_token'] = $token;
            $pending['ticket_expires'] = captcha_ticket_deadline($expire, $now);
            $_SESSION['tb_pending_captcha'] = $pending;
            image_out(['ok' => true, 'message' => 'Verification accepted.']);
        }
        unset($pending['capt_token'], $pending['ticket_expires']);
        $_SESSION['tb_pending_captcha'] = $pending;
        tb_log('captcha_verify_rejected', ['code' => image_code($r), 'keys' => array_keys($r)]);
        image_out(['ok' => false, 'message' => 'Position not accepted. Load another challenge and try again.'], 400);
    }

    image_out(['ok' => false, 'message' => 'Unknown action.'], 400);
} catch (Throwable $ex) {
    if (is_array($pending ?? null)) {
        if (isset($auth) && $auth instanceof TeraBoxAuth) $pending['cookie'] = $auth->getCookie();
        $_SESSION['tb_pending_captcha'] = $pending;
    }
    tb_log('captcha_error', ['action' => $action, 'msg' => $ex->getMessage()]);
    image_out(['ok' => false, 'message' => tb_public_error('Challenge error: ' . $ex->getMessage(),
        'Could not load the challenge. Please try again.')], 502);
}
