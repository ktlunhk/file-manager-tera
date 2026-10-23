<?php
declare(strict_types=1);
define('TB_NO_AUTH_GATE', true);
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/captcha_support.php';

function login_is_ajax(): bool
{
    return ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'LoginForm';
}
function login_redirect(): void
{
    if (login_is_ajax()) {
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode(['ok' => true, 'redirect' => 'index.php']);
    } else { header('Location: index.php', true, 303); }
    exit;
}

if (!empty($_SESSION['ndus'])) {
    login_redirect();
}

/* Automatic sign-in from the "keep me signed in" cookie: one cheap check, no password login. */
if ($_SERVER['REQUEST_METHOD'] !== 'POST' && ($rem = remember_get()) !== null) {
    try {
        $cookie = 'lang=en; ndus=' . $rem['ndus'] . (!empty($rem['browserid']) ? '; browserid=' . $rem['browserid'] : '');
        $api = new TeraBoxAuth($cookie, $rem['whost'] ?? null);
        $chk = $api->checkLogin();
        tb_log('auto_signin', ['errno' => $chk['errno'] ?? null, 'trace' => $api->getTrace()]);
        if (($chk['errno'] ?? -1) === 0) {
            session_regenerate_id(true);
            $_SESSION['ndus']   = $rem['ndus'];
            $_SESSION['cookie'] = $api->getCookie();
            $_SESSION['whost']  = $api->getWhost();
            $_SESSION['email']  = (string)($rem['email'] ?? '');
            login_redirect();
        }
        remember_clear();                       // TeraBox no longer accepts it
    } catch (Throwable $ex) {
        tb_log('auto_signin_error', ['msg' => $ex->getMessage()]);
        // network hiccup: keep the cookie and just show the form
    }
}

$error = $_SESSION['flash'] ?? '';
unset($_SESSION['flash']);
$email = (string)($_SESSION['tb_pending_captcha']['email'] ?? '');
$auth = null;
$openToken = false;
$rememberSelected = $_SERVER['REQUEST_METHOD'] !== 'POST' || ($_POST['remember'] ?? '') === '1';
$captchaLink = '';
if ((int)($_SESSION['tb_pending_captcha']['expires'] ?? 0) <= time()) {
    unset($_SESSION['tb_pending_captcha']);
}
if (!empty($_SESSION['tb_pending_captcha']['request_id'])) {
    $captchaLink = 'https://www.terabox.com/anticapt?type=dragdrop&requestId='
        . rawurlencode($_SESSION['tb_pending_captcha']['request_id']) . '&lang=en&platform=web';
}
$isToken = ($_SERVER['REQUEST_METHOD'] === 'POST' && trim((string)($_POST['ndus'] ?? '')) !== '');
$t0   = microtime(true);

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    tb_log('page_view', tb_env() + ['flash' => $error]);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email    = trim((string)($_POST['email'] ?? ''));
    $password = (string)($_POST['password'] ?? '');
    tb_log('login_post', ['email' => tb_mask_email($email), 'remember' => ($_POST['remember'] ?? '') === '1' ? 1 : 0,
                          'bid_cookie' => isset($_COOKIE['tb_bid']) ? 1 : 0, 'remember_cookie' => isset($_COOKIE['tb_remember']) ? 1 : 0,
                          'password_supplied' => $password !== '' ? 1 : 0, 'env' => tb_env()]);

    if (!csrf_ok($_POST['csrf'] ?? null)) {
        $error = csrf_error_message();
        tb_log('csrf_fail', ['reason' => $GLOBALS['tb_csrf_reason'] ?? '', 'token_len' => strlen((string)($_POST['csrf'] ?? ''))]);
    } elseif ($isToken && !TB_TOKEN_LOGIN_ENABLED) {
        $error = 'Session-token sign-in is disabled.';
    } elseif (!$isToken && ($wait = rl_wait()) > 0) {
        tb_log('throttled', ['wait_s' => $wait]);
        // Hammering TeraBox while it is limiting logins only extends the block, so we do not forward the attempt.
        $error = 'Please wait ' . $wait . ' seconds before trying again.';
    } elseif ($isToken) {
        // Sign in with a session token (ndus cookie) copied from a browser where TeraBox already let you in.
        $tok = rtrim(preg_replace('/^ndus=/i', '', trim((string)$_POST['ndus'])), "; \t");
        if (!preg_match('/^[A-Za-z0-9_\-+=%.~]{16,600}$/', $tok)) {
            $error = 'That does not look like an ndus value. Paste only the value of the ndus cookie.';
            $openToken = true;
            tb_log('token_bad_format', ['len' => strlen($tok)]);
        } else {
            try {
                $api = new TeraBoxAuth($tok);
                $chk = $api->checkLogin();
                tb_log('token_check', ['errno' => $chk['errno'] ?? null, 'trace' => $api->getTrace()]);
                if (($chk['errno'] ?? -1) === 0) {
                    rl_reset();
                    unset($_SESSION['tb_pending_captcha']);
                    session_regenerate_id(true);
                    $_SESSION['ndus']   = $tok;
                    $_SESSION['cookie'] = $api->getCookie();
                    $_SESSION['whost']  = $api->getWhost();
                    $_SESSION['email']  = '';
                    if (($_POST['remember'] ?? '') === '1') {
                        remember_set(['ndus' => $tok, 'browserid' => '', 'whost' => $api->getWhost(), 'email' => '']);
                    } else { remember_clear(); }
                    unset($_SESSION['csrf']);
                    login_redirect();
                }
                rl_fail();
                $error = 'TeraBox did not accept that token (errno ' . (int)($chk['errno'] ?? -1) . '). Copy the current ndus value while you are signed in at terabox.com.';
            } catch (Throwable $ex) {
                tb_log('token_error', ['msg' => $ex->getMessage()]);
                $error = tb_public_error('Could not verify the token: ' . $ex->getMessage(), 'Could not verify the session. Please try again.');
            }
            $openToken = true;
        }
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL) || $password === '') {
        $error = 'Enter a valid email and password.';
        tb_log('bad_input');
    } else {
        try {
            $pending = $_SESSION['tb_pending_captcha'] ?? null;
            $reusePending = is_array($pending)
                && hash_equals((string)($pending['email_hash'] ?? ''), hash('sha256', strtolower($email)));
            $auth = $reusePending
                ? new TeraBoxAuth((string)$pending['cookie'], (string)$pending['whost'])
                : new TeraBoxAuth();
            if ($reusePending) $auth->usePassportFormToken((string)($pending['pcftoken'] ?? ''));
            $captchaToken = $reusePending
                ? captcha_consume_token($pending, $email, ($_POST['use_captcha'] ?? '') === '1', time()) : '';
            unset($_SESSION['tb_pending_captcha']);
            $captchaLink = '';
            // Same browser id on every login (stored in a long-lived cookie) = one consistent device for TeraBox.
            $bid = (string)($_COOKIE['tb_bid'] ?? '');
            if (TB_REUSE_BROWSER_ID && $bid !== '') {
                $auth->useBrowserId($bid);
            }
            $result = $auth->login($email, $password, $captchaToken);

            tb_log($result['ok'] ? 'login_ok' : ((int)$result['code'] === 460030 ? 'login_challenge' : 'login_rejected'), ['email' => tb_mask_email($email), 'code' => $result['code'], 'msg' => $result['ok'] ? '' : $result['msg'],
                   'ms' => (int)((microtime(true) - $t0) * 1000), 'trace' => $auth->getTrace(), 'debug' => $auth->getDebug()]);
            if ($result['ok']) {
                rl_reset();
                session_regenerate_id(true);
                $_SESSION['ndus']   = $result['ndus'];    // session token only; password is never stored
                $_SESSION['cookie'] = $result['cookie'];  // TeraBox cookie jar (no password)
                $_SESSION['whost']  = $result['whost'];   // region host
                $_SESSION['email']  = $email;
                tb_set_browser_id((string)$result['browserid']);
                if (($_POST['remember'] ?? '') === '1') {
                    remember_set(['ndus' => $result['ndus'], 'browserid' => $result['browserid'],
                                  'whost' => $result['whost'], 'email' => $email]);
                } else { remember_clear(); }
                unset($_SESSION['csrf']);
                login_redirect();
            }

            if (TB_REUSE_BROWSER_ID) tb_set_browser_id($auth->getBrowserId());
            // Code 460030 is a challenge, not a wrong password. Other unknown codes
            // must not be assumed to mean wrong credentials either.
            if ((int)$result['code'] !== 460030) {
                rl_security_pause();
                tb_log('login_security_pause', ['code' => (int)$result['code']]);
            }
            if ((int)$result['code'] === 460030) {
                // TeraBox wants a human check (drag-and-drop slider). The user may complete it through the official TeraBox page; this does not bypass verification.
                $error = 'Please complete the security verification.';
                // The challenge ID is issued by TeraBox for this specific failed login.
                // Do not accept an arbitrary URL or host from the client.
                $rid = (string)($result['captcha']['request_id'] ?? '');
                if (preg_match('/^[0-9]{8,24}$/D', $rid)) {
                    $captchaLink = 'https://www.terabox.com/anticapt?type=dragdrop&requestId=' . rawurlencode($rid)
                                 . '&lang=en&platform=web';
                    $_SESSION['tb_pending_captcha'] = [
                        'request_id' => $rid, 'cookie' => $auth->getCookie(), 'whost' => $auth->getWhost(),
                        'pcftoken' => $auth->getPassportFormToken(),
                        'email_hash' => hash('sha256', strtolower($email)), 'email' => $email, 'expires' => time() + 600,
                    ];
                }
                $openToken = true;
            } else {
                $detail = ($result['msg'] !== '' ? $result['msg'] : 'Login failed.') . ' (code ' . $result['code'] . ')';
                if ((int)$result['code'] === 102 && $captchaToken !== '') {
                    $error = tb_public_error($detail, 'Security verification succeeded, but TeraBox declined the subsequent sign-in. Please try again later.');
                } else {
                    $error = tb_public_error($detail, 'TeraBox did not accept the sign-in. Please wait before retrying or use the official website.');
                }
            }
        } catch (Throwable $ex) {
            tb_log('login_error', ['email' => tb_mask_email($email), 'msg' => $ex->getMessage(),
                   'ms' => (int)((microtime(true) - $t0) * 1000), 'trace' => $auth ? $auth->getTrace() : [], 'debug' => $auth ? $auth->getDebug() : []]);
            tb_log('login_transport_error');
            $error = tb_public_error('Could not complete the TeraBox login: ' . $ex->getMessage(), 'Could not sign in right now. Please try again.');
        }
    }
}
if (login_is_ajax() && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode(['ok' => false, 'message' => $error, 'captcha' => $captchaLink !== '', 'csrf' => csrf_token()], JSON_INVALID_UTF8_SUBSTITUTE);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TeraBox File Manager — Sign in</title>
<style>
  :root { --bg:#f4f6fb; --card:#fff; --text:#1c2333; --muted:#6b7385; --primary:#2f6bff; --err:#c62828; --errbg:#fdecea; --border:#d9deea; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#12151d; --card:#1b2030; --text:#e8ebf4; --muted:#9aa3b8; --primary:#5b8cff; --err:#ff8a80; --errbg:#3a1f22; --border:#2c344a; }
  }
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center;
         background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif; padding:16px; }
  .card { width:100%; max-width:380px; background:var(--card); border:1px solid var(--border); border-radius:14px; padding:32px 28px; box-shadow:0 8px 30px rgba(0,0,0,.08); }
  h1 { margin:0 0 4px; font-size:1.5rem; }
  p.sub { margin:0 0 24px; color:var(--muted); font-size:.95rem; }
  label { display:block; font-size:.85rem; margin:14px 0 6px; color:var(--muted); }
  input { width:100%; padding:11px 12px; border:1px solid var(--border); border-radius:8px; background:transparent; color:var(--text); font-size:1rem; }
  input:focus { outline:2px solid var(--primary); border-color:transparent; }
  button { width:100%; margin-top:22px; padding:12px; border:0; border-radius:8px; background:var(--primary); color:#fff; font-size:1rem; font-weight:600; cursor:pointer; }
  button:disabled { opacity:.6; cursor:wait; }
  label.remember { display:flex; align-items:center; gap:8px; margin-top:16px; font-size:.85rem; }
  label.remember input { width:auto; }
  details.tok { margin-top:22px; border-top:1px solid var(--border); padding-top:14px; }
  details.tok summary { cursor:pointer; color:var(--primary); font-weight:600; font-size:.92rem; }
  details.tok p.hint { color:var(--muted); font-size:.82rem; line-height:1.5; }
  .err { background:var(--errbg); color:var(--err); padding:10px 12px; border-radius:8px; font-size:.9rem; margin-bottom:6px; }
  .login-layout { width:100%; max-width:380px; display:grid; grid-template-columns:minmax(0,380px); gap:20px; align-items:start; }
  .login-layout.has-captcha { max-width:850px; grid-template-columns:minmax(0,380px) minmax(0,450px); }
  .login-layout .card { max-width:none; min-width:0; }
  .verify-panel { margin:0; padding:18px; border:1px solid var(--border); border-radius:14px; background:var(--card); min-width:0; box-shadow:0 8px 30px rgba(0,0,0,.06); }
  .verify-panel h2 { font-size:1.05rem; margin:0 0 8px; }
  .verify-panel .verify-note { margin:0 0 12px; }
  .verify-panel .verify-actions { display:flex; flex-wrap:wrap; gap:10px; align-items:center; margin-top:12px; }
  .verify-panel .verify-actions a { font-size:.86rem; }
  .verify-panel .verify-actions button { margin:0; width:auto; padding:10px 14px; font-size:.88rem; }
  @media (max-width:780px) { .login-layout.has-captcha { max-width:450px; grid-template-columns:minmax(0,1fr); } }
  @media (min-width:781px) { body:has(.has-captcha) { align-items:center; } }
  .verify-panel p { font-size:.83rem; color:var(--muted); line-height:1.55; }
  .verify-panel a { color:var(--primary); }
  .verify-panel button { margin-top:10px; }
  .verify-panel .status { font-size:.85rem; margin-top:10px; }

  #captcha-stage { position:relative; width:100%; max-width:360px; overflow:hidden; user-select:none; margin:12px auto; background:var(--bg); border-radius:8px; }
  #captcha-stage[hidden] { display:none; }
  #captcha-master { display:block; width:100%; height:100%; pointer-events:none; }
  #captcha-tile { position:absolute; cursor:grab; touch-action:none; user-select:none; max-width:none; }
  #captcha-tile:focus-visible { outline:3px solid var(--primary); }
  #captcha-tile.dragging { cursor:grabbing; }
  .captcha-controls { display:flex; gap:8px; flex-wrap:wrap; }
  .captcha-controls button { width:auto; font-size:.85rem; padding:10px; }
  [hidden] { display:none !important; }
  .password-row { display:flex; align-items:stretch; gap:8px; }
  .password-row input { min-width:0; flex:1; }
  .password-row button { width:44px; min-width:44px; min-height:44px; margin:0; padding:10px; display:flex; align-items:center; justify-content:center; }
  #password-toggle .eye-slash { display:none; }
  #password-toggle[aria-pressed="true"] .eye-slash { display:block; }
  #password-toggle:focus-visible { outline:2px solid var(--primary); outline-offset:3px; }
  @media (max-width:780px) { body { align-items:flex-start; } }
</style>
</head>
<body>
  <div class="login-layout<?= $captchaLink !== '' ? ' has-captcha' : '' ?>">
  <main class="card">
    <h1>TeraBox</h1>
    <p class="sub">Sign in to your account</p>

    <div id="login-error" class="err" role="alert"<?= $error === '' ? ' hidden' : '' ?>><?= e($error) ?></div>
    <form id="login-form" method="post" autocomplete="on">
      <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
      <input id="use-captcha" type="hidden" name="use_captcha" value="<?= !empty($_SESSION['tb_pending_captcha']['capt_token']) && (int)($_SESSION['tb_pending_captcha']['ticket_expires'] ?? 0) > time() ? '1' : '0' ?>">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" required autofocus autocomplete="username" value="<?= e($email) ?>">
      <label for="password">Password</label>
      <div class="password-row"><input id="password" name="password" type="password" required autocomplete="current-password"><button id="password-toggle" type="button" aria-controls="password" aria-pressed="false" aria-label="Show password" title="Show password"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/><path class="eye-slash" d="m3 3 18 18"/></svg></button></div>
      <label class="remember"><input type="checkbox" name="remember" value="1"<?= $rememberSelected ? ' checked' : '' ?>> Keep me signed in on this browser (30 days)</label>
      <button id="login-submit" type="submit">Sign in</button>
    </form>

    <?php if (TB_TOKEN_LOGIN_ENABLED): ?>
    <details class="tok"<?= $openToken ? ' open' : '' ?>>
      <summary>Sign in with a session token</summary>
      <p class="hint">Use this when TeraBox asks for its slider check. Sign in at <b>terabox.com</b> in your browser, press <b>F12</b>,
        open <b>Application</b> (Chrome/Edge) or <b>Storage</b> (Firefox) &rarr; <b>Cookies</b> &rarr; terabox.com, and copy the value of <b>ndus</b>.
        Treat it like a password.</p>
      <form method="post" autocomplete="off">
        <input type="hidden" name="csrf" value="<?= e(csrf_token()) ?>">
        <label for="ndus">ndus cookie value</label>
        <input id="ndus" name="ndus" type="password" autocomplete="off" spellcheck="false">
        <label class="remember"><input type="checkbox" name="remember" value="1"<?= $rememberSelected ? ' checked' : '' ?>> Keep me signed in on this browser (30 days)</label>
        <button type="submit">Sign in with token</button>
      </form>
    </details>
    <?php endif; ?>
  </main>
    <aside id="verification-panel" class="verify-panel" aria-label="Security verification"<?= $captchaLink === '' ? ' hidden' : '' ?>>
      <h2>Security verification</h2>
      <p class="verify-note">Drag the puzzle piece into its matching position.</p>
      <div id="captcha-widget" data-csrf="<?= e(csrf_token()) ?>" data-active="<?= $captchaLink !== '' ? '1' : '0' ?>" data-auto-submit="<?= TB_CAPTCHA_AUTO_SUBMIT ? '1' : '0' ?>">
        <p id="captcha-status" role="status" aria-live="polite">Loading challenge…</p>
        <div id="captcha-stage" hidden>
          <img id="captcha-master" alt="CAPTCHA background" draggable="false" referrerpolicy="no-referrer">
          <img id="captcha-tile" alt="Draggable puzzle piece" draggable="false" referrerpolicy="no-referrer" tabindex="0" role="button" aria-label="Move the puzzle piece with arrow keys; Enter submits its position">
        </div>
        <div class="captcha-controls">
          <button id="captcha-load" type="button">Load another challenge</button>
          <button id="captcha-verify" type="button" disabled>Verify position</button>
        </div>
        <noscript>JavaScript is required to complete security verification.</noscript>
      </div>
      <p class="status"><?= TB_CAPTCHA_AUTO_SUBMIT ? 'Sign-in continues automatically after verification.' : 'After verification, click Sign in.' ?></p>
      <?php if (TB_DEBUG): ?><p class="status">CAPTCHA uses the retained server-side cookie jar and a one-use verified ticket.</p><?php endif; ?>
    </aside>
  </div>
<script src="captcha.js?v=<?= e(substr(hash_file('sha256', __DIR__ . '/captcha.js'), 0, 16)) ?>" defer></script>
</body>
</html>
