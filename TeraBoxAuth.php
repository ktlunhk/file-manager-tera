<?php
declare(strict_types=1);

/**
 * TeraBox password login — PHP port of terabox-api-ruby (Auth + Base + Crypto modules).
 * Requires: ext-curl, ext-openssl, ext-json.
 */
class TeraBoxAuth
{
    private const DOMAIN  = 'terabox.com';
    private const TIMEOUT = 20;
    private const UA      = 'terabox;1.40.0.132;PC;PC-Windows;10.0.26100;WindowsTeraBox';

    private string $whost  = 'https://www.' . self::DOMAIN;
    private string $cookie = 'lang=en';
    private string $pcftoken = '';
    private string $pubkey   = '';
    /** @var array<int,array> per-request trace for the log: step, status, ms (never bodies/cookies) */
    private array $trace = [];

    public function getTrace(): array { return $this->trace; }

    /** @var array diagnostic facts for the log (key names, sanitized failure response; never secrets) */
    private array $debug = [];
    public function getDebug(): array { return $this->debug; }

    /** Copy of a response with secrets hidden and long strings cut, safe to write to the log. */
    private function safeSummary($v, int $depth = 0)
    {
        if (!is_array($v)) {
            return is_string($v) ? substr($v, 0, 80) : $v;
        }
        if ($depth > 2) {
            return '[...]';
        }
        $out = [];
        foreach ($v as $k => $x) {
            $out[$k] = preg_match('/token|ndus|cookie|pwd|pass|key|sign|bduss|stoken|seval|random|prand|email|mail|uk$/i', (string)$k)
                ? '[hidden]' : $this->safeSummary($x, $depth + 1);
        }
        return $out;
    }

    private function cookieNames(array $setCookies): array
    {
        return array_map(function ($c) { return trim(explode('=', $c, 2)[0]); }, $setCookies);
    }

    /**
     * @param string|null $cookieOrNdus full cookie jar ("a=b; c=d") or just the ndus token
     * @param string|null $whost        region host saved from a previous call (https://xx.terabox.com)
     */
    public function __construct(?string $cookieOrNdus = null, ?string $whost = null)
    {
        if ($cookieOrNdus !== null && $cookieOrNdus !== '') {
            $this->cookie = strpos($cookieOrNdus, '=') === false
                ? 'lang=en; ndus=' . $cookieOrNdus
                : $cookieOrNdus;
        }
        if ($whost !== null && preg_match('#^https://(?:[a-z0-9-]+\.)*terabox\.com$#i', $whost)) {
            $this->whost = $whost;
        }
    }

    /** Reuse the same browser id across logins so TeraBox sees one consistent device. */
    public function useBrowserId(string $id): void
    {
        if (preg_match('/^[A-Za-z0-9_-]{8,128}$/', $id)) {
            $jar = $this->parseCookies($this->cookie);
            $jar['browserid'] = $id;
            $this->cookie = $this->joinCookies($jar);
        }
    }

    /** Preserve the passport form token across the challenge without fetching a fresh login page. */
    public function getPassportFormToken(): string { return $this->pcftoken; }
    public function usePassportFormToken(string $token): void
    {
        if (strlen($token) <= 8192 && !preg_match('/[\x00-\x1f\x7f]/', $token)) $this->pcftoken = $token;
    }

    public function getCookie(): string  { return $this->cookie; }
    public function getWhost(): string   { return $this->whost; }
    public function getBrowserId(): string { return $this->parseCookies($this->cookie)['browserid'] ?? ''; }

    /* ------------------------------------------------------------------ *
     *  Public API
     * ------------------------------------------------------------------ */

    /**
     * Full password login. Returns ['ok' => bool, 'ndus' => string, 'msg' => string, 'code' => int].
     */
    public function login(string $email, string $password, string $captchaToken = ''): array
    {
        $pre = $this->passportPreLogin($email);
        $captcha = self::captchaMetadata($pre);
        if ($captcha['required']) {
            return ['ok' => false, 'ndus' => '', 'code' => 460030,
                    'msg' => 'TeraBox requires human verification.', 'captcha' => $captcha];
        }
        if ((int)($pre['code'] ?? $pre['errno'] ?? -1) !== 0 || !isset($pre['seval'], $pre['random'])) {
            if (defined('TB_DEBUG') && TB_DEBUG) error_log('[terabox-login] prelogin failed code=' . (int)($pre['code'] ?? -1) . ' msg=' . preg_replace('/[^\w .,:;()-]/', '', (string)($pre['msg'] ?? '')));
            return ['ok' => false, 'ndus' => '', 'code' => (int)($pre['code'] ?? $pre['errno'] ?? -1),
                    'msg' => (string)($pre['msg'] ?? $pre['errmsg'] ?? 'Pre-login failed')];
        }
        $res = $this->passportLogin($pre, $email, $password, $captchaToken);

        $code = (int)($res['code'] ?? $res['errno'] ?? -1);   // TeraBox answers with code/msg OR errno/errmsg
        $ndus = (string)($res['data']['ndus'] ?? '');
        if ($code === 0 && $ndus !== '') {
            try {
                $check = $this->checkLogin();
                if ((int)($check['errno'] ?? -1) !== 0) {
                    return ['ok' => false, 'ndus' => '', 'code' => -2,
                            'msg' => 'Session verification was not accepted.'];
                }
            } catch (Throwable $e) {
                return ['ok' => false, 'ndus' => '', 'code' => -2,
                        'msg' => 'Session verification was unavailable.'];
            }
            return ['ok' => true, 'ndus' => $ndus, 'code' => 0, 'msg' => 'OK',
                    'cookie' => $this->cookie, 'whost' => $this->whost, 'browserid' => $this->getBrowserId()];
        }
        if (defined('TB_DEBUG') && TB_DEBUG) error_log('[terabox-login] failed code=' . $code . ' msg=' . preg_replace('/[^\w .,:;()-]/', '', (string)($res['msg'] ?? '')));
        return ['ok' => false, 'ndus' => '', 'code' => $code,
                'msg' => (string)($res['msg'] ?? $res['errmsg'] ?? 'Login failed'),
                'captcha' => self::captchaMetadata($res)];
    }

    /** Challenge metadata only. Never export a CAPTCHA token or infer a browser handoff. */
    public static function captchaMetadata(array $response): array
    {
        $data = isset($response['data']) && is_array($response['data']) ? $response['data'] : [];
        $code = (int)($response['code'] ?? $response['errno'] ?? -1);
        $rid = $response['request_id_string'] ?? $data['request_id_string']
             ?? $response['request_id'] ?? $data['request_id'] ?? '';
        $rid = is_string($rid) || is_int($rid) ? (string)$rid : '';
        return ['required' => $code === 460030,
                'request_id' => preg_match('/^[0-9]{8,24}$/D', $rid) ? $rid : '',
                'capt_token_present' => array_key_exists('capt_token', $response) || array_key_exists('capt_token', $data)];
    }

    /** The two drag/drop endpoints and fields observed in the supplied official JavaScript. */
    public function getSlide(string $requestId): array
    {
        if (!preg_match('/^[0-9]{8,24}$/D', $requestId)) {
            throw new InvalidArgumentException('Invalid challenge request ID.');
        }
        $query = http_build_query(['type' => 'dragdrop', 'lang' => 'en', 'platform' => 'web',
            'isDark' => 'false', 'relation_logid' => $requestId, '_t' => (string)round(microtime(true) * 1000)]);
        return $this->json($this->request('GET', 'https://www.terabox.com/captcha/getslide?' . $query, null,
            ['Referer: https://www.terabox.com/anticapt?type=dragdrop&requestId=' . $requestId . '&lang=en&platform=web']));
    }

    public function checkSlide(string $requestId, string $challengeId, int $deltaX, int $deltaY): array
    {
        if (!preg_match('/^[0-9]{8,24}$/D', $requestId) || $challengeId === '' || strlen($challengeId) > 512) {
            throw new InvalidArgumentException('Invalid challenge.');
        }
        return $this->json($this->request('POST', 'https://www.terabox.com/captcha/checkslide', [
            'challenge_id' => $challengeId, 'delta_x' => (string)$deltaX, 'delta_y' => (string)$deltaY,
            'type' => 'dragdrop', 'lang' => 'en', 'isDark' => 'false', 'platform' => 'web',
            'relation_logid' => $requestId,
        ], ['Referer: https://www.terabox.com/anticapt?type=dragdrop&requestId=' . $requestId . '&lang=en&platform=web'], true, true));
    }

    /** GET /api/check/login with the current cookie (follows region redirects). */
    public function checkLogin(int $depth = 0): array
    {
        $r = $this->request('GET', $this->whost . '/api/check/login');
        $prefix = $r['headers']['region-domain-prefix'] ?? null;
        if (is_string($prefix) && preg_match('/^[a-z0-9-]{1,63}$/i', $prefix) && $depth < 3 && $prefix . '.' . self::DOMAIN !== parse_url($this->whost, PHP_URL_HOST)) {
            $this->whost = 'https://' . $prefix . '.' . self::DOMAIN;
            return $this->checkLogin($depth + 1);
        }
        return $this->json($r);
    }

    /** GET /passport/get_info */
    public function passportGetInfo(): array
    {
        return $this->json($this->request('GET', $this->whost . '/passport/get_info'));
    }

    /**
     * List a remote directory (POST /api/list). Returns the decoded JSON.
     * Entries are in $res['list'] (some responses nest it as $res['data']['list']).
     */
    public function listDir(string $dir = '/', int $page = 1, int $num = 1000): array
    {
        $r = $this->request('POST', $this->whost . '/api/list', [
            'order'     => 'name',
            'desc'      => '0',
            'dir'       => $dir,
            'num'       => (string)$num,
            'page'      => (string)$page,
            'showempty' => '0',
        ]);
        $j = $this->json($r);
        if (!isset($j['list']) && isset($j['data']['list'])) {
            $j['list'] = $j['data']['list'];
        }
        return $j;
    }

    /** GET /api/quota -> ['total' => int, 'used' => int, 'available' => int, ...] */
    public function getQuota(): array
    {
        $r = $this->request('GET', $this->whost . '/api/quota?checkexpire=1&checkfree=1');
        $j = $this->json($r);
        if (($j['errno'] ?? -1) === 0) {
            $j['available'] = ($j['total'] ?? 0) - ($j['used'] ?? 0);
        }
        return $j;
    }

    /* ------------------------------------------------------------------ *
     *  File API — PHP port of terabox-api-ruby (Info / Files / Upload / Crypto.sign_download)
     * ------------------------------------------------------------------ */

    private const APP = ['app_id' => '250528', 'web' => '1', 'channel' => 'dubox', 'clienttype' => '0'];
    private const HOST_RE = '/(?:^|\.)(?:1024)?terabox\.com$/i';

    private string $jsToken = '';
    private string $uhost   = 'https://c-jp.terabox.com';

    public function getJsToken(): string { return $this->jsToken; }
    public function useJsToken(string $t): void
    {
        if (preg_match('/^[A-Za-z0-9%_.\-]{8,4096}$/D', $t)) $this->jsToken = $t;
    }
    public function getUploadHostUrl(): string { return $this->uhost; }
    public function useUploadHost(string $u): void
    {
        $h = parse_url($u, PHP_URL_HOST);
        if (is_string($h) && strncmp($u, 'https://', 8) === 0 && preg_match(self::HOST_RE, $h)) $this->uhost = 'https://' . $h;
    }

    private function q(array $extra = []): string
    {
        return http_build_query(self::APP + $extra, '', '&', PHP_QUERY_RFC3986);
    }

    /** Fetch the signed-in /main page and scrape jsToken (port of update_app_data). Needed by filemanager/precreate. */
    public function refreshAppData(string $path = 'main', int $hops = 0): void
    {
        $r = $this->request('GET', $this->whost . '/' . ltrim($path, '/'));
        if ($r['status'] === 302 && $hops < 5) {
            $loc = $r['headers']['location'] ?? '';
            if ($loc === '' || $loc === '/login' || strpos($loc, '/login') === 0) {
                throw new RuntimeException('TeraBox session is not signed in.');
            }
            $p = parse_url($loc);
            if (!is_array($p)) throw new RuntimeException('Bad redirect from TeraBox.');
            if (!empty($p['scheme']) || !empty($p['host'])) {
                if (($p['scheme'] ?? '') !== 'https' || empty($p['host']) || !preg_match(self::HOST_RE, $p['host'])
                    || isset($p['user']) || isset($p['pass']) || isset($p['port'])) {
                    throw new RuntimeException('Untrusted redirect rejected.');
                }
                $this->whost = 'https://' . $p['host'];
            }
            $this->refreshAppData(ltrim($p['path'] ?? '', '/') . (isset($p['query']) ? '?' . $p['query'] : ''), $hops + 1);
            return;
        }
        if ($r['status'] !== 200) throw new RuntimeException('HTTP error! Status: ' . $r['status']);
        $this->mergeCookies($r['set_cookies']);
        $body = $r['body'];
        $t = [];
        if (preg_match('#<script>var templateData = (.*?);</script>#s', $body, $m)) {
            $j = json_decode($m[1], true);
            if (is_array($j)) $t = $j;
        }
        $tok = '';
        if (!empty($t['jsToken']) && is_string($t['jsToken'])) {
            $tok = preg_match('/%28%22(.*)%22%29/', $t['jsToken'], $mm) ? $mm[1] : $t['jsToken'];
        } elseif (preg_match('/window\.jsToken%20%3D%20a%7D%3Bfn%28%22(.*?)%22%29/', $body, $mm)) {
            $tok = $mm[1];
        }
        if ($tok === '') throw new RuntimeException('Could not obtain the TeraBox page token (jsToken).');
        $this->useJsToken($tok);
        if ($this->jsToken === '') throw new RuntimeException('Unexpected TeraBox page token format.');
    }

    /** All entries of one directory. Returns the raw response when TeraBox reports an error. */
    public function listAll(string $dir): array
    {
        $all = [];
        $num = 1000;
        for ($page = 1; $page <= 100; $page++) {
            $j = $this->listDir($dir, $page, $num);
            if ((int)($j['errno'] ?? 0) !== 0) return $j;
            $items = is_array($j['list'] ?? null) ? $j['list'] : [];
            foreach ($items as $it) $all[] = $it;
            if (count($items) < $num) break;
        }
        return ['errno' => 0, 'list' => $all];
    }

    /** Server-side recursive name search (GET /api/search). */
    public function search(string $term, int $page = 1): array
    {
        $qs = http_build_query(['order' => 'name', 'desc' => '0', 'num' => '1000', 'page' => (string)$page,
            'recursion' => '1', 'key' => $term], '', '&', PHP_QUERY_RFC3986);
        return $this->json($this->request('GET', $this->whost . '/api/search?' . $qs));
    }

    public function mkdir(string $path): array
    {
        return $this->json($this->request('POST', $this->whost . '/api/create?a=commit',
            ['path' => $path, 'isdir' => '1', 'block_list' => '[]']));
    }

    /**
     * delete / copy / move / rename (POST /api/filemanager).
     * $list: delete => [['path'=>..]], rename => [['path'=>..,'newname'=>..]], copy|move => [['path'=>..,'dest'=>..,'newname'=>..]]
     */
    public function fileManager(string $op, array $list, bool $retried = false): array
    {
        if (!in_array($op, ['delete', 'copy', 'move', 'rename'], true)) throw new InvalidArgumentException('Unsupported operation.');
        if ($this->jsToken === '') $this->refreshAppData();
        $url = $this->whost . '/api/filemanager?' . $this->q(['jsToken' => $this->jsToken, 'onnest' => 'fail', 'opera' => $op]);
        $j = $this->json($this->request('POST', $url, ['filelist' => json_encode($list, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)]));
        if ((int)($j['errno'] ?? 0) === 450016 && !$retried) {      // jsToken expired
            $this->refreshAppData();
            return $this->fileManager($op, $list, true);
        }
        return $j;
    }

    /** RC4-like download signature (port of Crypto.sign_download). */
    public static function signDownload(string $s1, string $s2): string
    {
        $n1 = strlen($s1);
        if ($n1 === 0) throw new InvalidArgumentException('Empty signing key.');
        $p = range(0, 255);
        $a = [];
        for ($i = 0; $i < 256; $i++) $a[$i] = ord($s1[$i % $n1]);
        $j = 0;
        for ($i = 0; $i < 256; $i++) {
            $j = ($j + $p[$i] + $a[$i]) % 256;
            $tmp = $p[$i]; $p[$i] = $p[$j]; $p[$j] = $tmp;
        }
        $out = '';
        $i = 0; $j = 0;
        for ($q = 0, $n = strlen($s2); $q < $n; $q++) {
            $i = ($i + 1) % 256;
            $j = ($j + $p[$i]) % 256;
            $tmp = $p[$i]; $p[$i] = $p[$j]; $p[$j] = $tmp;
            $k = $p[($p[$i] + $p[$j]) % 256];
            $out .= chr(ord($s2[$q]) ^ $k);
        }
        return base64_encode($out);
    }

    private static function findDlink(array $j): string
    {
        foreach ([$j['dlink'] ?? null, $j['data']['list'][0]['dlink'] ?? null, $j['list'][0]['dlink'] ?? null,
                  $j['info'][0]['dlink'] ?? null, $j['data']['dlink'] ?? null] as $c) {
            if (is_string($c) && $c !== '') return $c;
        }
        return '';
    }

    /** Temporary direct-download link for one file (home/info signature + /api/download, filemetas as fallback). */
    public function getDownloadLink(string $path, int $fsId): string
    {
        $h = $this->json($this->request('GET', $this->whost . '/api/home/info'));
        $d = '';
        if ((int)($h['errno'] ?? -1) === 0 && !empty($h['data']['sign1']) && !empty($h['data']['sign3'])) {
            $sign = self::signDownload((string)$h['data']['sign3'], (string)$h['data']['sign1']);
            $j = $this->json($this->request('POST', $this->whost . '/api/download', [
                'fidlist' => json_encode([$fsId]), 'type' => 'dlink', 'vip' => '2', 'sign' => $sign,
                'timestamp' => (string)($h['data']['timestamp'] ?? ''), 'need_speed' => '1']));
            $this->debug['download_errno'] = $j['errno'] ?? null;
            $d = self::findDlink($j);
        }
        if ($d === '') {
            $j = $this->json($this->request('POST', $this->whost . '/api/filemetas', [
                'dlink' => '1', 'origin' => 'dlna', 'target' => json_encode([$path], JSON_UNESCAPED_UNICODE)]));
            $this->debug['filemetas_errno'] = $j['errno'] ?? null;
            $d = self::findDlink($j);
        }
        if ($d === '') throw new RuntimeException('TeraBox did not return a download link for this file.');
        return $d;
    }

    private static function absoluteUrl(string $base, string $loc): string
    {
        if (preg_match('#^https?://#i', $loc)) return $loc;
        $p = parse_url($base);
        $origin = ($p['scheme'] ?? 'https') . '://' . ($p['host'] ?? '');
        if (strncmp($loc, '/', 1) === 0) return $origin . $loc;
        return $origin . rtrim(dirname($p['path'] ?? '/'), '/') . '/' . $loc;
    }

    /** Stream a dlink to a local file. HTTPS only, public hosts only, cookies only to TeraBox hosts. */
    public function downloadUrlTo(string $url, string $dest): void
    {
        $fh = @fopen($dest, 'wb');
        if (!$fh) throw new RuntimeException('Cannot write temporary download file.');
        try {
            for ($hop = 0; $hop <= 6; $hop++) {
                $p = parse_url($url);
                $host = is_array($p) ? (string)($p['host'] ?? '') : '';
                if (!is_array($p) || ($p['scheme'] ?? '') !== 'https' || $host === '' || isset($p['user']) || isset($p['pass'])) {
                    throw new RuntimeException('Refusing a non-HTTPS download link.');
                }
                if (!filter_var($host, FILTER_VALIDATE_IP)) {
                    $ip = gethostbyname($host);
                    if ($ip === $host || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                        throw new RuntimeException('Download host is not a public address.');
                    }
                } elseif (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                    throw new RuntimeException('Download host is not a public address.');
                }
                $headers = ['User-Agent: ' . self::UA];
                if (preg_match(self::HOST_RE, $host)) $headers[] = 'Cookie: ' . $this->cookie;
                $loc = ''; $status = 0;
                ftruncate($fh, 0); rewind($fh);
                $ch = curl_init($url);
                curl_setopt_array($ch, [
                    CURLOPT_HTTPHEADER => $headers, CURLOPT_FILE => $fh, CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_TIMEOUT => 3600, CURLOPT_LOW_SPEED_LIMIT => 1024, CURLOPT_LOW_SPEED_TIME => 60,
                    CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
                    CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                    CURLOPT_HEADERFUNCTION => function ($c, string $line) use (&$loc): int {
                        if (stripos($line, 'location:') === 0) $loc = trim(substr($line, 9));
                        return strlen($line);
                    },
                ]);
                $ok = curl_exec($ch);
                $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
                $err = curl_error($ch);
                curl_close($ch);
                if ($ok === false) throw new RuntimeException('Download failed: ' . $err);
                if (in_array($status, [301, 302, 303, 307, 308], true) && $loc !== '') {
                    $url = self::absoluteUrl($url, $loc);
                    continue;
                }
                if ($status === 200 || $status === 206) return;
                throw new RuntimeException('Download failed (HTTP ' . $status . ').');
            }
            throw new RuntimeException('Too many download redirects.');
        } finally {
            fclose($fh);
        }
    }

    /**
     * Stream a dlink to a visitor (used by direct.php). Same safety rules as downloadUrlTo(): HTTPS only,
     * public hosts only, cookie only sent to TeraBox hosts. $range is a raw "bytes=a-b" value or ''.
     * $sendHeaders(int $status, array $headers) is called once, just before the first body byte;
     * $sendBody(string $chunk): bool returns false to stop (visitor went away).
     */
    public function streamUrl(string $url, string $range, bool $headOnly, callable $sendHeaders, callable $sendBody): void
    {
        for ($hop = 0; $hop <= 6; $hop++) {
            $p = parse_url($url);
            $host = is_array($p) ? (string)($p['host'] ?? '') : '';
            if (!is_array($p) || ($p['scheme'] ?? '') !== 'https' || $host === '' || isset($p['user']) || isset($p['pass'])) {
                throw new RuntimeException('Refusing a non-HTTPS download link.');
            }
            $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : gethostbyname($host);
            if ($ip === $host && !filter_var($host, FILTER_VALIDATE_IP)) throw new RuntimeException('Download host is not a public address.');
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                throw new RuntimeException('Download host is not a public address.');
            }
            $headers = ['User-Agent: ' . self::UA];
            if (preg_match(self::HOST_RE, $host)) $headers[] = 'Cookie: ' . $this->cookie;
            if ($range !== '' && preg_match('/^bytes=\d*-\d*$/D', $range)) $headers[] = 'Range: ' . $range;

            $status = 0; $loc = ''; $resp = []; $sent = false; $stopped = false;
            $ch = curl_init($url);
            $opts = [
                CURLOPT_HTTPHEADER => $headers, CURLOPT_FOLLOWLOCATION => false, CURLOPT_RETURNTRANSFER => false,
                CURLOPT_CONNECTTIMEOUT => 15, CURLOPT_TIMEOUT => 0, CURLOPT_LOW_SPEED_LIMIT => 1024, CURLOPT_LOW_SPEED_TIME => 60,
                CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
                CURLOPT_HEADERFUNCTION => function ($c, string $line) use (&$status, &$loc, &$resp): int {
                    if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) { $status = (int)$m[1]; $loc = ''; $resp = []; }
                    elseif (strpos($line, ':') !== false) {
                        [$k, $v] = explode(':', $line, 2);
                        $resp[strtolower(trim($k))] = trim($v);
                        if (strtolower(trim($k)) === 'location') $loc = trim($v);
                    }
                    return strlen($line);
                },
                CURLOPT_WRITEFUNCTION => function ($c, string $data) use (&$status, &$resp, &$sent, &$stopped, $sendHeaders, $sendBody): int {
                    if ($status !== 200 && $status !== 206) return strlen($data);          // redirect/error body: discard
                    if (!$sent) { $sent = true; $sendHeaders($status, $resp); }
                    if (!$sendBody($data)) { $stopped = true; return 0; }
                    return strlen($data);
                },
            ];
            if ($headOnly) $opts[CURLOPT_NOBODY] = true;
            curl_setopt_array($ch, $opts);
            $ok = curl_exec($ch);
            $err = curl_error($ch);
            curl_close($ch);

            if ($headOnly && ($status === 200 || $status === 206)) { $sendHeaders($status, $resp); return; }
            if ($stopped) return;
            if (in_array($status, [301, 302, 303, 307, 308], true) && $loc !== '') { $url = self::absoluteUrl($url, $loc); continue; }
            if ($status === 200 || $status === 206) { if ($ok === false && !$sent) throw new RuntimeException('Download failed: ' . $err); return; }
            throw new RuntimeException('Download failed (HTTP ' . $status . ').');
        }
        throw new RuntimeException('Too many download redirects.');
    }

    /** Chunk size used by terabox-api-ruby Helper.get_chunk_size (4 MiB up to 4 GiB, then larger steps). */
    public static function chunkSize(int $size): int
    {
        foreach ([4, 8, 16, 32, 64, 128] as $limit) {
            if ($size <= $limit * 1073741824) return $limit * 1048576;
        }
        return 128 * 1048576;
    }

    /** One pass over the file: chunk MD5 list, first-256KiB slice MD5, whole-file MD5 and CRC32 (Helper.hash_file). */
    public static function hashFile(string $path, int $size): array
    {
        $chunkSize = self::chunkSize($size);
        $fh = @fopen($path, 'rb');
        if (!$fh) throw new RuntimeException('Cannot read the file to upload.');
        $file = hash_init('md5'); $crc = hash_init('crc32b'); $slice = hash_init('md5'); $chunk = hash_init('md5');
        $all = 0; $inChunk = 0; $chunks = [];
        while (!feof($fh)) {
            $data = fread($fh, 65536);
            if ($data === false || $data === '') break;
            hash_update($file, $data); hash_update($crc, $data);
            $off = 0; $len = strlen($data);
            while ($off < $len) {
                $room = min($len - $off, $chunkSize - $inChunk);
                if ($all < 262144) $room = min($room, 262144 - $all);
                $piece = substr($data, $off, $room);
                hash_update($chunk, $piece);
                if ($all < 262144) hash_update($slice, $piece);
                $off += $room; $all += $room; $inChunk += $room;
                if ($inChunk >= $chunkSize) { $chunks[] = hash_final($chunk); $chunk = hash_init('md5'); $inChunk = 0; }
            }
        }
        fclose($fh);
        if ($inChunk > 0) $chunks[] = hash_final($chunk);
        return ['chunks' => $chunks, 'slice' => hash_final($slice), 'file' => hash_final($file),
                'crc32' => (int)hexdec(hash_final($crc)), 'chunk_size' => $chunkSize];
    }

    private function locateUploadHost(): void
    {
        try {
            $j = $this->json($this->request('GET', $this->whost . '/rest/2.0/pcs/file?method=locateupload'));
            if (is_string($j['host'] ?? null) && $j['host'] !== '') $this->useUploadHost('https://' . $j['host']);
        } catch (Throwable $e) { /* default upload host is used */ }
    }

    /** Empty file: no data to upload, so create it directly (two known shapes of /api/create are tried). */
    /**
     * If TeraBox kept the old file and saved the new one as "name(1).ext", replace the old file with it
     * (delete the original, then give the new file the original name).
     */
    private function fixAutoRename(array $res, string $remote, string $name): void
    {
        $got = (string)($res['path'] ?? '');
        if ($got === '' || $got === $remote) return;
        // Act only on TeraBox's own conflict rename ("name(N).ext" in the same folder). Anything else is left alone,
        // so a differently-normalised path can never make us delete an unrelated file.
        $dir = dirname($remote);
        $base = basename($remote);
        $dot = strrpos($base, '.');
        $stem = ($dot === false || $dot === 0) ? $base : substr($base, 0, $dot);
        $ext  = ($dot === false || $dot === 0) ? '' : substr($base, $dot);
        $re = '~^' . preg_quote(($dir === '/' ? '' : $dir) . '/' . $stem, '~') . '\(\d{1,3}\)' . preg_quote($ext, '~') . '$~u';
        if (!preg_match($re, $got)) return;
        try {
            $d = $this->fileManager('delete', [['path' => $remote]]);
            if ((int)($d['errno'] ?? -1) !== 0) return;      // old file could not be removed: keep both, lose nothing
            $this->fileManager('rename', [['path' => $got, 'newname' => $name]]);
        } catch (Throwable $e) { /* leave whatever exists rather than lose data */ }
    }

    private function createEmpty(string $remote): array
    {
        $last = -1;
        foreach ([[], ['d41d8cd98f00b204e9800998ecf8427e']] as $blocks) {
            $res = $this->json($this->request('POST', $this->whost . '/api/create', [
                'path' => $remote, 'size' => '0', 'isdir' => '0', 'block_list' => json_encode($blocks), 'rtype' => '3']));
            $last = (int)($res['errno'] ?? -1);
            if ($last === 0) { $this->fixAutoRename($res, $remote, basename($remote)); return $res; }
        }
        throw new RuntimeException('TeraBox refused to create an empty file (errno ' . $last . ').');
    }

    /* ---- Recycle bin (list/clear: terabox-api-ruby; restore/delete: same /api/recycle/* family, unverified) ---- */
    /** $dir = '' for the top level of the bin. */
    public function recycleList(string $dir = ''): array
    {
        $q = ['desc' => '0', 'num' => '20000', 'page' => '1'];
        if ($dir !== '') $q['dir'] = $dir;
        return $this->json($this->request('GET', $this->whost . '/api/recycle/list?' . http_build_query($q)));
    }

    private static function recycleItems(array $j): array
    {
        if (isset($j['list']) && is_array($j['list'])) return $j['list'];
        if (isset($j['data']['list']) && is_array($j['data']['list'])) return $j['data']['list'];
        return [];
    }

    /**
     * Contents of a deleted folder. TeraBox ignores unknown parameters and then returns the top level
     * again, so each candidate request is accepted only if it returns something different from the
     * top-level listing (and not the folder itself). Returns ['errno'=>0,'list'=>[...],'ok'=>bool].
     */
    public function recycleListIn(string $dir, string $fid = ''): array
    {
        $top = $this->recycleList('');
        if ((int)($top['errno'] ?? 0) !== 0) return $top + ['ok' => false];
        $topIds = [];
        foreach (self::recycleItems($top) as $it) if (isset($it['fs_id'])) $topIds[(string)$it['fs_id']] = true;

        $variants = [['dir' => $dir]];
        if ($fid !== '') {
            $variants[] = ['dir' => $dir, 'fid' => $fid];
            $variants[] = ['fid' => $fid];
            $variants[] = ['fs_id' => $fid];
            $variants[] = ['parent_id' => $fid];
            $variants[] = ['dir_fsid' => $fid];
        }
        $variants[] = ['path' => $dir];
        foreach ($variants as $extra) {
            $q = ['desc' => '0', 'num' => '20000', 'page' => '1'] + $extra;
            try { $j = $this->json($this->request('GET', $this->whost . '/api/recycle/list?' . http_build_query($q))); }
            catch (Throwable $e) { continue; }
            if ((int)($j['errno'] ?? 0) !== 0) continue;
            $list = self::recycleItems($j);
            if (!$list) continue;
            $ids = []; $self = false;
            foreach ($list as $it) {
                $id = isset($it['fs_id']) ? (string)$it['fs_id'] : '';
                $ids[$id] = true;
                if ($fid !== '' && $id === $fid) $self = true;
            }
            $a = array_map('strval', array_keys($ids)); $b = array_map('strval', array_keys($topIds)); sort($a); sort($b);
            if ($self || $a === $b) continue;     // same set as the top level: parameter ignored
            return ['errno' => 0, 'list' => $list, 'ok' => true];
        }
        return ['errno' => 0, 'list' => [], 'ok' => false];
    }
    public function recycleClear(): array
    {
        return $this->json($this->request('GET', $this->whost . '/api/recycle/clear?async=1'));
    }
    /** $op: 'restore' or 'delete' (delete = permanently). $fsIds: list of fs_id integers. */
    public function recycleAction(string $op, array $fsIds): array
    {
        if (!in_array($op, ['restore', 'delete'], true)) throw new InvalidArgumentException('Unsupported operation.');
        if ($this->jsToken === '') $this->refreshAppData();
        $ids = json_encode(array_values(array_map('intval', $fsIds)));
        // errno 2 = parameter error. The web client sends the app parameters + jsToken in the query,
        // and the id list under a field name that differs between deployments, so try the known variants.
        $last = [];
        foreach ([['fsidlist', '1'], ['fidlist', '1'], ['fsidlist', ''], ['fidlist', '']] as [$field, $async]) {
            for ($attempt = 0; $attempt < 2; $attempt++) {
                $extra = ['jsToken' => $this->jsToken, '_t' => (string)time()];
                if ($async !== '') $extra['async'] = $async;
                $url = $this->whost . '/api/recycle/' . $op . '?' . $this->q($extra);
                $j = $this->json($this->request('POST', $url, [$field => $ids], ['Referer: ' . $this->whost]));
                $e = (int)($j['errno'] ?? 0);
                if (($e === 450016 || $e === 4000020) && $attempt === 0) { $this->refreshAppData(); continue; }   // jsToken expired: retry same variant
                break;
            }
            if ($e !== 2 && $e !== -1) return $j;
            $last = $j;
        }
        return $last;
    }

    /* ---- Share links (port of terabox-api-ruby Share: share_set / share_list / share_cancel) ---- */
    public function shareSet(array $paths, string $pass = '', int $period = 0): array
    {
        if (!preg_match('/^[0-9a-z]{4}$/Di', $pass)) $pass = '';
        return $this->json($this->request('POST', $this->whost . '/share/pset', [
            'schannel' => $pass === '' ? '0' : '4', 'channel_list' => '[]', 'period' => (string)max(0, $period),
            'path_list' => json_encode(array_values($paths), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 'pwd' => $pass,
        ], ['Referer: ' . $this->whost]));
    }
    public function shareList(int $page = 1): array
    {
        // Pass the same web application context as other authenticated file APIs.
        // Avoid HTTP intermediary caching: this list must reflect newly cancelled shares.
        if ($this->jsToken === '') $this->refreshAppData();
        return $this->json($this->request('GET', $this->whost . '/share/teratransfer/sharelist?' .
            $this->q(['jsToken' => $this->jsToken, 'page_size' => '100', 'page' => (string)$page, '_t' => (string)time()]),
            null, ['Referer: ' . $this->whost, 'Cache-Control: no-cache', 'Pragma: no-cache']));
    }
    /** Inspect a public share, independently of historical share-list entries. */
    public function shortUrlInfo(string $shortUrl): array
    {
        // The share-details API expects a code beginning with 1.
        if (!preg_match('/^1[A-Za-z0-9_-]{3,127}$/D', $shortUrl)) {
            throw new InvalidArgumentException('Invalid public share code');
        }
        return $this->json($this->request('GET', $this->whost . '/api/shorturlinfo?' .
            $this->q(['shorturl' => $shortUrl, 'root' => '1', '_t' => (string)time()]),
            null, ['Referer: ' . $this->whost, 'Cache-Control: no-cache']));
    }

    /**
     * Check many public share codes at once (parallel, short timeout) instead of one slow request each.
     * Returns code => errno (int), or null when that request failed.
     */
    public function shortUrlInfoMulti(array $codes, int $parallel = 10, int $timeout = 8): array
    {
        $out = [];
        $codes = array_values(array_unique(array_filter($codes, function ($c) { return is_string($c) && preg_match('/^1[A-Za-z0-9_-]{3,127}$/D', $c); })));
        foreach (array_chunk($codes, max(1, $parallel)) as $chunk) {
            $mh = curl_multi_init(); $hs = [];
            foreach ($chunk as $code) {
                $ch = curl_init($this->whost . '/api/shorturlinfo?' . $this->q(['shorturl' => $code, 'root' => '1', '_t' => (string)time()]));
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false,
                    CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 5,
                    CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
                    CURLOPT_HTTPHEADER => ['User-Agent: ' . self::UA, 'Cookie: ' . $this->cookie,
                        'Referer: ' . $this->whost, 'Cache-Control: no-cache'],
                ]);
                curl_multi_add_handle($mh, $ch); $hs[$code] = $ch;
            }
            do {
                $st = curl_multi_exec($mh, $running);
                if ($running) curl_multi_select($mh, 0.5);
            } while ($running && $st === CURLM_OK);
            foreach ($hs as $code => $ch) {
                $body = curl_multi_getcontent($ch);
                $http = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
                $j = ($http === 200 && is_string($body)) ? json_decode($body, true) : null;
                $out[$code] = (is_array($j) && (isset($j['errno']) || isset($j['error_code']))) ? (int)($j['errno'] ?? $j['error_code']) : null;
                curl_multi_remove_handle($mh, $ch); curl_close($ch);
            }
            curl_multi_close($mh);
        }
        return $out;
    }

    public function shareCancel(array $shareIds): array
    {
        return $this->json($this->request('POST', $this->whost . '/share/cancel',
            ['shareid_list' => json_encode(array_values($shareIds))], ['Referer: ' . $this->whost]));
    }

    /**
     * Upload a local file: precreate -> superfile2 chunks -> create (port of usage/upload.rb).
     * $remoteDir must exist. An existing file of the same name is replaced (rtype=2, as in the Ruby client).
     */
    public function uploadFile(string $local, string $remoteDir, string $name): array
    {
        @set_time_limit(0);
        ignore_user_abort(true);   // finish the upload even if the browser/proxy gives up waiting
        $size = (int)filesize($local);
        $dir = '/' . trim($remoteDir, '/');
        $remote = ($dir === '/' ? '' : $dir) . '/' . $name;
        if ($size <= 0) return $this->createEmpty($remote);
        $h = self::hashFile($local, $size);
        if ($this->jsToken === '') $this->refreshAppData();

        // rtype: 3 = overwrite an existing file; 2 only overwrites when content is identical and
        // otherwise auto-renames to "name(1).ext" (which is what saving an edited file produced).
        $rtype = '3';
        $form = ['path' => $remote, 'autoinit' => '1', 'size' => (string)$size, 'file_limit_switch_v34' => 'true',
                 'block_list' => json_encode($h['chunks']), 'rtype' => $rtype, 'content-md5' => $h['file'],
                 'slice-md5' => $h['slice'], 'content-crc32' => (string)$h['crc32']];
        $pre = [];
        for ($try = 0; $try < 3; $try++) {
            $pre = $this->json($this->request('POST', $this->whost . '/api/precreate?' . $this->q(['jsToken' => $this->jsToken]), $form));
            $e = (int)($pre['errno'] ?? 0);
            if ($e === 4000023 && $try === 0) { $this->refreshAppData(); continue; }
            if ($e !== 0 && $rtype === '3') { $rtype = '2'; $form['rtype'] = '2'; continue; }   // overwrite mode refused: old behaviour
            break;
        }
        $uploadId = (string)($pre['uploadid'] ?? '');
        if ((int)($pre['errno'] ?? 0) !== 0 || $uploadId === '') {
            throw new RuntimeException('TeraBox precreate failed (errno ' . (int)($pre['errno'] ?? -1) . ').');
        }
        $this->locateUploadHost();

        $src = fopen($local, 'rb');
        if (!$src) throw new RuntimeException('Cannot read the file to upload.');
        $tmp = tempnam(sys_get_temp_dir(), 'tbchunk');
        try {
            foreach ($h['chunks'] as $seq => $md5) {
                $start = $seq * $h['chunk_size'];
                $want  = min($h['chunk_size'], $size - $start);
                fseek($src, $start);
                $out = fopen($tmp, 'wb');
                $left = $want;
                while ($left > 0 && !feof($src)) {
                    $buf = fread($src, min(1048576, $left));
                    if ($buf === false || $buf === '') break;
                    fwrite($out, $buf); $left -= strlen($buf);
                }
                fclose($out);
                if ($left !== 0) throw new RuntimeException('Short read while uploading.');
                $ok = false; $last = '';
                for ($try = 1; $try <= 3 && !$ok; $try++) {
                    try {
                        $url = $this->uhost . '/rest/2.0/pcs/superfile2?' . http_build_query(
                            ['method' => 'upload', 'path' => $remote, 'uploadid' => $uploadId, 'partseq' => (string)$seq] + self::APP,
                            '', '&', PHP_QUERY_RFC3986);
                        $j = $this->json($this->request('POST', $url,
                            ['file' => new CURLFile($tmp, 'application/octet-stream', 'blob')], [], true, true, 600));
                        if (!empty($j['error_code'])) throw new RuntimeException('Upload failed! Error Code #' . (int)$j['error_code']);
                        if (($j['md5'] ?? '') !== $md5) throw new RuntimeException('Chunk checksum mismatch (part ' . ($seq + 1) . ').');
                        $ok = true;
                    } catch (Throwable $e) {
                        $last = $e->getMessage();
                        if ($try < 3) sleep($try);
                    }
                }
                if (!$ok) throw new RuntimeException('Upload failed at part ' . ($seq + 1) . ' of ' . count($h['chunks']) . ': ' . $last);
            }
        } finally {
            fclose($src);
            @unlink($tmp);
        }

        $res = $this->json($this->request('POST', $this->whost . '/api/create', [
            'path' => $remote, 'size' => (string)$size, 'isdir' => '0', 'content-md5' => $h['file'],
            'slice-md5' => $h['slice'], 'content-crc32' => (string)$h['crc32'],
            'block_list' => json_encode($h['chunks']), 'uploadid' => $uploadId, 'rtype' => $rtype]));
        if ((int)($res['errno'] ?? 0) !== 0) throw new RuntimeException('TeraBox create failed (errno ' . (int)($res['errno'] ?? -1) . ').');
        $this->fixAutoRename($res, $remote, $name);
        return $res;
    }

    /* ------------------------------------------------------------------ *
     *  Login steps
     * ------------------------------------------------------------------ */

    private function passportPreLogin(string $email): array
    {
        if ($this->pcftoken === '') {
            $this->updateAppData('wap/outlogin/login');
        }
        $r = $this->request('POST', $this->whost . '/passport/prelogin', [
            'client'      => 'web',
            'pass_version'=> '2.8',
            'clientfrom'  => 'h5',
            'pcftoken'    => $this->pcftoken,
            'email'       => $email,
        ], ['Referer: ' . $this->whost]);

        $j = $this->json($r);
        $this->debug['pre_keys'] = array_keys($j);
        $this->debug['pre_code'] = $j['code'] ?? null;
        $this->debug['pre_msg']  = isset($j['msg']) ? substr((string)$j['msg'], 0, 80) : null;
        // Ruby reads seval/random/timestamp at the top level; tolerate a "data" wrapper too.
        if (!isset($j['seval']) && isset($j['data']['seval'])) {
            $j = array_merge($j, $j['data']);
        }
        return $j;
    }

    private function passportLogin(array $pre, string $email, string $pass, string $captchaToken = ''): array
    {
        if ($this->pubkey === '') {
            $this->getPublicKey();
        }
        $browserid = $this->parseCookies($this->cookie)['browserid'] ?? '';

        $encpwd = self::changeBase64Type(self::encryptRsa($pass, $this->pubkey, 2));
        $prand  = self::prandGen((string)$pre['seval'], $encpwd, $email, (string)$pre['random'], 'web', $browserid);

        $form = [
            'client'      => 'web',
            'pass_version'=> '2.8',
            'clientfrom'  => 'h5',
            'pcftoken'    => $this->pcftoken,
            'prand'       => $prand,
            'email'       => $email,
            'pwd'         => $encpwd,
            'seval'       => (string)$pre['seval'],
            'random'      => (string)$pre['random'],
            'timestamp'   => (string)($pre['timestamp'] ?? ''),
        ];
        // Observed browser field; compatibility with this web/h5 login variant is experimental.
        if ($captchaToken !== '') $form['capt_token'] = $captchaToken;
        $r = $this->request('POST', $this->whost . '/passport/login', $form, ['Referer: ' . $this->whost]);
        $this->debug['captcha_token_submitted'] = $captchaToken !== '';

        $j = $this->json($r);
        $this->debug['login_keys']        = array_keys($j);
        $this->debug['captcha']          = self::captchaMetadata($j);
        $this->debug['login_set_cookies'] = $this->cookieNames($r['set_cookies']);
        $this->debug['jar_names']         = array_keys($this->parseCookies($this->cookie));
        if ((int)($j['code'] ?? $j['errno'] ?? -1) === 0 && !empty($r['set_cookies'])) {
            $this->mergeCookies($r['set_cookies']);
            $j['data']         = $j['data'] ?? [];
            $j['data']['ndus'] = $this->parseCookies($this->cookie)['ndus'] ?? '';
        }
        return $j;
    }

    private function getPublicKey(): void
    {
        $r = $this->request('GET', $this->whost . '/passport/getpubkey', null, [], false);
        $j = $this->json($r);
        if (($j['code'] ?? -1) !== 0) {
            throw new RuntimeException('getPublicKey: ' . ($j['msg'] ?? 'unexpected response'));
        }
        $this->pubkey = self::decryptAes((string)$j['data']['pp1'], (string)$j['data']['pp2']);
    }

    /** Fetch a TeraBox page and scrape pcftoken (equivalent of update_app_data). */
    private function updateAppData(string $path, int $hops = 0): void
    {
        $r = $this->request('GET', $this->whost . '/' . ltrim($path, '/'));
        if ($r['status'] === 302 && $hops < 5) {
            $loc = $r['headers']['location'] ?? '/login';
            if ($loc === '/login') {
                $loc = $this->whost . '/login';
            }
            $p = parse_url($loc);
            if (!empty($p['scheme']) && !empty($p['host'])) {
                if ($p['scheme'] !== 'https' || !preg_match('/^(?:[a-z0-9-]+\.)*terabox\.com$/iD', $p['host'])
                    || isset($p['user']) || isset($p['pass']) || isset($p['port'])) {
                    throw new RuntimeException('Untrusted login redirect rejected.');
                }
                $this->whost = $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '');
            }
            $next = ltrim($p['path'] ?? '', '/') . (isset($p['query']) ? '?' . $p['query'] : '');
            $this->updateAppData($next, $hops + 1);
            return;
        }
        $this->mergeCookies($r['set_cookies']);

        if (preg_match('#<script>var templateData = (.*?);</script>#s', $r['body'], $m)) {
            $t = json_decode($m[1], true);
            if (is_array($t) && !empty($t['pcftoken'])) {
                $this->pcftoken = (string)$t['pcftoken'];
            }
        }
        if ($this->pcftoken === '') {
            if (defined('TB_DEBUG') && TB_DEBUG) error_log('[terabox-login] no pcftoken; http=' . $r['status'] . ' bytes=' . strlen($r['body']));
            throw new RuntimeException('TeraBox did not return a login token (HTTP ' . $r['status']
                . '). This usually means it is temporarily limiting requests from this server.');
        }
    }

    /* ------------------------------------------------------------------ *
     *  Crypto (port of TeraBoxApi::Crypto)
     * ------------------------------------------------------------------ */

    public static function changeBase64Type(string $s, int $mode = 1): string
    {
        return $mode === 1 ? strtr($s, '+/', '-_') : strtr($s, '-_', '+/');
    }

    public static function decryptAes(string $pp1, string $pp2): string
    {
        $pp1 = self::changeBase64Type($pp1, 2);
        $pp2 = self::changeBase64Type($pp2, 2);
        $iv  = substr($pp1, 0, 16);
        $ct  = base64_decode(substr($pp1, 16), true);
        if ($ct === false) {
            throw new RuntimeException('AES: invalid base64 payload');
        }
        $plain = openssl_decrypt($ct, 'aes-128-cbc', $pp2, OPENSSL_RAW_DATA, $iv);
        if ($plain === false) {
            throw new RuntimeException('AES: decryption failed');
        }
        return $plain;
    }

    public static function encryptRsa(string $message, string $pem, int $mode = 1): string
    {
        if ($mode === 2) {
            $md5     = md5($message);
            $message = $md5 . strlen($md5);
        }
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new RuntimeException('RSA: invalid public key');
        }
        if (!openssl_public_encrypt($message, $enc, $key, OPENSSL_PKCS1_PADDING)) {
            throw new RuntimeException('RSA: encryption failed');
        }
        return base64_encode($enc);
    }

    public static function prandGen(string $seval, string $encpwd, string $email, string $random,
                                    string $client = 'web', string $browserid = ''): string
    {
        return sha1("{$client}-{$seval}-{$encpwd}-{$email}-{$browserid}-{$random}");
    }

    /* ------------------------------------------------------------------ *
     *  HTTP + cookies
     * ------------------------------------------------------------------ */

    protected function request(string $method, string $url, ?array $form = null,
                             array $extraHeaders = [], bool $sendCookie = true, bool $multipart = false,
                             int $timeout = self::TIMEOUT): array
    {
        $setCookies = [];
        $headers    = [];

        $ch = curl_init($url);
        $h  = ['User-Agent: ' . self::UA];
        if ($sendCookie) {
            $h[] = 'Cookie: ' . $this->cookie;
        }
        foreach ($extraHeaders as $x) {
            $h[] = $x;
        }

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HEADERFUNCTION => function ($c, string $line) use (&$setCookies, &$headers): int {
                $len = strlen($line);
                $pos = strpos($line, ':');
                if ($pos !== false) {
                    $name = strtolower(trim(substr($line, 0, $pos)));
                    $val  = trim(substr($line, $pos + 1));
                    if ($name === 'set-cookie') {
                        $setCookies[] = $val;
                    } else {
                        $headers[$name] = $val;
                    }
                }
                return $len;
            },
        ]);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
            if ($multipart) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $form ?? []);
            } else {
                $h[] = 'Content-Type: application/x-www-form-urlencoded';
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($form ?? [], '', '&', PHP_QUERY_RFC3986));
            }
        }
        curl_setopt($ch, CURLOPT_HTTPHEADER, $h);

        $t0   = microtime(true);
        $step = $method . ' ' . (string)parse_url($url, PHP_URL_PATH);
        $body = curl_exec($ch);
        if ($body === false) {
            $err = curl_error($ch);
            curl_close($ch);
            $this->trace[] = ['step' => $step, 'err' => substr($err, 0, 120), 'ms' => (int)((microtime(true) - $t0) * 1000)];
            throw new RuntimeException('Network error: ' . $err);
        }
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        $row = ['step' => $step, 'http' => $status, 'ms' => (int)((microtime(true) - $t0) * 1000), 'bytes' => strlen((string)$body)];
        if (isset($headers['location'])) {
            $row['redirect'] = (string)parse_url($headers['location'], PHP_URL_PATH);
        }
        if (isset($headers['region-domain-prefix'])) {
            $row['region'] = $headers['region-domain-prefix'];
        }
        if (count($this->trace) < 200) $this->trace[] = $row;

        if ($sendCookie && $setCookies) {
            $this->mergeCookies($setCookies);
        }
        return ['status' => $status, 'headers' => $headers, 'set_cookies' => $setCookies, 'body' => (string)$body];
    }

    private function json(array $r): array
    {
        if ($r['status'] !== 200) {
            throw new RuntimeException('HTTP error! Status: ' . $r['status']);
        }
        $j = json_decode($r['body'], true);
        if (!is_array($j) && $this->trace) {
            $this->trace[count($this->trace) - 1]['not_json'] = true;
        }
        if (!is_array($j)) {
            throw new RuntimeException('Invalid JSON response from TeraBox');
        }
        return $j;
    }

    private function parseCookies(string $str): array
    {
        $out = [];
        foreach (explode(';', $str) as $part) {
            $part = trim($part);
            if ($part === '') {
                continue;
            }
            $kv = explode('=', $part, 2);
            $out[trim($kv[0])] = isset($kv[1]) ? trim($kv[1]) : '';
        }
        return $out;
    }

    private function mergeCookies(array $setCookieHeaders): void
    {
        $jar = $this->parseCookies($this->cookie);
        foreach ($setCookieHeaders as $header) {
            $parts = explode(';', $header);
            $kv = explode('=', trim(array_shift($parts)), 2);
            if (count($kv) !== 2) continue;
            $name = trim($kv[0]);
            if (!preg_match('/^[A-Za-z0-9_-]{1,128}$/', $name)) continue;
            $value = trim($kv[1]);
            $expired = ($value === '');
            foreach ($parts as $attribute) {
                $attribute = trim($attribute);
                if (preg_match('/^max-age\s*=\s*(-?\d+)/i', $attribute, $m) && (int)$m[1] <= 0) $expired = true;
                if (preg_match('/^expires\s*=\s*(.+)$/i', $attribute, $m)) {
                    $expiry = strtotime($m[1]);
                    if ($expiry !== false && $expiry <= time()) $expired = true;
                }
            }
            if ($expired) unset($jar[$name]);
            else $jar[$name] = $value;
        }
        $this->cookie = $this->joinCookies($jar);
    }

    private function joinCookies(array $jar): string
    {
        $pairs = [];
        foreach ($jar as $k => $v) {
            $pairs[] = "$k=$v";
        }
        return implode('; ', $pairs);
    }
}
