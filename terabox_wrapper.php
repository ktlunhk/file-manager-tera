<?php
/**
 * TeraBox backend for the file manager.
 *
 *  - TeraApi : path-based node cache + operations on top of TeraBoxAuth (list, mkdir, move/copy/delete, upload, download).
 *  - TeraFS  : "terabox://root/..." PHP stream wrapper, so the file manager UI can use ordinary filesystem functions.
 *  - tb_require_login() : gate used by config.php; sends visitors to login.php (email/password + slider CAPTCHA).
 *
 * Node handles are absolute remote paths ("/Docs/a.txt"); the root handle is "/".
 * Node types follow the previous backend: 0 = file, 1 = folder, 2 = root.
 */
require_once __DIR__ . '/TeraBoxAuth.php';

class TeraApi
{
    public static $sid   = '';          // non-empty once authenticated (also names the local temp folder)
    public static $nodes = array();     // handle => ['h','t','s','ts','n','fs']
    public static $kids  = array();     // dir handle => [name => handle]
    public static $trash = array();     // unused, kept for source compatibility
    public static $root  = '/';
    public static $lastError = '';
    private static $c = null;
    private static $listed = array();
    private static $missing = array();

    public static function init($client, $sid)
    {
        self::$c = $client;
        self::$sid = $sid;
        self::invalidate();
    }

    public static function client()
    {
        if (!self::$c) throw new RuntimeException('Not signed in to TeraBox');
        return self::$c;
    }

    /** The tree is listed lazily, one folder at a time; nothing to preload. */
    public static function load() { }

    public static function invalidate()
    {
        self::$nodes = array('/' => array('h' => '/', 't' => 2, 's' => 0, 'ts' => time(), 'n' => '', 'fs' => ''));
        self::$kids = array();
        self::$listed = array();
        self::$missing = array();
    }

    public static function join($dirHandle, $name)
    {
        return ($dirHandle === '/' ? '' : rtrim($dirHandle, '/')) . '/' . $name;
    }

    public static function handleFor($rel)
    {
        $rel = trim((string)$rel, '/');
        return $rel === '' ? '/' : '/' . $rel;
    }

    private static function log($msg)
    {
        error_log('[tbfm] ' . preg_replace('/[^\w .,:;()\/\[\]=-]/', '', $msg));
        if (function_exists('tb_log')) tb_log('fs', array('msg' => $msg));
    }

    /** Make sure $kids[$dir] is filled. False if the folder does not exist or cannot be read. */
    public static function ensureListed($dir)
    {
        if (isset(self::$listed[$dir])) return true;
        if (isset(self::$missing[$dir])) return false;
        try {
            $res = self::client()->listAll($dir);
        } catch (Throwable $e) {
            self::log('list failed: ' . $e->getMessage());
            self::$lastError = 'Could not read the TeraBox folder.';
            self::$missing[$dir] = true;
            return false;
        }
        $err = (int)(isset($res['errno']) ? $res['errno'] : 0);
        if ($err !== 0) {
            if ($err === -6) tb_session_expired();
            self::$missing[$dir] = true;
            if ($err !== -9 && $err !== 31066 && $err !== 31002) self::log('list errno=' . $err);
            return false;
        }
        $kids = array();
        foreach ((isset($res['list']) && is_array($res['list'])) ? $res['list'] : array() as $it) {
            $name = isset($it['server_filename']) ? (string)$it['server_filename'] : basename((string)(isset($it['path']) ? $it['path'] : ''));
            if ($name === '' || $name === '.' || $name === '..') continue;
            $h = self::join($dir, $name);
            self::$nodes[$h] = array(
                'h' => $h, 't' => !empty($it['isdir']) ? 1 : 0, 's' => (int)(isset($it['size']) ? $it['size'] : 0),
                'ts' => (int)(isset($it['server_mtime']) ? $it['server_mtime'] : (isset($it['local_mtime']) ? $it['local_mtime'] : 0)),
                'n' => $name, 'fs' => isset($it['fs_id']) ? $it['fs_id'] : '',
            );
            $kids[$name] = $h;
        }
        self::$kids[$dir] = $kids;
        self::$listed[$dir] = true;
        return true;
    }

    /** Handle for a path relative to the root ('' = root), or null. */
    public static function find($rel)
    {
        $h = self::handleFor($rel);
        if ($h === '/') return '/';
        if (isset(self::$nodes[$h])) return $h;
        if (!self::ensureListed(dirname($h))) return null;
        return isset(self::$nodes[$h]) ? $h : null;
    }

    public static function kids($handle)
    {
        self::ensureListed($handle);
        return isset(self::$kids[$handle]) ? self::$kids[$handle] : array();
    }

    private static function errnoOf($j) { return (int)(isset($j['errno']) ? $j['errno'] : (isset($j['error_code']) ? $j['error_code'] : -1)); }

    public static function mkdir($parentHandle, $name)
    {
        try {
            $j = self::client()->mkdir(self::join($parentHandle, $name));
            $e = self::errnoOf($j);
            if ($e === -6) tb_session_expired();
            if ($e !== 0) self::log('mkdir errno=' . $e);
            return $e === 0;
        } catch (Throwable $ex) {
            self::log('mkdir failed: ' . $ex->getMessage());
            return false;
        } finally {
            self::invalidate();
        }
    }

    public static function upload($local, $parentHandle, $name)
    {
        self::$lastError = '';
        try {
            self::client()->uploadFile($local, $parentHandle, $name);
            return true;
        } catch (Throwable $e) {
            self::$lastError = $e->getMessage();
            self::log('upload failed: ' . $e->getMessage());
            return false;
        } finally {
            self::invalidate();
        }
    }

    public static function download($handle, $local)
    {
        $n = isset(self::$nodes[$handle]) ? self::$nodes[$handle] : null;
        if (!$n || (int)$n['t'] !== 0 || $n['fs'] === '') return false;
        try {
            $c = self::client();
            $url = $c->getDownloadLink($handle, (int)$n['fs']);
            $c->downloadUrlTo($url, $local);
            $got = filesize($local);
            if ($got !== (int)$n['s']) { self::log('download size mismatch ' . $got . '/' . $n['s']); return false; }
            return true;
        } catch (Throwable $e) {
            self::$lastError = $e->getMessage();
            self::log('download failed: ' . $e->getMessage());
            return false;
        }
    }

    private static function fm($op, $items)
    {
        try {
            $j = self::client()->fileManager($op, $items);
            $e = self::errnoOf($j);
            if ($e === -6) tb_session_expired();
            if ($e !== 0) self::log($op . ' errno=' . $e);
            return $e === 0;
        } catch (Throwable $ex) {
            self::log($op . ' failed: ' . $ex->getMessage());
            return false;
        } finally {
            self::invalidate();
        }
    }

    /** Move and/or rename. */
    public static function move($handle, $parentHandle, $newName)
    {
        if (dirname($handle) === $parentHandle || ($parentHandle === '/' && dirname($handle) === '/')) {
            return self::fm('rename', array(array('path' => $handle, 'newname' => $newName)));
        }
        return self::fm('move', array(array('path' => $handle, 'dest' => $parentHandle, 'newname' => $newName)));
    }

    /** Server-side copy (no download/upload round trip). */
    public static function copy($handle, $parentHandle, $newName)
    {
        return self::fm('copy', array(array('path' => $handle, 'dest' => $parentHandle, 'newname' => $newName)));
    }

    public static function delete($handle)
    {
        if ($handle === '/' || $handle === '') return false;
        if (self::fm('delete', array(array('path' => $handle)))) return true;
        // Some TeraBox builds expect a plain path list; one retry with that shape.
        return self::fm('delete', array($handle));
    }

    public static function trash($handle) { return self::delete($handle); }

    public static function quota()
    {
        $q = self::client()->getQuota();
        if ((int)(isset($q['errno']) ? $q['errno'] : -1) !== 0) return null;
        return array('used' => (int)$q['used'], 'total' => (int)$q['total']);
    }

    /** Recursive name search below $dirHandle, using TeraBox's own search. Returns normalised entries. */
    public static function search($term, $dirHandle = '/')
    {
        $out = array();
        for ($page = 1; $page <= 5; $page++) {
            $j = self::client()->search($term, $page);
            if (self::errnoOf($j) !== 0) break;
            $list = (isset($j['list']) && is_array($j['list'])) ? $j['list'] : array();
            foreach ($list as $it) {
                $p = (string)(isset($it['path']) ? $it['path'] : '');
                if ($p === '' || ($dirHandle !== '/' && strpos($p . '/', rtrim($dirHandle, '/') . '/') !== 0)) continue;
                $out[] = array('path' => $p, 'name' => (string)(isset($it['server_filename']) ? $it['server_filename'] : basename($p)),
                    'isdir' => !empty($it['isdir']), 'size' => (int)(isset($it['size']) ? $it['size'] : 0),
                    'mtime' => (int)(isset($it['server_mtime']) ? $it['server_mtime'] : 0));
            }
            if (count($list) < 1000) break;
        }
        return $out;
    }

    /* ---------- share links ---------- */

    /** Normalize a TeraBox public URL or short code; never include session credentials. */
    private static function normalizeShareUrl($raw)
    {
        if (!is_scalar($raw)) return '';
        $value = trim((string)$raw);
        if ($value === '') return '';
        // A share URL can use the canonical site or one of TeraBox's published link domains.
        if (preg_match('~^https?://(?:[a-z0-9-]+\.)*(?:terabox\.com|teraboxapp\.com|1024terabox\.com|teraboxlink\.com)/(?:s/)?[A-Za-z0-9_\-/%]+(?:\?[A-Za-z0-9_=&%\-]+)?$~iD', $value)) {
            return $value;
        }
        // Short codes are only safe to expand when provided by a shorturl-named field.
        return '';
    }

    /** Turn TeraBox public-share fields into a usable link. */
    private static function shareUrlFrom($it)
    {
        if (!is_array($it)) return '';
        foreach (array('link', 'shortlink', 'short_link', 'share_url', 'share_link', 'shareurl', 'url', 'shorturl', 'short_url', 'surl', 'shorturl_id') as $key) {
            if (!isset($it[$key]) || !is_scalar($it[$key])) continue;
            $value = trim((string)$it[$key]);
            $url = self::normalizeShareUrl($value);
            if ($url !== '') return $url;
            if (in_array($key, array('shorturl','short_url','surl','shorturl_id'), true) &&
                preg_match('~^(?:s/)?[A-Za-z0-9_-]{3,128}$~D', $value)) {
                return 'https://www.terabox.com/s/' . (strpos($value, 's/') === 0 ? substr($value, 2) : $value);
            }
            // Some responses return a relative canonical /s/ link.
            if (preg_match('~^/s/[A-Za-z0-9_-]{3,128}$~D', $value)) return 'https://www.terabox.com' . $value;
        }
        return '';
    }

    /** Accept documented `list`, as well as the nested list shapes returned by some web deployments. */
    private static function shareRecords($response)
    {
        if (!is_array($response)) return null;
        if ($response === array() || array_keys($response) === range(0, count($response) - 1)) return $response;
        foreach (array('list', 'records', 'share_list', 'shareList', 'shares', 'items') as $key) {
            if (isset($response[$key]) && is_array($response[$key])) {
                $v = self::shareRecords($response[$key]);
                if ($v !== null) return $v;
            }
        }
        foreach (array('data', 'result', 'info') as $key) {
            if (isset($response[$key]) && is_array($response[$key])) {
                $v = self::shareRecords($response[$key]);
                if ($v !== null) return $v;
            }
        }
        return null;
    }

    /**
     * Explicit share-list status is authoritative when provided. The listing
     * endpoint may also return historical (cancelled) records with an old URL.
     * An unknown status is NOT automatically treated as active.
     */
    private static function shareState($it)
    {
        if (!is_array($it)) return 'unknown';
        foreach (array('is_cancelled', 'is_deleted', 'is_expired', 'cancelled', 'deleted') as $key) {
            if (isset($it[$key]) && ($it[$key] === true || $it[$key] === 1 || $it[$key] === '1')) return 'cancelled';
        }
        foreach (array('status', 'share_status', 'shareStatus', 'state', 'expiredType', 'expired_type') as $key) {
            if (!isset($it[$key])) continue;
            $state = strtolower(trim((string)$it[$key]));
            // Numeric flags: -1 = expired/cancelled. (0 = normal, 1 = also seen on active records, so not decisive.)
            if ($key !== 'expiredType' && $key !== 'expired_type' && $state === '-1') return 'cancelled';
            if (($key === 'expiredType' || $key === 'expired_type') && $state === '-1') return 'cancelled';
            if (in_array($state, array('cancelled', 'canceled', 'deleted', 'expired', 'invalid', 'inactive', 'revoked'), true)) return 'cancelled';
            if (in_array($state, array('active', 'valid', 'sharing'), true)) return 'active';
        }
        return 'unknown';
    }

    /**
     * Confirm public availability for status-less share-list records.
     * Returns active, cancelled, or unknown. Unknown responses must never be
     * represented as confirmed active (nor silently called cancelled).
     */
    private static function stateFromErrno($err)
    {
        if ($err === null) return 'unknown';
        if ($err === 0 || $err === -9) return 'active';
        // 105 = invalid link (documented); the others are codes TeraBox/Baidu-style share pages use for cancelled/expired/blocked links.
        if (in_array($err, array(105, 145, 115, -21, 200025, 200026, 2131, 110, 112, 114), true)) return 'cancelled';
        return 'unknown';
    }

    private static function shareCodeOf($url)
    {
        $code = parse_url((string)$url, PHP_URL_PATH);
        return (is_string($code) && preg_match('~^/s/(1[A-Za-z0-9_-]+)$~D', $code, $m)) ? $m[1] : '';
    }

    private static function markCancelled($id)
    {
        if (session_status() !== PHP_SESSION_ACTIVE) return;
        if (!isset($_SESSION['tb_cancelled_shares']) || !is_array($_SESSION['tb_cancelled_shares'])) $_SESSION['tb_cancelled_shares'] = array();
        $_SESSION['tb_cancelled_shares'][$id] = time();
        // keep the list small
        if (count($_SESSION['tb_cancelled_shares']) > 500) $_SESSION['tb_cancelled_shares'] = array_slice($_SESSION['tb_cancelled_shares'], -500, null, true);
    }

    private static function wasCancelledHere($id)
    {
        return session_status() === PHP_SESSION_ACTIVE && isset($_SESSION['tb_cancelled_shares'][$id]);
    }

    /** All shares of the account, normalised: id, url, path, name, isdir. */
    public static function sharedLinks()
    {
        $out = array();
        $seen = array();
        $unverified = 0;
        for ($page = 1; $page <= 20; $page++) {
            $response = self::client()->shareList($page);
            $err = self::errnoOf($response);
            if ($err === -6) tb_session_expired();
            if ($err !== 0) {
                self::log('share list page ' . $page . ' errno=' . $err);
                throw new RuntimeException('TeraBox rejected the Shared Links request (errno ' . $err . ').');
            }
            $list = self::shareRecords($response);
            if ($list === null) {
                self::log('share list has unknown response keys: ' . implode(',', array_keys($response)));
                throw new RuntimeException('TeraBox returned an unrecognized Shared Links response.');
            }
            foreach ($list as $it) {
                if (!is_array($it)) continue;
                $id = '';
                foreach (array('share_id', 'shareid', 'shareId', 'shareidstr') as $key) {
                    if (isset($it[$key]) && ctype_digit((string)$it[$key])) { $id = (string)$it[$key]; break; }
                }
                $path = '';
                foreach (array('typicalPath', 'typical_path', 'path', 'filename', 'server_filename', 'name', 'title') as $key) {
                    if (isset($it[$key]) && is_string($it[$key]) && $it[$key] !== '') { $path = $it[$key]; break; }
                }
                foreach (array('file_list','filelist','files') as $key) {
                    if ($path === '' && isset($it[$key][0]['path'])) $path = (string)$it[$key][0]['path'];
                }
                $url = self::shareUrlFrom($it);
                if ($url === '' && isset($it['data']) && is_array($it['data'])) $url = self::shareUrlFrom($it['data']);
                // The service may include historical or internal records. Only show
                // actionable, public shares. In particular, a missing URL cannot be
                // treated as evidence that a public link remains active.
                if ($id === '' || $url === '') {
                    self::log('Skipping share-list record without an actionable share ID/public URL');
                    continue;
                }
                if (self::wasCancelledHere($id)) continue;
                $state = self::shareState($it);
                if ($state === 'cancelled') continue;
                // Some regions reject /api/shorturlinfo or return an undocumented
                // status. An inconclusive check must not break the entire listing.
                // Only an explicit cancellation status (or invalid-link 105) is
                // enough to exclude a record. Unknown means UNKNOWN, not active.
                $dedup = 'id:' . $id;
                if (isset($seen[$dedup])) continue;
                $seen[$dedup] = true;
                $name = $path !== '' ? basename(rtrim($path, '/')) : ($id !== '' ? 'Share #' . $id : 'Shared item');
                $out[] = array('id' => $id, 'url' => $url, 'path' => $path, 'name' => $name,
                               'isdir' => !empty($it['isdir']) || (isset($it['typical_category']) && (int)$it['typical_category'] === -1),
                               'verification' => 'unknown');
            }
            if (count($list) < 100) break;
        }
        // Verify all public links in parallel, with a session cache so reopening the page is fast.
        if (session_status() === PHP_SESSION_ACTIVE && (!isset($_SESSION['tb_share_state']) || !is_array($_SESSION['tb_share_state']))) $_SESSION['tb_share_state'] = array();
        $now = time(); $need = array();
        foreach ($out as $row) {
            $code = self::shareCodeOf($row['url']);
            if ($code === '') continue;
            $c = isset($_SESSION['tb_share_state'][$code]) ? $_SESSION['tb_share_state'][$code] : null;
            $fresh = $c && ($c[0] === 'cancelled' || ($now - $c[1]) < 300);
            if (!$fresh) $need[] = $code;
        }
        if ($need) {
            try {
                foreach (self::client()->shortUrlInfoMulti($need) as $code => $err) {
                    $st = self::stateFromErrno($err);
                    if ($st !== 'unknown' && session_status() === PHP_SESSION_ACTIVE) $_SESSION['tb_share_state'][$code] = array($st, $now);
                    if (session_status() === PHP_SESSION_ACTIVE && count($_SESSION['tb_share_state']) > 300) $_SESSION['tb_share_state'] = array_slice($_SESSION['tb_share_state'], -300, null, true);
                    elseif ($err !== null) self::log('share status query inconclusive errno=' . $err);
                }
            } catch (Throwable $e) { self::log('share status batch failed'); }
        }
        $final = array();
        foreach ($out as $row) {
            $code = self::shareCodeOf($row['url']);
            $st = ($code !== '' && isset($_SESSION['tb_share_state'][$code])) ? $_SESSION['tb_share_state'][$code][0] : 'unknown';
            if ($st === 'cancelled') continue;
            if ($st === 'unknown') $unverified++;
            $row['verification'] = $st;
            $final[] = $row;
        }
        $out = $final;
        if ($unverified > 0) self::log('Shared Links: ' . $unverified . ' public URLs have unknown status; returning partial results');
        return $out;
    }

    /** Existing share for a remote path handle, or null. */
    public static function findShare($handle)
    {
        foreach (self::sharedLinks() as $sh) {
            if ($sh['path'] !== '' && ('/' . ltrim($sh['path'], '/') === $handle)) return $sh;
        }
        return null;
    }

    /** Create (or reuse) a public link. Returns array(id,url). Throws on failure. */
    public static function createShareLink($handle)
    {
        $j = self::client()->shareSet(array($handle));
        $e = self::errnoOf($j);
        if ($e === -6) tb_session_expired();
        if ($e !== 0) throw new RuntimeException('TeraBox could not create the link (errno ' . $e . ').');
        $src = (isset($j['data']) && is_array($j['data']) && self::shareUrlFrom($j['data']) !== '') ? $j['data'] : $j;
        $url = self::shareUrlFrom($src);
        $id = '';
        foreach (array('shareid', 'share_id', 'shareId') as $k) if (isset($src[$k]) && ctype_digit((string)$src[$k])) { $id = (string)$src[$k]; break; }
        if ($url === '') {                       // response had no link: look it up in the share list
            $sh = self::findShare($handle);
            if ($sh) return array('id' => $sh['id'], 'url' => $sh['url']);
            throw new RuntimeException('TeraBox did not return a share link.');
        }
        if ($id === '') { $sh = self::findShare($handle); if ($sh) $id = $sh['id']; }
        if (session_status() === PHP_SESSION_ACTIVE) {
            if ($id !== '') unset($_SESSION['tb_cancelled_shares'][$id]);
            $code = self::shareCodeOf($url);
            if ($code !== '') unset($_SESSION['tb_share_state'][$code]);
        }
        return array('id' => $id, 'url' => $url);
    }

    public static function stopShare($shareId)
    {
        if (!ctype_digit((string)$shareId)) return false;
        $j = self::client()->shareCancel(array((int)$shareId));
        $e = self::errnoOf($j);
        if ($e === -6) tb_session_expired();
        if ($e !== 0) {
            self::log('share cancel errno=' . $e);
            throw new RuntimeException('TeraBox rejected cancellation (errno ' . $e . ').');
        }
        // TeraBox acknowledged cancellation, but its sharelist endpoint keeps returning
        // historical records (and shorturlinfo can be inconclusive). Remember the ID so
        // the Shared Links page does not show it again.
        self::markCancelled((string)$shareId);
        return true;
    }

    /** Save refreshed cookies / region host / page token into the login session (runs at shutdown). */
    public static function persist()
    {
        if (!self::$c || session_status() !== PHP_SESSION_ACTIVE) return;
        $_SESSION['cookie'] = self::$c->getCookie();
        $_SESSION['whost'] = self::$c->getWhost();
        if (self::$c->getJsToken() !== '') $_SESSION['tb_js'] = self::$c->getJsToken();
        $_SESSION['tb_uhost'] = self::$c->getUploadHostUrl();
    }
}

class TeraFS
{
    public $context;
    private $fh, $tmp, $up, $flushed, $list, $pos;

    const SCHEME_LEN = 10; // strlen('terabox://')

    static function remote($url)
    {
        $parts = array();
        foreach (explode('/', trim(substr($url, self::SCHEME_LEN), '/')) as $s) {
            if ($s === '..') return false;
            if ($s !== '' && $s !== '.') $parts[] = $s;
        }
        if (!$parts || $parts[0] !== 'root') return false;
        array_shift($parts);
        return implode('/', $parts);
    }

    static function isPart($url) { return substr($url, -5) === '.part'; }

    /** Chunked-upload ".part" files stay local so appends are cheap. */
    static function partPath($url)
    {
        $d = sys_get_temp_dir() . '/tbfm_' . md5(TeraApi::$sid);
        if (!is_dir($d)) @mkdir($d, 0700, true);
        return $d . '/' . md5($url) . '.part';
    }

    static function sb($dir, $size, $mtime)
    {
        return array('dev' => 0, 'ino' => 0, 'mode' => $dir ? 040777 : 0100666, 'nlink' => 1, 'uid' => 0, 'gid' => 0,
            'rdev' => 0, 'size' => $size, 'atime' => $mtime, 'mtime' => $mtime, 'ctime' => $mtime,
            'blksize' => -1, 'blocks' => -1);
    }

    static function node($url)
    {
        $rem = self::remote($url);
        if ($rem === false) return null;
        $h = TeraApi::find($rem);
        return $h === null ? null : TeraApi::$nodes[$h];
    }

    /** [parentHandle, name] for a not-yet-existing path, or null. */
    static function parentOf($url)
    {
        $rem = self::remote($url);
        if ($rem === false || $rem === '') return null;
        $d = dirname($rem);
        $p = TeraApi::find($d === '.' ? '' : $d);
        if ($p === null || TeraApi::$nodes[$p]['t'] === 0) return null;
        return array($p, basename($rem));
    }

    /** One-level directory snapshot (single listing request). */
    static function directorySnapshot($url)
    {
        $n = self::node($url);
        if (!$n || (int)$n['t'] === 0) return false;
        $result = array('folders' => array(), 'files' => array());
        foreach (TeraApi::kids($n['h']) as $name => $handle) {
            if (!isset(TeraApi::$nodes[$handle])) continue;
            $result[((int)TeraApi::$nodes[$handle]['t'] === 0) ? 'files' : 'folders'][] = (string)$name;
        }
        return $result;
    }

    /* ---------- stat / directories ---------- */

    function url_stat($path, $flags)
    {
        if (self::isPart($path)) return @stat(self::partPath($path)) ?: false;
        $n = self::node($path);
        return $n ? self::sb($n['t'] !== 0, $n['s'], $n['ts']) : false;
    }

    function dir_opendir($path, $opts)
    {
        $n = self::node($path);
        if (!$n || $n['t'] === 0) return false;
        $this->list = array_merge(array('.', '..'), array_map('strval', array_keys(TeraApi::kids($n['h']))));
        $this->pos = 0;
        return true;
    }
    function dir_readdir() { return $this->pos < count($this->list) ? $this->list[$this->pos++] : false; }
    function dir_rewinddir() { $this->pos = 0; return true; }
    function dir_closedir() { return true; }

    function mkdir($path, $mode, $opts)
    {
        $rem = self::remote($path);
        if ($rem === false || $rem === '') return false;
        $cur = 'terabox://root';
        $segs = explode('/', $rem);
        foreach ($segs as $i => $s) {
            $cur .= '/' . $s;
            if (self::node($cur)) continue;
            if ($i < count($segs) - 1 && !($opts & STREAM_MKDIR_RECURSIVE)) return false;
            $po = self::parentOf($cur);
            if (!$po || !TeraApi::mkdir($po[0], $po[1])) return false;
        }
        return true;
    }

    function rmdir($path, $opts)
    {
        $n = self::node($path);
        return $n && $n['t'] === 1 && TeraApi::delete($n['h']);
    }

    function unlink($path)
    {
        if (self::isPart($path)) return @unlink(self::partPath($path));
        $n = self::node($path);
        return $n && $n['t'] === 0 && TeraApi::delete($n['h']);
    }

    function rename($from, $to)
    {
        $dst = self::parentOf($to);
        if (!$dst) return false;
        if (self::isPart($from)) {
            $local = self::partPath($from);
            if (self::isPart($to)) return @rename($local, self::partPath($to));
            // TeraBox replaces an existing file of the same name while uploading (rtype=2).
            if (!TeraApi::upload($local, $dst[0], $dst[1])) return false;
            @unlink($local);
            return true;
        }
        $n = self::node($from);
        if (!$n || $n['t'] === 2) return false;
        $old = self::node($to);
        // Never destroy the destination: refuse replacement, caller handles conflicts.
        if ($old && $old['h'] !== $n['h']) return false;
        if ($old && $old['h'] === $n['h']) return true;
        return TeraApi::move($n['h'], $dst[0], $dst[1]);
    }

    function stream_metadata($path, $option, $value) { return false; } // no chmod/touch on TeraBox

    /* ---------- file streams (downloaded/buffered via local temp files) ---------- */

    function stream_open($path, $mode, $opts, &$opened)
    {
        $this->fh = $this->tmp = $this->up = null;
        $this->flushed = false;

        if (self::isPart($path)) {
            $this->fh = @fopen(self::partPath($path), $mode[0] === 'a' ? 'ab' : ($mode[0] === 'r' ? 'rb' : 'wb'));
            return (bool)$this->fh;
        }

        $n = self::node($path);
        if ($n && $n['t'] !== 0) return false;
        $readOnly = $mode[0] === 'r' && strpos($mode, '+') === false;
        if (($readOnly || $mode[0] === 'r') && !$n) return false;
        if ($mode[0] === 'x' && $n) return false;

        $this->tmp = tempnam(sys_get_temp_dir(), 'tbfm');
        $keep = $n && ($mode[0] === 'a' || $mode[0] === 'r');
        if ($keep || $readOnly) {
            if (!TeraApi::download($n['h'], $this->tmp)) { @unlink($this->tmp); return false; }
        }
        if ($readOnly) {
            $this->fh = fopen($this->tmp, 'rb');
            return (bool)$this->fh;
        }
        if (!self::parentOf($path)) { @unlink($this->tmp); return false; }
        $this->fh = fopen($this->tmp, $keep ? 'r+b' : 'wb');
        if ($keep && $mode[0] === 'a') fseek($this->fh, 0, SEEK_END);
        $this->up = $path;
        return (bool)$this->fh;
    }

    function stream_read($n) { return fread($this->fh, $n); }
    function stream_write($d) { return fwrite($this->fh, $d); }
    function stream_eof() { return feof($this->fh); }
    function stream_seek($o, $w) { return fseek($this->fh, $o, $w) === 0; }
    function stream_tell() { return ftell($this->fh); }
    function stream_set_option($o, $a, $b) { return false; }
    function stream_stat() { return fstat($this->fh); }

    function stream_flush()
    {
        if ($this->up === null || $this->flushed) return true;
        fflush($this->fh);
        $po = self::parentOf($this->up);
        if (!$po || !TeraApi::upload($this->tmp, $po[0], $po[1])) return false;
        $this->flushed = true;
        return true;
    }

    function stream_close()
    {
        if (!$this->stream_flush()) error_log('[tbfm] file upload failed during stream_close');
        if ($this->fh) fclose($this->fh);
        if ($this->tmp) @unlink($this->tmp);
    }
}

/* ---------- session gate ---------- */

function tb_is_ajax_request()
{
    return isset($_POST['ajax']) || (isset($_SERVER['HTTP_X_REQUESTED_WITH']) && $_SERVER['HTTP_X_REQUESTED_WITH'] !== '')
        || (isset($_SERVER['HTTP_ACCEPT']) && strpos($_SERVER['HTTP_ACCEPT'], 'application/json') !== false);
}

function tb_goto_login()
{
    if (tb_is_ajax_request()) {
        http_response_code(401);
        header('Content-Type: application/json; charset=UTF-8');
        echo json_encode(array('ok' => false, 'message' => 'Session expired. Reload the page and sign in again.'));
    } else {
        header('Location: login.php', true, 303);
    }
    exit;
}

/** TeraBox rejected our session: forget it locally and send the visitor to the login page. */
function tb_session_expired()
{
    if (function_exists('remember_clear')) remember_clear();
    unset($_SESSION['ndus'], $_SESSION['cookie'], $_SESSION['whost'], $_SESSION['tb_js'], $_SESSION['tb_uhost'], $_SESSION['tb_checked']);
    $_SESSION['flash'] = 'Your TeraBox session expired. Please sign in again.';
    tb_goto_login();
}

/** Call from config.php. Requires a completed login.php sign-in, then registers terabox://. */
function tb_require_login()
{
    $missing = array();
    foreach (array('curl', 'openssl', 'json') as $x) if (!extension_loaded($x)) $missing[] = $x;
    if (PHP_VERSION_ID < 70400) $missing[] = 'PHP 7.4+';
    if ($missing) die('Missing on this server: ' . implode(', ', $missing));

    require_once __DIR__ . '/bootstrap.php';   // starts the isolated login session, loads TB_* settings

    if (isset($_GET['tb_logout'])) { header('Location: login.php', true, 303); exit; } // logging out needs the POST form
    if (empty($_SESSION['ndus'])) tb_goto_login();

    $api = new TeraBoxAuth(isset($_SESSION['cookie']) ? $_SESSION['cookie'] : $_SESSION['ndus'], isset($_SESSION['whost']) ? $_SESSION['whost'] : null);
    if (!empty($_SESSION['tb_js'])) $api->useJsToken((string)$_SESSION['tb_js']);
    if (!empty($_SESSION['tb_uhost'])) $api->useUploadHost((string)$_SESSION['tb_uhost']);

    // One cheap validity check every few minutes; not on every click.
    if (time() - (int)(isset($_SESSION['tb_checked']) ? $_SESSION['tb_checked'] : 0) > 300) {
        try {
            $chk = $api->checkLogin();
        } catch (Throwable $e) {
            tb_log('gate_check_error', array('msg' => $e->getMessage()));
            http_response_code(503);
            exit('Could not reach TeraBox right now. Reload in a moment. Your sign-in is kept.');
        }
        if ((int)(isset($chk['errno']) ? $chk['errno'] : -1) !== 0) tb_session_expired();
        $_SESSION['tb_checked'] = time();
    }

    TeraApi::init($api, substr(hash('sha256', session_id()), 0, 24));
    register_shutdown_function(array('TeraApi', 'persist'));

    $who = !empty($_SESSION['email']) ? strtolower((string)$_SESSION['email']) : (string)$_SESSION['ndus'];
    $GLOBALS['mega_authenticated_pref_id'] = hash('sha256', $who);  // scopes per-account UI preferences
    stream_wrapper_register('terabox', 'TeraFS');
}

/** Drop-in for move_uploaded_file() that also works for terabox:// targets. */
function tb_move_uploaded($tmp, $dest)
{
    if (strpos($dest, 'terabox://') === 0) {
        if (!is_uploaded_file($tmp)) return false;
        $po = TeraFS::parentOf($dest);
        if (!$po || !TeraApi::upload($tmp, $po[0], $po[1])) return false;
        @unlink($tmp);
        return true;
    }
    return move_uploaded_file($tmp, $dest);
}
