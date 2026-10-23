<?php
declare(strict_types=1);

/**
 * Direct download links.
 *
 * TeraBox's own share page asks visitors to sign in before they can download. A direct link instead
 * points at direct.php on THIS server, which downloads the file from TeraBox with the owner's account
 * and streams it to the visitor. To do that without the owner being signed in, the owner's TeraBox
 * session cookie is stored on the server, encrypted with secret.key.php.
 *
 * Each link is a random 256-bit token; knowing the token is the only credential.
 */
final class TeraDirect
{
    /** Legacy location (server temp folder) used by the first version; records are moved from here. */
    private static function legacyDir(): string
    {
        return sys_get_temp_dir() . '/tbfm_direct_' . substr(hash('sha256', __DIR__), 0, 12);
    }

    /**
     * Folder for link records: "direct_links" next to this file. Each record is a .php file whose first line
     * stops execution, so a web request for it returns nothing even if the server serves the folder
     * (nginx ignores .htaccess). Falls back to the server temp folder if the app folder is not writable.
     */
    public static function dir(): string
    {
        static $d = null;
        if ($d !== null) return $d;
        $app = __DIR__ . '/direct_links';
        if (!is_dir($app)) @mkdir($app, 0700, true);
        if (!is_dir($app) || !is_writable($app)) {
            $legacy = self::legacyDir();
            if (!is_dir($legacy)) @mkdir($legacy, 0700, true);
            return $d = $legacy;
        }
        if (!is_file($app . '/.htaccess')) {
            @file_put_contents($app . '/.htaccess', "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
            @file_put_contents($app . '/index.html', '');
        }
        $d = $app;
        self::migrate();
        return $d;
    }

    /** One-time move of records from the old temp-folder location. */
    private static function migrate(): void
    {
        $old = self::legacyDir();
        if (!is_dir($old) || realpath($old) === realpath(self::dir())) return;
        foreach (glob($old . '/*.json') ?: [] as $f) {
            $rec = json_decode((string)@file_get_contents($f), true);
            $token = basename($f, '.json');
            if (is_array($rec) && preg_match('/^[0-9a-f]{64}$/D', $token)) {
                try { self::write($token, $rec); @unlink($f); } catch (Throwable $e) { /* keep the old file */ }
            }
        }
    }

    private static function read(string $f): ?array
    {
        $raw = @file_get_contents($f);
        if (!is_string($raw)) return null;
        $nlPos = strpos($raw, "\n");
        $rec = json_decode($nlPos === false ? $raw : substr($raw, $nlPos + 1), true);
        return is_array($rec) ? $rec : null;
    }

    private static function key(): ?string
    {
        $f = __DIR__ . '/secret.key.php';
        if (!is_file($f)) return null;
        $k = @include $f;
        return (is_string($k) && strlen($k) === 64 && ctype_xdigit($k)) ? hex2bin($k) : null;
    }

    private static function file(string $token): ?string
    {
        return preg_match('/^[0-9a-f]{64}$/D', $token) ? self::dir() . '/' . $token . '.php' : null;
    }

    private static function seal(string $plain): ?string
    {
        $key = self::key();
        if ($key === null) return null;
        $iv = random_bytes(12);
        $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        return $ct === false ? null : base64_encode($iv . $tag . $ct);
    }

    private static function open(string $blob): ?string
    {
        $key = self::key();
        $raw = base64_decode($blob, true);
        if ($key === null || $raw === false || strlen($raw) < 29) return null;
        $pt = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16));
        return $pt === false ? null : $pt;
    }

    /** Identifies the account that owns a link, so one user cannot list or revoke another's. */
    public static function ownerId(string $who): string { return hash('sha256', 'direct-owner|' . strtolower($who)); }

    private static function write(string $token, array $rec): void
    {
        $f = self::file($token);
        if ($f === null) throw new RuntimeException('Bad token.');
        $tmp = $f . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, "<?php exit; ?>\n" . json_encode($rec), LOCK_EX) === false) throw new RuntimeException('Cannot store the direct link: make the folder "direct_links" next to index.php writable by the web server.');
        @chmod($tmp, 0600);
        if (!@rename($tmp, $f)) { @unlink($tmp); throw new RuntimeException('Cannot store the direct link: make the folder "direct_links" next to index.php writable by the web server.'); }
    }

    /** @return array{token:string,exp:int} */
    public static function create(string $owner, string $cookie, string $whost, string $path, int $fsId, string $name, int $size, int $days): array
    {
        $sealed = self::seal($cookie);
        if ($sealed === null) throw new RuntimeException('Cannot encrypt the session: secret.key.php is missing or unreadable.');
        $token = bin2hex(random_bytes(32));
        $exp = $days > 0 ? time() + $days * 86400 : 0;
        self::write($token, ['v' => 1, 'owner' => self::ownerId($owner), 'path' => $path, 'fs' => $fsId, 'name' => $name,
            'size' => $size, 'created' => time(), 'exp' => $exp, 'whost' => $whost, 'c' => $sealed]);
        self::sweep();
        return ['token' => $token, 'exp' => $exp];
    }

    /** Record for a token, or null if unknown/expired. The cookie is decrypted into 'cookie'. */
    public static function load(string $token): ?array
    {
        $f = self::file($token);
        if ($f === null || !is_file($f)) return null;
        $rec = self::read($f);
        if (!is_array($rec) || empty($rec['c'])) return null;
        if (!empty($rec['exp']) && (int)$rec['exp'] < time()) { @unlink($f); return null; }
        $cookie = self::open((string)$rec['c']);
        if ($cookie === null) return null;
        $rec['cookie'] = $cookie;
        return $rec;
    }

    /** The owner's existing, still-valid link for this path (without decrypting anything). */
    public static function findForPath(string $owner, string $path): ?array
    {
        $oid = self::ownerId($owner);
        foreach (glob(self::dir() . '/*.php') ?: [] as $f) {
            $rec = self::read($f);
            if (!is_array($rec) || ($rec['owner'] ?? '') !== $oid || ($rec['path'] ?? '') !== $path) continue;
            if (!empty($rec['exp']) && (int)$rec['exp'] < time()) { @unlink($f); continue; }
            return ['token' => basename($f, '.php'), 'exp' => (int)($rec['exp'] ?? 0), 'created' => (int)($rec['created'] ?? 0)];
        }
        return null;
    }

    /** Keep the stored session current while the owner is signed in. */
    public static function refreshCookie(string $owner, string $token, string $cookie): void
    {
        $f = self::file($token);
        if ($f === null || !is_file($f)) return;
        $rec = self::read($f);
        if (!is_array($rec) || ($rec['owner'] ?? '') !== self::ownerId($owner)) return;
        $sealed = self::seal($cookie);
        if ($sealed === null) return;
        $rec['c'] = $sealed;
        self::write($token, $rec);
    }

    /** All of the owner's links in one pass: path => ['token','exp','created']. */
    public static function mapForOwner(string $owner): array
    {
        $oid = self::ownerId($owner); $out = [];
        foreach (glob(self::dir() . '/*.php') ?: [] as $f) {
            $rec = self::read($f);
            if (!is_array($rec) || ($rec['owner'] ?? '') !== $oid || empty($rec['path'])) continue;
            if (!empty($rec['exp']) && (int)$rec['exp'] < time()) { @unlink($f); continue; }
            $out[(string)$rec['path']] = ['token' => basename($f, '.php'), 'exp' => (int)($rec['exp'] ?? 0), 'created' => (int)($rec['created'] ?? 0), 'name' => (string)($rec['name'] ?? '')];
        }
        return $out;
    }

    /** Remove the owner's link(s) for a path (used when sharing is stopped). */
    public static function revokeByPath(string $owner, string $path): void
    {
        $oid = self::ownerId($owner);
        foreach (glob(self::dir() . '/*.php') ?: [] as $f) {
            $rec = self::read($f);
            if (is_array($rec) && ($rec['owner'] ?? '') === $oid && ($rec['path'] ?? '') === $path) @unlink($f);
        }
    }

    public static function revoke(string $owner, string $token): bool
    {
        $f = self::file($token);
        if ($f === null || !is_file($f)) return false;
        $rec = self::read($f);
        if (!is_array($rec) || ($rec['owner'] ?? '') !== self::ownerId($owner)) return false;
        return @unlink($f);
    }

    /** Delete expired records now and then. */
    private static function sweep(): void
    {
        foreach (glob(self::dir() . '/*.php') ?: [] as $f) {
            $rec = self::read($f);
            if (is_array($rec) && !empty($rec['exp']) && (int)$rec['exp'] < time()) @unlink($f);
        }
    }
}
