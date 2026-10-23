<?php
declare(strict_types=1);

/** Expose only rendering data, never arbitrary upstream fields or tokens. */
function captcha_render_data(array $data): array
{
    $out = [];
    foreach (['master_width', 'master_height', 'tile_width', 'tile_height', 'tile_x', 'tile_y'] as $key) {
        $value = $data[$key] ?? null;
        if (!is_numeric($value) || !is_finite((float)$value) || (float)$value != (int)$value
            || (int)$value < 0 || (int)$value > 4096) {
            throw new RuntimeException('Unsupported challenge geometry.');
        }
        $out[$key] = (int)$value;
    }
    if ($out['master_width'] < 1 || $out['master_height'] < 1 || $out['tile_width'] < 1 || $out['tile_height'] < 1
        || $out['tile_x'] + $out['tile_width'] > $out['master_width']
        || $out['tile_y'] + $out['tile_height'] > $out['master_height']) {
        throw new RuntimeException('Unsupported challenge dimensions.');
    }
    foreach (['master_image', 'tile_image'] as $key) {
        $image = $data[$key] ?? null;
        if (!is_string($image) || strlen($image) > 8 * 1024 * 1024) {
            throw new RuntimeException('Unsupported challenge image.');
        }
        $url = parse_url($image);
        $https = is_array($url) && ($url['scheme'] ?? '') === 'https' && !empty($url['host'])
            && !isset($url['user']) && !isset($url['pass']) && !isset($url['port'])
            && preg_match('/(^|\.)(?:terabox\.com|teraboxcdn\.com)$/i', (string)$url['host'])
            && !preg_match('/[\x00-\x20]/', $image);
        $raster = preg_match('#^data:image/(?:png|jpeg|webp|gif);base64,[A-Za-z0-9+/=\r\n]+$#D', $image);
        if (!$https && !$raster) throw new RuntimeException('Unsupported challenge image URL.');
        $out[$key] = $image;
    }
    return $out;
}

/** Token is short lived and consumed once, only for a manual same-account login. */
function captcha_consume_token(array &$pending, string $email, bool $requested, int $now): string
{
    $token = '';
    if ($requested && (int)($pending['expires'] ?? 0) > $now
        && (int)($pending['ticket_expires'] ?? 0) > $now
        && hash_equals((string)($pending['email_hash'] ?? ''), hash('sha256', strtolower(trim($email))))
        && is_string($pending['capt_token'] ?? null)) {
        $token = $pending['capt_token'];
    }
    unset($pending['capt_token'], $pending['ticket_expires']);
    return $token;
}

function captcha_ticket_deadline($expire, int $now): int
{
    // Our own 120-second limit. Honor shorter recognizable durations/Unix seconds;
    // this is not a claim about undocumented upstream expiry units.
    $deadline = $now + 120;
    if (is_numeric($expire) && (float)$expire <= 0) return $now;
    if (is_numeric($expire) && (float)$expire > 0) {
        $value = (float)$expire;
        if ($value <= 86400) $deadline = min($deadline, $now + (int)$value);
        elseif ($value <= $now + 86400) $deadline = min($deadline, (int)$value);
    }
    return $deadline;
}
