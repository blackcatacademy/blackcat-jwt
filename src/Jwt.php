<?php
declare(strict_types=1);

namespace BlackCat\Jwt;

use BlackCat\Core\Database;
use BlackCat\Core\Security\KeyManager;
use BlackCat\Database\Packages\JwtTokens\Repository\JwtTokenRepository;

final class Jwt
{
    private const ALG = 'HS256';
    private const TYP = 'JWT';
    private const ACCESS_TTL = 900; // 15m default
    private const REFRESH_TTL = 1209600; // 14 days default

    private function __construct() {}

    private static function keysDir(?string $keysDir = null): ?string
    {
        if (is_string($keysDir) && trim($keysDir) !== '') {
            return trim($keysDir);
        }
        return defined('KEYS_DIR') ? (string)KEYS_DIR : ($_ENV['KEYS_DIR'] ?? null);
    }

    private static function base64urlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64urlDecode(string $b64u): ?string
    {
        $remainder = strlen($b64u) % 4;
        if ($remainder) {
            $b64u .= str_repeat('=', 4 - $remainder);
        }
        $decoded = base64_decode(strtr($b64u, '-_', '+/'), true);
        return $decoded === false ? null : $decoded;
    }

    private static function generateJti(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);
        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }

    /**
     * Issue access token (JWT compact) — returns string.
     *
     * @param array<string,mixed> $extraClaims
     */
    public static function issueAccessToken(int $userId, array $extraClaims = [], ?int $ttl = null, ?string $keysDir = null): string
    {
        $ttl = $ttl ?? self::ACCESS_TTL;
        $now = time();

        $payload = array_merge([
            'iss' => $_ENV['APP_ISSUER'] ?? 'app',
            'sub' => (string)$userId,
            'iat' => $now,
            'nbf' => $now,
            'exp' => $now + max(1, $ttl),
            'jti' => self::generateJti(),
        ], $extraClaims);

        $hdr = ['alg' => self::ALG, 'typ' => self::TYP];

        $keysDir = self::keysDir($keysDir);

        $info = KeyManager::getRawKeyBytes('JWT_KEY', $keysDir, 'jwt_key', false, KeyManager::keyByteLen());
        $rawKey = $info['raw'];
        $ver = $info['version'] ?? 'v1';
        $hdr['kid'] = $ver;

        $hjson = json_encode($hdr, JSON_UNESCAPED_SLASHES);
        $pjson = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($hjson === false || $pjson === false) {
            throw new \RuntimeException('jwt_encode_failed');
        }

        $hb64 = self::base64urlEncode($hjson);
        $pb64 = self::base64urlEncode($pjson);
        $sigInput = $hb64 . '.' . $pb64;

        $sig = hash_hmac('sha256', $sigInput, $rawKey, true);
        try {
            KeyManager::memzero($rawKey);
        } catch (\Throwable) {
        }

        $sb64 = self::base64urlEncode($sig);
        return $hb64 . '.' . $pb64 . '.' . $sb64;
    }

    /**
     * Verify compact JWT.
     *
     * If $checkJtiInDb = true, requires $db (Database or PDO) to check revocation in `jwt_tokens`.
     *
     * @return array<string,mixed>|null
     */
    public static function verify(string $jwt, ?string $keysDir = null, bool $checkJtiInDb = false, Database|\PDO|null $db = null): ?array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }
        [$hb64, $pb64, $sb64] = $parts;

        $hjson = self::base64urlDecode($hb64);
        $pjson = self::base64urlDecode($pb64);
        $sig = self::base64urlDecode($sb64);
        if ($hjson === null || $pjson === null || $sig === null) {
            return null;
        }

        $hdr = json_decode($hjson, true);
        $payload = json_decode($pjson, true);
        if (!is_array($hdr) || !is_array($payload)) {
            return null;
        }

        $sigInput = $hb64 . '.' . $pb64;
        $keysDir = self::keysDir($keysDir);

        $kid = $hdr['kid'] ?? null;
        if (is_string($kid) && $kid !== '' && $keysDir !== null) {
            try {
                $info = KeyManager::getRawKeyBytesByVersion('JWT_KEY', $keysDir, 'jwt_key', $kid, KeyManager::keyByteLen());
                $key = $info['raw'];
                $h = hash_hmac('sha256', $sigInput, $key, true);
                try {
                    KeyManager::memzero($key);
                } catch (\Throwable) {
                }
                if (hash_equals($h, $sig)) {
                    return self::validateClaimsAndReturn($payload, $checkJtiInDb, $db);
                }
            } catch (\Throwable) {
                // fallthrough to candidates
            }
        }

        $candidates = KeyManager::deriveHmacCandidates('JWT_KEY', $keysDir, 'jwt_key', $sigInput);
        foreach ($candidates as $cand) {
            if (is_array($cand) && isset($cand['hash'])) {
                if (hash_equals((string)$cand['hash'], $sig)) {
                    return self::validateClaimsAndReturn($payload, $checkJtiInDb, $db);
                }
            } elseif (is_string($cand)) {
                if (hash_equals($cand, $sig)) {
                    return self::validateClaimsAndReturn($payload, $checkJtiInDb, $db);
                }
            }
        }

        return null;
    }

    /**
     * Issue refresh token (random string) and return array:
     * ['raw' => $refreshTokenRaw, 'hash' => binary32_hash_to_store, 'pepver' => string|null, 'jti' => string, 'expires_at' => string]
     *
     * @return array{raw: string, hash: string, pepver: string|null, jti: string, expires_at: string, user_id: int}
     */
    public static function generateRefreshToken(int $userId, ?int $ttl = null, ?string $keysDir = null): array
    {
        $ttl = $ttl ?? self::REFRESH_TTL;
        $raw = bin2hex(random_bytes(48));
        $jti = self::generateJti();
        $expiresAt = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))
            ->modify('+' . max(1, $ttl) . ' seconds')
            ->format('Y-m-d H:i:s.u');

        $keysDir = self::keysDir($keysDir);
        $pepRes = KeyManager::deriveHmacWithLatest('REFRESH_TOKEN_KEY', $keysDir, 'refresh_token', $raw);
        $hash = $pepRes['hash'];
        $pepver = $pepRes['version'] ?? null;

        return ['raw' => $raw, 'hash' => $hash, 'pepver' => $pepver, 'jti' => $jti, 'expires_at' => $expiresAt, 'user_id' => $userId];
    }

    public static function validateRefreshTokenRaw(string $rawToken, string $storedHashBin, ?string $keysDir = null): bool
    {
        $keysDir = self::keysDir($keysDir);
        $cands = KeyManager::deriveHmacCandidates('REFRESH_TOKEN_KEY', $keysDir, 'refresh_token', $rawToken);
        foreach ($cands as $c) {
            if (is_array($c) && isset($c['hash'])) {
                if (hash_equals((string)$c['hash'], $storedHashBin)) {
                    return true;
                }
            } elseif (is_string($c)) {
                if (hash_equals($c, $storedHashBin)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>|null
     */
    private static function validateClaimsAndReturn(array $payload, bool $checkDbJti, Database|\PDO|null $db): ?array
    {
        $now = time();
        if (isset($payload['nbf']) && (int)$payload['nbf'] > $now) {
            return null;
        }
        if (isset($payload['exp']) && (int)$payload['exp'] < $now) {
            return null;
        }

        if ($checkDbJti) {
            $jti = $payload['jti'] ?? null;
            if (!is_string($jti) || $jti === '') {
                return null;
            }

            $dbc = null;
            if ($db instanceof Database) {
                $dbc = $db;
            } elseif ($db instanceof \PDO) {
                Database::initFromPdo($db);
                $dbc = Database::getInstance();
            } else {
                return null;
            }

            $repo = new JwtTokenRepository($dbc);
            $row = $repo->getByJti($jti, false);
            if (!is_array($row)) {
                return null;
            }
            if (!empty($row['revoked'])) {
                return null;
            }
            $expiresAt = $row['expires_at'] ?? null;
            if ($expiresAt !== null && $expiresAt !== '') {
                try {
                    $exp = $expiresAt instanceof \DateTimeInterface
                        ? $expiresAt
                        : new \DateTimeImmutable((string)$expiresAt, new \DateTimeZone('UTC'));
                    if ($exp < new \DateTimeImmutable('now', new \DateTimeZone('UTC'))) {
                        return null;
                    }
                } catch (\Throwable) {
                    return null;
                }
            }
        }

        return $payload;
    }
}
