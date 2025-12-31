<?php
declare(strict_types=1);

namespace BlackCat\Jwt\CoreCompat;

use BlackCat\Core\Database;
use BlackCat\Jwt\Jwt;

/**
 * Backwards-compat facade for the legacy global `JWT` helper from blackcat-core.
 */
final class CoreJWT
{
    private function __construct() {}

    /**
     * @param array<string,mixed> $extraClaims
     */
    public static function issueAccessToken(int $userId, array $extraClaims = [], ?int $ttl = null, ?string $keysDir = null): string
    {
        return Jwt::issueAccessToken($userId, $extraClaims, $ttl, $keysDir);
    }

    /**
     * @return array<string,mixed>|null
     */
    public static function verify(string $jwt, ?string $keysDir = null, bool $checkJtiInDb = false, mixed $db = null): ?array
    {
        if ($db instanceof \PDO) {
            Database::initFromPdo($db);
            $db = Database::getInstance();
        }
        if ($db !== null && !$db instanceof Database) {
            $db = null;
        }
        return Jwt::verify($jwt, $keysDir, $checkJtiInDb, $db);
    }

    /**
     * @return array{raw: string, hash: string, pepver: string|null, jti: string, expires_at: string, user_id: int}
     */
    public static function generateRefreshToken(int $userId, ?int $ttl = null, ?string $keysDir = null): array
    {
        return Jwt::generateRefreshToken($userId, $ttl, $keysDir);
    }

    public static function validateRefreshTokenRaw(string $rawToken, string $storedHashBin, ?string $keysDir = null): bool
    {
        return Jwt::validateRefreshTokenRaw($rawToken, $storedHashBin, $keysDir);
    }
}
