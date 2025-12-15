<?php
declare(strict_types=1);

namespace BlackCat\Jwt\Tests\Unit;

use BlackCat\Jwt\Jwt;
use PHPUnit\Framework\TestCase;

final class JwtTest extends TestCase
{
    public function testIssueAndVerifyRoundTrip(): void
    {
        $keysDir = $this->prepareKeysDir();

        $token = Jwt::issueAccessToken(123, ['roles' => ['admin']], ttl: 60, keysDir: $keysDir);
        $claims = Jwt::verify($token, keysDir: $keysDir);

        self::assertIsArray($claims);
        self::assertSame('123', (string)($claims['sub'] ?? ''));
        self::assertSame(['admin'], $claims['roles'] ?? null);
        self::assertNotSame('', (string)($claims['jti'] ?? ''));
    }

    private function prepareKeysDir(): string
    {
        $tmp = rtrim(sys_get_temp_dir(), '/\\') . '/blackcat-jwt-keys-' . bin2hex(random_bytes(6));
        if (!mkdir($tmp, 0700, true) && !is_dir($tmp)) {
            throw new \RuntimeException('Unable to create temp keys dir');
        }

        $jwtKey = "0123456789abcdef0123456789abcdef";
        $refreshKey = "fedcba9876543210fedcba9876543210";
        if (strlen($jwtKey) !== 32 || strlen($refreshKey) !== 32) {
            throw new \RuntimeException('Invalid fixture key length');
        }

        if (file_put_contents($tmp . '/jwt_key_v1.key', $jwtKey) === false) {
            throw new \RuntimeException('Unable to write jwt key');
        }
        if (file_put_contents($tmp . '/refresh_token_v1.key', $refreshKey) === false) {
            throw new \RuntimeException('Unable to write refresh token key');
        }

        return $tmp;
    }
}

