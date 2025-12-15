<?php
declare(strict_types=1);

namespace BlackCat\Jwt\Tests\Integration;

use BlackCat\Core\Database;
use BlackCat\Database\Packages\JwtTokens\JwtTokensModule;
use BlackCat\Database\Packages\JwtTokens\Repository\JwtTokenRepository;
use BlackCat\Database\Packages\Users\Repository\UserRepository;
use BlackCat\Database\Packages\Users\UsersModule;
use BlackCat\Jwt\Jwt;
use PHPUnit\Framework\TestCase;

/**
 * Requires a real DB (MySQL/Postgres); skipped unless DB_DSN is provided.
 *
 * @runInSeparateProcess
 * @preserveGlobalState disabled
 */
final class JwtDbRevocationIntegrationTest extends TestCase
{
    public function testVerifyWithDbJtiCheck(): void
    {
        $db = $this->initDbOrSkip();
        $dialect = $db->dialect();

        (new UsersModule())->install($db, $dialect);
        (new JwtTokensModule())->install($db, $dialect);
        $this->wipeTables($db, ['jwt_tokens', 'users']);

        $userId = $this->createUser($db);

        $keysDir = $this->prepareKeysDir();
        $token = Jwt::issueAccessToken($userId, [], ttl: 60, keysDir: $keysDir);
        $claims = Jwt::verify($token, keysDir: $keysDir);
        self::assertIsArray($claims);

        $jti = (string)($claims['jti'] ?? '');
        self::assertNotSame('', $jti);

        // Insert row to satisfy DB revocation gate.
        $repo = new JwtTokenRepository($db);
        $repo->insert([
            'jti' => $jti,
            'user_id' => $userId,
            'token_hash' => random_bytes(32),
            'token_hash_algo' => 'test-only',
            'type' => 'api',
            'expires_at' => (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->modify('+60 seconds')->format('Y-m-d H:i:s.u'),
            'revoked' => false,
        ]);

        self::assertIsArray(Jwt::verify($token, keysDir: $keysDir, checkJtiInDb: true, db: $db));

        $row = $repo->getByJti($jti, false);
        self::assertIsArray($row);
        $repo->updateById((int)($row['id'] ?? 0), ['revoked' => true]);

        self::assertNull(Jwt::verify($token, keysDir: $keysDir, checkJtiInDb: true, db: $db));
    }

    private function initDbOrSkip(): Database
    {
        $dsn = (string)(getenv('DB_DSN') ?: '');
        if ($dsn === '') {
            self::markTestSkipped('Set DB_DSN to run integration tests.');
        }

        Database::init([
            'dsn' => $dsn,
            'user' => getenv('DB_USER') ?: null,
            'pass' => getenv('DB_PASSWORD') ?: null,
        ]);

        return Database::getInstance();
    }

    private function createUser(Database $db): int
    {
        $repo = new UserRepository($db);
        $repo->insert([
            'password_hash' => 'x',
            'password_algo' => 'plaintext-test-only',
        ]);

        $id = $db->lastInsertId();
        if (is_string($id) && ctype_digit($id) && (int)$id > 0) {
            return (int)$id;
        }
        return 0;
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

    /**
     * @param list<string> $tables
     */
    private function wipeTables(Database $db, array $tables): void
    {
        foreach ($tables as $table) {
            $table = trim($table);
            if ($table === '') {
                continue;
            }
            try {
                $db->exec('DELETE FROM ' . $table);
            } catch (\Throwable) {
            }
        }
    }
}

