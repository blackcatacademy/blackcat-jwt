# BlackCat JWT

`blackcat-jwt` je samostatný modul pro vydávání/ověřování JWT a volitelnou kontrolu revokace přes `blackcat-database` package `jwt-tokens`.

- Signing/verification používá HMAC (HS256) a `BlackCat\\Core\\Security\\KeyManager` (`jwt_key_vN.key`).
- Kontrola JTI v DB používá generated repository (`JwtTokenRepository`), žádné raw SQL v modulu.

## Instalace

```bash
composer require blackcatacademy/blackcat-jwt
```

## Použití

```php
use BlackCat\Jwt\Jwt;

$token = Jwt::issueAccessToken(userId: 123, extraClaims: ['roles' => ['admin']], keysDir: '/keys');
$claims = Jwt::verify($token, keysDir: '/keys');
```

## Legacy kompatibilita

`blackcat-core/src/JWT.php` je nyní shim a po instalaci tohoto modulu deleguje na `BlackCat\\Jwt\\CoreCompat\\CoreJWT`.

