<?php

declare(strict_types=1);

final class Auth
{
    public static function start(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_set_cookie_params([
                'lifetime' => 0,
                'path' => '/',
                'httponly' => true,
                'samesite' => 'Strict',
            ]);
            session_start();
        }
    }

    public static function isLoggedIn(): bool
    {
        self::start();
        return !empty($_SESSION['auth_user']);
    }

    public static function requireLogin(): void
    {
        if (!self::isLoggedIn()) {
            self::renderLoginPage();
            exit;
        }
    }

    public static function clientIp(): string
    {
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private static function pdo(): PDO
    {
        return Database::connection();
    }

    public static function isLockedOut(): bool
    {
        $config = Config::all();
        $maxAttempts = (int) ($config['auth']['max_login_attempts'] ?? 5);
        $lockoutSeconds = (int) ($config['auth']['lockout_seconds'] ?? 900);

        $stmt = self::pdo()->prepare(
            'SELECT COUNT(*) AS c FROM login_attempts
             WHERE ip = :ip AND success = 0
               AND attempted_at >= datetime("now", :window)'
        );
        $stmt->execute([
            ':ip' => self::clientIp(),
            ':window' => '-' . $lockoutSeconds . ' seconds',
        ]);
        $row = $stmt->fetch();

        return ((int) $row['c']) >= $maxAttempts;
    }

    private static function recordAttempt(bool $success): void
    {
        $stmt = self::pdo()->prepare(
            'INSERT INTO login_attempts (ip, success) VALUES (:ip, :success)'
        );
        $stmt->execute([
            ':ip' => self::clientIp(),
            ':success' => $success ? 1 : 0,
        ]);
    }

    public static function attemptLogin(string $username, string $password): bool
    {
        if (self::isLockedOut()) {
            return false;
        }

        $config = Config::all();
        $expectedUser = (string) ($config['auth']['username'] ?? '');
        $expectedHash = (string) ($config['auth']['password_hash'] ?? '');

        $ok = hash_equals($expectedUser, $username) && password_verify($password, $expectedHash);
        self::recordAttempt($ok);

        if ($ok) {
            self::start();
            session_regenerate_id(true);
            $_SESSION['auth_user'] = $username;
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }

        return $ok;
    }

    public static function logout(): void
    {
        self::start();
        $_SESSION = [];
        session_destroy();
    }

    public static function csrfToken(): string
    {
        self::start();
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }

    public static function requireCsrf(): void
    {
        self::start();
        $token = $_POST['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!is_string($token) || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
            http_response_code(403);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'CSRF token inválido o ausente.']);
            exit;
        }
    }

    private static function renderLoginPage(): void
    {
        http_response_code(200);
        $lockedOut = self::isLockedOut();
        $error = $_SESSION['login_error'] ?? null;
        unset($_SESSION['login_error']);
        ?>
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Scanner Antimalware — Acceso</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body class="login-body">
<main class="login-card">
    <h1>Scanner Antimalware</h1>
    <?php if ($lockedOut): ?>
        <p class="alert alert-error">Demasiados intentos fallidos. Intenta de nuevo más tarde.</p>
    <?php elseif ($error): ?>
        <p class="alert alert-error"><?= htmlspecialchars($error, ENT_QUOTES) ?></p>
    <?php endif; ?>
    <form method="post" action="index.php?action=login">
        <label>Usuario
            <input type="text" name="username" autocomplete="username" required <?= $lockedOut ? 'disabled' : '' ?>>
        </label>
        <label>Contraseña
            <input type="password" name="password" autocomplete="current-password" required <?= $lockedOut ? 'disabled' : '' ?>>
        </label>
        <button type="submit" <?= $lockedOut ? 'disabled' : '' ?>>Entrar</button>
    </form>
</main>
</body>
</html>
        <?php
    }
}
