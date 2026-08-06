<?php

declare(strict_types=1);

final class Config
{
    private static ?array $data = null;

    public static function all(): array
    {
        if (self::$data !== null) {
            return self::$data;
        }

        $userConfigPath = __DIR__ . '/../config.php';
        if (!is_file($userConfigPath)) {
            http_response_code(500);
            die(
                'Falta config.php. Copia config.sample.php a config.php y completa tus valores '
                . '(password_hash, scan_roots, y opcionalmente las API keys de IA/VirusTotal).'
            );
        }

        /** @var array $userConfig */
        $userConfig = require $userConfigPath;
        self::$data = $userConfig;

        return self::$data;
    }

    public static function get(string $dotPath, $default = null)
    {
        $data = self::all();
        $segments = explode('.', $dotPath);
        $cursor = $data;

        foreach ($segments as $segment) {
            if (!is_array($cursor) || !array_key_exists($segment, $cursor)) {
                return $default;
            }
            $cursor = $cursor[$segment];
        }

        return $cursor;
    }
}
