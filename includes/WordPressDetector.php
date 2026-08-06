<?php

declare(strict_types=1);

final class WordPressDetector
{
    private const MAX_DEPTH = 4; // evita recorrer árboles enormes solo para ubicar instalaciones WP

    /** @return array<int, array{root:string, version:string}> */
    public static function findInstallations(): array
    {
        $installations = [];

        foreach (PathGuard::scanRoots() as $root) {
            self::searchFrom($root, 0, $installations);
        }

        return array_values($installations);
    }

    private static function searchFrom(string $dir, int $depth, array &$installations): void
    {
        $versionFile = $dir . '/wp-includes/version.php';
        if (is_file($versionFile)) {
            $key = realpath($dir) ?: $dir;
            $installations[$key] = ['root' => $key, 'version' => self::readVersion($versionFile)];
            return; // no seguir bajando dentro de una instalación WP ya identificada
        }

        if ($depth >= self::MAX_DEPTH) {
            return;
        }

        $entries = @scandir($dir);
        if ($entries === false) {
            return;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..' || str_starts_with($entry, '.')) {
                continue;
            }
            $path = $dir . '/' . $entry;
            if (is_dir($path) && !is_link($path)) {
                self::searchFrom($path, $depth + 1, $installations);
            }
        }
    }

    private static function readVersion(string $versionFile): string
    {
        $contents = @file_get_contents($versionFile, false, null, 0, 4096);
        if ($contents !== false && preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $contents, $m)) {
            return $m[1];
        }
        return 'desconocida';
    }

    /** Detecta plugins instalados leyendo la cabecera estándar de cada plugin principal. */
    public static function findPlugins(string $wpRoot): array
    {
        $pluginsDir = $wpRoot . '/wp-content/plugins';
        $plugins = [];

        if (!is_dir($pluginsDir)) {
            return $plugins;
        }

        foreach (scandir($pluginsDir) ?: [] as $slug) {
            if ($slug === '.' || $slug === '..') {
                continue;
            }
            $pluginDir = $pluginsDir . '/' . $slug;
            if (!is_dir($pluginDir)) {
                continue;
            }

            $mainFile = self::findPluginMainFile($pluginDir, $slug);
            if ($mainFile === null) {
                continue;
            }

            $version = self::readHeaderField($mainFile, 'Version');
            if ($version !== null) {
                $plugins[] = ['slug' => $slug, 'dir' => $pluginDir, 'version' => $version];
            }
        }

        return $plugins;
    }

    /** Detecta temas instalados leyendo style.css. */
    public static function findThemes(string $wpRoot): array
    {
        $themesDir = $wpRoot . '/wp-content/themes';
        $themes = [];

        if (!is_dir($themesDir)) {
            return $themes;
        }

        foreach (scandir($themesDir) ?: [] as $slug) {
            if ($slug === '.' || $slug === '..') {
                continue;
            }
            $styleFile = $themesDir . '/' . $slug . '/style.css';
            if (!is_file($styleFile)) {
                continue;
            }

            $version = self::readHeaderField($styleFile, 'Version');
            if ($version !== null) {
                $themes[] = ['slug' => $slug, 'dir' => $themesDir . '/' . $slug, 'version' => $version];
            }
        }

        return $themes;
    }

    private static function findPluginMainFile(string $pluginDir, string $slug): ?string
    {
        $candidate = $pluginDir . '/' . $slug . '.php';
        if (is_file($candidate) && self::readHeaderField($candidate, 'Plugin Name') !== null) {
            return $candidate;
        }

        foreach (glob($pluginDir . '/*.php') ?: [] as $phpFile) {
            if (self::readHeaderField($phpFile, 'Plugin Name') !== null) {
                return $phpFile;
            }
        }

        return null;
    }

    private static function readHeaderField(string $file, string $field): ?string
    {
        $contents = @file_get_contents($file, false, null, 0, 8192);
        if ($contents === false) {
            return null;
        }

        $pattern = '/^[ \t\/*#@]*' . preg_quote($field, '/') . ':\s*(.+)$/mi';
        if (preg_match($pattern, $contents, $m)) {
            return trim($m[1]);
        }

        return null;
    }
}
