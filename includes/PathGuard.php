<?php

declare(strict_types=1);

/**
 * Central choke point for validating that any path the UI touches (view/quarantine/restore)
 * stays inside the configured scan roots. Prevents the file-viewer from becoming an LFI.
 */
final class PathGuard
{
    /** @return string[] absolute, real, deduplicated scan roots */
    public static function scanRoots(): array
    {
        $configured = Config::get('scan_roots', []);
        $resolved = [];

        foreach ($configured as $root) {
            $real = realpath($root);
            if ($real !== false && is_dir($real)) {
                $resolved[$real] = true;
            }
        }

        return array_keys($resolved);
    }

    public static function isWithinScanRoots(string $path): bool
    {
        $real = realpath($path);
        if ($real === false) {
            return false;
        }

        foreach (self::scanRoots() as $root) {
            if ($real === $root || str_starts_with($real, $root . DIRECTORY_SEPARATOR)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Resolves and validates a path coming from user input (e.g. GET param).
     * Returns the real path or null if it escapes the allowed roots / doesn't exist.
     */
    public static function resolveUserPath(string $userPath): ?string
    {
        $real = realpath($userPath);
        if ($real === false) {
            return null;
        }

        return self::isWithinScanRoots($real) ? $real : null;
    }
}
