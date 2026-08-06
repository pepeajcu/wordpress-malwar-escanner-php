<?php

declare(strict_types=1);

final class HashCache
{
    /**
     * Returns ['sha256' => string, 'unchanged' => bool] where unchanged=true means the file's
     * mtime/size/hash match a previous scan AND that previous scan's verdict was "clean" —
     * safe to skip re-running heuristics/AI on it.
     */
    public static function check(string $path, int $mtime, int $size): array
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare('SELECT sha256, mtime, size, last_verdict FROM file_hashes WHERE path = :path');
        $stmt->execute([':path' => $path]);
        $cached = $stmt->fetch();

        if ($cached && (int) $cached['mtime'] === $mtime && (int) $cached['size'] === $size) {
            return [
                'sha256' => $cached['sha256'],
                'unchanged' => $cached['last_verdict'] === 'clean',
            ];
        }

        $sha256 = @hash_file('sha256', $path);
        if ($sha256 === false) {
            $sha256 = hash('sha256', $path . '|' . $mtime . '|' . $size);
        }

        return ['sha256' => $sha256, 'unchanged' => false];
    }

    public static function store(string $path, string $sha256, int $mtime, int $size, string $verdict): void
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare(
            'INSERT INTO file_hashes (path, sha256, mtime, size, last_verdict, updated_at)
             VALUES (:path, :sha256, :mtime, :size, :verdict, CURRENT_TIMESTAMP)
             ON CONFLICT(path) DO UPDATE SET
                sha256 = excluded.sha256,
                mtime = excluded.mtime,
                size = excluded.size,
                last_verdict = excluded.last_verdict,
                updated_at = excluded.updated_at'
        );
        $stmt->execute([
            ':path' => $path,
            ':sha256' => $sha256,
            ':mtime' => $mtime,
            ':size' => $size,
            ':verdict' => $verdict,
        ]);
    }

    public static function isWhitelisted(string $sha256): bool
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare('SELECT 1 FROM whitelist WHERE sha256 = :sha256');
        $stmt->execute([':sha256' => $sha256]);
        return (bool) $stmt->fetchColumn();
    }

    public static function addToWhitelist(string $sha256, string $path, ?string $reason = null): void
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare(
            'INSERT INTO whitelist (sha256, path, reason) VALUES (:sha256, :path, :reason)
             ON CONFLICT(sha256) DO UPDATE SET path = excluded.path, reason = excluded.reason'
        );
        $stmt->execute([':sha256' => $sha256, ':path' => $path, ':reason' => $reason]);
    }
}
