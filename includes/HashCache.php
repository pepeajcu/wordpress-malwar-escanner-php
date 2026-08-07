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
        // No usamos "INSERT ... ON CONFLICT DO UPDATE" (upsert) porque el SQLite que trae
        // compilado el PHP en algunos hostings compartidos es anterior a 3.24 y no soporta esa
        // sintaxis (error "near ON: syntax error"). UPDATE + INSERT condicional es compatible
        // con cualquier versión.
        $pdo = Database::connection();
        $params = [
            ':path' => $path,
            ':sha256' => $sha256,
            ':mtime' => $mtime,
            ':size' => $size,
            ':verdict' => $verdict,
        ];

        $update = $pdo->prepare(
            'UPDATE file_hashes
             SET sha256 = :sha256, mtime = :mtime, size = :size, last_verdict = :verdict, updated_at = CURRENT_TIMESTAMP
             WHERE path = :path'
        );
        $update->execute($params);

        if ($update->rowCount() === 0) {
            $insert = $pdo->prepare(
                'INSERT INTO file_hashes (path, sha256, mtime, size, last_verdict, updated_at)
                 VALUES (:path, :sha256, :mtime, :size, :verdict, CURRENT_TIMESTAMP)'
            );
            $insert->execute($params);
        }
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
        $params = [':sha256' => $sha256, ':path' => $path, ':reason' => $reason];

        $update = $pdo->prepare('UPDATE whitelist SET path = :path, reason = :reason WHERE sha256 = :sha256');
        $update->execute($params);

        if ($update->rowCount() === 0) {
            $insert = $pdo->prepare('INSERT INTO whitelist (sha256, path, reason) VALUES (:sha256, :path, :reason)');
            $insert->execute($params);
        }
    }
}
