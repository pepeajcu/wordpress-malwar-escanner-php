<?php

declare(strict_types=1);

/**
 * Generic key/value cache backed by SQLite, used to avoid re-downloading WordPress core/plugin/
 * theme checksum manifests on every scan (and to avoid re-querying VirusTotal/AI for hashes
 * already resolved). Entries are considered valid for $ttlSeconds; callers decide freshness.
 */
final class RemoteCache
{
    public static function get(string $key, int $ttlSeconds): ?array
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare(
            'SELECT value FROM remote_cache WHERE cache_key = :key AND fetched_at >= datetime("now", :window)'
        );
        $stmt->execute([':key' => $key, ':window' => '-' . $ttlSeconds . ' seconds']);
        $row = $stmt->fetch();

        if (!$row) {
            return null;
        }

        $decoded = json_decode($row['value'], true);
        return is_array($decoded) ? $decoded : null;
    }

    public static function set(string $key, array $value): void
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare(
            'INSERT INTO remote_cache (cache_key, value, fetched_at) VALUES (:key, :value, CURRENT_TIMESTAMP)
             ON CONFLICT(cache_key) DO UPDATE SET value = excluded.value, fetched_at = excluded.fetched_at'
        );
        $stmt->execute([':key' => $key, ':value' => json_encode($value)]);
    }
}
