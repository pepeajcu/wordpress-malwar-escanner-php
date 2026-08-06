<?php

declare(strict_types=1);

final class Database
{
    private static ?PDO $instance = null;

    public static function connection(): PDO
    {
        if (self::$instance !== null) {
            return self::$instance;
        }

        $dataDir = __DIR__ . '/../data';
        if (!is_dir($dataDir)) {
            mkdir($dataDir, 0750, true);
        }

        $dbPath = $dataDir . '/scan.sqlite';
        $pdo = new PDO('sqlite:' . $dbPath);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $pdo->exec('PRAGMA journal_mode = WAL');
        $pdo->exec('PRAGMA foreign_keys = ON');

        self::$instance = $pdo;
        self::migrate($pdo);

        return $pdo;
    }

    private static function migrate(PDO $pdo): void
    {
        $pdo->exec('
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                status TEXT NOT NULL DEFAULT "running",
                scan_roots TEXT NOT NULL,
                total_files INTEGER NOT NULL DEFAULT 0,
                processed_files INTEGER NOT NULL DEFAULT 0,
                findings_count INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                finished_at TEXT
            )
        ');

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS scan_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                size INTEGER NOT NULL DEFAULT 0,
                mtime INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT "pending",
                FOREIGN KEY (run_id) REFERENCES scan_runs(id)
            )
        ');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_scan_queue_run_status ON scan_queue (run_id, status)');

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS file_hashes (
                path TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL,
                mtime INTEGER NOT NULL,
                size INTEGER NOT NULL,
                last_verdict TEXT NOT NULL DEFAULT "clean",
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        ');

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                severity TEXT NOT NULL,
                source TEXT NOT NULL,
                reason TEXT NOT NULL,
                detail TEXT,
                ai_provider TEXT,
                ai_verdict TEXT,
                ai_confidence REAL,
                ai_explanation TEXT,
                vt_ratio TEXT,
                vt_detail TEXT,
                status TEXT NOT NULL DEFAULT "open",
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (run_id) REFERENCES scan_runs(id)
            )
        ');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_findings_run ON findings (run_id)');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (status)');

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS whitelist (
                sha256 TEXT PRIMARY KEY,
                path TEXT NOT NULL,
                reason TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        ');

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS ai_verdict_cache (
                sha256 TEXT NOT NULL,
                provider TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence REAL,
                explanation TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (sha256, provider)
            )
        ');

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS vt_cache (
                sha256 TEXT PRIMARY KEY,
                ratio TEXT,
                detail TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        ');

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                success INTEGER NOT NULL,
                attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        ');
        $pdo->exec('CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts (ip, attempted_at)');

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS remote_cache (
                cache_key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        ');

        $pdo->exec('
            CREATE TABLE IF NOT EXISTS quarantine_manifest (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_path TEXT NOT NULL,
                quarantined_path TEXT NOT NULL,
                finding_id INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                restored_at TEXT
            )
        ');
    }
}
