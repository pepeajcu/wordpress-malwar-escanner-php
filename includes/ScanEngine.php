<?php

declare(strict_types=1);

final class ScanEngine
{
    private const SEVERITY_RANK = ['info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];

    public static function startRun(): int
    {
        $pdo = Database::connection();
        $roots = PathGuard::scanRoots();

        if (empty($roots)) {
            throw new RuntimeException('Ninguna de las scan_roots configuradas existe o es accesible.');
        }

        $stmt = $pdo->prepare('INSERT INTO scan_runs (status, scan_roots) VALUES ("running", :roots)');
        $stmt->execute([':roots' => implode(PHP_EOL, $roots)]);
        $runId = (int) $pdo->lastInsertId();

        FileWalker::enqueueAll($runId);

        return $runId;
    }

    public static function resumableRunId(): ?int
    {
        $pdo = Database::connection();
        $stmt = $pdo->query(
            'SELECT id FROM scan_runs WHERE status = "running" ORDER BY id DESC LIMIT 1'
        );
        $row = $stmt->fetch();
        return $row ? (int) $row['id'] : null;
    }

    /** @return array{processed:int, pending:int, total:int, new_findings:int, finished:bool} */
    public static function processBatch(int $runId): array
    {
        $pdo = Database::connection();
        $batchSize = (int) Config::get('limits.batch_size', 25);
        $maxFullRead = (int) Config::get('limits.max_file_size_full_read', 5 * 1024 * 1024);

        $select = $pdo->prepare(
            'SELECT id, path, size, mtime FROM scan_queue
             WHERE run_id = :run_id AND status = "pending"
             ORDER BY id ASC LIMIT :limit'
        );
        $select->bindValue(':run_id', $runId, PDO::PARAM_INT);
        $select->bindValue(':limit', $batchSize, PDO::PARAM_INT);
        $select->execute();
        $rows = $select->fetchAll();

        $newFindings = 0;
        $insertFinding = $pdo->prepare(
            'INSERT INTO findings (run_id, path, sha256, severity, source, reason, detail, status)
             VALUES (:run_id, :path, :sha256, :severity, :source, :reason, :detail, "open")'
        );
        $markDone = $pdo->prepare('UPDATE scan_queue SET status = "done" WHERE id = :id');

        foreach ($rows as $row) {
            $path = $row['path'];
            $size = (int) $row['size'];
            $mtime = (int) $row['mtime'];

            if (!is_file($path) || !is_readable($path)) {
                $markDone->execute([':id' => $row['id']]);
                continue;
            }

            $hashInfo = HashCache::check($path, $mtime, $size);
            $sha256 = $hashInfo['sha256'];

            if ($hashInfo['unchanged'] || HashCache::isWhitelisted($sha256)) {
                HashCache::store($path, $sha256, $mtime, $size, 'clean');
                $markDone->execute([':id' => $row['id']]);
                continue;
            }

            $findings = HeuristicEngine::analyzeFile($path, $size, $maxFullRead);
            if (class_exists('WPChecksumChecker')) {
                array_push($findings, ...WPChecksumChecker::analyzeFile($path));
            }

            $worstSeverity = 'clean';
            foreach ($findings as $finding) {
                $insertFinding->execute([
                    ':run_id' => $runId,
                    ':path' => $path,
                    ':sha256' => $sha256,
                    ':severity' => $finding['severity'],
                    ':source' => $finding['source'],
                    ':reason' => $finding['reason'],
                    ':detail' => $finding['detail'],
                ]);
                $newFindings++;

                if ($worstSeverity === 'clean' || self::SEVERITY_RANK[$finding['severity']] > self::SEVERITY_RANK[$worstSeverity]) {
                    $worstSeverity = $finding['severity'];
                }
            }

            HashCache::store($path, $sha256, $mtime, $size, $worstSeverity === 'clean' ? 'clean' : 'suspicious');
            $markDone->execute([':id' => $row['id']]);
        }

        $processedCount = count($rows);

        $pdo->prepare(
            'UPDATE scan_runs SET
                processed_files = processed_files + :processed,
                findings_count = findings_count + :new_findings
             WHERE id = :id'
        )->execute([
            ':processed' => $processedCount,
            ':new_findings' => $newFindings,
            ':id' => $runId,
        ]);

        $pendingStmt = $pdo->prepare('SELECT COUNT(*) FROM scan_queue WHERE run_id = :run_id AND status = "pending"');
        $pendingStmt->execute([':run_id' => $runId]);
        $pending = (int) $pendingStmt->fetchColumn();

        $totalStmt = $pdo->prepare('SELECT total_files, processed_files FROM scan_runs WHERE id = :id');
        $totalStmt->execute([':id' => $runId]);
        $runRow = $totalStmt->fetch();

        $finished = $pending === 0;
        if ($finished) {
            if (class_exists('WPChecksumChecker')) {
                try {
                    WPChecksumChecker::finalize($runId);
                } catch (Throwable $e) {
                    // La verificación de integridad de WP es una capa adicional; un fallo aquí
                    // (p. ej. sin salida a internet) no debe impedir cerrar el escaneo.
                }
            }

            $countStmt = $pdo->prepare('SELECT COUNT(*) FROM findings WHERE run_id = :run_id');
            $countStmt->execute([':run_id' => $runId]);
            $totalFindings = (int) $countStmt->fetchColumn();

            $pdo->prepare('UPDATE scan_runs SET status = "completed", finished_at = CURRENT_TIMESTAMP, findings_count = :fc WHERE id = :id')
                ->execute([':fc' => $totalFindings, ':id' => $runId]);
        }

        return [
            'processed' => (int) $runRow['processed_files'],
            'pending' => $pending,
            'total' => (int) $runRow['total_files'],
            'new_findings' => $newFindings,
            'finished' => $finished,
        ];
    }

    public static function findings(int $runId, ?string $severity = null, ?string $status = null): array
    {
        $pdo = Database::connection();
        $sql = 'SELECT * FROM findings WHERE run_id = :run_id';
        $params = [':run_id' => $runId];

        if ($severity !== null) {
            $sql .= ' AND severity = :severity';
            $params[':severity'] = $severity;
        }
        if ($status !== null) {
            $sql .= ' AND status = :status';
            $params[':status'] = $status;
        }

        $sql .= ' ORDER BY CASE severity
            WHEN "critical" THEN 0 WHEN "high" THEN 1 WHEN "medium" THEN 2 WHEN "low" THEN 3 ELSE 4 END, id DESC';

        $stmt = $pdo->prepare($sql);
        $stmt->execute($params);
        return $stmt->fetchAll();
    }

    public static function run(int $runId): ?array
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare('SELECT * FROM scan_runs WHERE id = :id');
        $stmt->execute([':id' => $runId]);
        $row = $stmt->fetch();
        return $row ?: null;
    }
}
