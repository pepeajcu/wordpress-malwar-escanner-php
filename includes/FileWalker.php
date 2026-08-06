<?php

declare(strict_types=1);

/**
 * Fase de descubrimiento: recorre el árbol de carpetas EN LOTES (una tanda de carpetas por
 * request), igual que ScanEngine hace con los archivos. Esto permite mostrar progreso real
 * ("N carpetas revisadas, M archivos encontrados") en vez de bloquear un solo request hasta
 * terminar de contar todo el sitio, y evita chocar con max_execution_time en sitios grandes.
 *
 * Carpetas sin permiso de lectura (frecuente en shared hosting: backups de plugins, caches de
 * otros procesos, etc.) se registran como aviso y se saltan, sin abortar el resto del recorrido.
 */
final class FileWalker
{
    public static function seedDiscovery(int $runId): void
    {
        $pdo = Database::connection();
        $insert = $pdo->prepare('INSERT INTO scan_dir_queue (run_id, path, status) VALUES (:run_id, :path, "pending")');

        foreach (PathGuard::scanRoots() as $root) {
            if (!is_readable($root)) {
                self::recordUnreadable($runId, $root);
                continue;
            }
            $insert->execute([':run_id' => $runId, ':path' => $root]);
        }
    }

    /** @return array{dirs_done:int, dirs_pending:int, files_found:int, unreadable_count:int, finished:bool} */
    public static function discoverBatch(int $runId, int $batchSize): array
    {
        $pdo = Database::connection();
        $excludeDirs = array_map('strtolower', Config::get('exclude_dirs', []));

        $select = $pdo->prepare(
            'SELECT id, path FROM scan_dir_queue WHERE run_id = :run_id AND status = "pending" ORDER BY id ASC LIMIT :limit'
        );
        $select->bindValue(':run_id', $runId, PDO::PARAM_INT);
        $select->bindValue(':limit', $batchSize, PDO::PARAM_INT);
        $select->execute();
        $dirs = $select->fetchAll();

        $markDirDone = $pdo->prepare('UPDATE scan_dir_queue SET status = "done" WHERE id = :id');
        $insertDir = $pdo->prepare('INSERT INTO scan_dir_queue (run_id, path, status) VALUES (:run_id, :path, "pending")');
        $insertFile = $pdo->prepare(
            'INSERT INTO scan_queue (run_id, path, size, mtime, status) VALUES (:run_id, :path, :size, :mtime, "pending")'
        );

        foreach ($dirs as $dirRow) {
            $entries = @scandir($dirRow['path']);
            if ($entries === false) {
                // No debería pasar (ya se validó legible al encolarla), pero por si los permisos
                // cambiaron entre el chequeo y este momento.
                self::recordUnreadable($runId, $dirRow['path']);
                $markDirDone->execute([':id' => $dirRow['id']]);
                continue;
            }

            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') {
                    continue;
                }

                $fullPath = rtrim($dirRow['path'], '/') . '/' . $entry;
                if (is_link($fullPath)) {
                    continue;
                }

                if (is_dir($fullPath)) {
                    if (in_array(strtolower($entry), $excludeDirs, true)) {
                        continue;
                    }
                    if (!is_readable($fullPath)) {
                        self::recordUnreadable($runId, $fullPath);
                        continue;
                    }
                    $insertDir->execute([':run_id' => $runId, ':path' => $fullPath]);
                    continue;
                }

                if (!is_file($fullPath) || !is_readable($fullPath)) {
                    continue;
                }

                $insertFile->execute([
                    ':run_id' => $runId,
                    ':path' => $fullPath,
                    ':size' => filesize($fullPath) ?: 0,
                    ':mtime' => filemtime($fullPath) ?: 0,
                ]);
            }

            $markDirDone->execute([':id' => $dirRow['id']]);
        }

        return self::progress($runId);
    }

    /** @return array{dirs_done:int, dirs_pending:int, files_found:int, unreadable_count:int, finished:bool} */
    private static function progress(int $runId): array
    {
        $pdo = Database::connection();

        $dirsDone = (int) self::scalar($pdo, 'SELECT COUNT(*) FROM scan_dir_queue WHERE run_id = ? AND status = "done"', $runId);
        $dirsPending = (int) self::scalar($pdo, 'SELECT COUNT(*) FROM scan_dir_queue WHERE run_id = ? AND status = "pending"', $runId);
        $filesFound = (int) self::scalar($pdo, 'SELECT COUNT(*) FROM scan_queue WHERE run_id = ?', $runId);
        $unreadableCount = (int) self::scalar($pdo, "SELECT COUNT(*) FROM findings WHERE run_id = ? AND source = 'scan_warning'", $runId);

        $finished = $dirsPending === 0;
        if ($finished) {
            $pdo->prepare('UPDATE scan_runs SET status = "running", total_files = :total WHERE id = :id')
                ->execute([':total' => $filesFound, ':id' => $runId]);
        }

        return [
            'dirs_done' => $dirsDone,
            'dirs_pending' => $dirsPending,
            'files_found' => $filesFound,
            'unreadable_count' => $unreadableCount,
            'finished' => $finished,
        ];
    }

    private static function scalar(PDO $pdo, string $sql, int $runId)
    {
        $stmt = $pdo->prepare($sql);
        $stmt->execute([$runId]);
        return $stmt->fetchColumn();
    }

    public static function recordUnreadable(int $runId, string $path): void
    {
        $pdo = Database::connection();

        $exists = $pdo->prepare(
            "SELECT 1 FROM findings WHERE run_id = :run_id AND path = :path AND source = 'scan_warning'"
        );
        $exists->execute([':run_id' => $runId, ':path' => $path]);
        if ($exists->fetchColumn()) {
            return; // evita duplicados si la misma ruta se reintenta
        }

        $pdo->prepare(
            'INSERT INTO findings (run_id, path, sha256, severity, source, reason, detail, status)
             VALUES (:run_id, :path, :sha256, "info", "scan_warning", :reason, :detail, "open")'
        )->execute([
            ':run_id' => $runId,
            ':path' => $path,
            ':sha256' => hash('sha256', $path),
            ':reason' => 'Sin acceso: esta ruta no se pudo leer (permisos) y quedó fuera del escaneo',
            ':detail' => 'Revisa los permisos de archivo en tu hosting si esperabas que se incluyera en el escaneo.',
        ]);
    }
}
