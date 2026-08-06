<?php

declare(strict_types=1);

final class FileWalker
{
    private const MAX_UNREADABLE_WARNINGS = 15; // evita spamear el panel si medio hosting está sin permisos

    /**
     * Walks all configured scan roots and inserts every eligible file path into scan_queue
     * for the given run. Cheap pass: no content is read here, only stat().
     *
     * Carpetas sin permiso de lectura (frecuente en shared hosting: backups de plugins, caches
     * de otros procesos, etc.) se saltan SIN abortar el resto del escaneo, y quedan registradas
     * como hallazgo informativo para que el usuario sepa que esa carpeta no se revisó.
     */
    public static function enqueueAll(int $runId): int
    {
        $pdo = Database::connection();
        $excludeDirs = array_map('strtolower', Config::get('exclude_dirs', []));

        $insert = $pdo->prepare(
            'INSERT INTO scan_queue (run_id, path, size, mtime, status) VALUES (:run_id, :path, :size, :mtime, "pending")'
        );

        $count = 0;
        $seen = [];
        $unreadableDirs = [];

        foreach (PathGuard::scanRoots() as $root) {
            if (!is_readable($root)) {
                $unreadableDirs[] = $root;
                continue;
            }

            $iterator = new RecursiveIteratorIterator(
                new RecursiveCallbackFilterIterator(
                    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS),
                    function (SplFileInfo $file) use ($excludeDirs, &$unreadableDirs): bool {
                        if ($file->isDir()) {
                            $name = strtolower($file->getFilename());
                            if (in_array($name, $excludeDirs, true)) {
                                return false;
                            }
                            if (!$file->isReadable()) {
                                $unreadableDirs[] = $file->getPathname();
                                return false;
                            }
                        }
                        return true;
                    }
                ),
                RecursiveIteratorIterator::LEAVES_ONLY,
                // Red de seguridad adicional: si igual una carpeta falla al abrirse (permisos
                // cambian entre el chequeo y el acceso real, ACLs, etc.), se ignora esa rama en
                // vez de abortar todo el recorrido.
                RecursiveIteratorIterator::CATCH_GET_CHILD
            );

            foreach ($iterator as $fileInfo) {
                /** @var SplFileInfo $fileInfo */
                if (!$fileInfo->isFile() || $fileInfo->isLink()) {
                    continue;
                }

                if (!$fileInfo->isReadable()) {
                    continue; // archivo puntual sin permisos: se ignora sin generar ruido
                }

                $realPath = $fileInfo->getRealPath();
                if ($realPath === false || isset($seen[$realPath])) {
                    continue;
                }
                $seen[$realPath] = true;

                $insert->execute([
                    ':run_id' => $runId,
                    ':path' => $realPath,
                    ':size' => $fileInfo->getSize(),
                    ':mtime' => $fileInfo->getMTime(),
                ]);
                $count++;
            }
        }

        $pdo->prepare('UPDATE scan_runs SET total_files = :total WHERE id = :id')
            ->execute([':total' => $count, ':id' => $runId]);

        self::recordUnreadableWarnings($runId, $unreadableDirs);

        return $count;
    }

    private static function recordUnreadableWarnings(int $runId, array $unreadableDirs): void
    {
        if (empty($unreadableDirs)) {
            return;
        }

        $pdo = Database::connection();
        $insertFinding = $pdo->prepare(
            'INSERT INTO findings (run_id, path, sha256, severity, source, reason, detail, status)
             VALUES (:run_id, :path, :sha256, "info", "scan_warning", :reason, :detail, "open")'
        );

        $unreadableDirs = array_values(array_unique($unreadableDirs));

        if (count($unreadableDirs) > self::MAX_UNREADABLE_WARNINGS) {
            $insertFinding->execute([
                ':run_id' => $runId,
                ':path' => $unreadableDirs[0],
                ':sha256' => hash('sha256', 'unreadable-summary-' . $runId),
                ':reason' => count($unreadableDirs) . ' carpetas no se pudieron leer por permisos y quedaron sin escanear',
                ':detail' => implode("\n", array_slice($unreadableDirs, 0, 50)) . "\n(lista truncada)",
            ]);
            return;
        }

        foreach ($unreadableDirs as $dir) {
            $insertFinding->execute([
                ':run_id' => $runId,
                ':path' => $dir,
                ':sha256' => hash('sha256', $dir),
                ':reason' => 'Carpeta sin permisos de lectura: no se pudo escanear su contenido',
                ':detail' => 'Revisa manualmente esta ruta (permisos de archivo en tu hosting) si esperabas que se incluyera en el escaneo.',
            ]);
        }
    }
}
