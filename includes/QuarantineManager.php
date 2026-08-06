<?php

declare(strict_types=1);

/**
 * Cuarentena 100% manual (nunca automática): el usuario decide, hallazgo por hallazgo, mover un
 * archivo desde la UI. Se conserva un manifest para poder restaurarlo tal cual estaba, y un log
 * humano-legible en quarantine/suspicious_files.log con la ruta original y el motivo.
 */
final class QuarantineManager
{
    private static function quarantineDir(): string
    {
        $dir = __DIR__ . '/../quarantine/files';
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
        return $dir;
    }

    private static function logFile(): string
    {
        return __DIR__ . '/../quarantine/suspicious_files.log';
    }

    /** @return array{ok:bool, error?:string} */
    public static function quarantine(int $findingId): array
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare('SELECT * FROM findings WHERE id = :id');
        $stmt->execute([':id' => $findingId]);
        $finding = $stmt->fetch();

        if (!$finding) {
            return ['ok' => false, 'error' => 'Hallazgo no encontrado.'];
        }

        $originalPath = $finding['path'];
        if (!PathGuard::isWithinScanRoots($originalPath) || !is_file($originalPath)) {
            return ['ok' => false, 'error' => 'La ruta del archivo ya no es válida o está fuera de las rutas permitidas.'];
        }

        $safeName = str_replace(['/', '\\'], '__', ltrim($originalPath, '/'));
        $quarantinedPath = self::quarantineDir() . '/' . substr(hash('sha256', $originalPath), 0, 12) . '__' . $safeName . '.quarantined';

        if (!@rename($originalPath, $quarantinedPath)) {
            if (!@copy($originalPath, $quarantinedPath) || !@unlink($originalPath)) {
                return ['ok' => false, 'error' => 'No se pudo mover el archivo (revisa permisos de escritura).'];
            }
        }

        $pdo->prepare(
            'INSERT INTO quarantine_manifest (original_path, quarantined_path, finding_id) VALUES (:orig, :quar, :fid)'
        )->execute([':orig' => $originalPath, ':quar' => $quarantinedPath, ':fid' => $findingId]);

        $pdo->prepare('UPDATE findings SET status = "quarantined" WHERE id = :id')->execute([':id' => $findingId]);

        self::appendLog(sprintf(
            "[%s] CUARENTENA | %s | severidad=%s | motivo=%s",
            date('Y-m-d H:i:s'),
            $originalPath,
            $finding['severity'],
            $finding['reason']
        ));

        return ['ok' => true];
    }

    /** @return array{ok:bool, error?:string} */
    public static function restore(int $manifestId): array
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare('SELECT * FROM quarantine_manifest WHERE id = :id AND restored_at IS NULL');
        $stmt->execute([':id' => $manifestId]);
        $entry = $stmt->fetch();

        if (!$entry) {
            return ['ok' => false, 'error' => 'Entrada de cuarentena no encontrada o ya restaurada.'];
        }

        if (!is_file($entry['quarantined_path'])) {
            return ['ok' => false, 'error' => 'El archivo en cuarentena ya no existe en disco.'];
        }

        $targetDir = dirname($entry['original_path']);
        if (!is_dir($targetDir) && !@mkdir($targetDir, 0750, true)) {
            return ['ok' => false, 'error' => 'No se pudo recrear la carpeta original.'];
        }

        if (!@rename($entry['quarantined_path'], $entry['original_path'])) {
            if (!@copy($entry['quarantined_path'], $entry['original_path']) || !@unlink($entry['quarantined_path'])) {
                return ['ok' => false, 'error' => 'No se pudo restaurar el archivo (revisa permisos de escritura).'];
            }
        }

        $pdo->prepare('UPDATE quarantine_manifest SET restored_at = CURRENT_TIMESTAMP WHERE id = :id')->execute([':id' => $manifestId]);

        if ($entry['finding_id']) {
            $pdo->prepare('UPDATE findings SET status = "open" WHERE id = :id')->execute([':id' => $entry['finding_id']]);
        }

        self::appendLog(sprintf("[%s] RESTAURADO | %s", date('Y-m-d H:i:s'), $entry['original_path']));

        return ['ok' => true];
    }

    public static function activeEntries(): array
    {
        $pdo = Database::connection();
        $stmt = $pdo->query(
            'SELECT qm.*, f.severity, f.reason FROM quarantine_manifest qm
             LEFT JOIN findings f ON f.id = qm.finding_id
             WHERE qm.restored_at IS NULL ORDER BY qm.id DESC'
        );
        return $stmt->fetchAll();
    }

    private static function appendLog(string $line): void
    {
        file_put_contents(self::logFile(), $line . PHP_EOL, FILE_APPEND | LOCK_EX);
    }
}
