<?php

declare(strict_types=1);

/**
 * Capa 4: segundo check independiente, solo para hallazgos de alta severidad (heurística fuerte
 * y/o veredicto de IA positivo). Por defecto SOLO hace lookup por hash (no sube contenido de
 * archivos: subirlos los haría públicamente buscables en VirusTotal, exponiendo código del
 * cliente). Se ejecuta en su propio lote ("vt_batch"), nunca dentro del lote de escaneo normal.
 */
final class VirusTotalChecker
{
    private const SEVERITY_RANK = ['info' => 0, 'low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];

    public static function isEnabled(): bool
    {
        return (bool) Config::get('virustotal.enabled', false) && (string) Config::get('virustotal.api_key', '') !== '';
    }

    public static function pendingCount(int $runId): int
    {
        $pdo = Database::connection();
        $minSeverity = self::minSeverityRank();

        $stmt = $pdo->prepare(
            "SELECT COUNT(*) FROM findings WHERE run_id = :run_id AND status = 'open' AND vt_ratio IS NULL"
        );
        $stmt->execute([':run_id' => $runId]);
        $candidates = (int) $stmt->fetchColumn();

        if ($candidates === 0) {
            return 0;
        }

        // Filtrado fino por severidad se hace en PHP porque SQLite no conoce el orden custom.
        $rows = $pdo->prepare("SELECT severity FROM findings WHERE run_id = :run_id AND status = 'open' AND vt_ratio IS NULL");
        $rows->execute([':run_id' => $runId]);
        $count = 0;
        foreach ($rows->fetchAll() as $r) {
            if ((self::SEVERITY_RANK[$r['severity']] ?? 0) >= $minSeverity) {
                $count++;
            }
        }
        return $count;
    }

    /** @return array{processed:int, remaining:int} */
    public static function processBatch(int $runId): array
    {
        $pdo = Database::connection();
        $batchSize = (int) Config::get('limits.vt_batch_size', 4);
        $minSeverity = self::minSeverityRank();

        $stmt = $pdo->prepare(
            "SELECT id, path, sha256, severity FROM findings
             WHERE run_id = :run_id AND status = 'open' AND vt_ratio IS NULL
             ORDER BY id ASC"
        );
        $stmt->execute([':run_id' => $runId]);

        $processed = 0;
        foreach ($stmt->fetchAll() as $row) {
            if ($processed >= $batchSize) {
                break;
            }
            if ((self::SEVERITY_RANK[$row['severity']] ?? 0) < $minSeverity) {
                continue;
            }

            self::lookupAndStore($row['id'], $row['sha256']);
            $processed++;
        }

        return ['processed' => $processed, 'remaining' => self::pendingCount($runId)];
    }

    /**
     * Consulta manual bajo demanda para UN hallazgo puntual, disparada desde la UI ("Consultar
     * VirusTotal"). A diferencia de processBatch(), ignora el filtro de severidad mínima: el
     * usuario pidió explícitamente consultar este hash.
     *
     * @return array{vt_ratio?:?string, vt_detail?:?string, error?:string}
     */
    public static function checkOne(int $findingId): array
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare('SELECT sha256 FROM findings WHERE id = :id');
        $stmt->execute([':id' => $findingId]);
        $finding = $stmt->fetch();

        if (!$finding) {
            return ['error' => 'Hallazgo no encontrado.'];
        }

        $apiKey = (string) Config::get('virustotal.api_key', '');
        if ($apiKey === '' && !Config::get('dev.dry_run_virustotal', false)) {
            return ['error' => 'VirusTotal no está configurado. Agrega virustotal.api_key en config.php.'];
        }

        self::lookupAndStore($findingId, $finding['sha256']);

        $refreshed = $pdo->prepare('SELECT vt_ratio, vt_detail FROM findings WHERE id = :id');
        $refreshed->execute([':id' => $findingId]);
        $row = $refreshed->fetch();

        if (!$row || $row['vt_ratio'] === null) {
            return ['error' => 'VirusTotal no devolvió un resultado definitivo (puede reintentarse más tarde).'];
        }

        return $row;
    }

    private static function lookupAndStore(int $findingId, string $sha256): void
    {
        $pdo = Database::connection();

        if (Config::get('dev.dry_run_virustotal', false)) {
            self::storeResult($findingId, '0/0 (dry-run)', 'Modo dry-run: sin llamada real a VirusTotal.');
            return;
        }

        $cached = RemoteCache::get('vt_' . $sha256, 3600 * 24 * 7);
        if ($cached !== null) {
            self::storeResult($findingId, $cached['ratio'], $cached['detail']);
            return;
        }

        $apiKey = (string) Config::get('virustotal.api_key', '');
        $response = HttpClient::get(
            'https://www.virustotal.com/api/v3/files/' . $sha256,
            ['x-apikey: ' . $apiKey],
            15
        );

        if ($response['status'] === 404) {
            $result = ['ratio' => 'no encontrado', 'detail' => 'Este hash no está en la base de datos de VirusTotal (no implica que sea inofensivo).'];
            RemoteCache::set('vt_' . $sha256, $result);
            self::storeResult($findingId, $result['ratio'], $result['detail']);
            return;
        }

        if (!$response['ok']) {
            self::storeResult($findingId, null, null); // deja pendiente para reintentar en un lote posterior
            return;
        }

        $decoded = json_decode($response['body'], true);
        $stats = $decoded['data']['attributes']['last_analysis_stats'] ?? null;

        if (!is_array($stats)) {
            self::storeResult($findingId, null, null);
            return;
        }

        $malicious = (int) ($stats['malicious'] ?? 0);
        $suspicious = (int) ($stats['suspicious'] ?? 0);
        $total = array_sum($stats);
        $ratio = ($malicious + $suspicious) . '/' . $total;
        $detail = "Motores que lo marcan: {$malicious} maliciosos, {$suspicious} sospechosos, de {$total} totales.";

        $result = ['ratio' => $ratio, 'detail' => $detail];
        RemoteCache::set('vt_' . $sha256, $result);
        self::storeResult($findingId, $ratio, $detail);
    }

    private static function storeResult(int $findingId, ?string $ratio, ?string $detail): void
    {
        if ($ratio === null) {
            return; // sin resultado definitivo: se reintenta en el próximo lote
        }

        $pdo = Database::connection();
        $pdo->prepare('UPDATE findings SET vt_ratio = :ratio, vt_detail = :detail WHERE id = :id')
            ->execute([':ratio' => $ratio, ':detail' => $detail, ':id' => $findingId]);
    }

    private static function minSeverityRank(): int
    {
        $min = (string) Config::get('virustotal.min_severity', 'high');
        return self::SEVERITY_RANK[$min] ?? self::SEVERITY_RANK['high'];
    }
}
