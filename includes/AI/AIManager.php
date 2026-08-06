<?php

declare(strict_types=1);

/**
 * Orquesta la Capa 3 (IA). Se invoca en lotes propios (acción "ai_batch"), NUNCA dentro del lote
 * de escaneo normal, para no alargar esos requests. Solo procesa hallazgos de severidad
 * media/alta/crítica que aún no tienen veredicto de IA, agrupados por archivo (un archivo con
 * varios hallazgos heurísticos se manda una sola vez a la IA).
 */
final class AIManager
{
    private const ELIGIBLE_SEVERITIES = ['medium', 'high', 'critical'];
    private const SNIPPET_MAX_BYTES = 6000;

    public static function isEnabled(): bool
    {
        return (bool) Config::get('ai.enabled', false);
    }

    public static function pendingCount(int $runId): int
    {
        $pdo = Database::connection();
        $placeholders = implode(',', array_fill(0, count(self::ELIGIBLE_SEVERITIES), '?'));
        $stmt = $pdo->prepare(
            "SELECT COUNT(DISTINCT path) FROM findings
             WHERE run_id = ? AND status = 'open' AND ai_verdict IS NULL AND severity IN ($placeholders)"
        );
        $stmt->execute(array_merge([$runId], self::ELIGIBLE_SEVERITIES));
        return (int) $stmt->fetchColumn();
    }

    /** @return array{processed:int, remaining:int} */
    public static function processBatch(int $runId): array
    {
        $pdo = Database::connection();
        $batchSize = (int) Config::get('limits.ai_batch_size', 3);
        $placeholders = implode(',', array_fill(0, count(self::ELIGIBLE_SEVERITIES), '?'));

        $select = $pdo->prepare(
            "SELECT DISTINCT path, sha256 FROM findings
             WHERE run_id = ? AND status = 'open' AND ai_verdict IS NULL AND severity IN ($placeholders)
             ORDER BY id ASC LIMIT ?"
        );
        $select->execute(array_merge([$runId], self::ELIGIBLE_SEVERITIES, [$batchSize]));
        $rows = $select->fetchAll();

        $providers = self::buildProviders();

        foreach ($rows as $row) {
            self::analyzeAndStore($runId, $row['path'], $row['sha256'], $providers);
        }

        return [
            'processed' => count($rows),
            'remaining' => self::pendingCount($runId),
        ];
    }

    private static function analyzeAndStore(int $runId, string $path, string $sha256, array $providers): void
    {
        $pdo = Database::connection();

        $reasonsStmt = $pdo->prepare(
            "SELECT DISTINCT reason FROM findings WHERE run_id = :run_id AND path = :path AND status = 'open'"
        );
        $reasonsStmt->execute([':run_id' => $runId, ':path' => $path]);
        $reasons = array_column($reasonsStmt->fetchAll(), 'reason');

        $verdict = null;
        $providerUsed = null;

        if (Config::get('dev.dry_run_ai', false)) {
            $verdict = [
                'verdict' => 'suspicious',
                'confidence' => 0.5,
                'explanation' => 'Modo dry-run: respuesta simulada, sin llamada real a un proveedor de IA.',
            ];
            $providerUsed = 'dry-run';
        } else {
            foreach ($providers as $provider) {
                /** @var AIProviderInterface $provider */
                $cached = AIVerdictCache::get($sha256, $provider->name());
                if ($cached !== null) {
                    $verdict = $cached;
                    $providerUsed = $provider->name();
                    break;
                }

                $snippet = self::readSnippet($path);
                $result = $provider->analyze($path, $snippet, $reasons);
                if ($result !== null) {
                    AIVerdictCache::set($sha256, $provider->name(), $result);
                    $verdict = $result;
                    $providerUsed = $provider->name();
                    break;
                }
            }
        }

        if ($verdict === null) {
            $verdict = ['verdict' => 'unknown', 'confidence' => 0.0, 'explanation' => 'Ningún proveedor de IA configurado respondió correctamente.'];
            $providerUsed = 'none';
        }

        $pdo->prepare(
            'UPDATE findings SET ai_provider = :provider, ai_verdict = :verdict, ai_confidence = :confidence, ai_explanation = :explanation
             WHERE run_id = :run_id AND path = :path'
        )->execute([
            ':provider' => $providerUsed,
            ':verdict' => $verdict['verdict'],
            ':confidence' => $verdict['confidence'],
            ':explanation' => $verdict['explanation'],
            ':run_id' => $runId,
            ':path' => $path,
        ]);
    }

    private static function readSnippet(string $path): string
    {
        $content = @file_get_contents($path, false, null, 0, self::SNIPPET_MAX_BYTES);
        return $content === false ? '' : $content;
    }

    /** @return AIProviderInterface[] en orden de fallback, solo proveedores con api_key configurada */
    private static function buildProviders(): array
    {
        $config = Config::get('ai', []);
        $order = $config['fallback_order'] ?? ['anthropic', 'gemini', 'openai', 'minimax'];
        $providersConfig = $config['providers'] ?? [];

        $classMap = [
            'anthropic' => AnthropicProvider::class,
            'gemini' => GeminiProvider::class,
            'openai' => OpenAIProvider::class,
            'minimax' => MinimaxProvider::class,
        ];

        $instances = [];
        foreach ($order as $key) {
            $apiKey = (string) ($providersConfig[$key]['api_key'] ?? '');
            $model = (string) ($providersConfig[$key]['model'] ?? '');
            $class = $classMap[$key] ?? null;

            if ($apiKey !== '' && $class !== null) {
                $instances[] = new $class($apiKey, $model);
            }
        }

        return $instances;
    }
}
