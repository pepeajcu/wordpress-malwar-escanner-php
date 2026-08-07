<?php

declare(strict_types=1);

final class AIVerdictCache
{
    public static function get(string $sha256, string $provider): ?array
    {
        $pdo = Database::connection();
        $stmt = $pdo->prepare('SELECT verdict, confidence, explanation FROM ai_verdict_cache WHERE sha256 = :sha256 AND provider = :provider');
        $stmt->execute([':sha256' => $sha256, ':provider' => $provider]);
        $row = $stmt->fetch();
        return $row ?: null;
    }

    public static function set(string $sha256, string $provider, array $verdict): void
    {
        $pdo = Database::connection();
        $params = [
            ':sha256' => $sha256,
            ':provider' => $provider,
            ':verdict' => $verdict['verdict'],
            ':confidence' => $verdict['confidence'],
            ':explanation' => $verdict['explanation'],
        ];

        $update = $pdo->prepare(
            'UPDATE ai_verdict_cache
             SET verdict = :verdict, confidence = :confidence, explanation = :explanation
             WHERE sha256 = :sha256 AND provider = :provider'
        );
        $update->execute($params);

        if ($update->rowCount() === 0) {
            $insert = $pdo->prepare(
                'INSERT INTO ai_verdict_cache (sha256, provider, verdict, confidence, explanation)
                 VALUES (:sha256, :provider, :verdict, :confidence, :explanation)'
            );
            $insert->execute($params);
        }
    }
}
