<?php

declare(strict_types=1);

abstract class AbstractAIProvider implements AIProviderInterface
{
    protected string $apiKey;
    protected string $model;

    public function __construct(string $apiKey, string $model)
    {
        $this->apiKey = $apiKey;
        $this->model = $model;
    }

    protected function buildPrompt(string $filename, string $snippet, array $heuristicReasons): string
    {
        $reasonsList = empty($heuristicReasons) ? '(ninguno específico)' : "- " . implode("\n- ", $heuristicReasons);

        return <<<PROMPT
Eres un analista de seguridad revisando un archivo de un sitio WordPress en shared hosting en busca de malware/webshells/backdoors.

Archivo: {$filename}

Motivos por los que un escáner heurístico local marcó este archivo como sospechoso:
{$reasonsList}

Contenido del archivo (puede estar truncado):
---
{$snippet}
---

Responde ÚNICAMENTE con un objeto JSON, sin texto adicional ni markdown, con este formato exacto:
{"verdict": "malicious" | "suspicious" | "clean", "confidence": 0.0-1.0, "explanation": "explicación breve en español, 1-3 frases"}
PROMPT;
    }

    /** Extrae el primer objeto JSON válido de una respuesta de texto libre del modelo. */
    protected function parseVerdict(string $text): ?array
    {
        if (preg_match('/\{.*\}/s', $text, $m) !== 1) {
            return null;
        }

        $decoded = json_decode($m[0], true);
        if (!is_array($decoded) || !isset($decoded['verdict'])) {
            return null;
        }

        $verdict = strtolower((string) $decoded['verdict']);
        if (!in_array($verdict, ['malicious', 'suspicious', 'clean'], true)) {
            $verdict = 'unknown';
        }

        return [
            'verdict' => $verdict,
            'confidence' => isset($decoded['confidence']) ? max(0.0, min(1.0, (float) $decoded['confidence'])) : 0.5,
            'explanation' => isset($decoded['explanation']) ? (string) $decoded['explanation'] : '',
        ];
    }
}
