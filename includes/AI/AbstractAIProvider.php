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
        $snippet = $this->numberLines($snippet);

        return <<<PROMPT
Eres un analista de seguridad revisando un archivo de un sitio WordPress en shared hosting en busca de malware/webshells/backdoors.

Archivo: {$filename}

Motivos por los que un escáner heurístico local marcó este archivo como sospechoso:
{$reasonsList}

Contenido del archivo (puede estar truncado; las líneas están numeradas al inicio como "N: " solo como referencia, no forman parte del código real):
---
{$snippet}
---

Además de dar tu veredicto, indica si el código malicioso/sospechoso ocupa TODO el archivo (p. ej. es un webshell dedicado, no hay código legítimo alrededor) o es un FRAGMENTO inyectado dentro de un archivo que por lo demás es legítimo (p. ej. una línea de eval() agregada al final de un plugin real). Si es un fragmento, indica en qué línea(s) aproximadas está, usando la numeración "N: " del contenido de arriba.

Responde ÚNICAMENTE con un objeto JSON, sin texto adicional ni markdown, con este formato exacto:
{"verdict": "malicious" | "suspicious" | "clean", "confidence": 0.0-1.0, "explanation": "explicación breve en español, 1-3 frases", "scope": "whole_file" | "partial" | "unknown", "lines": "rango o lista de líneas si scope es partial, texto vacío si no aplica"}
PROMPT;
    }

    /** Numera las líneas del snippet ("1: <código>") para que el modelo pueda referenciarlas en su respuesta. */
    protected function numberLines(string $snippet): string
    {
        $lines = explode("\n", $snippet);
        $numbered = [];
        foreach ($lines as $i => $line) {
            $numbered[] = ($i + 1) . ': ' . $line;
        }
        return implode("\n", $numbered);
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

        $scope = isset($decoded['scope']) ? strtolower((string) $decoded['scope']) : 'unknown';
        if (!in_array($scope, ['whole_file', 'partial', 'unknown'], true)) {
            $scope = 'unknown';
        }
        $lines = isset($decoded['lines']) ? trim((string) $decoded['lines']) : '';

        $location = null;
        if ($scope === 'whole_file') {
            $location = 'Todo el archivo (según la IA)';
        } elseif ($scope === 'partial' && $lines !== '') {
            $location = 'Línea(s) ' . $lines . ' (según la IA)';
        } elseif ($scope === 'partial') {
            $location = 'Fragmento del archivo, línea exacta no especificada (según la IA)';
        }

        return [
            'verdict' => $verdict,
            'confidence' => isset($decoded['confidence']) ? max(0.0, min(1.0, (float) $decoded['confidence'])) : 0.5,
            'explanation' => isset($decoded['explanation']) ? (string) $decoded['explanation'] : '',
            'location' => $location,
        ];
    }
}
