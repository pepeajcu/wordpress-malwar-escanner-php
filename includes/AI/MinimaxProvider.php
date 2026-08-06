<?php

declare(strict_types=1);

/**
 * NOTA: la API de Minimax es menos estandarizada que OpenAI/Anthropic/Gemini y ha cambiado de
 * endpoint/formato entre versiones. Si Minimax devuelve error persistente, revisa la documentación
 * vigente en su plataforma y ajusta $endpoint / el payload de esta clase — el resto del sistema
 * (caché, fallback, parseo de veredicto) no necesita cambios.
 */
final class MinimaxProvider extends AbstractAIProvider
{
    public function name(): string
    {
        return 'minimax';
    }

    public function analyze(string $filename, string $snippet, array $heuristicReasons): ?array
    {
        $prompt = $this->buildPrompt($filename, $snippet, $heuristicReasons);
        $endpoint = 'https://api.minimax.chat/v1/text/chatcompletion_v2';

        $response = HttpClient::postJson(
            $endpoint,
            [
                'model' => $this->model,
                'temperature' => 0,
                'messages' => [
                    ['role' => 'user', 'content' => $prompt],
                ],
            ],
            [
                'Authorization: Bearer ' . $this->apiKey,
            ],
            20
        );

        if (!$response['ok']) {
            return null;
        }

        $decoded = json_decode($response['body'], true);
        $text = $decoded['choices'][0]['message']['content'] ?? null;
        if (!is_string($text)) {
            return null;
        }

        return $this->parseVerdict($text);
    }
}
