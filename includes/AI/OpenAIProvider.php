<?php

declare(strict_types=1);

final class OpenAIProvider extends AbstractAIProvider
{
    public function name(): string
    {
        return 'openai';
    }

    public function analyze(string $filename, string $snippet, array $heuristicReasons): ?array
    {
        $prompt = $this->buildPrompt($filename, $snippet, $heuristicReasons);

        $response = HttpClient::postJson(
            'https://api.openai.com/v1/chat/completions',
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
