<?php

declare(strict_types=1);

final class AnthropicProvider extends AbstractAIProvider
{
    public function name(): string
    {
        return 'anthropic';
    }

    public function analyze(string $filename, string $snippet, array $heuristicReasons): ?array
    {
        $prompt = $this->buildPrompt($filename, $snippet, $heuristicReasons);

        $response = HttpClient::postJson(
            'https://api.anthropic.com/v1/messages',
            [
                'model' => $this->model,
                'max_tokens' => 500,
                'messages' => [
                    ['role' => 'user', 'content' => $prompt],
                ],
            ],
            [
                'x-api-key: ' . $this->apiKey,
                'anthropic-version: 2023-06-01',
            ],
            20
        );

        if (!$response['ok']) {
            return null;
        }

        $decoded = json_decode($response['body'], true);
        $text = $decoded['content'][0]['text'] ?? null;
        if (!is_string($text)) {
            return null;
        }

        return $this->parseVerdict($text);
    }
}
