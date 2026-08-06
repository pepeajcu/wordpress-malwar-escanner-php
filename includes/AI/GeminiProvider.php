<?php

declare(strict_types=1);

final class GeminiProvider extends AbstractAIProvider
{
    public function name(): string
    {
        return 'gemini';
    }

    public function analyze(string $filename, string $snippet, array $heuristicReasons): ?array
    {
        $prompt = $this->buildPrompt($filename, $snippet, $heuristicReasons);
        $url = 'https://generativelanguage.googleapis.com/v1beta/models/' . urlencode($this->model)
            . ':generateContent?key=' . urlencode($this->apiKey);

        $response = HttpClient::postJson(
            $url,
            [
                'contents' => [
                    ['parts' => [['text' => $prompt]]],
                ],
                'generationConfig' => ['temperature' => 0],
            ],
            [],
            20
        );

        if (!$response['ok']) {
            return null;
        }

        $decoded = json_decode($response['body'], true);
        $text = $decoded['candidates'][0]['content']['parts'][0]['text'] ?? null;
        if (!is_string($text)) {
            return null;
        }

        return $this->parseVerdict($text);
    }
}
