<?php

declare(strict_types=1);

/**
 * Minimal outbound HTTP helper shared by WPChecksumChecker, the AI providers and
 * VirusTotalChecker. Uses cURL when available (most shared hosting has it), falls back to
 * stream contexts otherwise. Every call degrades gracefully (returns ok=false) instead of
 * throwing, since outbound internet access is not guaranteed on every shared host.
 */
final class HttpClient
{
    private const DEFAULT_TIMEOUT = 12;

    /** @return array{ok:bool, status:int, body:string, error:?string} */
    public static function get(string $url, array $headers = [], int $timeout = self::DEFAULT_TIMEOUT): array
    {
        return self::request('GET', $url, $headers, null, $timeout);
    }

    /** @return array{ok:bool, status:int, body:string, error:?string} */
    public static function postJson(string $url, array $payload, array $headers = [], int $timeout = self::DEFAULT_TIMEOUT): array
    {
        $headers[] = 'Content-Type: application/json';
        return self::request('POST', $url, $headers, json_encode($payload), $timeout);
    }

    /** @return array{ok:bool, status:int, body:string, error:?string} */
    public static function postForm(string $url, array $fields, array $headers = [], int $timeout = self::DEFAULT_TIMEOUT): array
    {
        return self::request('POST', $url, $headers, http_build_query($fields), $timeout);
    }

    /** @return array{ok:bool, status:int, body:string, error:?string} */
    private static function request(string $method, string $url, array $headers, ?string $body, int $timeout): array
    {
        if (function_exists('curl_init')) {
            return self::viaCurl($method, $url, $headers, $body, $timeout);
        }

        return self::viaStream($method, $url, $headers, $body, $timeout);
    }

    private static function viaCurl(string $method, string $url, array $headers, ?string $body, int $timeout): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_CONNECTTIMEOUT => $timeout,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_USERAGENT => 'AntimalwareScanner/1.0',
        ]);

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $response = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch) ?: null;
        curl_close($ch);

        if ($response === false) {
            return ['ok' => false, 'status' => 0, 'body' => '', 'error' => $error ?? 'curl error desconocido'];
        }

        return ['ok' => $status >= 200 && $status < 300, 'status' => $status, 'body' => (string) $response, 'error' => null];
    }

    private static function viaStream(string $method, string $url, array $headers, ?string $body, int $timeout): array
    {
        if (!ini_get('allow_url_fopen')) {
            return ['ok' => false, 'status' => 0, 'body' => '', 'error' => 'allow_url_fopen deshabilitado y cURL no disponible'];
        }

        $context = stream_context_create([
            'http' => [
                'method' => $method,
                'header' => implode("\r\n", $headers) . "\r\nUser-Agent: AntimalwareScanner/1.0",
                'content' => $body ?? '',
                'timeout' => $timeout,
                'ignore_errors' => true,
            ],
        ]);

        $response = @file_get_contents($url, false, $context);
        $status = 0;

        if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) {
            $status = (int) $m[1];
        }

        if ($response === false) {
            return ['ok' => false, 'status' => $status, 'body' => '', 'error' => 'No se pudo contactar el host remoto'];
        }

        return ['ok' => $status >= 200 && $status < 300, 'status' => $status, 'body' => $response, 'error' => null];
    }
}
