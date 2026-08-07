<?php

declare(strict_types=1);

/**
 * Local, network-free detection layer (Capa 2). Runs on every eligible file. Combines:
 *  - known webshell / obfuscation signatures (regex)
 *  - dangerous-function + superglobal combinations
 *  - filename red flags (double extensions, polyglots)
 *  - Shannon entropy as a proxy for packed/obfuscated payloads
 *
 * Returns a list of findings; an empty list means "nothing suspicious at this layer".
 */
final class HeuristicEngine
{
    private const SCRIPT_EXTENSIONS = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phar', 'inc', 'cgi', 'pl'];

    /** Firmas de webshells "dedicados": el archivo completo existe para eso, no es un fragmento inyectado en un archivo legítimo. */
    private const FULL_FILE_SIGNATURE_IDS = [
        'known_shell_c99', 'known_shell_r57', 'known_shell_wso',
        'known_shell_b374k', 'known_shell_filesman', 'known_shell_indoxploit',
    ];

    /** @var array<int, array{id:string, severity:string, pattern:string, reason:string}> */
    private const SIGNATURES = [
        // --- Ejecución de código decodificado dinámicamente: patrón clásico de webshell ---
        ['id' => 'eval_base64', 'severity' => 'critical', 'pattern' => '/\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode)\s*\(/i', 'reason' => 'eval() sobre contenido decodificado dinámicamente (patrón clásico de webshell ofuscado)'],
        ['id' => 'assert_base64', 'severity' => 'critical', 'pattern' => '/\bassert\s*\(\s*(?:base64_decode|gzinflate|str_rot13)\s*\(/i', 'reason' => 'assert() usado como eval() sobre contenido decodificado'],
        ['id' => 'eval_superglobal', 'severity' => 'critical', 'pattern' => '/\b(?:eval|assert)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/i', 'reason' => 'eval()/assert() ejecutando directamente input del usuario ($_GET/$_POST/...)'],
        ['id' => 'create_function_dynamic', 'severity' => 'high', 'pattern' => '/create_function\s*\(\s*[\'"].*[\'"]\s*,\s*\$_(GET|POST|REQUEST)/i', 'reason' => 'create_function() construyendo código ejecutable a partir de input del usuario'],

        // --- Ejecución de comandos del sistema con input externo ---
        ['id' => 'exec_superglobal', 'severity' => 'critical', 'pattern' => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[/i', 'reason' => 'Ejecución de comandos del sistema directamente con input del usuario'],
        ['id' => 'backtick_superglobal', 'severity' => 'high', 'pattern' => '/`\s*\.?\s*\$_(GET|POST|REQUEST)\s*\[/i', 'reason' => 'Operador backtick (shell_exec) con input del usuario'],

        // --- preg_replace con modificador /e (permite ejecutar código arbitrario, deprecated pero aún explotado) ---
        ['id' => 'preg_replace_e', 'severity' => 'critical', 'pattern' => '/preg_replace\s*\(\s*[\'"][^\'"]*\/[a-zA-Z]*e[a-zA-Z]*[\'"]/i', 'reason' => 'preg_replace() con modificador /e: permite ejecución de código arbitrario'],

        // --- Firmas de webshells conocidos ---
        ['id' => 'known_shell_c99', 'severity' => 'critical', 'pattern' => '/c99shell|c99_buff|c99_locus/i', 'reason' => 'Firma del webshell conocido "c99shell"'],
        ['id' => 'known_shell_r57', 'severity' => 'critical', 'pattern' => '/r57shell|r57 shell/i', 'reason' => 'Firma del webshell conocido "r57shell"'],
        ['id' => 'known_shell_wso', 'severity' => 'critical', 'pattern' => '/wso\s*shell|WSO\s*[0-9.]+\s*web\s*shell/i', 'reason' => 'Firma del webshell conocido "WSO"'],
        ['id' => 'known_shell_b374k', 'severity' => 'critical', 'pattern' => '/b374k/i', 'reason' => 'Firma del webshell conocido "b374k"'],
        ['id' => 'known_shell_filesman', 'severity' => 'critical', 'pattern' => '/FilesMan|File\s*Manager\s*by/i', 'reason' => 'Firma del webshell conocido "FilesMan"'],
        ['id' => 'known_shell_indoxploit', 'severity' => 'critical', 'pattern' => '/IndoXploit|Mini\s*Shell|Alfa\s*[Ss]hell|Priv8|Ninja\s*[Ss]hell|Cyber\s*[Ss]hell/i', 'reason' => 'Firma de webshell conocido (familia IndoXploit/Alfa/Priv8/Ninja/Cyber)'],

        // --- Descarga y ejecución remota ---
        ['id' => 'remote_fetch_eval', 'severity' => 'critical', 'pattern' => '/eval\s*\(\s*(?:file_get_contents|curl_exec)\s*\(/i', 'reason' => 'Descarga contenido remoto y lo ejecuta con eval() (dropper/backdoor)'],

        // --- Ofuscación de nombres de función/variable ---
        ['id' => 'hex_var_obfuscation', 'severity' => 'high', 'pattern' => '/\$\{\s*["\'](?:\\\\x[0-9a-f]{2}){3,}["\']\s*\}/i', 'reason' => 'Ofuscación de nombres de variable mediante escapes hexadecimales'],
        ['id' => 'chr_concat_function', 'severity' => 'medium', 'pattern' => '/\bcall_user_func\s*\(\s*(?:base64_decode|str_rot13|chr\s*\(|\$\w+\s*\.\s*\$\w+)/i', 'reason' => 'Construcción dinámica de nombre de función a ejecutar (evasión de firmas)'],

        // --- Manipulación sospechosa de archivos ---
        ['id' => 'php_uname_fingerprint', 'severity' => 'low', 'pattern' => '/php_uname\s*\(\s*\)\s*\.\s*(?:PHP_OS|phpversion)/i', 'reason' => 'Recolección de fingerprint del servidor típica de webshells'],
    ];

    /** @return array<int, array{severity:string, source:string, reason:string, detail:string}> */
    public static function analyzeFile(string $path, int $size, int $maxFullReadSize): array
    {
        $findings = [];

        $filenameFindings = self::analyzeFilename($path);
        array_push($findings, ...$filenameFindings);

        if ($size > $maxFullReadSize) {
            return $findings;
        }

        $content = @file_get_contents($path);
        if ($content === false || $content === '') {
            return $findings;
        }

        array_push($findings, ...self::analyzeContent($content));
        array_push($findings, ...self::analyzePolyglot($path, $content));

        return $findings;
    }

    /** @return array<int, array{severity:string, source:string, reason:string, detail:string, location:string}> */
    private static function analyzeContent(string $content): array
    {
        $findings = [];

        foreach (self::SIGNATURES as $signature) {
            if (preg_match($signature['pattern'], $content, $m, PREG_OFFSET_CAPTURE) === 1) {
                $isFullFile = in_array($signature['id'], self::FULL_FILE_SIGNATURE_IDS, true);
                $location = $isFullFile
                    ? 'Todo el archivo (webshell dedicado, no un fragmento inyectado)'
                    : 'Línea ' . self::lineFromOffset($content, $m[0][1]);

                $findings[] = [
                    'severity' => $signature['severity'],
                    'source' => 'heuristic',
                    'reason' => $signature['reason'],
                    'detail' => 'Firma: ' . $signature['id'],
                    'location' => $location,
                ];
            }
        }

        $entropy = self::shannonEntropy($content);
        if ($entropy >= 5.7 && strlen($content) > 300) {
            $findings[] = [
                'severity' => $entropy >= 6.4 ? 'high' : 'medium',
                'source' => 'heuristic',
                'reason' => 'Alta entropía de contenido (posible código empaquetado/ofuscado/cifrado)',
                'detail' => sprintf('Entropía de Shannon: %.2f bits/byte', $entropy),
                'location' => 'Todo el archivo (métrica calculada sobre el contenido completo, no aplica a una línea puntual)',
            ];
        }

        return $findings;
    }

    /** Número de línea (1-based) donde cae un offset de bytes dentro de $content. */
    private static function lineFromOffset(string $content, int $offset): int
    {
        return substr_count($content, "\n", 0, max(0, $offset)) + 1;
    }

    /** @return array<int, array{severity:string, source:string, reason:string, detail:string}> */
    private static function analyzeFilename(string $path): array
    {
        $findings = [];
        $filename = strtolower(basename($path));
        $parts = explode('.', $filename);

        if (count($parts) >= 3) {
            $lastExt = end($parts);
            $secondLastExt = prev($parts);
            $mediaExtensions = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'pdf', 'txt', 'zip'];

            if (in_array($lastExt, self::SCRIPT_EXTENSIONS, true) && in_array($secondLastExt, $mediaExtensions, true)) {
                $findings[] = [
                    'severity' => 'high',
                    'source' => 'heuristic',
                    'reason' => 'Extensión doble sospechosa (' . $secondLastExt . '.' . $lastExt . '): intenta parecer un archivo no ejecutable',
                    'detail' => 'Nombre de archivo: ' . basename($path),
                    'location' => 'Todo el archivo (el problema es el nombre, no una sección puntual del contenido)',
                ];
            }
        }

        return $findings;
    }

    /** @return array<int, array{severity:string, source:string, reason:string, detail:string}> */
    private static function analyzePolyglot(string $path, string $content): array
    {
        $findings = [];
        $header = substr($content, 0, 16);

        $isImageHeader =
            str_starts_with($header, "\xFF\xD8\xFF") ||               // JPEG
            str_starts_with($header, "\x89PNG\r\n\x1a\n") ||           // PNG
            str_starts_with($header, 'GIF87a') || str_starts_with($header, 'GIF89a'); // GIF

        if ($isImageHeader && (str_contains($content, '<?php') || str_contains($content, '<?='))) {
            $tagOffset = strpos($content, '<?php');
            if ($tagOffset === false) {
                $tagOffset = strpos($content, '<?=');
            }
            $location = $tagOffset === false
                ? 'No se pudo ubicar el tag PHP embebido'
                : 'Línea ' . self::lineFromOffset($content, $tagOffset) . ' en adelante (código PHP embebido tras la cabecera de imagen)';

            $findings[] = [
                'severity' => 'critical',
                'source' => 'heuristic',
                'reason' => 'Archivo polyglot: cabecera de imagen válida pero contiene código PHP embebido',
                'detail' => 'Nombre de archivo: ' . basename($path),
                'location' => $location,
            ];
        }

        return $findings;
    }

    private static function shannonEntropy(string $data): float
    {
        $length = strlen($data);
        if ($length === 0) {
            return 0.0;
        }

        $frequencies = array_count_values(array_map('ord', str_split($data)));
        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $p = $count / $length;
            $entropy -= $p * log($p, 2);
        }

        return $entropy;
    }
}
