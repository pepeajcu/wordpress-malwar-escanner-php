<?php

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0'); // nunca mostrar errores crudos en un panel expuesto a internet

require_once __DIR__ . '/Config.php';
require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/Auth.php';
require_once __DIR__ . '/PathGuard.php';
require_once __DIR__ . '/FileWalker.php';
require_once __DIR__ . '/HashCache.php';
require_once __DIR__ . '/HeuristicEngine.php';
require_once __DIR__ . '/ScanEngine.php';
require_once __DIR__ . '/HttpClient.php';
require_once __DIR__ . '/RemoteCache.php';

if (is_file(__DIR__ . '/WordPressDetector.php')) {
    require_once __DIR__ . '/WordPressDetector.php';
}
if (is_file(__DIR__ . '/WPChecksumChecker.php')) {
    require_once __DIR__ . '/WPChecksumChecker.php';
}
if (is_file(__DIR__ . '/VirusTotalChecker.php')) {
    require_once __DIR__ . '/VirusTotalChecker.php';
}
if (is_file(__DIR__ . '/QuarantineManager.php')) {
    require_once __DIR__ . '/QuarantineManager.php';
}
$aiOrderedFiles = [
    'AI/AIProviderInterface.php',
    'AI/AbstractAIProvider.php',
    'AI/AIVerdictCache.php',
    'AI/AnthropicProvider.php',
    'AI/GeminiProvider.php',
    'AI/OpenAIProvider.php',
    'AI/MinimaxProvider.php',
    'AI/AIManager.php',
];
foreach ($aiOrderedFiles as $relativeFile) {
    $fullPath = __DIR__ . '/' . $relativeFile;
    if (is_file($fullPath)) {
        require_once $fullPath;
    }
}

date_default_timezone_set('UTC');
