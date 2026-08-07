<?php

declare(strict_types=1);

/**
 * Continúa el escaneo activo (o los pendientes de IA/VirusTotal del último escaneo) en tandas
 * acotadas por tiempo, para correr desde un Cron Job en vez de depender de que el navegador
 * siga abierto. NO arranca un escaneo nuevo por sí solo: eso se sigue haciendo a mano desde el
 * panel ("Iniciar escaneo"); este script solo retoma lo que ya está en cola.
 *
 * Alta en cPanel → Cron Jobs (ver README, sección "Modo cron"):
 *   /usr/local/bin/ea-phpXX /ruta/absoluta/a/esta/carpeta/tools/cron_scan.php >/dev/null 2>&1
 *
 * Uso por línea de comandos, NUNCA por navegador.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    die('Este script solo puede ejecutarse por Cron Job o línea de comandos (SSH/terminal de tu hosting), nunca desde el navegador.');
}

require_once __DIR__ . '/../includes/bootstrap.php';

if (!Config::get('cron.enabled', false)) {
    echo "El modo cron está desactivado (cron.enabled = false en config.php). Nada que hacer.\n";
    exit(0);
}

// --- Lock no bloqueante: si el tick anterior todavía está trabajando (p. ej. esperando una API
// de IA lenta), este salimos enseguida en vez de pisarle el trabajo. ---
$dataDir = __DIR__ . '/../data';
if (!is_dir($dataDir)) {
    mkdir($dataDir, 0750, true);
}
$lockPath = $dataDir . '/cron.lock';
$lockHandle = fopen($lockPath, 'c');
if ($lockHandle === false || !flock($lockHandle, LOCK_EX | LOCK_NB)) {
    echo "Ya hay una corrida de cron_scan.php en curso; salgo sin hacer nada.\n";
    exit(0);
}

register_shutdown_function(static function () use ($lockHandle): void {
    flock($lockHandle, LOCK_UN);
    fclose($lockHandle);
});

$budgetSeconds = (int) Config::get('cron.time_budget_seconds', 45);
$runAiLayer = (bool) Config::get('cron.run_ai_layer', true);
$runVtLayer = (bool) Config::get('cron.run_vt_layer', true);
$start = microtime(true);

$timeLeft = static function () use ($start, $budgetSeconds): float {
    return $budgetSeconds - (microtime(true) - $start);
};

/** Busca un escaneo para continuar: en curso, o el último completado con IA/VT aún pendientes. */
$findRunToContinue = static function (): ?int {
    $resumable = ScanEngine::resumableRunId();
    if ($resumable !== null) {
        return $resumable;
    }

    $history = ScanEngine::history(1);
    if (empty($history)) {
        return null;
    }
    $lastId = (int) $history[0]['id'];

    if (class_exists('AIManager') && AIManager::isEnabled() && AIManager::pendingCount($lastId) > 0) {
        return $lastId;
    }
    if (class_exists('VirusTotalChecker') && VirusTotalChecker::isEnabled() && VirusTotalChecker::pendingCount($lastId) > 0) {
        return $lastId;
    }

    return null;
};

$runId = $findRunToContinue();
if ($runId === null) {
    echo "No hay ningún escaneo activo ni pendiente de IA/VirusTotal. Nada que hacer.\n";
    exit(0);
}

echo "Continuando escaneo #{$runId}...\n";

// --- 1) Descubrimiento del árbol de carpetas ---
$run = ScanEngine::run($runId);
while ($run !== null && $run['status'] === 'discovering' && $timeLeft() > 5) {
    $res = ScanEngine::discoverBatch($runId);
    echo "Descubrimiento: {$res['dirs_done']} carpeta(s) revisadas, {$res['files_found']} archivo(s) encontrados"
        . ($res['finished'] ? " — listo.\n" : "...\n");
    $run = ScanEngine::run($runId);
}

// --- 2) Escaneo de contenido (heurística + integridad WP) ---
$run = ScanEngine::run($runId);
while ($run !== null && $run['status'] === 'running' && $timeLeft() > 5) {
    $res = ScanEngine::processBatch($runId);
    echo "Escaneo: {$res['processed']}/{$res['total']} archivo(s), {$res['new_findings']} hallazgo(s) nuevo(s)"
        . ($res['finished'] ? " — listo.\n" : "...\n");
    $run = ScanEngine::run($runId);
}

// --- 3) Capa de IA ---
if ($runAiLayer && class_exists('AIManager') && AIManager::isEnabled()) {
    while (AIManager::pendingCount($runId) > 0 && $timeLeft() > 5) {
        $res = AIManager::processBatch($runId);
        echo "IA: {$res['processed']} analizado(s), {$res['remaining']} pendiente(s)...\n";
        if ($res['processed'] === 0) {
            break; // nada procesable en este intento; evita loop infinito
        }
    }
}

// --- 4) VirusTotal ---
if ($runVtLayer && class_exists('VirusTotalChecker') && VirusTotalChecker::isEnabled()) {
    while (VirusTotalChecker::pendingCount($runId) > 0 && $timeLeft() > 5) {
        $res = VirusTotalChecker::processBatch($runId);
        echo "VirusTotal: {$res['processed']} consultado(s), {$res['remaining']} pendiente(s)...\n";
        if ($res['processed'] === 0) {
            break;
        }
    }
}

printf("Corrida de cron terminada en %.1fs.\n", microtime(true) - $start);
