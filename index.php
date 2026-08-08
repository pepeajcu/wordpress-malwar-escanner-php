<?php

declare(strict_types=1);

require_once __DIR__ . '/includes/bootstrap.php';

Auth::start();

$action = $_GET['action'] ?? $_POST['action'] ?? 'dashboard';

// --- Rutas públicas (sin sesión) ---
if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = (string) ($_POST['username'] ?? '');
    $password = (string) ($_POST['password'] ?? '');

    if (Auth::attemptLogin($username, $password)) {
        header('Location: index.php');
        exit;
    }

    $_SESSION['login_error'] = 'Usuario o contraseña incorrectos.';
    header('Location: index.php');
    exit;
}

if ($action === 'logout') {
    Auth::logout();
    header('Location: index.php');
    exit;
}

// --- A partir de aquí, todo requiere sesión iniciada ---
Auth::requireLogin();

// --- Endpoints JSON (POST, requieren CSRF) ---
if ($action === 'start_scan' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::requireCsrf();
    header('Content-Type: application/json');
    try {
        $runId = ScanEngine::startRun();
        echo json_encode(['run_id' => $runId]);
    } catch (Throwable $e) {
        http_response_code(400);
        echo json_encode(['error' => $e->getMessage()]);
    }
    exit;
}

if ($action === 'discover_batch' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::requireCsrf();
    header('Content-Type: application/json');
    $runId = (int) ($_POST['run_id'] ?? 0);

    if ($runId <= 0 || !ScanEngine::run($runId)) {
        http_response_code(400);
        echo json_encode(['error' => 'run_id inválido.']);
        exit;
    }

    echo json_encode(ScanEngine::discoverBatch($runId));
    exit;
}

if ($action === 'scan_batch' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::requireCsrf();
    header('Content-Type: application/json');
    $runId = (int) ($_POST['run_id'] ?? 0);

    if ($runId <= 0 || !ScanEngine::run($runId)) {
        http_response_code(400);
        echo json_encode(['error' => 'run_id inválido.']);
        exit;
    }

    try {
        echo json_encode(ScanEngine::processBatch($runId));
    } catch (Throwable $e) {
        http_response_code(409);
        echo json_encode(['error' => $e->getMessage()]);
    }
    exit;
}

if ($action === 'ai_batch' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::requireCsrf();
    header('Content-Type: application/json');
    $runId = (int) ($_POST['run_id'] ?? 0);

    if (!AIManager::isEnabled()) {
        echo json_encode(['processed' => 0, 'remaining' => 0, 'enabled' => false]);
        exit;
    }

    $result = AIManager::processBatch($runId);
    echo json_encode($result + ['enabled' => true]);
    exit;
}

if ($action === 'vt_batch' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::requireCsrf();
    header('Content-Type: application/json');
    $runId = (int) ($_POST['run_id'] ?? 0);

    if (!VirusTotalChecker::isEnabled()) {
        echo json_encode(['processed' => 0, 'remaining' => 0, 'enabled' => false]);
        exit;
    }

    $result = VirusTotalChecker::processBatch($runId);
    echo json_encode($result + ['enabled' => true]);
    exit;
}

if ($action === 'cancel_run' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::requireCsrf();
    header('Content-Type: application/json');
    $runId = (int) ($_POST['run_id'] ?? 0);
    $ok = ScanEngine::cancelRun($runId);
    echo json_encode(['ok' => $ok]);
    exit;
}

if ($action === 'ai_analyze_one' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::requireCsrf();
    header('Content-Type: application/json');
    $findingId = (int) ($_POST['finding_id'] ?? 0);
    echo json_encode(AIManager::analyzeOne($findingId));
    exit;
}

if ($action === 'vt_check_one' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::requireCsrf();
    header('Content-Type: application/json');
    $findingId = (int) ($_POST['finding_id'] ?? 0);
    echo json_encode(VirusTotalChecker::checkOne($findingId));
    exit;
}

if ($action === 'whitelist' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::requireCsrf();
    header('Content-Type: application/json');
    $findingId = (int) ($_POST['finding_id'] ?? 0);

    $pdo = Database::connection();
    $stmt = $pdo->prepare('SELECT * FROM findings WHERE id = :id');
    $stmt->execute([':id' => $findingId]);
    $finding = $stmt->fetch();

    if (!$finding) {
        http_response_code(404);
        echo json_encode(['error' => 'Hallazgo no encontrado.']);
        exit;
    }

    HashCache::addToWhitelist($finding['sha256'], $finding['path'], 'Marcado como falso positivo desde la UI');
    $pdo->prepare('UPDATE findings SET status = "whitelisted" WHERE id = :id')->execute([':id' => $findingId]);

    echo json_encode(['ok' => true]);
    exit;
}

if ($action === 'quarantine' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::requireCsrf();
    header('Content-Type: application/json');
    $findingId = (int) ($_POST['finding_id'] ?? 0);
    echo json_encode(QuarantineManager::quarantine($findingId));
    exit;
}

if ($action === 'restore' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::requireCsrf();
    header('Content-Type: application/json');
    $manifestId = (int) ($_POST['manifest_id'] ?? 0);
    echo json_encode(QuarantineManager::restore($manifestId));
    exit;
}

if ($action === 'quarantine_list') {
    header('Content-Type: application/json');
    echo json_encode(QuarantineManager::activeEntries());
    exit;
}

if ($action === 'view_file') {
    header('Content-Type: application/json');
    $requestedPath = (string) ($_GET['path'] ?? '');
    $real = PathGuard::resolveUserPath($requestedPath);

    if ($real === null) {
        http_response_code(403);
        echo json_encode(['error' => 'Ruta no permitida o inexistente.']);
        exit;
    }

    $maxPreview = 200 * 1024; // 200KB de vista previa como máximo
    $size = filesize($real);
    $content = file_get_contents($real, false, null, 0, $maxPreview);

    echo json_encode([
        'path' => $real,
        'size' => $size,
        'truncated' => $size > $maxPreview,
        'content' => $content === false ? '' : $content,
    ]);
    exit;
}

if ($action === 'findings_json') {
    header('Content-Type: application/json');
    $runId = (int) ($_GET['run_id'] ?? 0);
    $severity = isset($_GET['severity']) && $_GET['severity'] !== '' ? (string) $_GET['severity'] : null;
    echo json_encode(ScanEngine::findings($runId, $severity));
    exit;
}

if ($action === 'unreadable_list') {
    header('Content-Type: application/json');
    $runId = (int) ($_GET['run_id'] ?? 0);
    echo json_encode(ScanEngine::unreadableFindings($runId));
    exit;
}

if ($action === 'scan_history') {
    header('Content-Type: application/json');
    echo json_encode(ScanEngine::history());
    exit;
}

// --- Dashboard (HTML) ---
$activeRunId = ScanEngine::resumableRunId();
$run = $activeRunId ? ScanEngine::run($activeRunId) : null;
$csrfToken = Auth::csrfToken();
?>
<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Scanner Antimalware</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body>
<header class="topbar">
    <h1>Scanner Antimalware</h1>
    <a href="index.php?action=logout" class="link-muted">Cerrar sesión</a>
</header>

<main class="dashboard">
    <section class="panel">
        <h2>Escaneo</h2>
        <div id="scan-controls">
            <button id="start-scan-btn" type="button">Iniciar escaneo</button>
        </div>
        <div id="scan-progress" class="hidden">
            <div id="discover-phase">
                <progress id="discover-bar" class="indeterminate"></progress>
                <p id="discover-text">Explorando el árbol de carpetas...</p>
            </div>
            <div id="process-phase" class="hidden">
                <progress id="progress-bar" value="0" max="100"></progress>
                <p id="progress-text"></p>
            </div>
            <p id="ai-progress-text" class="muted"></p>
            <p id="vt-progress-text" class="muted"></p>
            <button id="force-restart-btn" type="button" class="btn-danger">Cancelar este escaneo y empezar uno nuevo</button>
        </div>
    </section>

    <section class="panel">
        <h2>Carpetas sin acceso <span id="unreadable-count" class="badge hidden">0</span></h2>
        <p class="muted">Estas rutas no se pudieron leer por permisos y quedaron fuera del escaneo. No son necesariamente un problema, pero conviene revisarlas.</p>
        <table id="unreadable-table">
            <thead>
                <tr>
                    <th>Ruta</th>
                    <th>Detectado</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </section>

    <section class="panel">
        <h2>Hallazgos</h2>
        <p id="viewing-banner" class="muted hidden">Viendo escaneo #<span id="viewing-run-id"></span> (histórico). <a href="#" id="back-to-current">Volver al escaneo actual</a></p>
        <div class="filters">
            <label>Severidad
                <select id="severity-filter">
                    <option value="">Todas</option>
                    <option value="critical">Crítica</option>
                    <option value="high">Alta</option>
                    <option value="medium">Media</option>
                    <option value="low">Baja</option>
                </select>
            </label>
        </div>
        <div class="table-wrap">
        <table id="findings-table">
            <thead>
                <tr>
                    <th>Severidad</th>
                    <th>Archivo</th>
                    <th>Motivo</th>
                    <th>Ubicación</th>
                    <th>Origen</th>
                    <th>Veredicto IA</th>
                    <th>VirusTotal</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
        </div>
    </section>

    <section class="panel">
        <h2>Cuarentena</h2>
        <p class="muted">Los archivos aquí fueron movidos manualmente desde "Hallazgos". Puedes restaurarlos si fue un falso positivo.</p>
        <table id="quarantine-table">
            <thead>
                <tr>
                    <th>Ruta original</th>
                    <th>Severidad</th>
                    <th>Movido</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </section>

    <section class="panel">
        <h2>Historial de escaneos</h2>
        <p class="muted">Se conserva en <code>data/scan.sqlite</code> y sobrevive a actualizaciones de código (no borres esa carpeta al resubir archivos).</p>
        <table id="history-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Estado</th>
                    <th>Iniciado</th>
                    <th>Archivos</th>
                    <th>Hallazgos</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
    </section>
</main>

<div id="file-viewer" class="modal hidden">
    <div class="modal-content">
        <button id="close-viewer" type="button" class="close-btn">×</button>
        <pre id="file-viewer-content"></pre>
    </div>
</div>

<script>
    window.SCANNER = {
        csrfToken: <?= json_encode($csrfToken) ?>,
        activeRunId: <?= json_encode($activeRunId) ?>,
        activeRunStatus: <?= json_encode($run['status'] ?? null) ?>,
        batchDelayMs: <?= json_encode((int) Config::get('limits.batch_delay_ms', 300)) ?>,
        cronEnabled: <?= json_encode((bool) Config::get('cron.enabled', false)) ?>
    };
</script>
<script src="assets/app.js"></script>
</body>
</html>
