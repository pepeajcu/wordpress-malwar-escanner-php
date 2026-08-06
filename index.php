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

if ($action === 'scan_batch' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    Auth::requireCsrf();
    header('Content-Type: application/json');
    $runId = (int) ($_POST['run_id'] ?? 0);

    if ($runId <= 0 || !ScanEngine::run($runId)) {
        http_response_code(400);
        echo json_encode(['error' => 'run_id inválido.']);
        exit;
    }

    echo json_encode(ScanEngine::processBatch($runId));
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
            <progress id="progress-bar" value="0" max="100"></progress>
            <p id="progress-text">Preparando escaneo (recorriendo el árbol de archivos)... en sitios grandes esto puede tardar varios minutos antes de que aparezca el primer avance.</p>
            <p id="ai-progress-text" class="muted"></p>
            <p id="vt-progress-text" class="muted"></p>
        </div>
    </section>

    <section class="panel">
        <h2>Hallazgos</h2>
        <div class="filters">
            <label>Severidad
                <select id="severity-filter">
                    <option value="">Todas</option>
                    <option value="critical">Crítica</option>
                    <option value="high">Alta</option>
                    <option value="medium">Media</option>
                    <option value="low">Baja</option>
                    <option value="info">Info / avisos</option>
                </select>
            </label>
        </div>
        <table id="findings-table">
            <thead>
                <tr>
                    <th>Severidad</th>
                    <th>Archivo</th>
                    <th>Motivo</th>
                    <th>Origen</th>
                    <th>Veredicto IA</th>
                    <th>VirusTotal</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
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
        batchDelayMs: <?= json_encode((int) Config::get('limits.batch_delay_ms', 300)) ?>
    };
</script>
<script src="assets/app.js"></script>
</body>
</html>
