<?php
/**
 * Copia este archivo a config.php y completa tus valores.
 * config.php NUNCA debe subirse a un repositorio público ni compartirse.
 */

return [
    // --- Acceso al panel ---
    // Genera el hash con: php -r "echo password_hash('tu-clave', PASSWORD_DEFAULT);"
    'auth' => [
        'username' => 'admin',
        'password_hash' => '$2y$10$REEMPLAZA.ESTE.HASH.CON.EL.TUYO....................',
        'max_login_attempts' => 5,
        'lockout_seconds' => 900,
    ],

    // --- Rutas a escanear ---
    // Rutas relativas a la carpeta donde vive este script, o absolutas.
    // Por defecto: public_html (donde normalmente se sube esta carpeta) y un nivel arriba.
    'scan_roots' => [
        __DIR__ . '/..',            // un nivel arriba de la carpeta del scanner
        __DIR__ . '/../public_html', // ajustar si el nombre real difiere
    ],

    // Carpetas que nunca se recorren (rutas o nombres de carpeta)
    'exclude_dirs' => [
        'node_modules',
        '.git',
        'quarantine',
        'cache',
        'wp-content/cache',
    ],

    // --- Límites de recursos ---
    'limits' => [
        'discover_batch_size' => 40,   // carpetas exploradas por request en la fase de conteo inicial
        'batch_size' => 25,           // archivos procesados por request
        'batch_delay_ms' => 300,      // pausa sugerida al frontend entre lotes
        'max_file_size_full_read' => 5 * 1024 * 1024, // 5MB: por encima, solo se evalúa por nombre/extensión
        'max_execution_time_hint' => 20, // segundos objetivo por lote (guía interna, no reemplaza php.ini)
        'ai_batch_size' => 3,   // archivos distintos consultados a la IA por request (capa 3)
        'vt_batch_size' => 4,   // hallazgos consultados a VirusTotal por request (capa 4)
        'max_cold_wp_fetches_per_batch' => 2, // tope de descargas nuevas de paquetes de WordPress.org (plugins/temas) por lote de escaneo; evita que un solo request se alargue demasiado en sitios con muchos plugins nunca antes escaneados
    ],

    // --- Modo cron (opcional): retoma el escaneo activo en tandas, disparado por un Cron Job de
    // tu hosting en vez de depender de que el navegador siga abierto. Ver tools/cron_scan.php y
    // la sección "Modo cron" del README para cómo darlo de alta en cPanel.
    'cron' => [
        'enabled' => false,             // ponelo en true una vez que hayas configurado el Cron Job en cPanel
        'time_budget_seconds' => 45,    // cuánto puede trabajar cada corrida de cron antes de cortar y dejar el resto para el próximo tick
        'run_ai_layer' => true,         // si el cron también dispara la capa de IA sobre hallazgos pendientes (consume tus API keys automáticamente)
        'run_vt_layer' => true,         // ídem para VirusTotal
    ],

    // --- Proveedores de IA (capa 3) ---
    // Se activa cada proveedor solo si tiene api_key definida.
    'ai' => [
        'enabled' => false,
        'primary' => 'anthropic', // anthropic | gemini | openai | minimax
        'fallback_order' => ['anthropic', 'gemini', 'openai', 'minimax'],
        'providers' => [
            'anthropic' => [
                'api_key' => '',
                'model' => 'claude-sonnet-5',
            ],
            'gemini' => [
                'api_key' => '',
                'model' => 'gemini-2.5-flash',
            ],
            'openai' => [
                'api_key' => '',
                'model' => 'gpt-4o-mini',
            ],
            'minimax' => [
                'api_key' => '',
                'model' => 'MiniMax-Text-01',
            ],
        ],
    ],

    // --- VirusTotal (capa 4, segundo check sobre hallazgos de alta severidad) ---
    'virustotal' => [
        'enabled' => false,
        'api_key' => '',
        'allow_upload' => false, // si true, sube el archivo completo cuando no hay hash conocido (expone el contenido públicamente en VT)
        'min_severity' => 'high', // solo se consulta VT para hallazgos con esta severidad o mayor
    ],

    // --- Modo de desarrollo/pruebas ---
    'dev' => [
        'dry_run_ai' => false,       // si true, simula respuestas de IA sin llamar a la API real
        'dry_run_virustotal' => false,
    ],
];
