<?php

declare(strict_types=1);

/**
 * Capa 1: integridad de WordPress contra el repositorio oficial de WordPress.org.
 *  - Core: usa la API oficial de checksums (api.wordpress.org/core/checksums/1.0/).
 *  - Plugins/temas: descarga el paquete oficial (si el slug+versión existen en el repo) y
 *    compara hashes propios, ya que no hay una API pública de checksums de plugins con
 *    cobertura garantizada.
 * Todo se degrada de forma silenciosa (sin bloquear el escaneo) si no hay salida a internet,
 * si el plugin/tema no es del repositorio oficial (premium/nulled), o si falta ext-zip.
 */
final class WPChecksumChecker
{
    private const MANIFEST_TTL = 86400; // 1 día: la versión ya publicada no cambia sus checksums
    private const CORE_DIRS = ['wp-admin', 'wp-includes'];

    // Tope de descargas de paquete "en frío" (sin caché todavía) por lote de escaneo: cada una
    // puede tardar hasta el timeout de HttpClient, y un lote con varios plugins/temas nuevos a
    // la vez puede hacer que ese único request de PHP se pase de largo del límite del hosting.
    private const MAX_COLD_FETCHES_PER_BATCH = 2;
    private static int $coldFetchesThisBatch = 0;

    /** @var array<int, array{root:string, version:string}>|null */
    private static ?array $installations = null;

    /** @return array<int, array{root:string, version:string}> */
    public static function installations(): array
    {
        if (self::$installations === null) {
            self::$installations = WordPressDetector::findInstallations();
        }
        return self::$installations;
    }

    /** Llamado por ScanEngine al empezar cada lote de escaneo. */
    public static function resetBatchBudget(): void
    {
        self::$coldFetchesThisBatch = 0;
    }

    /** Punto de entrada por-archivo, llamado desde ScanEngine dentro del lote normal. */
    public static function analyzeFile(string $path): array
    {
        $installs = self::installations();
        if (empty($installs)) {
            return [];
        }

        foreach ($installs as $install) {
            $root = $install['root'];
            if ($path !== $root && !str_starts_with($path, $root . '/')) {
                continue;
            }

            $relative = ltrim(substr($path, strlen($root)), '/');
            return self::compareAgainstCore($path, $relative, $install['version'])
                ?? self::compareAgainstPluginOrTheme($path, $relative, $root);
        }

        return [];
    }

    private static function compareAgainstCore(string $path, string $relative, string $version): ?array
    {
        $isCorePath = str_starts_with($relative, 'wp-admin/')
            || str_starts_with($relative, 'wp-includes/')
            || !str_contains($relative, '/'); // archivos sueltos en la raíz (wp-login.php, index.php, etc.)

        if (!$isCorePath || str_starts_with($relative, 'wp-content/')) {
            return null;
        }

        $manifest = self::coreManifest($version);
        if ($manifest === null || !array_key_exists($relative, $manifest)) {
            return null; // no está en el manifest de core: puede ser un archivo custom en la raíz, no es señal
        }

        $localMd5 = @md5_file($path);
        if ($localMd5 === false) {
            return null;
        }

        if (!hash_equals($manifest[$relative], $localMd5)) {
            return [[
                'severity' => 'critical',
                'source' => 'wp_checksum',
                'reason' => 'Archivo core de WordPress modificado respecto a la versión oficial ' . $version,
                'detail' => 'Ruta relativa: ' . $relative,
                'location' => 'Todo el archivo (difiere del hash oficial; no distinguimos qué línea exacta cambió)',
            ]];
        }

        return [];
    }

    private static function compareAgainstPluginOrTheme(string $path, string $relative, string $installRoot): ?array
    {
        if (preg_match('#^wp-content/plugins/([^/]+)/#', $relative, $m) === 1) {
            return self::compareAgainstPackage($path, $relative, $installRoot, 'plugin', $m[1]);
        }

        if (preg_match('#^wp-content/themes/([^/]+)/#', $relative, $m) === 1) {
            return self::compareAgainstPackage($path, $relative, $installRoot, 'theme', $m[1]);
        }

        return [];
    }

    private static function compareAgainstPackage(string $path, string $relative, string $installRoot, string $type, string $slug): array
    {
        $items = $type === 'plugin'
            ? WordPressDetector::findPlugins($installRoot)
            : WordPressDetector::findThemes($installRoot);

        $matching = null;
        foreach ($items as $item) {
            if ($item['slug'] === $slug) {
                $matching = $item;
                break;
            }
        }

        if ($matching === null) {
            return [];
        }

        $manifest = $type === 'plugin'
            ? self::pluginManifest($slug, $matching['version'])
            : self::themeManifest($slug, $matching['version']);

        if ($manifest === null) {
            return []; // no está en el repo oficial (premium/nulled) o no se pudo descargar: sin señal de esta capa
        }

        $prefixLen = strlen('wp-content/' . $type . 's/' . $slug . '/');
        $withinPackage = substr($relative, $prefixLen);

        if (!array_key_exists($withinPackage, $manifest)) {
            return []; // archivo fuera del paquete oficial (uploads, configs propios) no es señal por sí sola
        }

        $localHash = @sha1_file($path);
        if ($localHash === false || hash_equals($manifest[$withinPackage], $localHash)) {
            return [];
        }

        return [[
            'severity' => 'high',
            'source' => 'wp_checksum',
            'reason' => ucfirst($type) . " oficial \"$slug\" modificado respecto al paquete publicado en WordPress.org (v{$matching['version']})",
            'detail' => 'Ruta relativa dentro del paquete: ' . $withinPackage,
            'location' => 'Todo el archivo (difiere del hash oficial; no distinguimos qué línea exacta cambió)',
        ]];
    }

    /** @return array<string,string>|null relPath => md5 */
    private static function coreManifest(string $version): ?array
    {
        $cacheKey = 'wp_core_checksums_' . $version;
        $cached = RemoteCache::get($cacheKey, self::MANIFEST_TTL);
        if ($cached !== null) {
            return $cached;
        }

        $url = 'https://api.wordpress.org/core/checksums/1.0/?version=' . urlencode($version) . '&locale=en_US';
        $response = HttpClient::get($url);
        if (!$response['ok']) {
            return null;
        }

        $decoded = json_decode($response['body'], true);
        $checksums = $decoded['checksums'] ?? null;
        if (!is_array($checksums)) {
            return null;
        }

        RemoteCache::set($cacheKey, $checksums);
        return $checksums;
    }

    /** @return array<string,string>|null relPath (dentro del zip, sin el folder raíz) => sha1 */
    private static function pluginManifest(string $slug, string $version): ?array
    {
        return self::packageManifest('plugin', $slug, $version);
    }

    /** @return array<string,string>|null */
    private static function themeManifest(string $slug, string $version): ?array
    {
        return self::packageManifest('theme', $slug, $version);
    }

    private static function packageManifest(string $type, string $slug, string $version): ?array
    {
        $cacheKey = "wp_{$type}_checksums_{$slug}_{$version}";
        $cached = RemoteCache::get($cacheKey, self::MANIFEST_TTL);
        if ($cached !== null) {
            return $cached ?: null; // caché de "no disponible" se guarda como []
        }

        if (!class_exists('ZipArchive')) {
            return null;
        }

        if (self::$coldFetchesThisBatch >= self::MAX_COLD_FETCHES_PER_BATCH) {
            // Ya se agotó el presupuesto de descargas nuevas para este lote; no se cachea como
            // "no disponible" (a propósito) para que se reintente en un lote posterior.
            return null;
        }
        self::$coldFetchesThisBatch++;

        $url = "https://downloads.wordpress.org/{$type}/{$slug}.{$version}.zip";
        $response = HttpClient::get($url, [], 20);
        if (!$response['ok'] || $response['body'] === '') {
            RemoteCache::set($cacheKey, []); // evita reintentar en cada archivo del mismo plugin/tema
            return null;
        }

        $tmpFile = tempnam(sys_get_temp_dir(), 'wpchk_');
        file_put_contents($tmpFile, $response['body']);

        $zip = new ZipArchive();
        $manifest = [];

        if ($zip->open($tmpFile) === true) {
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $name = $zip->getNameIndex($i);
                if ($name === false || str_ends_with($name, '/')) {
                    continue;
                }
                // El zip oficial contiene una carpeta raíz con el slug; la quitamos para comparar relativo.
                $relative = preg_replace('#^[^/]+/#', '', $name, 1) ?? $name;
                $content = $zip->getFromIndex($i);
                if ($content !== false) {
                    $manifest[$relative] = sha1($content);
                }
            }
            $zip->close();
        }

        @unlink($tmpFile);

        RemoteCache::set($cacheKey, $manifest);
        return $manifest ?: null;
    }

    /**
     * Pasada de cierre: detecta archivos core FALTANTES (borrados) y archivos EXTRA dentro de
     * wp-admin/wp-includes que no pertenecen al manifest oficial (señal fuerte de backdoor).
     * Se ejecuta una sola vez, al terminar el escaneo.
     */
    public static function finalize(int $runId): void
    {
        $installs = self::installations();
        if (empty($installs)) {
            return;
        }

        $pdo = Database::connection();
        $insertFinding = $pdo->prepare(
            'INSERT INTO findings (run_id, path, sha256, severity, source, reason, detail, location, status)
             VALUES (:run_id, :path, :sha256, :severity, :source, :reason, :detail, :location, "open")'
        );

        foreach ($installs as $install) {
            $manifest = self::coreManifest($install['version']);
            if ($manifest === null) {
                continue;
            }

            $missing = [];
            foreach (array_keys($manifest) as $relative) {
                if (!is_file($install['root'] . '/' . $relative)) {
                    $missing[] = $relative;
                }
            }

            // Si falta la mayor parte del core, casi seguro la versión detectada no coincide con
            // la instalación real (o es un WP muy atípico) — una sola alerta agregada es más útil
            // (y evita miles de INSERTs) que un hallazgo por cada archivo "faltante".
            $missingRatio = count($manifest) > 0 ? count($missing) / count($manifest) : 0;

            if ($missingRatio > 0.15 && count($missing) > 30) {
                $insertFinding->execute([
                    ':run_id' => $runId,
                    ':path' => $install['root'],
                    ':sha256' => hash('sha256', $install['root'] . '|version-mismatch'),
                    ':severity' => 'medium',
                    ':source' => 'wp_checksum',
                    ':reason' => sprintf(
                        'La instalación de WordPress en esta ruta difiere masivamente del manifest oficial de la versión %s (%d de %d archivos core no encontrados) — probablemente la versión detectada es incorrecta o la instalación está incompleta',
                        $install['version'],
                        count($missing),
                        count($manifest)
                    ),
                    ':detail' => 'No se listan los archivos individualmente por ser demasiados; revisa manualmente la versión real de WordPress instalada.',
                    ':location' => 'No aplica (el hallazgo es la instalación completa, no un archivo puntual)',
                ]);
            } elseif (!empty($missing)) {
                $pdo->beginTransaction();
                foreach ($missing as $relative) {
                    $insertFinding->execute([
                        ':run_id' => $runId,
                        ':path' => $install['root'] . '/' . $relative,
                        ':sha256' => hash('sha256', $install['root'] . '/' . $relative),
                        ':severity' => 'high',
                        ':source' => 'wp_checksum',
                        ':reason' => 'Archivo core de WordPress faltante (versión ' . $install['version'] . ')',
                        ':detail' => 'Esperado en: ' . $relative,
                        ':location' => 'Todo el archivo (no existe; debería estar y no está)',
                    ]);
                }
                $pdo->commit();
            }

            foreach (self::CORE_DIRS as $coreDir) {
                self::findExtraFiles($install['root'] . '/' . $coreDir, $install['root'], $manifest, $runId, $insertFinding);
            }
        }
    }

    private static function findExtraFiles(string $dir, string $installRoot, array $manifest, int $runId, PDOStatement $insertFinding): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS)
        );

        foreach ($iterator as $fileInfo) {
            /** @var SplFileInfo $fileInfo */
            if (!$fileInfo->isFile()) {
                continue;
            }

            $relative = ltrim(substr($fileInfo->getPathname(), strlen($installRoot)), '/');
            if (array_key_exists($relative, $manifest)) {
                continue;
            }

            $sha256 = @hash_file('sha256', $fileInfo->getPathname()) ?: hash('sha256', $fileInfo->getPathname());
            $insertFinding->execute([
                ':run_id' => $runId,
                ':path' => $fileInfo->getPathname(),
                ':sha256' => $sha256,
                ':severity' => 'critical',
                ':source' => 'wp_checksum',
                ':reason' => 'Archivo no reconocido dentro de una carpeta core de WordPress (' . $relative . ') — fuerte indicio de backdoor',
                ':detail' => 'No forma parte del paquete oficial de WordPress para esta versión.',
                ':location' => 'Todo el archivo (archivo entero ajeno al paquete oficial de WordPress)',
            ]);
        }
    }
}
