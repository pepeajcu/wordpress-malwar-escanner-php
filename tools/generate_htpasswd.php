<?php

declare(strict_types=1);

/**
 * Genera la línea para .htpasswd (Basic Auth, segunda capa de acceso — ver .htaccess).
 * Uso por línea de comandos, NUNCA por navegador:
 *   php tools/generate_htpasswd.php usuario "tu-password"
 *
 * Intenta escribir ../.htpasswd directamente; si no puede (permisos), imprime la línea
 * para que la pegues a mano con el Administrador de Archivos de tu hosting.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    die('Este script solo puede ejecutarse por línea de comandos (SSH / terminal de tu hosting), nunca desde el navegador.');
}

if ($argc < 3) {
    fwrite(STDERR, "Uso: php generate_htpasswd.php <usuario> <password>\n");
    exit(1);
}

[, $username, $password] = $argv;
$hash = password_hash($password, PASSWORD_BCRYPT);
$line = $username . ':' . $hash;

$targetFile = __DIR__ . '/../.htpasswd';
if (@file_put_contents($targetFile, $line . PHP_EOL) !== false) {
    @chmod($targetFile, 0640);
    echo "Escrito en: {$targetFile}\n";
    echo "Recuerda descomentar el bloque Basic Auth en .htaccess y ajustar AuthUserFile a la ruta absoluta real.\n";
} else {
    echo "No se pudo escribir el archivo automáticamente. Copia esta línea a mano en un archivo .htpasswd:\n\n";
    echo $line . "\n";
}
