# Scanner Antimalware para Shared Hosting (WordPress-aware, con IA + VirusTotal)

Escáner de malware en PHP puro, pensado para subirse a un shared hosting (cPanel/Hostgator y
similares) sin acceso a shell ni cron confiable. Escanea `public_html` y un nivel arriba,
reconoce la estructura de WordPress, y usa 4 detecciones en capas: heurística local, integridad
oficial de WordPress.org, IA (Gemini/Anthropic/OpenAI/Minimax) y VirusTotal como segundo check.

**Nunca mueve archivos automáticamente.** Todo hallazgo es un reporte; poner algo en cuarentena
es siempre una acción manual del usuario desde el panel.

## Instalación

1. Sube toda esta carpeta al hosting (por ejemplo `public_html/scanner-xyz/` — usa un nombre no
   obvio, no lo llames `scanner` o `antimalware`).
2. Copia `config.sample.php` a `config.php` y edítalo:
   - Genera el hash de tu contraseña:
     `php -r "echo password_hash('tu-clave-segura', PASSWORD_DEFAULT);"`
     (si no tienes PHP CLI a mano, pídeselo a cualquier entorno con PHP, o a esta misma IA).
   - Ajusta `scan_roots` a las rutas reales de tu hosting (por defecto asume que esta carpeta
     está dentro de `public_html` y escanea `public_html` + un nivel arriba).
   - Si quieres usar IA y/o VirusTotal, completa las API keys correspondientes y pon
     `enabled => true`. Si no, el escaneo funciona igual solo con las capas 1 y 2 (integridad de
     WordPress + heurística local).
3. (Recomendado) Segunda capa de acceso con Basic Auth:
   - Por SSH/terminal de tu hosting: `php tools/generate_htpasswd.php tu_usuario tu_password`
   - Descomenta el bloque `AuthType Basic` en `.htaccess` y ajusta `AuthUserFile` a la ruta
     absoluta real de tu `.htpasswd`.
4. Entra por el navegador a `https://tudominio.com/scanner-xyz/index.php`, inicia sesión, y
   presiona "Iniciar escaneo".
5. **Cuando termines, elimina esta carpeta del hosting o dale acceso restringido por IP.** Un
   scanner de malware olvidado y accesible es en sí mismo un riesgo.

## Cómo funciona

- El escaneo corre en lotes disparados desde tu navegador (no depende de cron). Si cierras la
  pestaña, el progreso queda guardado en `data/scan.sqlite` y se retoma solo.
- **Capa 1 — Integridad WordPress**: compara el core contra los checksums oficiales de
  `api.wordpress.org`, y plugins/temas contra el paquete oficial de WordPress.org cuando el
  slug+versión coinciden con el repositorio.
- **Capa 2 — Heurística local**: firmas de webshells conocidos, `eval()`/`assert()` sobre
  contenido decodificado, ejecución de comandos con input del usuario, polyglots, extensiones
  dobles, entropía alta. Corre sobre todo archivo, sin red.
- **Capa 3 — IA**: solo se consulta para archivos que las capas 1-2 ya marcaron como
  sospechosos, agrupando por archivo (no se re-envía el mismo archivo dos veces). Usa el primer
  proveedor disponible según `fallback_order` en `config.php`.
- **Capa 4 — VirusTotal**: solo para hallazgos de severidad alta/crítica, y solo hace *lookup por
  hash* — nunca sube el contenido del archivo (subirlo lo haría públicamente buscable en
  VirusTotal, exponiendo tu código). Si quieres permitir subida como último recurso, actívalo
  explícitamente con `virustotal.allow_upload` (no implementado por defecto a propósito).

## Acciones sobre un hallazgo

- **Ver**: muestra el contenido del archivo (solo lectura, restringido a las rutas configuradas).
- **Falso positivo**: lo whitelistea por hash — no volverá a aparecer en futuros escaneos aunque
  el archivo no cambie.
- **Cuarentena**: mueve el archivo a `quarantine/files/`, deja constancia en
  `quarantine/suspicious_files.log` y en el manifest interno. Se puede **restaurar** en cualquier
  momento desde la sección "Cuarentena" del panel.

## Límites de recursos (ajustables en `config.php`)

- `limits.batch_size`: archivos por request del lote de escaneo normal.
- `limits.max_file_size_full_read`: por encima de este tamaño, un archivo solo se evalúa por
  nombre/extensión, no se lee su contenido completo.
- `limits.ai_batch_size` / `limits.vt_batch_size`: cuántos hallazgos se consultan por request en
  las capas de IA/VirusTotal (llamadas de red, van en su propio lote para no alargar el escaneo
  normal).
- Si tu hosting es muy restrictivo (`max_execution_time` bajo), reduce estos valores.

## Advertencias importantes

- Este script puede leer y (si tú lo pides) mover cualquier archivo dentro de las rutas que
  configures. Protégelo con contraseña fuerte + Basic Auth, y quítalo del servidor cuando
  termines de usarlo.
- Si activas la capa de IA, el contenido de los archivos marcados como sospechosos se envía al
  proveedor de IA que configures. Revisa la política de privacidad del proveedor si tu código
  tiene información sensible.
- Un hallazgo no es una condena: revisa cada caso (botón "Ver") antes de poner algo en
  cuarentena, especialmente en plugins/temas premium o código legítimo pero poco convencional.

## Desarrollo / pruebas

`config.php` admite un modo `dev.dry_run_ai` / `dev.dry_run_virustotal` que simula las
respuestas de esas capas sin llamar a las APIs reales — útil para probar el flujo completo sin
gastar créditos.
