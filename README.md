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

- El escaneo tiene dos fases, ambas en lotes disparados desde tu navegador por defecto (no
  requiere cron para funcionar; ver la sección "Modo cron" más abajo si querés que se procese
  solo, repartido en el tiempo, sin depender de que dejes la pestaña abierta):
  1. **Descubrimiento**: recorre el árbol de carpetas en tandas cortas, mostrando en vivo cuántas
     carpetas ya revisó y cuántos archivos encontró. En sitios grandes esto puede tardar varios
     minutos, pero ahora se ve avanzar en vez de parecer congelado.
  2. **Escaneo de contenido**: una vez que se sabe el total de archivos, la barra de progreso
     muestra porcentaje real (procesados / total).
  Si cierras la pestaña en cualquiera de las dos fases, el progreso queda guardado en
  `data/scan.sqlite` y se retoma solo al volver a entrar.
- **Carpetas sin acceso**: si una carpeta no se puede leer por permisos (típico de backups de
  plugins como UpdraftPlus, o de caches de otros procesos), se salta sin abortar el resto del
  escaneo y queda listada aparte, en el panel "Carpetas sin acceso" — separada de los hallazgos
  de malware para que se note a simple vista que es un tema de permisos, no una infección.
- **Historial de escaneos**: cada corrida (con su fecha, cantidad de archivos y hallazgos) queda
  guardada en `data/scan.sqlite` y es consultable desde el panel "Historial de escaneos", con un
  botón para ver los hallazgos de cualquier escaneo pasado. Esta data sobrevive a actualizaciones
  del código del scanner — al subir una versión nueva de los archivos `.php`, nunca toques la
  carpeta `data/` y tu historial seguirá ahí (las tablas nuevas que agregue una actualización se
  crean solas sin tocar lo que ya existía).
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

## Modo cron (opcional)

Si tu sitio es grande y el escaneo desde el navegador choca con el límite de tiempo de tu
hosting ("Se perdió la conexión con el servidor o tardó demasiado..."), podés hacer que un Cron
Job de tu hosting vaya retomando el escaneo activo en tandas cortas, repartido en el tiempo, sin
depender de que dejes la pestaña abierta.

**Cómo funciona:** vos arrancás el escaneo una vez desde el panel ("Iniciar escaneo") y podés
cerrar la pestaña; el Cron Job ejecuta `tools/cron_scan.php` cada cierto tiempo, y cada corrida
retoma el descubrimiento de carpetas, el escaneo de archivos, y (si están activadas) las capas
de IA y VirusTotal, durante como máximo `cron.time_budget_seconds` segundos, dejando el resto
para el próximo tick. No arranca escaneos nuevos por su cuenta — solo continúa lo que ya
iniciaste manualmente.

**Alta:**
1. En `config.php`, dentro de `cron`, poné `'enabled' => true`. Ajustá `run_ai_layer` /
   `run_vt_layer` a `false` si preferís que esas capas queden solo para disparar manualmente por
   hallazgo desde el panel (botones "Analizar con IA" / "Consultar VirusTotal"), en vez de que el
   cron las corra automáticamente (con el consumo de API que eso implica).
2. En cPanel → Avanzado → **Cron Jobs**, agregá un nuevo cron con un comando como:
   ```
   /usr/local/bin/ea-phpXX /home2/tu_usuario/public_html/tu-carpeta-del-scanner/tools/cron_scan.php >/dev/null 2>&1
   ```
   Reemplazá `ea-phpXX` por la versión de PHP real que le tenés asignada a ese dominio (se ve en
   **MultiPHP Manager**) y la ruta por la ruta absoluta real de esta carpeta en tu hosting.
3. Elegí una frecuencia de arranque — por ejemplo cada 10-15 minutos es un buen punto de
   partida. Ajustala junto con `cron.time_budget_seconds`: con esos valores, un escaneo grande
   queda repartido a lo largo de varias horas o de todo el día en vez de intentar completarse de
   una sola vez.
4. El script tiene su propio lock (`data/cron.lock`) para que dos corridas de cron no se pisen si
   una tarda más de lo esperado (por ejemplo, esperando una API de IA lenta).

Con `cron.enabled = true`, el panel deja de disparar lotes automáticamente al abrir la página
mientras haya un escaneo en curso (para no procesar los mismos archivos dos veces a la vez que
el cron) — solo muestra el progreso. El botón "Iniciar escaneo" y las acciones manuales sobre
cada hallazgo siguen funcionando igual.

## Límites de recursos (ajustables en `config.php`)

- `limits.batch_size`: archivos por request del lote de escaneo normal.
- `limits.max_file_size_full_read`: por encima de este tamaño, un archivo solo se evalúa por
  nombre/extensión, no se lee su contenido completo.
- `limits.ai_batch_size` / `limits.vt_batch_size`: cuántos hallazgos se consultan por request en
  las capas de IA/VirusTotal (llamadas de red, van en su propio lote para no alargar el escaneo
  normal).
- `limits.max_cold_wp_fetches_per_batch`: cuántos paquetes de plugin/tema nuevos (sin caché
  todavía) se descargan de WordPress.org por lote de escaneo. En sitios con muchos plugins/temas
  nunca antes escaneados, esto es una causa frecuente de que un solo lote tarde mucho más de lo
  que sugiere `batch_size` — bajalo si seguís viendo timeouts.
- Si tu hosting es muy restrictivo (`max_execution_time` bajo), reduce estos valores. Para sitios
  grandes, considerá además el **modo cron** de arriba en vez de bajar mucho estos números.

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
