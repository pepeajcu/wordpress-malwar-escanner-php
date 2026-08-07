(function () {
    'use strict';

    const state = {
        runId: window.SCANNER.activeRunId || null, // escaneo activo (el que se está corriendo/reanudando)
        viewRunId: window.SCANNER.activeRunId || null, // escaneo que se está mostrando en la tabla de hallazgos (puede ser histórico)
        polling: false,
    };

    const el = {
        startBtn: document.getElementById('start-scan-btn'),
        controls: document.getElementById('scan-controls'),
        progressWrap: document.getElementById('scan-progress'),
        discoverPhase: document.getElementById('discover-phase'),
        discoverText: document.getElementById('discover-text'),
        processPhase: document.getElementById('process-phase'),
        progressBar: document.getElementById('progress-bar'),
        progressText: document.getElementById('progress-text'),
        aiProgressText: document.getElementById('ai-progress-text'),
        vtProgressText: document.getElementById('vt-progress-text'),
        severityFilter: document.getElementById('severity-filter'),
        findingsBody: document.querySelector('#findings-table tbody'),
        quarantineBody: document.querySelector('#quarantine-table tbody'),
        unreadableBody: document.querySelector('#unreadable-table tbody'),
        unreadableCount: document.getElementById('unreadable-count'),
        historyBody: document.querySelector('#history-table tbody'),
        viewingBanner: document.getElementById('viewing-banner'),
        viewingRunId: document.getElementById('viewing-run-id'),
        backToCurrent: document.getElementById('back-to-current'),
        viewer: document.getElementById('file-viewer'),
        viewerContent: document.getElementById('file-viewer-content'),
        closeViewer: document.getElementById('close-viewer'),
    };

    function postForm(action, data) {
        const body = new URLSearchParams(Object.assign({ csrf_token: window.SCANNER.csrfToken }, data));
        return fetch('index.php?action=' + encodeURIComponent(action), {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString(),
        }).then((r) => r.json());
    }

    const CONNECTION_ERROR = {
        error: 'Se perdió la conexión con el servidor o tardó demasiado en responder (puede ser el límite max_execution_time de tu hosting). Intenta de nuevo; si persiste, reduce los *_batch_size en config.php.',
    };

    function startScan() {
        el.startBtn.disabled = true;
        el.controls.classList.add('hidden');
        el.progressWrap.classList.remove('hidden');
        el.discoverPhase.classList.remove('hidden');
        el.processPhase.classList.add('hidden');
        el.discoverText.textContent = 'Preparando escaneo...';

        postForm('start_scan', {})
            .catch(() => CONNECTION_ERROR)
            .then((res) => {
                if (res.error) {
                    showStartError(res.error);
                    return;
                }
                state.runId = res.run_id;
                state.viewRunId = res.run_id;
                showViewingBanner();
                runNextDiscoverBatch();
            });
    }

    function showStartError(message) {
        el.discoverText.textContent = 'Error al iniciar el escaneo: ' + message;
        el.progressWrap.classList.add('hidden');
        el.controls.classList.remove('hidden');
        el.startBtn.disabled = false;
    }

    function runNextDiscoverBatch() {
        if (!state.runId) return;

        postForm('discover_batch', { run_id: state.runId })
            .catch(() => CONNECTION_ERROR)
            .then((res) => {
                if (res.error) {
                    el.discoverText.textContent = 'Error explorando carpetas: ' + res.error;
                    return;
                }

                let text = 'Explorando: ' + res.dirs_done + ' carpeta(s) revisadas, ' + res.files_found + ' archivo(s) encontrados';
                if (res.unreadable_count > 0) {
                    text += ', ' + res.unreadable_count + ' carpeta(s) sin acceso';
                    loadUnreadable();
                }
                el.discoverText.textContent = text + '...';

                if (res.finished) {
                    el.discoverPhase.classList.add('hidden');
                    el.processPhase.classList.remove('hidden');
                    loadUnreadable();
                    runNextBatch();
                    return;
                }

                setTimeout(runNextDiscoverBatch, window.SCANNER.batchDelayMs || 300);
            });
    }

    function runNextBatch() {
        if (!state.runId) return;
        state.polling = true;

        postForm('scan_batch', { run_id: state.runId })
            .catch(() => CONNECTION_ERROR)
            .then((res) => {
                if (res.error) {
                    el.progressText.textContent = 'Error: ' + res.error;
                    state.polling = false;
                    return;
                }

                const pct = res.total > 0 ? Math.round((res.processed / res.total) * 100) : 100;
                el.progressBar.value = pct;
                el.progressText.textContent =
                    res.processed + ' / ' + res.total + ' archivos procesados — ' +
                    res.new_findings + ' hallazgo(s) nuevo(s) en este lote.';

                if (res.new_findings > 0) {
                    loadFindings();
                }

                if (res.finished) {
                    state.polling = false;
                    el.progressText.textContent += ' — Escaneo heurístico completo.';
                    loadFindings();
                    loadHistory();
                    runNextAiBatch();
                    return;
                }

                setTimeout(runNextBatch, window.SCANNER.batchDelayMs || 300);
            });
    }

    function runNextAiBatch() {
        postForm('ai_batch', { run_id: state.runId }).then((res) => {
            if (!res.enabled) {
                el.aiProgressText.textContent = 'Capa de IA desactivada (configúrala en config.php si quieres usarla).';
                runNextVtBatch();
                return;
            }

            el.aiProgressText.textContent = 'IA: ' + res.remaining + ' archivo(s) pendientes de analizar...';

            if (res.remaining > 0) {
                loadFindings();
                setTimeout(runNextAiBatch, window.SCANNER.batchDelayMs || 300);
                return;
            }

            el.aiProgressText.textContent = 'IA: análisis completo.';
            loadFindings();
            runNextVtBatch();
        });
    }

    function runNextVtBatch() {
        postForm('vt_batch', { run_id: state.runId }).then((res) => {
            if (!res.enabled) {
                el.vtProgressText.textContent = 'VirusTotal desactivado (configúralo en config.php si quieres usarlo).';
                return;
            }

            el.vtProgressText.textContent = 'VirusTotal: ' + res.remaining + ' hallazgo(s) pendientes...';

            if (res.remaining > 0) {
                loadFindings();
                setTimeout(runNextVtBatch, window.SCANNER.batchDelayMs || 300);
                return;
            }

            el.vtProgressText.textContent = 'VirusTotal: verificación completa.';
            loadFindings();
        });
    }

    function severityLabel(sev) {
        const map = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja', info: 'Info' };
        return map[sev] || sev;
    }

    function showViewingBanner() {
        if (state.viewRunId && state.viewRunId !== state.runId) {
            el.viewingRunId.textContent = state.viewRunId;
            el.viewingBanner.classList.remove('hidden');
        } else {
            el.viewingBanner.classList.add('hidden');
        }
    }

    function loadFindings() {
        const severity = el.severityFilter.value;
        const params = new URLSearchParams({ run_id: state.viewRunId || '', severity: severity });

        fetch('index.php?action=findings_json&' + params.toString())
            .then((r) => r.json())
            .then((rows) => {
                el.findingsBody.innerHTML = '';
                rows.forEach((row) => {
                    const tr = document.createElement('tr');
                    tr.className = 'severity-' + row.severity;

                    const tdSev = document.createElement('td');
                    tdSev.textContent = severityLabel(row.severity);
                    tr.appendChild(tdSev);

                    const tdPath = document.createElement('td');
                    tdPath.textContent = row.path;
                    tdPath.className = 'mono';
                    tr.appendChild(tdPath);

                    const tdReason = document.createElement('td');
                    tdReason.textContent = row.reason;
                    tr.appendChild(tdReason);

                    const tdLocation = document.createElement('td');
                    const locationParts = [];
                    if (row.location) locationParts.push(row.location);
                    if (row.ai_location) locationParts.push(row.ai_location);
                    tdLocation.textContent = locationParts.length ? locationParts.join(' · ') : '—';
                    tr.appendChild(tdLocation);

                    const tdSource = document.createElement('td');
                    tdSource.textContent = row.source;
                    tr.appendChild(tdSource);

                    const tdAi = document.createElement('td');
                    if (row.ai_verdict) {
                        tdAi.textContent = row.ai_verdict + ' (' + Math.round((row.ai_confidence || 0) * 100) + '%)';
                        tdAi.title = row.ai_explanation || '';
                    } else {
                        tdAi.textContent = '—';
                    }
                    tr.appendChild(tdAi);

                    const tdVt = document.createElement('td');
                    if (row.vt_ratio) {
                        tdVt.textContent = row.vt_ratio;
                        tdVt.title = row.vt_detail || '';
                    } else {
                        tdVt.textContent = '—';
                    }
                    tr.appendChild(tdVt);

                    const tdActions = document.createElement('td');
                    const isCurrentRun = state.viewRunId === state.runId;

                    const viewBtn = document.createElement('button');
                    viewBtn.type = 'button';
                    viewBtn.textContent = 'Ver';
                    viewBtn.addEventListener('click', () => viewFile(row.path));
                    tdActions.appendChild(viewBtn);

                    const aiBtn = document.createElement('button');
                    aiBtn.type = 'button';
                    aiBtn.textContent = row.ai_verdict ? 'Reanalizar con IA' : 'Analizar con IA';
                    aiBtn.addEventListener('click', () => analyzeWithAi(row.id, aiBtn));
                    tdActions.appendChild(aiBtn);

                    const vtBtn = document.createElement('button');
                    vtBtn.type = 'button';
                    vtBtn.textContent = row.vt_ratio ? 'Reconsultar VirusTotal' : 'Consultar VirusTotal';
                    vtBtn.addEventListener('click', () => checkWithVt(row.id, vtBtn));
                    tdActions.appendChild(vtBtn);

                    if (row.status === 'open' && isCurrentRun) {
                        const whitelistBtn = document.createElement('button');
                        whitelistBtn.type = 'button';
                        whitelistBtn.textContent = 'Falso positivo';
                        whitelistBtn.addEventListener('click', () => whitelistFinding(row.id));
                        tdActions.appendChild(whitelistBtn);

                        const quarantineBtn = document.createElement('button');
                        quarantineBtn.type = 'button';
                        quarantineBtn.textContent = 'Cuarentena';
                        quarantineBtn.addEventListener('click', () => quarantineFinding(row.id));
                        tdActions.appendChild(quarantineBtn);
                    } else {
                        const statusSpan = document.createElement('span');
                        statusSpan.className = 'status-badge';
                        statusSpan.textContent = isCurrentRun ? row.status : 'histórico';
                        tdActions.appendChild(statusSpan);
                    }

                    tr.appendChild(tdActions);
                    el.findingsBody.appendChild(tr);
                });
            });
    }

    function loadUnreadable() {
        const runId = state.viewRunId || state.runId;
        if (!runId) return;

        fetch('index.php?action=unreadable_list&run_id=' + encodeURIComponent(runId))
            .then((r) => r.json())
            .then((rows) => {
                el.unreadableBody.innerHTML = '';
                rows.forEach((row) => {
                    const tr = document.createElement('tr');

                    const tdPath = document.createElement('td');
                    tdPath.textContent = row.path;
                    tdPath.className = 'mono';
                    tr.appendChild(tdPath);

                    const tdDate = document.createElement('td');
                    tdDate.textContent = row.created_at;
                    tr.appendChild(tdDate);

                    el.unreadableBody.appendChild(tr);
                });

                if (rows.length > 0) {
                    el.unreadableCount.textContent = String(rows.length);
                    el.unreadableCount.classList.remove('hidden');
                } else {
                    el.unreadableCount.classList.add('hidden');
                }
            });
    }

    function loadHistory() {
        fetch('index.php?action=scan_history')
            .then((r) => r.json())
            .then((rows) => {
                el.historyBody.innerHTML = '';
                rows.forEach((row) => {
                    const tr = document.createElement('tr');

                    const tdId = document.createElement('td');
                    tdId.textContent = '#' + row.id;
                    tr.appendChild(tdId);

                    const tdStatus = document.createElement('td');
                    const statusLabels = { discovering: 'Explorando...', running: 'Escaneando...', completed: 'Completo' };
                    tdStatus.textContent = statusLabels[row.status] || row.status;
                    tr.appendChild(tdStatus);

                    const tdStarted = document.createElement('td');
                    tdStarted.textContent = row.started_at;
                    tr.appendChild(tdStarted);

                    const tdFiles = document.createElement('td');
                    tdFiles.textContent = row.processed_files + ' / ' + row.total_files;
                    tr.appendChild(tdFiles);

                    const tdFindings = document.createElement('td');
                    tdFindings.textContent = row.findings_count;
                    tr.appendChild(tdFindings);

                    const tdActions = document.createElement('td');
                    const viewBtn = document.createElement('button');
                    viewBtn.type = 'button';
                    viewBtn.textContent = 'Ver hallazgos';
                    viewBtn.addEventListener('click', () => {
                        state.viewRunId = row.id;
                        showViewingBanner();
                        loadFindings();
                        loadUnreadable();
                        window.scrollTo({ top: document.querySelector('#findings-table').offsetTop - 20, behavior: 'smooth' });
                    });
                    tdActions.appendChild(viewBtn);
                    tr.appendChild(tdActions);

                    el.historyBody.appendChild(tr);
                });
            });
    }

    function viewFile(path) {
        fetch('index.php?action=view_file&path=' + encodeURIComponent(path))
            .then((r) => r.json())
            .then((res) => {
                if (res.error) {
                    alert(res.error);
                    return;
                }
                el.viewerContent.textContent = res.content + (res.truncated ? '\n\n[... contenido truncado ...]' : '');
                el.viewer.classList.remove('hidden');
            });
    }

    function whitelistFinding(id) {
        if (!confirm('¿Marcar este hallazgo como falso positivo? Se omitirá en futuros escaneos.')) return;
        postForm('whitelist', { finding_id: id }).then((res) => {
            if (res.error) {
                alert(res.error);
                return;
            }
            loadFindings();
        });
    }

    function analyzeWithAi(findingId, btn) {
        btn.disabled = true;
        const original = btn.textContent;
        btn.textContent = 'Analizando...';

        postForm('ai_analyze_one', { finding_id: findingId })
            .catch(() => CONNECTION_ERROR)
            .then((res) => {
                if (res.error) {
                    alert(res.error);
                    btn.disabled = false;
                    btn.textContent = original;
                    return;
                }
                loadFindings();
            });
    }

    function checkWithVt(findingId, btn) {
        btn.disabled = true;
        const original = btn.textContent;
        btn.textContent = 'Consultando...';

        postForm('vt_check_one', { finding_id: findingId })
            .catch(() => CONNECTION_ERROR)
            .then((res) => {
                if (res.error) {
                    alert(res.error);
                    btn.disabled = false;
                    btn.textContent = original;
                    return;
                }
                loadFindings();
            });
    }

    function quarantineFinding(id) {
        if (!confirm('¿Mover este archivo a cuarentena? Se sacará del sitio (podrás restaurarlo luego).')) return;
        postForm('quarantine', { finding_id: id }).then((res) => {
            if (!res.ok) {
                alert(res.error || 'No se pudo poner en cuarentena.');
                return;
            }
            loadFindings();
            loadQuarantine();
        });
    }

    function restoreEntry(manifestId) {
        if (!confirm('¿Restaurar este archivo a su ubicación original?')) return;
        postForm('restore', { manifest_id: manifestId }).then((res) => {
            if (!res.ok) {
                alert(res.error || 'No se pudo restaurar.');
                return;
            }
            loadFindings();
            loadQuarantine();
        });
    }

    function loadQuarantine() {
        fetch('index.php?action=quarantine_list')
            .then((r) => r.json())
            .then((rows) => {
                el.quarantineBody.innerHTML = '';
                rows.forEach((row) => {
                    const tr = document.createElement('tr');

                    const tdPath = document.createElement('td');
                    tdPath.textContent = row.original_path;
                    tdPath.className = 'mono';
                    tr.appendChild(tdPath);

                    const tdSev = document.createElement('td');
                    tdSev.textContent = row.severity || '—';
                    tr.appendChild(tdSev);

                    const tdDate = document.createElement('td');
                    tdDate.textContent = row.created_at;
                    tr.appendChild(tdDate);

                    const tdActions = document.createElement('td');
                    const restoreBtn = document.createElement('button');
                    restoreBtn.type = 'button';
                    restoreBtn.textContent = 'Restaurar';
                    restoreBtn.addEventListener('click', () => restoreEntry(row.id));
                    tdActions.appendChild(restoreBtn);
                    tr.appendChild(tdActions);

                    el.quarantineBody.appendChild(tr);
                });
            });
    }

    el.startBtn.addEventListener('click', startScan);
    el.severityFilter.addEventListener('change', loadFindings);
    el.closeViewer.addEventListener('click', () => el.viewer.classList.add('hidden'));
    el.backToCurrent.addEventListener('click', (ev) => {
        ev.preventDefault();
        state.viewRunId = state.runId;
        showViewingBanner();
        loadFindings();
        loadUnreadable();
    });

    if (state.runId) {
        el.controls.classList.add('hidden');
        el.progressWrap.classList.remove('hidden');

        if (window.SCANNER.cronEnabled) {
            // El Cron Job de tu hosting se encarga de ir retomando el escaneo en tandas (ver
            // README, "Modo cron"). No disparamos el mismo lote también desde el navegador: eso
            // haría que ambos procesaran los mismos archivos a la vez.
            el.discoverPhase.classList.remove('hidden');
            el.processPhase.classList.add('hidden');
            el.discoverText.textContent = 'Este escaneo se está procesando en segundo plano vía cron. Actualizá la página para ver el progreso.';
        } else if (window.SCANNER.activeRunStatus === 'discovering') {
            el.discoverPhase.classList.remove('hidden');
            el.processPhase.classList.add('hidden');
            runNextDiscoverBatch();
        } else {
            el.discoverPhase.classList.add('hidden');
            el.processPhase.classList.remove('hidden');
            runNextBatch();
        }
    }

    showViewingBanner();
    loadFindings();
    loadUnreadable();
    loadQuarantine();
    loadHistory();
})();
