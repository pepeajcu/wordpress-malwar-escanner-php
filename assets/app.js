(function () {
    'use strict';

    const state = {
        runId: window.SCANNER.activeRunId || null,
        polling: false,
    };

    const el = {
        startBtn: document.getElementById('start-scan-btn'),
        controls: document.getElementById('scan-controls'),
        progressWrap: document.getElementById('scan-progress'),
        progressBar: document.getElementById('progress-bar'),
        progressText: document.getElementById('progress-text'),
        aiProgressText: document.getElementById('ai-progress-text'),
        vtProgressText: document.getElementById('vt-progress-text'),
        severityFilter: document.getElementById('severity-filter'),
        findingsBody: document.querySelector('#findings-table tbody'),
        quarantineBody: document.querySelector('#quarantine-table tbody'),
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

    function startScan() {
        el.startBtn.disabled = true;
        postForm('start_scan', {}).then((res) => {
            if (res.error) {
                alert('Error al iniciar el escaneo: ' + res.error);
                el.startBtn.disabled = false;
                return;
            }
            state.runId = res.run_id;
            el.controls.classList.add('hidden');
            el.progressWrap.classList.remove('hidden');
            runNextBatch();
        });
    }

    function runNextBatch() {
        if (!state.runId) return;
        state.polling = true;

        postForm('scan_batch', { run_id: state.runId }).then((res) => {
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

    function loadFindings() {
        const severity = el.severityFilter.value;
        const params = new URLSearchParams({ run_id: state.runId || '', severity: severity });

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

                    const viewBtn = document.createElement('button');
                    viewBtn.type = 'button';
                    viewBtn.textContent = 'Ver';
                    viewBtn.addEventListener('click', () => viewFile(row.path));
                    tdActions.appendChild(viewBtn);

                    if (row.status === 'open') {
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
                        statusSpan.textContent = row.status;
                        tdActions.appendChild(statusSpan);
                    }

                    tr.appendChild(tdActions);
                    el.findingsBody.appendChild(tr);
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

    if (state.runId) {
        el.controls.classList.add('hidden');
        el.progressWrap.classList.remove('hidden');
        runNextBatch();
    }
    loadFindings();
    loadQuarantine();
})();
