const form = document.querySelector('#scan-form');
const tabs = [...document.querySelectorAll('.source-tab')];
const fileInput = document.querySelector('#zip-file');
const dropzone = document.querySelector('#dropzone');
const fileLabel = document.querySelector('#file-label');
const scanButton = document.querySelector('#scan-button');
const aiStatusHint = document.querySelector('#ai-status-hint');
const resultsSection = document.querySelector('#results');
const toast = document.querySelector('#toast');
const promptPanel = document.querySelector('#prompt-panel');
const claudePrompt = document.querySelector('#claude-prompt');
const apiBaseUrl = resolveApiBaseUrl();
let selectedSource = 'zip';
let currentReport = null;
let toastTimer;
const severityLabels = {
    critical: 'Crítica',
    high: 'Alta',
    medium: 'Média',
    low: 'Baixa',
    info: 'Informativa'
};

for (const tab of tabs) {
    tab.addEventListener('click', () => selectSource(tab.id === 'tab-zip' ? 'zip' : 'github'));
}

function selectSource(source) {
    selectedSource = source;
    for (const tab of tabs) {
        const active = tab.id === `tab-${source}`;
        tab.classList.toggle('active', active);
        tab.setAttribute('aria-selected', String(active));
    }
    document.querySelector('#panel-zip').hidden = source !== 'zip';
    document.querySelector('#panel-github').hidden = source !== 'github';
}

fileInput.addEventListener('change', () => {
    const file = fileInput.files[0];
    fileLabel.textContent = file ? `${file.name} · ${formatBytes(file.size)}` : 'Solte o ZIP aqui ou selecione um arquivo';
});

for (const eventName of ['dragenter', 'dragover']) {
    dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.add('dragover');
    });
}
for (const eventName of ['dragleave', 'drop']) {
    dropzone.addEventListener(eventName, (event) => {
        event.preventDefault();
        dropzone.classList.remove('dragover');
    });
}
dropzone.addEventListener('drop', (event) => {
    const file = event.dataTransfer.files[0];
    if (!file) return;
    const transfer = new DataTransfer();
    transfer.items.add(file);
    fileInput.files = transfer.files;
    fileInput.dispatchEvent(new Event('change'));
});

form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!serviceStatus.aiConfigured) return showToast('A análise por IA é obrigatória. Configure OPENAI_API_KEY no servidor e tente novamente.');
    const options = { method: 'POST', headers: {} };
    let endpoint;
    if (selectedSource === 'zip') {
        const file = fileInput.files[0];
        if (!file) return showToast('Selecione um arquivo ZIP para continuar.');
        if (!file.name.toLowerCase().endsWith('.zip')) return showToast('O arquivo selecionado precisa ter extensão .zip.');
        if (file.size > 20 * 1024 * 1024) return showToast('O ZIP não pode exceder 20 MB.');
        const data = new FormData();
        data.append('file', file);
        options.body = data;
        endpoint = '/api/scan/zip';
    } else {
        const url = document.querySelector('#github-url').value.trim();
        if (!url) return showToast('Informe a URL do repositório público.');
        options.headers['Content-Type'] = 'application/json';
        options.body = JSON.stringify({ url });
        endpoint = '/api/scan/github';
    }

    setBusy(true, 'Analisando código...');
    document.querySelector('#email-status').textContent = '';
    try {
        const body = await fetchJson(endpoint, options);
        currentReport = body;
        renderReport(body);
        resultsSection.hidden = false;
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
        showToast(error.message || 'Falha de conexão com o serviço.');
    } finally {
        setBusy(false);
    }
});

function setBusy(busy, label = 'Iniciar análise') {
    scanButton.disabled = busy || !serviceStatus.aiConfigured;
    scanButton.querySelector('span').textContent = label;
}

function renderReport(report) {
    const verdict = document.querySelector('#verdict');
    const mark = document.querySelector('#verdict-mark');
    const hasHigh = report.counts.critical || report.counts.high;
    const requiresReview = report.recommendation === 'REVISÃO MANUAL';
    verdict.className = `verdict${hasHigh ? ' danger' : requiresReview ? ' review' : ''}`;
    mark.textContent = hasHigh ? '!' : requiresReview ? '!' : '✓';
    document.querySelector('#verdict-title').textContent = report.recommendation;
    document.querySelector('#verdict-description').textContent = report.recommendationDetail;
    document.querySelector('#finding-total').textContent = String(report.findings.length);
    document.querySelector('#scan-meta').textContent = `${report.project} · ${new Date(report.scannedAt).toLocaleString('pt-BR')}`;
    document.querySelector('#findings-summary').textContent = `${report.filesAnalyzed} arquivos analisados`;

    const metricLabels = [
        ['critical', 'Crítica'], ['high', 'Alta'], ['medium', 'Média'], ['low', 'Baixa'], ['info', 'Informativa']
    ];
    const metrics = document.querySelector('#metrics');
    metrics.replaceChildren(...metricLabels.map(([severity, label]) => {
        const item = document.createElement('div');
        item.className = 'metric';
        const count = document.createElement('strong');
        count.textContent = String(report.counts[severity]);
        const caption = document.createElement('span');
        caption.textContent = label;
        item.append(count, caption);
        return item;
    }));

    const scanNotes = document.querySelector('#scan-notes');
    const completedChecks = [
        `Análise estática: concluída`,
        `Auditoria OSV: ${report.checks.dependencyAudit ? 'concluída' : 'não executada'}`,
        `Hospedagem: ${report.checks.hostingReview ? 'verificada nos arquivos enviados' : 'não verificada'}`,
        `Banco de dados: ${report.checks.databaseReview ? 'verificado nos arquivos enviados' : 'não verificado'}`,
        `Análise por IA: ${report.checks.aiAnalysis ? 'concluída' : 'não executada'}`
    ];
    const legalNotes = Array.isArray(report.legalContext) ? report.legalContext : [];
    const architecture = report.architecture;
    const architectureNotes = architecture ? [
        `Hospedagem identificada: ${architecture.hosting.assessment}${architecture.hosting.configFiles.length ? ` Arquivos: ${architecture.hosting.configFiles.join(', ')}.` : ''}`,
        ...architecture.hosting.securityObservations,
        `Banco de dados identificado: ${architecture.database.assessment}${architecture.database.configFiles.length ? ` Arquivos: ${architecture.database.configFiles.join(', ')}.` : ''}`,
        ...architecture.database.connectionSettings.map((setting) => `Configuração de conexão (somente nome da variável): ${setting}.`),
        ...architecture.database.securityObservations
    ] : [];
    scanNotes.replaceChildren(...[...completedChecks, ...architectureNotes, ...legalNotes, ...(report.warnings || [])].map((message) => {
        const note = document.createElement('p');
        note.textContent = message;
        return note;
    }));

    const list = document.querySelector('#findings-list');
    const groupDefinitions = [
        { severity: 'critical', label: 'Críticas', guidance: 'Trate imediatamente e avalie o impacto antes de prosseguir.', open: true },
        { severity: 'high', label: 'Altas', guidance: 'Priorize a correção antes da homologação.', open: true },
        { severity: 'medium', label: 'Médias', guidance: 'Revise o contexto e defina uma ação corretiva.' },
        { severity: 'low', label: 'Baixas', guidance: 'Avalie a aplicabilidade e registre a decisão.' },
        { severity: 'info', label: 'Informativas', guidance: 'Considere como contexto para a revisão técnica.' }
    ];
    list.replaceChildren(...groupDefinitions.flatMap((group) => {
        const findings = report.findings.filter((finding) => finding.severity === group.severity);
        return findings.length ? [createFindingGroup(group, findings)] : [];
    }));
    document.querySelector('#empty-findings').hidden = report.findings.length !== 0;
    document.querySelector('#email-button').disabled = !serviceStatus.emailConfigured;
    document.querySelector('#email-button').title = serviceStatus.emailConfigured ? '' : 'Configure SMTP e SECURITY_EMAIL no servidor.';
}

function createFindingGroup(group, findings) {
    const section = document.createElement('details');
    section.className = `finding-group ${group.severity}`;
    section.open = Boolean(group.open);

    const heading = document.createElement('summary');
    heading.className = 'finding-group-heading';
    const title = document.createElement('h4');
    title.id = `finding-group-${group.severity}`;
    title.textContent = group.label;
    const count = document.createElement('span');
    count.className = 'finding-group-count';
    count.textContent = `${findings.length} ${findings.length === 1 ? 'achado' : 'achados'}`;
    const guidance = document.createElement('p');
    guidance.className = 'finding-group-guidance';
    guidance.textContent = group.guidance;
    heading.append(title, count, guidance);

    const items = document.createElement('div');
    items.className = 'finding-group-items';
    items.append(...findings.map(createFinding));
    section.append(heading, items);
    return section;
}

function createFinding(finding) {
    const article = document.createElement('article');
    article.className = 'finding';
    const summary = document.createElement('div');
    summary.className = 'finding-summary';
    const severity = document.createElement('span');
    severity.className = `severity ${finding.severity}`;
    severity.textContent = severityLabels[finding.severity] || finding.severity;
    const title = document.createElement('span');
    title.className = 'finding-title';
    title.textContent = finding.title;
    const location = document.createElement('span');
    location.className = 'finding-location';
    location.textContent = `${finding.file}${finding.line ? `:${finding.line}` : ''}`;
    summary.append(severity, title, location);

    const detail = document.createElement('p');
    detail.className = 'finding-detail';
    detail.textContent = finding.description;
    article.append(summary, detail);
    if (finding.evidence) {
        const evidence = document.createElement('div');
        evidence.className = 'finding-evidence';
        const evidenceLabel = document.createElement('span');
        evidenceLabel.textContent = 'Trecho identificado';
        const evidenceText = document.createElement('code');
        evidenceText.textContent = finding.evidence;
        evidence.append(evidenceLabel, evidenceText);
        article.append(evidence);
    }
    if (finding.source) {
        const sourceLabels = { static: 'Regra automática', openai: 'Análise contextual por IA', osv: 'Base de vulnerabilidades OSV' };
        const source = document.createElement('p');
        source.className = 'finding-source';
        source.textContent = `Origem do achado: ${sourceLabels[finding.source] || finding.source}`;
        article.append(source);
    }
    return article;
}

document.querySelector('#docx-button').addEventListener('click', async () => {
    if (!currentReport) return;
    try {
        const response = await fetch(`${apiBaseUrl}/api/report-docx?scanId=${encodeURIComponent(currentReport.scanId)}`);
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            throw new Error(errorData.error || 'Não foi possível gerar o documento Word.');
        }
        const blob = await response.blob();
        const downloadUrl = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = downloadUrl;
        link.download = `relatorio-${safeFileName(currentReport.project)}.docx`;
        link.click();
        URL.revokeObjectURL(downloadUrl);
        showToast('Relatório em DOCX baixado com o resumo em linguagem simples.');
    } catch (error) {
        showToast(error.message || 'Falha ao gerar o DOCX.');
    }
});

document.querySelector('#prompt-button').addEventListener('click', async () => {
    if (!currentReport) return;
    try {
        const data = await fetchJson('/api/report-prompt', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scanId: currentReport.scanId })
        }, 30000);
        claudePrompt.value = data.prompt;
        promptPanel.hidden = false;
        showToast('Prompt de correção gerado para revisão.');
    } catch (error) {
        showToast(error.message || 'Não foi possível gerar o prompt.');
    }
});

document.querySelector('#copy-prompt-button').addEventListener('click', async () => {
    if (!claudePrompt.value) return;
    try {
        await navigator.clipboard.writeText(claudePrompt.value);
        showToast('Prompt copiado para a área de transferência.');
    } catch {
        claudePrompt.focus();
        claudePrompt.select();
        showToast('Selecione o texto e copie manualmente.');
    }
});

document.querySelector('#email-button').addEventListener('click', async (event) => {
    if (!currentReport) return;
    const button = event.currentTarget;
    button.disabled = true;
    document.querySelector('#email-status').textContent = 'Enviando...';
    try {
        await fetchJson('/api/report-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ scanId: currentReport.scanId })
        }, 30000);
        document.querySelector('#email-status').textContent = 'Relatório enviado ao responsável configurado.';
    } catch (error) {
        document.querySelector('#email-status').textContent = error.message;
    } finally {
        button.disabled = !serviceStatus.emailConfigured;
    }
});

function safeFileName(value) {
    return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 70) || 'analise';
}

function formatBytes(bytes) {
    return bytes < 1024 * 1024 ? `${Math.ceil(bytes / 1024)} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function showToast(message) {
    toast.textContent = message;
    toast.classList.add('visible');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => toast.classList.remove('visible'), 4200);
}

async function fetchJson(url, options = {}, timeoutMs = 75000) {
    let response;
    try {
        response = await fetch(`${apiBaseUrl}${url}`, {
            ...options,
            signal: options.signal || AbortSignal.timeout(timeoutMs)
        });
    } catch (error) {
        if (error.name === 'TimeoutError' || error.name === 'AbortError') {
            const message = url.startsWith('/api/scan/')
                ? 'A análise excedeu o tempo limite de 75 segundos. Tente um projeto menor ou tente novamente.'
                : 'O serviço demorou para responder. Verifique se o backend está ativo e tente novamente.';
            throw new Error(message);
        }
        throw new Error('Não foi possível conectar ao serviço. Inicie o backend com npm start e abra http://localhost:3000.');
    }

    const contentType = response.headers.get('content-type') || '';
    const responseText = await response.text();
    if (!responseText) {
        throw new Error('O serviço respondeu sem dados. Verifique se o backend está ativo em http://localhost:3000.');
    }

    let data;
    try {
        data = JSON.parse(responseText);
    } catch {
        const message = contentType.includes('application/json')
            ? 'O serviço retornou JSON inválido. Confira o terminal do backend.'
            : 'A resposta não veio da API Sentinela. Abra http://localhost:3000 em vez de usar Live Server ou abrir o HTML diretamente.';
        throw new Error(message);
    }

    if (!response.ok) {
        throw new Error(data.error || `O serviço respondeu com erro HTTP ${response.status}.`);
    }

    return data;
}

function resolveApiBaseUrl() {
    const configuredBase = document.querySelector('meta[name="sentinela-api-base"]')?.content.trim();
    if (configuredBase) return configuredBase.replace(/\/+$/, '');

    const localHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
    const { hostname, port, protocol } = window.location;
    if (localHosts.has(hostname) && port !== '3000') return `${protocol}//${hostname}:3000`;
    return '';
}

let serviceStatus = { emailConfigured: false };
async function loadServiceStatus() {
    const dot = document.querySelector('#service-dot');
    const label = document.querySelector('#service-label');
    const footer = document.querySelector('#footer-capabilities');
    try {
        serviceStatus = await fetchJson('/api/health', {}, 8000);
        aiStatusHint.textContent = serviceStatus.aiConfigured
            ? 'Disponível. O projeto será enviado à API OpenAI configurada; credenciais reconhecidas são mascaradas antes do envio.'
            : 'Indisponível. Configure OPENAI_API_KEY no servidor para liberar a análise.';
        scanButton.disabled = !serviceStatus.aiConfigured;
        dot?.classList.add('online');
        if (label) label.textContent = serviceStatus.aiConfigured ? 'Serviço ativo · IA obrigatória disponível' : 'Serviço ativo · IA obrigatória indisponível';
        if (footer) footer.textContent = `Análise contextual por IA obrigatória ${serviceStatus.emailConfigured ? '· e-mail configurado' : '· e-mail indisponível'}`;
    } catch {
        serviceStatus.aiConfigured = false;
        scanButton.disabled = true;
        aiStatusHint.textContent = 'Indisponível: não foi possível verificar a configuração do serviço.';
        dot?.classList.add('offline');
        if (label) label.textContent = 'Serviço indisponível';
        if (footer) footer.textContent = 'Inicie o servidor para analisar projetos';
    }
}

loadServiceStatus();