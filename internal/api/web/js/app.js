document.addEventListener('DOMContentLoaded', () => {
    // 1. Tab Switching Logic
    const navItems = document.querySelectorAll('.nav-item');
    const tabContents = document.querySelectorAll('.tab-content');
    const pageTitle = document.getElementById('page-title');

    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const targetTab = item.getAttribute('data-tab');
            
            navItems.forEach(i => i.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            item.classList.add('active');
            document.getElementById(`tab-${targetTab}`).classList.add('active');
            pageTitle.textContent = item.innerText.trim();

            // Refresh tab data
            if (targetTab === 'events') fetchEvents();
            if (targetTab === 'threats') fetchThreats();
            if (targetTab === 'processes') fetchProcesses();
            if (targetTab === 'quarantine') fetchQuarantine();
            if (targetTab === 'system') fetchSystemInfo();
        });
    });

    // 2. Initial Data Load
    fetchOverview();
    fetchSystemInfo();
    setupWebSocket();

    // 3. Buttons Handlers
    document.getElementById('btn-refresh-events')?.addEventListener('click', fetchEvents);
    document.getElementById('btn-refresh-processes')?.addEventListener('click', fetchProcesses);
    
    document.getElementById('btn-baseline-create')?.addEventListener('click', async () => {
        if (!confirm('Are you sure you want to create/update the security baseline?')) return;
        try {
            const res = await fetch('/api/baseline/create', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                showToast(`Baseline updated for ${data.data.count} files`, 'success');
            } else {
                showToast('Failed creating baseline', 'danger');
            }
        } catch (e) {
            showToast('Error connecting to API', 'danger');
        }
    });

    document.getElementById('btn-baseline-check')?.addEventListener('click', async () => {
        try {
            const res = await fetch('/api/baseline/check', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                const diff = data.data;
                showToast(`Check complete: ${diff.new_files.length} New, ${diff.modified_files.length} Modified, ${diff.deleted_files.length} Deleted`, 'info');
                fetchEvents();
            }
        } catch (e) {
            showToast('Error checking baseline', 'danger');
        }
    });
});

// REST APIs
async function fetchOverview() {
    try {
        const [evtRes, threatRes, qRes] = await Promise.all([
            fetch('/api/events?limit=10'),
            fetch('/api/threats?limit=5'),
            fetch('/api/quarantine')
        ]);

        const evts = await evtRes.json();
        const threats = await threatRes.json();
        const quarantine = await qRes.json();

        if (evts.success) {
            document.getElementById('stat-event-total').textContent = evts.data.length;
            renderRecentEvents(evts.data);
            document.getElementById('event-count-badge').textContent = evts.data.length;
        }

        if (threats.success) {
            const criticals = threats.data.filter(t => t.severity === 'CRITICAL' || t.severity === 'HIGH').length;
            document.getElementById('stat-critical-count').textContent = criticals;
            document.getElementById('threat-count-badge').textContent = threats.data.length;
            
            const riskLevel = criticals > 0 ? 'HIGH' : (threats.data.length > 0 ? 'MEDIUM' : 'LOW');
            const riskEl = document.getElementById('stat-risk-level');
            riskEl.textContent = riskLevel;
            riskEl.className = 'stat-value ' + (riskLevel === 'HIGH' ? 'danger' : (riskLevel === 'MEDIUM' ? 'warning' : ''));
        }

        if (quarantine.success) {
            const activeQ = quarantine.data.filter(q => q.status === 'QUARANTINED').length;
            document.getElementById('stat-quarantine-total').textContent = activeQ;
        }
    } catch (e) {
        console.error('Error fetching overview', e);
    }
}

async function fetchEvents() {
    try {
        const res = await fetch('/api/events?limit=50');
        const data = await res.json();
        if (!data.success) return;

        const tbody = document.querySelector('#table-events tbody');
        tbody.innerHTML = '';
        data.data.forEach(e => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="mono">${new Date(e.timestamp).toLocaleTimeString()}</td>
                <td><span class="sev-tag sev-${e.severity}">${e.severity}</span></td>
                <td><strong>${e.type}</strong></td>
                <td><code>${e.path || e.process || '-'}</code></td>
                <td><strong>${e.score}</strong></td>
                <td>${e.description}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Error fetching events', e);
    }
}

async function fetchThreats() {
    try {
        const res = await fetch('/api/threats?limit=50');
        const data = await res.json();
        if (!data.success) return;

        const tbody = document.querySelector('#table-threats tbody');
        tbody.innerHTML = '';
        data.data.forEach(t => {
            const tr = document.createElement('tr');
            const reasons = (t.reasons || []).map(r => `<div>• ${r}</div>`).join('');
            tr.innerHTML = `
                <td><span class="sev-tag sev-${t.severity}">${t.severity}</span></td>
                <td><strong class="text-danger">${t.score}</strong></td>
                <td><code>${t.path || t.process || '-'}</code></td>
                <td>${t.user || 'root'}</td>
                <td style="font-size:0.8rem; color:var(--text-muted);">${reasons || t.description}</td>
                <td>
                    ${t.path ? `<button class="btn btn-sm btn-danger" onclick="quarantineFile('${t.path.replace(/'/g, "\\'")}', '${t.score}')">Quarantine</button>` : '-'}
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Error fetching threats', e);
    }
}

async function fetchProcesses() {
    try {
        const res = await fetch('/api/processes');
        const data = await res.json();
        if (!data.success) return;

        const tbody = document.querySelector('#table-processes tbody');
        tbody.innerHTML = '';
        data.data.forEach(p => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="mono">${p.pid}</td>
                <td class="mono">${p.ppid}</td>
                <td><strong>${p.name}</strong></td>
                <td>${p.user}</td>
                <td><code>${p.exe_path || '-'}</code></td>
                <td style="font-size:0.75rem; color:var(--text-muted);">${p.cmdline || '-'}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Error fetching processes', e);
    }
}

async function fetchQuarantine() {
    try {
        const res = await fetch('/api/quarantine');
        const data = await res.json();
        if (!data.success) return;

        const tbody = document.querySelector('#table-quarantine tbody');
        tbody.innerHTML = '';
        data.data.forEach(q => {
            const tr = document.createElement('tr');
            const dateStr = new Date(q.created_at).toLocaleString();
            tr.innerHTML = `
                <td class="mono">${q.id}</td>
                <td><code>${q.original_path}</code></td>
                <td class="mono" style="font-size:0.7rem;">${q.sha256.substring(0, 16)}...</td>
                <td><strong>${q.score}</strong></td>
                <td>${dateStr}</td>
                <td><span class="sev-tag sev-${q.status === 'QUARANTINED' ? 'HIGH' : 'LOW'}">${q.status}</span></td>
                <td>
                    ${q.status === 'QUARANTINED' ? `
                        <button class="btn btn-sm btn-primary" onclick="restoreQuarantine('${q.id}')">Restore</button>
                        <button class="btn btn-sm btn-danger" onclick="deleteQuarantine('${q.id}')">Delete</button>
                    ` : '-'}
                </td>
            `;
            tbody.appendChild(tr);
        });
    } catch (e) {
        console.error('Error fetching quarantine', e);
    }
}

async function fetchSystemInfo() {
    try {
        const res = await fetch('/api/system');
        const data = await res.json();
        if (!data.success) return;

        const sys = data.data;
        document.getElementById('sys-hostname').textContent = sys.hostname;
        document.getElementById('sys-os').textContent = `${sys.os} (${sys.arch})`;
        document.getElementById('sys-cpus').textContent = `${sys.cpus} Cores`;
        document.getElementById('sys-mem').textContent = `${(sys.memory_used / (1024*1024)).toFixed(0)} MB / ${(sys.memory_total / (1024*1024)).toFixed(0)} MB`;
        document.getElementById('sys-uptime').textContent = `${(sys.uptime_sec / 3600).toFixed(1)} hrs`;

        const diag = document.getElementById('system-diagnostics');
        if (diag) {
            diag.innerHTML = `
                <div class="info-item"><span>Hostname</span><strong>${sys.hostname}</strong></div>
                <div class="info-item"><span>Architecture</span><strong>${sys.arch}</strong></div>
                <div class="info-item"><span>Go Runtime</span><strong>${sys.go_version}</strong></div>
                <div class="info-item"><span>System Uptime</span><strong>${sys.uptime_sec}s</strong></div>
            `;
        }
    } catch (e) {
        console.error('Error fetching system info', e);
    }
}

// Global actions
async function quarantineFile(path, score) {
    if (!confirm(`Are you sure you want to quarantine file:\n${path}?`)) return;
    try {
        const res = await fetch('/api/quarantine', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: path, reason: 'Manual quarantine from dashboard', score: parseInt(score) || 80 })
        });
        const data = await res.json();
        if (data.success) {
            showToast(`File quarantined successfully (${data.data.id})`, 'success');
            fetchOverview();
            fetchQuarantine();
        } else {
            showToast(`Quarantine failed: ${data.error.message}`, 'danger');
        }
    } catch (e) {
        showToast('Error calling quarantine API', 'danger');
    }
}

async function restoreQuarantine(id) {
    if (!confirm(`Deliberate action required: Restore quarantined item ${id}?`)) return;
    try {
        const res = await fetch(`/api/quarantine/${id}/restore`, { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            showToast(`Item ${id} restored cleanly`, 'success');
            fetchQuarantine();
        } else {
            showToast(`Restore failed: ${data.error.message}`, 'danger');
        }
    } catch (e) {
        showToast('Error restoring item', 'danger');
    }
}

async function deleteQuarantine(id) {
    if (!confirm(`PERMANENT DELETE: Are you sure you want to permanently delete quarantined item ${id}?`)) return;
    try {
        const res = await fetch(`/api/quarantine/${id}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            showToast(`Item ${id} permanently deleted`, 'info');
            fetchQuarantine();
        } else {
            showToast('Delete failed', 'danger');
        }
    } catch (e) {
        showToast('Error deleting item', 'danger');
    }
}

function renderRecentEvents(events) {
    const tbody = document.querySelector('#table-recent-events tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    events.slice(0, 5).forEach(e => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td class="mono">${new Date(e.timestamp).toLocaleTimeString()}</td>
            <td><span class="sev-tag sev-${e.severity}">${e.severity}</span></td>
            <td><strong>${e.type}</strong></td>
            <td><code>${e.path || e.process || '-'}</code></td>
        `;
        tbody.appendChild(tr);
    });
}

// WebSocket Connection
function setupWebSocket() {
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/ws/events`;
    const wsStatusEl = document.getElementById('ws-status');

    let socket = new WebSocket(wsUrl);

    socket.onopen = () => {
        wsStatusEl.classList.add('connected');
    };

    socket.onmessage = (msg) => {
        try {
            const event = JSON.parse(msg.data);
            showToast(`Event: [${event.severity}] ${event.type} on ${event.path || event.process || 'system'}`, event.score >= 50 ? 'danger' : 'info');
            fetchOverview();
        } catch (e) {}
    };

    socket.onclose = () => {
        wsStatusEl.classList.remove('connected');
        setTimeout(setupWebSocket, 3000);
    };
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.remove();
    }, 4000);
}
