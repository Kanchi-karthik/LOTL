document.addEventListener('DOMContentLoaded', () => {
    
    // --- Global State ---
    let latestData = {};
    let attackerMap;
    let attackerLayer;
    let markers = {};
    let activeView = 'view-overview';
    let threatHistory = []; // [ {time, score} ]
    let lastContainers = []; // Cache for topology
    let isFirstLoad = true;

    // --- DOM Elements ---
    const elements = {
        navItems: document.querySelectorAll('.nav-item'),
        views: document.querySelectorAll('.view-section'),
        pageTitle: document.getElementById('page-title'),
        
        // KPIs
        kpiPods: document.getElementById('kpi-pods'),
        kpiAttackers: document.getElementById('kpi-attackers'),
        kpiAnomalies: document.getElementById('kpi-anomalies'),
        kpiQuarantined: document.getElementById('kpi-quarantined'),
        
        // Dashboard Sections
        alertFeed: document.getElementById('alert-feed'),
        mitreMatrix: document.getElementById('mitre-matrix'),
        podHeatmap: document.getElementById('pod-heatmap'),
        eventsTableBody: document.getElementById('events-table-body'),
        
        // Quarantine Manager
        quarantinePodsBody: document.getElementById('quarantine-pods-body'),
        blockedIpsBody: document.getElementById('blocked-ips-body'),
        
        // Search
        omniSearch: document.getElementById('omni-search'),
        searchTableBody: document.getElementById('search-table-body'),

        // New Elements
        btnRefresh: document.getElementById('btn-refresh'),
        btnReset: document.getElementById('btn-reset'),
        btnClearLogs: document.getElementById('btn-clear-logs'),
        btnAttack: document.getElementById('btn-attack'),
        historyTableBody: document.getElementById('history-table-body'),
        topologyCanvas: document.getElementById('topology'),
        topologyInfo: document.getElementById('topology-info')
    };

    // --- Tooltip System for Canvas Charts ---
    let tooltipElement = null;
    let tooltipTimeout = null;

    function showCanvasTooltip(event, data, source = "chart") {
        // Clear any existing tooltip
        hideCanvasTooltip();
        
        // Create tooltip DOM element
        if (!tooltipElement) {
            tooltipElement = document.createElement('div');
            tooltipElement.className = 'canvas-tooltip';
            document.body.appendChild(tooltipElement);
        }
        
        // Build tooltip HTML
        let html = '';
        if (data.title) html += `<div class="tooltip-title">${data.title}</div>`;
        if (data.value !== undefined) {
            html += `<div class="tooltip-value">${data.value}</div>`;
        }
        if (data.unit) html += `<div class="tooltip-unit">${data.unit}</div>`;
        if (data.desc) html += `<div class="tooltip-desc">${data.desc}</div>`;
        
        tooltipElement.innerHTML = html;
        
        // Position tooltip near mouse
        const x = event.clientX + 15;
        const y = event.clientY + 15;
        tooltipElement.style.left = x + 'px';
        tooltipElement.style.top = y + 'px';
        tooltipElement.style.display = 'block';
    }

    function hideCanvasTooltip() {
        if (tooltipElement) {
            tooltipElement.style.display = 'none';
        }
        if (tooltipTimeout) {
            clearTimeout(tooltipTimeout);
        }
    }

    // --- Initialization ---
    showLoadingStates();
    initMap();
    setupNavigation();
    setupEventListeners();
    fetchStatus();
    setInterval(fetchStatus, 3000);

    // --- Core Functions ---

    function setupEventListeners() {
        // Refresh Button
        if (elements.btnRefresh) {
            elements.btnRefresh.addEventListener('click', () => {
                elements.btnRefresh.classList.add('fa-spin');
                fetchStatus().finally(() => {
                    setTimeout(() => elements.btnRefresh.classList.remove('fa-spin'), 500);
                });
            });
        }

        // Reset Button
        if (elements.btnReset) {
            elements.btnReset.addEventListener('click', async () => {
                if (!confirm("Are you sure you want to clear all dashboard statistics and logs for this session? This will NOT delete the actual log files.")) return;
                
                try {
                    const resp = await fetch('/api/action/reset', { method: 'POST' });
                    const result = await resp.json();
                    if (result.status === 'success') {
                        alert("Reset Successful: All statistics have been cleared.");
                        fetchStatus(); // Refresh UI
                    } else {
                        alert("Error: Failed to reset: " + result.message);
                    }
                } catch (err) {
                    alert("Error: Failed to connect to backend");
                }
            });
        }

        // Clear Logs Button
        if (elements.btnClearLogs) {
            elements.btnClearLogs.addEventListener('click', async () => {
                if (!confirm("⚠️ WARNING: This will PERMANENTLY delete all recorded security events in the log file. This cannot be undone. Proceed?")) return;
                
                try {
                    const resp = await fetch('/api/logs', { method: 'DELETE' });
                    const result = await resp.json();
                    if (result.status === 'success') {
                        alert("Log file wiped successfully.");
                        fetchStatus(); // Refresh UI
                    } else {
                        alert("Error: " + result.message);
                    }
                } catch (err) {
                    alert("Error: Failed to connect to backend");
                }
            });
        }

        // Omni Search
        if (elements.omniSearch) {
            elements.omniSearch.addEventListener('input', (e) => {
                const query = e.target.value.toLowerCase();
                filterDashboard(query);
            });
        }

        // Manual Attack
        if (elements.btnAttack) {
            elements.btnAttack.addEventListener('click', async () => {
                const pod = document.getElementById('pod-name').value || "web-app";
                const command = document.getElementById('attack-command').value;

                if (!command) {
                    alert("Please enter a command to simulate.");
                    return;
                }

                // UI Reset
                const analysisBox = document.getElementById('simulation-analysis');
                const simStatus = document.getElementById('sim-status');
                const simRisk = document.getElementById('sim-risk');
                const simTech = document.getElementById('sim-technique');
                
                analysisBox.classList.remove('hidden');
                simStatus.innerText = "ANALYZING...";
                simStatus.style.background = "#F59E0B"; // Orange for analyzing
                simRisk.innerText = "-";
                simTech.innerText = "-";

                elements.btnAttack.disabled = true;
                elements.btnAttack.innerText = "INJECTING...";

                try {
                    const resp = await fetch('/api/action/simulate', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ pod, command })
                    });
                    const result = await resp.json();
                    
                    if (result.status === 'success') {
                        // Wait for Event Processor to pick it up (log tailing takes ~1-2s)
                        setTimeout(() => {
                            // Find the event in latestData
                            const event = (latestData.latest_events || []).find(e => 
                                e.command.includes(command) || command.includes(e.command)
                            );

                            if (event) {
                                simStatus.innerText = "DETECTED";
                                simStatus.style.background = "#EF4444"; // Red for detected
                                simRisk.innerText = event.threat_level || "Medium";
                                simRisk.className = event.threat_level === 'Critical' ? 'text-red' : 'text-orange';
                                simTech.innerText = event.mitre_id + " (" + (event.mitre_technique || "Logic") + ")";
                                
                                // Auto-populate search to show the trace
                                if (elements.omniSearch) {
                                    elements.omniSearch.value = command;
                                    filterDashboard(command);
                                }
                            } else {
                                simStatus.innerText = "PENDING";
                                simStatus.style.background = "#64748B";
                                simRisk.innerText = "Processing...";
                                simTech.innerText = "Check Forensic Timeline";
                            }
                        }, 2500);
                    } else {
                        showNotification("Error", result.message, "error");
                        analysisBox.classList.add('hidden');
                    }
                } catch (err) {
                    showNotification("Error", "Failed to connect to backend", "error");
                    analysisBox.classList.add('hidden');
                } finally {
                    elements.btnAttack.disabled = false;
                    elements.btnAttack.innerText = "SYNC ATTACK TO KERNEL";
                }
            });
        }
    }

    function filterDashboard(query) {
        if (!latestData) return;

        // Filter Timeline
        const filteredEvents = (latestData.latest_events || []).filter(evt => 
            evt.command.toLowerCase().includes(query) || 
            evt.container.toLowerCase().includes(query) ||
            evt.threat_level.toLowerCase().includes(query)
        );
        renderTimeline(filteredEvents);

        // Filter Alert Feed
        const filteredIncidents = (latestData.incidents || []).filter(inc => 
            inc.command.toLowerCase().includes(query) || 
            inc.container.toLowerCase().includes(query) ||
            inc.threat_level.toLowerCase().includes(query)
        );
        renderAlertFeed(filteredIncidents);

        // POPULATE SEARCH TABLE
        if (elements.searchTableBody) {
            if (!query) {
                elements.searchTableBody.innerHTML = '<tr><td colspan="5" class="empty-state">Enter a query to search artifacts and logs...</td></tr>';
            } else {
                elements.searchTableBody.innerHTML = filteredEvents.map(evt => `
                    <tr>
                        <td style="font-size:0.7rem;">${new Date(evt.time).toLocaleTimeString()}</td>
                        <td class="text-blue" style="font-weight:600;">${evt.container}</td>
                        <td><code style="background:#F1F5F9; padding:2px 5px; border-radius:4px;">${evt.command}</code></td>
                        <td><span class="badge ${evt.threat_level === 'Critical' ? 'badge-anomaly' : 'badge-normal'}">${evt.threat_level}</span></td>
                        <td><button class="action-btn-sm" onclick="window.killPod('${evt.container}', '${evt.command}')">Mitigate</button></td>
                    </tr>
                `).join('') || '<tr><td colspan="5" class="empty-state">No matches found for your query.</td></tr>';
            }
        }
    }

    function showNotification(title, message, type) {
        // Simple alert for now, could be a toast
        alert(`${title}: ${message}`);
    }

    function showLoadingStates() {
        const loadingHtml = '<div class="empty-state"><i class="fa-solid fa-spinner fa-spin"></i><p>Fetching real-time intelligence...</p></div>';
        elements.alertFeed.innerHTML = loadingHtml;
        elements.mitreMatrix.innerHTML = loadingHtml;
        elements.podHeatmap.innerHTML = loadingHtml;
        elements.eventsTableBody.innerHTML = '<tr><td colspan="5" class="empty-state">Loading timeline...</td></tr>';
    }

    function initMap() {
        if (!attackerMap && document.getElementById('attacker-map')) {
            attackerMap = L.map('attacker-map', {
                center: [20, 0],
                zoom: 2,
                zoomControl: false,
                attributionControl: false
            });
            
            // Light Theme Map Tiles
            L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png', {
                maxZoom: 19
            }).addTo(attackerMap);

            attackerLayer = L.layerGroup().addTo(attackerMap);
            
            L.control.zoom({ position: 'bottomright' }).addTo(attackerMap);
        }
    }

    function setupNavigation() {
        elements.navItems.forEach(item => {
            item.addEventListener('click', () => {
                const targetId = item.getAttribute('data-target');
                activeView = targetId;
                
                elements.navItems.forEach(nav => nav.classList.remove('active'));
                elements.views.forEach(view => {
                    view.classList.remove('active');
                    view.classList.add('hidden');
                });
                
                item.classList.add('active');
                const targetView = document.getElementById(targetId);
                targetView.classList.add('active');
                targetView.classList.remove('hidden');
                
                elements.pageTitle.innerText = item.innerText;
                
                if (targetId === 'view-map') {
                    setTimeout(() => attackerMap.invalidateSize(), 150);
                    setTimeout(() => updateMapMarkers(), 200);
                }
                if (targetId === 'view-users') {
                    setTimeout(() => renderTopology(), 150);
                }
                if (targetId === 'view-history') {
                    renderHistory();
                }
                if (targetId === 'view-quarantine') {
                    renderQuarantine();
                }
                if (targetId === 'view-behavioral') {
                    renderBehavioralGraphs();
                }
            });
        });

        window.addEventListener('resize', () => {
            if (activeView === 'view-users') renderTopology();
        });
    }

    async function fetchStatus() {
        try {
            const response = await fetch('/api/status');
            if (!response.ok) throw new Error("Backend offline");
            latestData = await response.json();
            updateDashboard();
            isFirstLoad = false;
        } catch (error) {
            console.error("Error fetching status:", error);
            if (isFirstLoad) {
                const errorHtml = `<div class="empty-state"><i class="fa-solid fa-triangle-exclamation text-red"></i><p>Unable to connect to SOC Backend. Please ensure 'app.py' is running.</p></div>`;
                elements.alertFeed.innerHTML = errorHtml;
            }
        }
    }

    function updateDashboard() {
        if (!latestData) return;

        // --- NEW: Update Threat History for Behavioral Analytics ---
        if (latestData.threat_score !== undefined) {
            threatHistory.push({
                time: new Date().toLocaleTimeString(),
                score: latestData.threat_score
            });
            // Keep last 60 points for a "1-hour" feel (if polling every 3s, 60 points = 3 mins, but let's do 100)
            if (threatHistory.length > 100) threatHistory.shift();
        }

        // 1. Update KPIs with safety checks
        elements.kpiPods.innerText = latestData.containers_monitored || 0;
        elements.kpiAnomalies.innerText = latestData.anomalies_detected || 0;
        elements.kpiAttackers.innerText = Object.keys(latestData.attacker_stats || {}).length;
        elements.kpiQuarantined.innerText = (latestData.incidents || []).filter(i => i.action && i.action.includes("Quarantine")).length;

        // 2. Render UI Components
        renderAlertFeed();
        renderMitreMatrix();
        renderPodHeatmap();
        renderTimeline();
        updateMapMarkers();

        if (activeView === 'view-quarantine') {
            renderQuarantine();
        }
        if (activeView === 'view-history') {
            renderHistory();
        }
        if (activeView === 'view-users') {
             renderTopology();
        }
    }

    async function killPod(podName, command) {
        if (!confirm(`Are you sure you want to terminate pod ${podName}?`)) return;
        
        try {
            const resp = await fetch('/api/action/kill_process', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pod: podName, command: command || 'Manual Kill' })
            });
            const result = await resp.json();
            if (result.status === 'success') {
                showNotification("Terminated", result.message, "success");
                fetchStatus();
            } else {
                showNotification("Error", result.message, "error");
            }
        } catch (err) {
            showNotification("Error", "Failed to connect to backend", "error");
        }
    }

    async function quarantinePod(podName, incident) {
        if (!confirm(`Are you sure you want to ISOLATE pod ${podName}? This will move it to the Secure Isolation Vault.`)) return;
        
        try {
            const resp = await fetch('/api/action/quarantine_pod', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pod: podName, threat_data: incident || {} })
            });
            const result = await resp.json();
            if (result.status === 'success') {
                showNotification("Isolated", result.message, "success");
                fetchStatus();
                switchView('view-quarantine'); // Automatically go to Vault to see the result
            } else {
                showNotification("Error", result.message, "error");
            }
        } catch (err) {
            showNotification("Error", "Failed to connect to backend", "error");
        }
    }

    async function blockUser(userName) {
        if (!confirm(`Are you sure you want to REVOKE access for user '${userName}'?`)) return;
        
        try {
            const resp = await fetch('/api/action/block_user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user: userName })
            });
            const result = await resp.json();
            if (result.status === 'success') {
                showNotification("Blocked", result.message, "success");
                fetchStatus();
            } else {
                showNotification("Error", result.message, "error");
            }
        } catch (err) {
            showNotification("Error", "Failed to connect to backend", "error");
        }
    }

    async function releaseAction(quarantineId) {
        if (!confirm(`Are you sure you want to RELEASE this item from quarantine?`)) return;
        
        try {
            const resp = await fetch(`/api/quarantine/release/${quarantineId}`, {
                method: 'POST'
            });
            const result = await resp.json();
            if (result.status === 'success') {
                showNotification("Released", result.message, "success");
                fetchStatus();
            } else {
                showNotification("Error", result.message, "error");
            }
        } catch (err) {
            showNotification("Error", "Failed to connect to backend", "error");
        }
    }

    function renderHistory() {
        if (!latestData || !latestData.actions_taken) return;
        
        const actions = [...latestData.actions_taken].reverse();
        
        if (actions.length === 0) {
            elements.historyTableBody.innerHTML = '<tr><td colspan="4" class="empty-state">No historical actions logged.</td></tr>';
            return;
        }

        elements.historyTableBody.innerHTML = actions.map(act => `
            <tr>
                <td style="font-weight:600; font-size:0.75rem;">${act.time}</td>
                <td><span class="badge ${act.action.includes('Kill') ? 'badge-anomaly' : 'badge-normal'}">${act.action}</span></td>
                <td class="text-blue" style="font-weight:600;">${act.target}</td>
                <td class="text-muted" style="font-size:0.8rem;">${act.reason || act.id || 'Manual Intervention'}</td>
                <td>
                    ${act.action.includes('Kill') ? '' : `<button class="action-btn-sm" onclick="window.killPod('${act.target}', 'Forensic Cleanup')"><i class="fa-solid fa-skull"></i> Kill</button>`}
                </td>
            </tr>
        `).join('');
    }

    let topoAnimationId = null;
    let topoOffset = 0;

    async function renderTopology() {
        const canvas = elements.topologyCanvas;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const topologyInfo = elements.topologyInfo;
        
        try {
            const resp = await fetch('/api/containers');
            const data = await resp.json();
            
            lastContainers = data;

            let containers = (Array.isArray(data) ? data : [])
                .filter(item => item && item.pod)
                .map(item => ({
                    pod: item.pod,
                    namespace: (item.namespace || 'default').toLowerCase(),
                    status: item.status || 'Running'
                }));

            // In simulation mode there may be no live cluster objects, so fall back to the
            // current SOC state only when the runtime has no active container list.
            if (containers.length === 0 && latestData && (latestData.containers_monitored || 0) > 0) {
                containers = Object.keys(latestData.pod_stats || {}).map(podName => ({
                    pod: podName,
                    status: 'Running',
                    namespace: podName.includes('shared-kernel') ? 'shared-kernel' :
                        (podName.includes('kube') ? 'kube-system' : (podName.includes('falco') ? 'falco' : 'default'))
                }));
            }

            const namespaceOrder = ['shared-kernel', 'default', 'kube-system', 'falco', 'ingress'];
            const groups = new Map();

            containers.forEach(container => {
                const namespace = container.namespace || 'default';
                if (!groups.has(namespace)) {
                    groups.set(namespace, []);
                }
                groups.get(namespace).push(container);
            });

            const orderedNamespaces = [...groups.keys()].sort((left, right) => {
                const leftIndex = namespaceOrder.indexOf(left);
                const rightIndex = namespaceOrder.indexOf(right);
                if (leftIndex === -1 && rightIndex === -1) return left.localeCompare(right);
                if (leftIndex === -1) return 1;
                if (rightIndex === -1) return -1;
                return leftIndex - rightIndex;
            });

            const podStats = latestData.pod_stats || {};
            const summary = {
                totalPods: containers.length,
                namespaces: orderedNamespaces.length,
                sharedKernelPods: (groups.get('shared-kernel') || []).length,
                quarantinedPods: 0,
                anomalousPods: 0,
                activePods: 0
            };

            containers.forEach(container => {
                const stats = podStats[container.pod] || {};
                if (stats.quarantined) summary.quarantinedPods += 1;
                if ((stats.anomalies || 0) > 0) summary.anomalousPods += 1;
                if (container.status === 'Running') summary.activePods += 1;
            });

            if (topologyInfo) {
                topologyInfo.classList.remove('hidden');
                topologyInfo.innerHTML = `
                    <div style="font-weight:800; color:#0F172A; margin-bottom:10px;">Cluster Snapshot</div>
                    <div style="display:grid; grid-template-columns:repeat(2, 1fr); gap:8px; margin-bottom:12px;">
                        <div style="background:#EFF6FF; padding:8px; border-radius:10px; border:1px solid rgba(59,130,246,0.18);">
                            <div style="font-size:0.65rem; color:#64748B; text-transform:uppercase;">Pods</div>
                            <div style="font-size:1rem; font-weight:800; color:#1E293B;">${summary.totalPods}</div>
                        </div>
                        <div style="background:#FEF3C7; padding:8px; border-radius:10px; border:1px solid rgba(245,158,11,0.18);">
                            <div style="font-size:0.65rem; color:#64748B; text-transform:uppercase;">Shared Kernel</div>
                            <div style="font-size:1rem; font-weight:800; color:#92400E;">${summary.sharedKernelPods}</div>
                        </div>
                        <div style="background:#FEE2E2; padding:8px; border-radius:10px; border:1px solid rgba(239,68,68,0.18);">
                            <div style="font-size:0.65rem; color:#64748B; text-transform:uppercase;">Anomalies</div>
                            <div style="font-size:1rem; font-weight:800; color:#B91C1C;">${summary.anomalousPods}</div>
                        </div>
                        <div style="background:#ECFDF5; padding:8px; border-radius:10px; border:1px solid rgba(16,185,129,0.18);">
                            <div style="font-size:0.65rem; color:#64748B; text-transform:uppercase;">Quarantined</div>
                            <div style="font-size:1rem; font-weight:800; color:#047857;">${summary.quarantinedPods}</div>
                        </div>
                    </div>
                    <div style="font-size:0.72rem; color:#64748B; line-height:1.45;">
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;"><span style="width:10px; height:10px; border-radius:50%; background:#3B82F6; display:inline-block;"></span> SOC root</div>
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;"><span style="width:10px; height:10px; border-radius:50%; background:#8B5CF6; display:inline-block;"></span> Namespace lane</div>
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;"><span style="width:10px; height:10px; border-radius:50%; background:#10B981; display:inline-block;"></span> Healthy pod</div>
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:6px;"><span style="width:10px; height:10px; border-radius:50%; background:#F59E0B; display:inline-block;"></span> Shared kernel / quarantined</div>
                        <div style="display:flex; align-items:center; gap:8px;"><span style="width:10px; height:10px; border-radius:50%; background:#EF4444; display:inline-block;"></span> Active anomaly</div>
                    </div>
                `;
            }

            function startAnimation() {
                if (topoAnimationId) cancelAnimationFrame(topoAnimationId);
                function animate() {
                    if (activeView !== 'view-users') {
                        cancelAnimationFrame(topoAnimationId);
                        topoAnimationId = null;
                        return;
                    }
                    topoOffset += 0.6;
                    draw(topoOffset);
                    topoAnimationId = requestAnimationFrame(animate);
                }
                animate();
            }

            function roundedRectPath(x, y, w, h, r) {
                const radius = Math.min(r, w / 2, h / 2);
                ctx.beginPath();
                ctx.moveTo(x + radius, y);
                ctx.lineTo(x + w - radius, y);
                ctx.quadraticCurveTo(x + w, y, x + w, y + radius);
                ctx.lineTo(x + w, y + h - radius);
                ctx.quadraticCurveTo(x + w, y + h, x + w - radius, y + h);
                ctx.lineTo(x + radius, y + h);
                ctx.quadraticCurveTo(x, y + h, x, y + h - radius);
                ctx.lineTo(x, y + radius);
                ctx.quadraticCurveTo(x, y, x + radius, y);
                ctx.closePath();
            }

            function drawCard(x, y, w, h, options = {}) {
                const {
                    fill = '#111827',
                    border = '#1E293B',
                    accent = '#3B82F6',
                    title = '',
                    subtitle = '',
                    badge = '',
                    badgeFill = '#0F172A',
                    badgeText = '#FFFFFF',
                    shadow = 'rgba(15, 23, 42, 0.45)',
                    titleColor = '#FFFFFF',
                    subtitleColor = '#CBD5E1'
                } = options;

                ctx.save();
                ctx.shadowBlur = 18;
                ctx.shadowColor = shadow;
                ctx.fillStyle = fill;
                ctx.strokeStyle = border;
                ctx.lineWidth = 1.2;
                roundedRectPath(x, y, w, h, 16);
                ctx.fill();
                ctx.stroke();
                ctx.shadowBlur = 0;

                ctx.fillStyle = accent;
                roundedRectPath(x, y, 5, h, 16);
                ctx.fill();

                ctx.fillStyle = titleColor;
                ctx.font = '700 13px Inter, system-ui, sans-serif';
                ctx.textAlign = 'left';
                ctx.fillText(title, x + 16, y + 24);

                if (subtitle) {
                    ctx.fillStyle = subtitleColor;
                    ctx.font = '600 10px Inter, system-ui, sans-serif';
                    ctx.fillText(subtitle, x + 16, y + 42);
                }

                if (badge) {
                    const badgeWidth = Math.max(32, badge.length * 7 + 14);
                    ctx.fillStyle = badgeFill;
                    roundedRectPath(x + w - badgeWidth - 12, y + 12, badgeWidth, 20, 10);
                    ctx.fill();
                    ctx.fillStyle = badgeText;
                    ctx.font = '700 9px Inter, system-ui, sans-serif';
                    ctx.textAlign = 'center';
                    ctx.fillText(badge, x + w - badgeWidth / 2 - 12, y + 26);
                }

                ctx.restore();
            }

            function drawPodCard(x, y, w, h, label, meta = {}) {
                const {
                    accent = '#10B981',
                    fill = '#FFFFFF',
                    border = '#D1D5DB',
                    subtitle = '',
                    statusDot = accent,
                    badge = '',
                    badgeFill = '#EFF6FF',
                    badgeText = '#1E293B',
                    isMuted = false
                } = meta;

                ctx.save();
                ctx.shadowBlur = 12;
                ctx.shadowColor = accent;
                ctx.fillStyle = fill;
                ctx.strokeStyle = border;
                ctx.lineWidth = 1.2;
                roundedRectPath(x, y, w, h, 14);
                ctx.fill();
                ctx.stroke();
                ctx.shadowBlur = 0;

                ctx.fillStyle = accent;
                roundedRectPath(x, y, 5, h, 14);
                ctx.fill();

                ctx.beginPath();
                ctx.fillStyle = statusDot;
                ctx.arc(x + 16, y + 18, 5, 0, Math.PI * 2);
                ctx.fill();

                ctx.fillStyle = isMuted ? '#64748B' : '#0F172A';
                ctx.font = '700 11px JetBrains Mono, monospace';
                ctx.textAlign = 'left';
                const title = label.length > 18 ? `${label.slice(0, 15)}...` : label;
                ctx.fillText(title, x + 28, y + 22);

                if (subtitle) {
                    ctx.fillStyle = '#64748B';
                    ctx.font = '600 9px Inter, system-ui, sans-serif';
                    ctx.fillText(subtitle, x + 28, y + 38);
                }

                if (badge) {
                    const badgeWidth = Math.max(28, badge.length * 6.5 + 12);
                    ctx.fillStyle = badgeFill;
                    roundedRectPath(x + w - badgeWidth - 10, y + 12, badgeWidth, 18, 9);
                    ctx.fill();
                    ctx.fillStyle = badgeText;
                    ctx.font = '700 8px Inter, system-ui, sans-serif';
                    ctx.textAlign = 'center';
                    ctx.fillText(badge, x + w - badgeWidth / 2 - 10, y + 24);
                }

                ctx.restore();
            }

            function drawLink(x1, y1, x2, y2, color, offset, dash = [6, 10]) {
                ctx.save();
                ctx.beginPath();
                ctx.strokeStyle = color;
                ctx.lineWidth = 1.5;
                ctx.setLineDash(dash);
                ctx.lineDashOffset = -offset;
                const controlY = Math.min(y1 + 40, y2 - 20);
                ctx.moveTo(x1, y1);
                ctx.quadraticCurveTo((x1 + x2) / 2, controlY, x2, y2);
                ctx.stroke();
                ctx.restore();
            }

            function drawBackground() {
                ctx.fillStyle = '#0F172A';
                ctx.fillRect(0, 0, canvas.width, canvas.height);

                ctx.strokeStyle = 'rgba(148, 163, 184, 0.08)';
                ctx.lineWidth = 1;
                for (let x = 40; x < canvas.width; x += 60) {
                    ctx.beginPath();
                    ctx.moveTo(x, 0);
                    ctx.lineTo(x, canvas.height);
                    ctx.stroke();
                }
                for (let y = 40; y < canvas.height; y += 60) {
                    ctx.beginPath();
                    ctx.moveTo(0, y);
                    ctx.lineTo(canvas.width, y);
                    ctx.stroke();
                }
            }

            function draw(offset) {
                drawBackground();
                const width = canvas.width;
                const height = canvas.height;
                const centerX = width / 2;
                const rootY = 34;
                const namespaceY = 160;
                const podStartY = 270;
                const laneHeight = height - podStartY - 30;

                drawCard(centerX - 165, rootY, 330, 76, {
                    fill: '#111827',
                    border: '#1E293B',
                    accent: '#3B82F6',
                    title: 'SOC ANALYTICS ENGINE',
                    subtitle: 'Live cluster tree view',
                    badge: `${summary.totalPods} PODS`,
                    badgeFill: '#1D4ED8',
                    badgeText: '#FFFFFF'
                });

                drawLink(centerX, rootY + 76, centerX, namespaceY - 14, 'rgba(59, 130, 246, 0.35)', offset);

                if (orderedNamespaces.length === 0) {
                    ctx.fillStyle = '#94A3B8';
                    ctx.font = '600 13px Inter, system-ui, sans-serif';
                    ctx.textAlign = 'center';
                    ctx.fillText('No active shared kernels or pods found', centerX, height / 2);
                    return;
                }

                const branchSpacing = width / orderedNamespaces.length;

                orderedNamespaces.forEach((namespace, namespaceIndex) => {
                    const pods = groups.get(namespace) || [];
                    const laneLeft = branchSpacing * namespaceIndex;
                    const laneCenter = laneLeft + branchSpacing / 2;
                    const laneWidth = branchSpacing;
                    const isSharedKernel = namespace === 'shared-kernel';
                    const namespaceLabel = isSharedKernel ? 'SHARED KERNELS' : namespace.toUpperCase();
                    const namespaceColor = isSharedKernel ? '#F59E0B' : '#8B5CF6';
                    const namespaceAccent = isSharedKernel ? '#B45309' : '#7C3AED';
                    const podColumns = Math.min(3, Math.max(1, Math.ceil(Math.sqrt(Math.max(pods.length, 1)))));
                    const podRows = Math.max(1, Math.ceil(pods.length / podColumns));
                    const cardWidth = Math.min(260, Math.max(190, laneWidth * 0.76));
                    const cardHeight = 70;

                    drawLink(centerX, rootY + 76, laneCenter, namespaceY - 10, 'rgba(139, 92, 246, 0.30)', offset * 0.8);
                    drawCard(laneCenter - cardWidth / 2, namespaceY, cardWidth, cardHeight, {
                        fill: isSharedKernel ? '#1F2937' : '#111827',
                        border: isSharedKernel ? '#F59E0B' : '#8B5CF6',
                        accent: namespaceAccent,
                        title: namespaceLabel,
                        subtitle: `${pods.length} pod${pods.length === 1 ? '' : 's'}  •  ${summary.activePods} running`,
                        badge: isSharedKernel ? 'SIM' : 'NS',
                        badgeFill: isSharedKernel ? '#78350F' : '#312E81',
                        badgeText: '#FFFFFF'
                    });

                    if (pods.length === 0) return;

                    const rowGap = 72;
                    const podWidth = Math.min(170, Math.max(130, laneWidth * 0.62));
                    const podHeight = 54;
                    const topCenterY = namespaceY + cardHeight;
                    const spineY = topCenterY + 24;

                    drawLink(laneCenter, topCenterY, laneCenter, spineY, 'rgba(148, 163, 184, 0.34)', offset * 1.1, [4, 10]);

                    pods.forEach((pod, podIndex) => {
                        const row = Math.floor(podIndex / podColumns);
                        const column = podIndex % podColumns;
                        const slotWidth = laneWidth / podColumns;
                        const podX = laneLeft + slotWidth * (column + 0.5) - podWidth / 2;
                        const podY = podStartY + row * rowGap;
                        const stats = podStats[pod.pod] || {};
                        const isAnomaly = (stats.anomalies || 0) > 0;
                        const isQuarantined = !!stats.quarantined;
                        const isSharedKernelPod = pod.pod.includes('shared-kernel');
                        const isRemoved = pod.status && pod.status !== 'Running';
                        const severityLabel = isQuarantined ? 'VAULT' : isAnomaly ? 'ALERT' : isRemoved ? 'OFFLINE' : 'OK';

                        const cardFill = isQuarantined ? '#FFFBEB' : isAnomaly ? '#FEF2F2' : isSharedKernelPod ? '#FFF7ED' : '#FFFFFF';
                        const cardBorder = isQuarantined ? '#F59E0B' : isAnomaly ? '#EF4444' : isSharedKernelPod ? '#F97316' : '#CBD5E1';
                        const accent = isQuarantined ? '#F59E0B' : isAnomaly ? '#EF4444' : isSharedKernelPod ? '#F97316' : '#10B981';
                        const podLabel = isSharedKernelPod ? `shared-kernel` : pod.pod;
                        const podSubtitle = `cmds ${stats.total || 0}  |  alerts ${stats.anomalies || 0}`;

                        drawLink(laneCenter, spineY, podX + podWidth / 2, podY, isQuarantined ? 'rgba(245, 158, 11, 0.5)' : isAnomaly ? 'rgba(239, 68, 68, 0.5)' : 'rgba(16, 185, 129, 0.25)', offset * 1.4);

                        drawPodCard(podX, podY, podWidth, podHeight, podLabel, {
                            accent,
                            fill: cardFill,
                            border: cardBorder,
                            subtitle: podSubtitle,
                            statusDot: accent,
                            badge: severityLabel,
                            badgeFill: isQuarantined ? '#FEF3C7' : isAnomaly ? '#FEE2E2' : isSharedKernelPod ? '#FFEDD5' : '#DCFCE7',
                            badgeText: isQuarantined ? '#92400E' : isAnomaly ? '#B91C1C' : isSharedKernelPod ? '#C2410C' : '#166534',
                            isMuted: isRemoved
                        });

                        if (isAnomaly) {
                            const attackerX = podX + podWidth + 34;
                            const attackerY = podY + 10;
                            drawLink(podX + podWidth, podY + 18, attackerX, attackerY, 'rgba(239, 68, 68, 0.8)', offset * 1.9, [3, 8]);
                            drawPodCard(attackerX, attackerY - 20, 98, 42, 'ATTACKER', {
                                accent: '#EF4444',
                                fill: '#FEF2F2',
                                border: '#EF4444',
                                subtitle: 'source trace',
                                badge: 'SRC',
                                badgeFill: '#FEE2E2',
                                badgeText: '#B91C1C'
                            });
                        }
                    });
                });
            }

            startAnimation();
            
        } catch (err) {
            console.error("Topology Error:", err);
        }
    }

    function renderBehavioralGraphs() {
        renderThreatTrend();
        renderCmdFreq();
        renderHeatmap();
    }

    function renderThreatTrend() {
        const canvas = document.getElementById('threatTrend');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const w = canvas.width;
        const h = canvas.height;
        const marginLeft = 50;
        const marginRight = 20;
        const marginTop = 20;
        const marginBottom = 30;
        const graphWidth = w - marginLeft - marginRight;
        const graphHeight = h - marginTop - marginBottom;
        
        ctx.clearRect(0, 0, w, h);
        
        // Draw axes with units
        ctx.strokeStyle = "#CBD5E1";
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.moveTo(marginLeft, marginTop);
        ctx.lineTo(marginLeft, h - marginBottom);
        ctx.lineTo(w - marginRight, h - marginBottom);
        ctx.stroke();
        
        // Y-axis labels (0-100 score)
        ctx.fillStyle = "#94A3B8";
        ctx.font = "9px Inter, sans-serif";
        ctx.textAlign = "right";
        [0, 25, 50, 75, 100].forEach(val => {
            const y = h - marginBottom - (val / 100) * graphHeight;
            ctx.fillText(val, marginLeft - 12, y + 3);
        });
        
        // Y-axis label
        ctx.save();
        ctx.translate(12, h / 2);
        ctx.rotate(-Math.PI / 2);
        ctx.fillStyle = "#64748B";
        ctx.font = "600 10px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("THREAT SCORE (0-100)", 0, 0);
        ctx.restore();
        
        if (threatHistory.length < 2) {
            ctx.fillStyle = "#64748B";
            ctx.font = "11px Inter, sans-serif";
            ctx.textAlign = "center";
            ctx.fillText("Collecting telemetry...", w/2, h/2);
            return;
        }

        // Draw grid lines
        ctx.strokeStyle = "rgba(203, 213, 225, 0.15)";
        ctx.lineWidth = 1;
        [0, 25, 50, 75, 100].forEach(val => {
            const y = h - marginBottom - (val / 100) * graphHeight;
            ctx.beginPath();
            ctx.moveTo(marginLeft, y);
            ctx.lineTo(w - marginRight, y);
            ctx.stroke();
        });

        // Draw threat line
        ctx.strokeStyle = "#3B82F6";
        ctx.lineWidth = 3;
        ctx.beginPath();
        
        const points = [];
        threatHistory.forEach((pt, i) => {
            const x = marginLeft + (i / Math.max(1, threatHistory.length - 1)) * graphWidth;
            const y = h - marginBottom - (pt.score / 100) * graphHeight;
            points.push({x, y, score: pt.score, time: pt.time});
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        });
        ctx.stroke();

        // Area fill
        ctx.lineTo(marginLeft + graphWidth, h - marginBottom);
        ctx.lineTo(marginLeft, h - marginBottom);
        ctx.fillStyle = "rgba(59, 130, 246, 0.1)";
        ctx.fill();
        
        // Time axis label
        ctx.fillStyle = "#64748B";
        ctx.font = "600 10px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("TIME (Last " + threatHistory.length + " samples)", w/2, h - 8);
        
        // Add legend
        const legendY = marginTop + 10;
        ctx.fillStyle = "rgba(59, 130, 246, 0.2)";
        ctx.fillRect(w - 220, legendY, 200, 50);
        ctx.fillStyle = "#3B82F6";
        ctx.font = "700 10px Inter, sans-serif";
        ctx.textAlign = "left";
        ctx.fillText("● Current Threat Level", w - 210, legendY + 18);
        ctx.fillStyle = "#64748B";
        ctx.font = "600 8px Inter, sans-serif";
        ctx.fillText("Score: 0-100 | Higher = More Threat", w - 210, legendY + 35);
        
        // Add tooltip
        let hoveredPoint = null;
        canvas.addEventListener('mousemove', (e) => {
            const rect = canvas.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;
            
            hoveredPoint = null;
            points.forEach(pt => {
                if (Math.abs(mouseX - pt.x) < 8 && Math.abs(mouseY - pt.y) < 8) {
                    hoveredPoint = pt;
                }
            });
            
            if (hoveredPoint) {
                showCanvasTooltip(e, {
                    title: "Threat Score",
                    value: hoveredPoint.score.toFixed(1),
                    unit: "/ 100",
                    desc: "Aggregate security threat level assessment"
                });
            } else {
                hideCanvasTooltip();
            }
        });
        
        canvas.addEventListener('mouseleave', hideCanvasTooltip);
    }

    function renderCmdFreq() {
        const canvas = document.getElementById('cmdFreq');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const w = canvas.width;
        const h = canvas.height;
        const marginLeft = 120;
        const marginRight = 50;
        const marginTop = 20;
        const marginBottom = 40;
        const graphW = w - marginLeft - marginRight;
        
        ctx.clearRect(0, 0, w, h);
        
        // Draw title
        ctx.fillStyle = "#0F172A";
        ctx.font = "600 11px Inter, sans-serif";
        ctx.textAlign = "left";
        ctx.fillText("TOP COMMANDS BY FREQUENCY", marginLeft, marginTop + 12);
        
        const stats = latestData.pod_stats || {};
        const cmdMap = {};
        Object.values(stats).forEach(p => {
            (p.events || []).forEach(e => {
                const cmd = e.command.split(' ')[0] || "unknown";
                cmdMap[cmd] = (cmdMap[cmd] || 0) + 1;
            });
        });

        const sorted = Object.entries(cmdMap).sort((a,b) => b[1] - a[1]).slice(0, 5);
        
        if (sorted.length === 0) {
            ctx.fillStyle = "#94A3B8";
            ctx.font = "10px Inter, sans-serif";
            ctx.textAlign = "center";
            ctx.fillText("No command data available", w / 2, h / 2);
            return;
        }
        
        const maxVal = sorted[0][1];
        const barHeight = 22;
        const barGap = 8;
        const startY = marginTop + 36;
        
        // Draw bars with interaction
        const bars = [];
        sorted.forEach((ent, i) => {
            const label = ent[0];
            const val = ent[1];
            const barW = (val / maxVal) * graphW;
            const y = startY + i * (barHeight + barGap);
            
            // Draw bar background
            ctx.fillStyle = i === 0 ? "#1E40AF" : "#3B82F6";
            ctx.fillRect(marginLeft, y, barW, barHeight);
            
            // Command label
            ctx.fillStyle = "#0F172A";
            ctx.font = "600 10px JetBrains Mono, monospace";
            ctx.textAlign = "right";
            ctx.fillText(label, marginLeft - 15, y + 15);
            
            // Count
            ctx.fillStyle = "#FFFFFF";
            ctx.font = "700 9px Inter, sans-serif";
            ctx.textAlign = "left";
            ctx.fillText(`${val} executions`, marginLeft + barW + 8, y + 15);
            
            bars.push({x: marginLeft, y, w: barW, h: barHeight, cmd: label, count: val});
        });
        
        // X-axis label
        ctx.fillStyle = "#64748B";
        ctx.font = "600 9px Inter, sans-serif";
        ctx.textAlign = "center";
        ctx.fillText("Execution Count", marginLeft + graphW / 2, h - 10);
        
        // Legend
        ctx.fillStyle = "rgba(16, 185, 129, 0.1)";
        ctx.fillRect(marginLeft, h - 38, 250, 30);
        ctx.fillStyle = "#10B981";
        ctx.font = "700 9px Inter, sans-serif";
        ctx.textAlign = "left";
        ctx.fillText("💡 Hover over bars to see execution count", marginLeft + 8, h - 18);
        
        // Add tooltips
        canvas.addEventListener('mousemove', (e) => {
            const rect = canvas.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;
            
            let hoveredBar = null;
            bars.forEach(bar => {
                if (mouseX >= bar.x && mouseX <= bar.x + bar.w && 
                    mouseY >= bar.y && mouseY <= bar.y + bar.h) {
                    hoveredBar = bar;
                }
            });
            
            if (hoveredBar) {
                showCanvasTooltip(e, {
                    title: "Command: " + hoveredBar.cmd,
                    value: hoveredBar.count,
                    unit: "times executed",
                    desc: "Total invocations of this command in pods"
                });
            } else {
                hideCanvasTooltip();
            }
        });
        
        canvas.addEventListener('mouseleave', hideCanvasTooltip);
    }

    function renderHeatmap() {
        const container = document.getElementById('anomalyHeatmap');
        if (!container) return;
        
        container.innerHTML = '';
        const events = latestData.latest_events || [];
        const recent = events.slice(-40);
        
        if (recent.length === 0) {
            container.innerHTML = `<div style="padding:20px; text-align:center; color:#94A3B8; font-size:0.85rem;">No events yet. Awaiting activity...</div>`;
            return;
        }
        
        // Add title and info
        const info = document.createElement('div');
        info.style.cssText = "padding:8px 12px; margin-bottom:8px; font-size:0.8rem; color:#64748B; border-bottom:1px solid #E2E8F0;";
        info.innerHTML = `<strong>Recent 40 Events</strong> • ${recent.length} shown | 🟩 Safe (green) | 🟥 Anomaly (red)`;
        container.appendChild(info);
        
        // Create heatmap container
        const heatmapWrapper = document.createElement('div');
        heatmapWrapper.style.cssText = "display:flex; gap:2px; padding:12px; height:100px; align-items:flex-end; background:#F8FAFC; border-radius:8px;";
        
        recent.forEach((e, idx) => {
            const div = document.createElement('div');
            const threatScore = Math.max(10, e.threat_score || 20);
            const isAnomaly = e.prediction === 'anomaly';
            
            div.style.flex = "1";
            div.style.minWidth = "4px";
            div.style.height = threatScore + "%";
            div.style.background = isAnomaly ? "#EF4444" : "#10B981";
            div.style.borderRadius = "2px";
            div.style.cursor = "pointer";
            div.style.transition = "all 0.2s ease";
            div.style.boxShadow = "0 0 0 0 transparent";
            
            // Hover effect
            div.addEventListener('mouseenter', (evt) => {
                div.style.boxShadow = isAnomaly ? "0 0 8px 2px rgba(239, 68, 68, 0.4)" : "0 0 8px 2px rgba(16, 185, 129, 0.4)";
                div.style.transform = "scaleY(1.1)";
                
                showCanvasTooltip(evt, {
                    title: isAnomaly ? "⚠️ ANOMALY EVENT" : "✓ NORMAL EVENT",
                    value: e.threat_score ? e.threat_score.toFixed(1) : "20",
                    unit: "/ 100 threat",
                    desc: `${e.command.substring(0, 40)}... | Pod: ${e.container || 'unknown'} | ${new Date(e.time).toLocaleTimeString()}`
                }, "heatmap");
            });
            
            div.addEventListener('mouseleave', () => {
                div.style.boxShadow = "0 0 0 0 transparent";
                div.style.transform = "scaleY(1)";
                hideCanvasTooltip();
            });
            
            div.title = `${e.time}: ${e.command}`;
            heatmapWrapper.appendChild(div);
        });
        
        container.appendChild(heatmapWrapper);
        
        // Add legend
        const legend = document.createElement('div');
        legend.style.cssText = "margin-top:12px; padding:8px 12px; font-size:0.75rem; color:#64748B; display:flex; gap:16px; border-top:1px solid #E2E8F0;";
        legend.innerHTML = `
            <div><strong>Legend:</strong></div>
            <div>🟥 Red = Anomaly (threat detected)</div>
            <div>🟩 Green = Normal (safe activity)</div>
            <div>Height = Threat Score 0-100</div>
        `;
        container.appendChild(legend);
    }

    function drawAnimatedLine(ctx, x1, y1, x2, y2, offset, color) {
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.setLineDash([4, 12]);
        ctx.lineDashOffset = -offset;
        ctx.lineWidth = 1;
        ctx.moveTo(x1, y1);
        ctx.lineTo(x2, y2);
        ctx.stroke();
        ctx.setLineDash([]);
    }

    function drawNode(ctx, x, y, label, color, isPod, size = 30) {
        ctx.textAlign = "center";
        
        // Glow effect
        ctx.shadowBlur = isPod ? 10 : 20;
        ctx.shadowColor = color;
        
        ctx.fillStyle = color;
        ctx.beginPath();
        if (isPod) {
            ctx.arc(x, y, size, 0, Math.PI * 2);
        } else {
            // Hexagon for infrastructure
            const sides = 6;
            for (let i = 0; i < sides; i++) {
                const angle = (i / sides) * Math.PI * 2 + Math.PI/6;
                const px = x + size * Math.cos(angle);
                const py = y + size * Math.sin(angle);
                if (i === 0) ctx.moveTo(px, py);
                else ctx.lineTo(px, py);
            }
            ctx.closePath();
        }
        ctx.fill();
        
        ctx.shadowBlur = 0; // Reset glow
        
        ctx.fillStyle = "#FFFFFF";
        ctx.font = `600 ${size > 30 ? '11px' : '9px'} Inter, system-ui, sans-serif`;
        const displayLabel = label.length > 20 ? label.substring(0, 17) + "..." : label;
        ctx.fillText(displayLabel, x, y + size + 15);
    }

    function renderAlertFeed(data) {
        const incidents = (data || latestData.incidents || []).slice(-10).reverse();
        if (incidents.length === 0) {
            elements.alertFeed.innerHTML = `
                <div class="empty-state">
                    <i class="fa-solid fa-shield-halved"></i>
                    <p>No threats detected yet. Cluster is secure.</p>
                </div>`;
            return;
        }

        elements.alertFeed.innerHTML = incidents.map(inc => `
            <div class="alert-item ${inc.threat_level.toLowerCase() === 'critical' ? 'critical' : ''}">
                <div style="background:var(--bg-soft-red); width:40px; height:40px; border-radius:10px; display:flex; align-items:center; justify-content:center;">
                    <i class="fa-solid fa-triangle-exclamation ${inc.threat_level.toLowerCase() === 'critical' ? 'text-red' : 'text-orange'}"></i>
                </div>
                <div style="flex:1">
                    <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                        <span style="font-weight:700; font-size:0.85rem;">${inc.threat_level.toUpperCase()} ALERT</span>
                        <span style="font-size:0.7rem; color:var(--text-muted)">${new Date(inc.time).toLocaleTimeString()}</span>
                    </div>
                    <div style="font-size:0.85rem; margin-bottom:8px;">
                        <span class="text-blue" style="font-weight:600;">${inc.container}</span>: <span class="cmd-text">${inc.command}</span>
                    </div>
                    <div style="display:flex; gap:12px; font-size:0.7rem; color:var(--text-muted);">
                        <span><i class="fa-solid fa-fingerprint"></i> ${inc.mitre_id || 'N/A'}</span>
                        <span><i class="fa-solid fa-location-dot"></i> ${inc.location?.label || inc.location?.city || 'Internal Trace'}</span>
                        <span><i class="fa-solid fa-hashtag"></i> ${inc.kernel_id || inc.location?.kernel_id || 'n/a'}</span>
                        <span><i class="fa-solid fa-network-wired"></i> ${inc.attacker_ip || inc.location?.source_ip || 'n/a'}</span>
                    </div>
                    <div style="flex:1; display:flex; gap:8px; margin-top:10px;">
                        <button class="action-btn-sm" onclick="window.killPod('${inc.container}', '${inc.command}')" title="Kill Pod">
                            <i class="fa-solid fa-skull"></i> KILL
                        </button>
                        <button class="action-btn-sm" style="color:var(--accent-orange); border-color:var(--accent-orange);" onclick="window.quarantinePod('${inc.container}', ${JSON.stringify(inc).replace(/"/g, '&quot;')})" title="Quarantine">
                            <i class="fa-solid fa-vault"></i> VAULT
                        </button>
                    </div>
                </div>
            </div>
        `).join('');
    }

    function renderMitreMatrix() {
        const stats = latestData.mitre_stats || {};
        const techniques = [
            { id: 'T1003', name: 'Cred Dumping' },
            { id: 'T1059', name: 'Cmd Execution' },
            { id: 'T1071', name: 'C2 Protocol' },
            { id: 'T1552', name: 'Credentials' },
            { id: 'T1105', name: 'Tool Transfer' },
            { id: 'T1611', name: 'Escape' }
        ];

        // Normalize MITRE keys so IDs like "T1003.008" and "T1105 / T1071"
        // correctly contribute to top-level buckets in the matrix.
        const normalizedStats = {};
        Object.entries(stats).forEach(([rawId, rawCount]) => {
            const count = Number(rawCount) || 0;
            if (!rawId || count <= 0) return;

            String(rawId)
                .split('/')
                .map(part => part.trim())
                .filter(Boolean)
                .forEach(part => {
                    const baseId = part.split('.')[0].trim();
                    if (!baseId || baseId === 'None' || baseId === '-' || baseId === 'Unknown') return;
                    normalizedStats[baseId] = (normalizedStats[baseId] || 0) + count;
                });
        });

        elements.mitreMatrix.innerHTML = techniques.map(tech => {
            const count = normalizedStats[tech.id] || 0;
            return `
                <div class="mitre-cell ${count > 0 ? 'active' : ''}">
                    <h4 style="font-size:0.65rem; color:var(--text-muted); text-transform:uppercase;">${tech.name}</h4>
                    <div class="count">${count}</div>
                    <div style="font-size:0.6rem; opacity:0.6;">${tech.id}</div>
                </div>
            `;
        }).join('');
    }

    function renderPodHeatmap() {
        const stats = latestData.pod_stats || {};
        const pods = Object.keys(stats).sort((a, b) => stats[b].anomalies - stats[a].anomalies);

        if (pods.length === 0) {
            elements.podHeatmap.innerHTML = '<div class="empty-state"><p>No pod activity recorded.</p></div>';
            return;
        }

        elements.podHeatmap.innerHTML = `<div style="padding:1.5rem; display:flex; flex-direction:column; gap:15px;">` + 
            pods.slice(0, 6).map(pod => {
                const p = stats[pod];
                const ratio = p.total > 0 ? (p.anomalies / p.total) * 100 : 0;
                const color = ratio > 50 ? 'var(--accent-red)' : (ratio > 20 ? 'var(--accent-orange)' : 'var(--accent-green)');
                return `
                    <div style="display:grid; grid-template-columns: 120px 1fr 30px; align-items:center; gap:15px;">
                        <span style="font-size:0.8rem; font-weight:600; overflow:hidden; text-overflow:ellipsis;">${pod}</span>
                        <div style="height:8px; background:#F1F5F9; border-radius:4px; overflow:hidden;">
                            <div style="height:100%; width:${Math.max(5, ratio)}%; background:${color}; border-radius:4px;"></div>
                        </div>
                        <span style="font-size:0.75rem; text-align:right; font-weight:700;">${p.anomalies}</span>
                    </div>
                `;
            }).join('') + `</div>`;
    }

    function renderTimeline(data) {
        // Expose to window for onclick
        window.killPod = killPod;
        window.quarantinePod = quarantinePod;
        window.blockUser = blockUser;
        window.releaseAction = releaseAction;

        const events = [...(data || latestData.latest_events || [])].reverse().slice(0, 15);
        if (events.length === 0) {
            elements.eventsTableBody.innerHTML = '<tr><td colspan="5" class="empty-state">No telemetry data flowing. Run real_attack_simulator.sh to generate traffic.</td></tr>';
            return;
        }

        elements.eventsTableBody.innerHTML = events.map(evt => {
            const riskClass = evt.threat_level === 'Critical' ? 'badge-anomaly' : 
                             evt.threat_level === 'High' ? 'badge-anomaly' : 
                             evt.threat_level === 'Medium' ? 'badge-normal' : 'badge-normal';
            return `
                <tr>
                    <td style="font-weight:600;">${new Date(evt.time).toLocaleTimeString()}</td>
                    <td class="text-muted" style="font-size:0.75rem;">${evt.attacker_ip || 'Internal'}</td>
                    <td class="text-blue" style="font-weight:600;">${evt.container}</td>
                    <td><span class="cmd-text">${evt.command}</span></td>
                    <td><span class="badge ${riskClass}">${evt.threat_level || 'Low Risk'}</span></td>
                    <td>
                        <div style="display:flex; gap:5px;">
                            <button class="action-btn-sm" style="background:rgba(239, 68, 68, 0.1); color:var(--accent-red); border:1px solid rgba(239, 68, 68, 0.2); padding:4px 8px; border-radius:6px; cursor:pointer;" onclick="killPod('${evt.container}', '${evt.command}')" title="Kill">
                                <i class="fa-solid fa-skull"></i>
                            </button>
                            <button class="action-btn-sm" style="background:rgba(245, 158, 11, 0.1); color:var(--accent-orange); border:1px solid rgba(245, 158, 11, 0.2); padding:4px 8px; border-radius:6px; cursor:pointer;" onclick="quarantinePod('${evt.container}', ${JSON.stringify(evt).replace(/"/g, '&quot;')})" title="Quarantine">
                                <i class="fa-solid fa-vault"></i>
                            </button>
                            <button class="action-btn-sm" style="background:rgba(59, 130, 246, 0.1); color:var(--text-blue); border:1px solid rgba(59, 130, 246, 0.2); padding:4px 8px; border-radius:6px; cursor:pointer;" onclick="blockUser('${evt.user || 'root'}')" title="Block User">
                                <i class="fa-solid fa-user-slash"></i>
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    }

    function updateMapMarkers() {
        if (!attackerMap || !attackerLayer) return;

        const attackers = latestData.attacker_stats || {};

        attackerLayer.clearLayers();
        markers = {};

        const boundsPoints = [];

        Object.keys(attackers).forEach(ip => {
            const data = attackers[ip];
            const loc = data.location;
            if (loc?.lat !== undefined && loc?.lon !== undefined && loc?.lat !== null && loc?.lon !== null) {
                const point = [loc.lat, loc.lon];
                boundsPoints.push(point);

                const marker = L.circleMarker(point, {
                    radius: Math.max(7, Math.min(16, 6 + Math.log2((data.count || 1) + 1) * 2)),
                    fillColor: "#EF4444",
                    color: "#FFFFFF",
                    weight: 2,
                    opacity: 1,
                    fillOpacity: 0.85
                });

                const locationLabel = loc.label || `${loc.city}, ${loc.country}`;

                marker.bindPopup(`
                    <strong>Attacker:</strong> ${ip}<br>
                    <strong>Location:</strong> ${locationLabel}<br>
                    <strong>Kernel ID:</strong> ${loc.kernel_id || 'n/a'}<br>
                    <strong>Source IP:</strong> ${loc.source_ip || ip}<br>
                    <strong>Pod:</strong> ${loc.pod_name || 'unknown'}<br>
                    <strong>Events:</strong> ${data.count}
                `);

                marker.addTo(attackerLayer);
                markers[ip] = marker;
            }
        });

        if (boundsPoints.length > 0) {
            if (boundsPoints.length === 1) {
                attackerMap.setView(boundsPoints[0], 3);
            } else {
                attackerMap.fitBounds(boundsPoints, { padding: [40, 40], maxZoom: 4 });
            }
        }
    }

    function renderQuarantine() {
        const activeItems = (latestData.active_quarantine || []).filter(i => i.status === 'quarantined');
        
        if (activeItems.length === 0) {
            elements.quarantinePodsBody.innerHTML = '<tr><td colspan="4" class="empty-state">No pods or users currently in quarantine.</td></tr>';
            return;
        }

        elements.quarantinePodsBody.innerHTML = activeItems.map(item => `
            <tr>
                <td class="text-blue" style="font-weight:600;">${item.name}</td>
                <td class="text-muted" style="font-size:0.75rem;">${new Date(item.timestamp).toLocaleString()}</td>
                <td><span class="badge ${item.threat_level === 'Critical' ? 'badge-anomaly' : 'badge-normal'}">${item.mitre_id || item.mitre_technique || 'Isolated'}</span></td>
                <td>
                    <button class="action-btn-sm" style="background:var(--accent-green); color:white; border:none;" onclick="window.releaseAction('${item.id}')">
                        <i class="fa-solid fa-unlock"></i> Release
                    </button>
                </td>
            </tr>
        `).join('');
    }
});
