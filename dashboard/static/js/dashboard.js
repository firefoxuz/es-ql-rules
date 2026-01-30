let allRules = [];
let healthChart, categoryChart;

document.addEventListener('DOMContentLoaded', () => {
    fetchRules();
    setupEventListeners();
});

async function fetchRules() {
    try {
        const response = await fetch('/api/rules');
        allRules = await response.json();
        updateDashboard(allRules);
        renderRules(allRules);
        setupCharts(allRules);
    } catch (err) {
        console.error('Error fetching rules:', err);
    }
}

function updateDashboard(rules) {
    document.getElementById('total-rules').textContent = rules.length;
    document.getElementById('healthy-rules').textContent = rules.filter(r => r.status === 'success').length;
    document.getElementById('error-rules').textContent = rules.filter(r => r.status === 'error').length;
    document.getElementById('total-hits').textContent = rules.reduce((acc, r) => acc + r.hits, 0);
}

function renderRules(rules, sourceFilter = null) {
    const container = document.getElementById('rules-container');
    container.innerHTML = '';

    let filteredRules = rules;
    if (sourceFilter) {
        filteredRules = rules.filter(r => r.source === sourceFilter);
    }

    filteredRules.forEach(rule => {
        const card = document.createElement('div');
        card.className = 'rule-card';
        card.innerHTML = `
            <div class="meta">
                <span>${rule.rule_id}</span>
                <span class="tag">${rule.category}</span>
            </div>
            <h4>${rule.title}</h4>
            <div class="status-indicator">
                <div class="indicator ${rule.status}"></div>
                <span>${rule.status === 'success' ? rule.hits + ' Hits' : 'Scan Error'}</span>
            </div>
        `;
        card.onclick = () => showRuleDetails(rule);
        container.appendChild(card);
    });
}

function showRuleDetails(rule) {
    const modal = document.getElementById('rule-modal');
    const body = document.getElementById('modal-body');

    body.innerHTML = `
        <div class="rule-detail-header">
            <span class="tag" style="margin-bottom: 10px; display: inline-block;">${rule.source} | ${rule.category}</span>
            <h2>${rule.title}</h2>
            <p style="color: var(--text-dim); margin-top: 10px;">${rule.description}</p>
        </div>
        <div class="rule-detail-body">
            ${rule.status === 'error' ? `
                <div class="error-notice" style="background: rgba(239, 68, 68, 0.1); border: 1px solid var(--red); padding: 15px; border-radius: 10px; margin-bottom: 20px; color: var(--red);">
                    <i class="fas fa-triangle-exclamation"></i> <strong>Skanerlash xatosi:</strong><br>
                    <small>${rule.error_msg}</small>
                </div>
            ` : ''}
            <div style="display: flex; gap: 20px; margin-bottom: 20px;">
                <div>
                    <h5>Standard Identifier</h5>
                    <p>${rule.mapping}</p>
                </div>
                <div>
                    <h5>Rule ID</h5>
                    <p>${rule.rule_id}</p>
                </div>
                ${rule.mitre ? `<div><h5>MITRE ATT&CK</h5><p>${rule.mitre}</p></div>` : ''}
            </div>
            <h5>ES|QL Soya (Query)</h5>
            <div class="code-block">${rule.query}</div>
        </div>
    `;

    modal.style.display = 'block';
}

function setupCharts(rules) {
    const ctxHealth = document.getElementById('healthChart').getContext('2d');
    const ctxCat = document.getElementById('categoryChart').getContext('2d');

    if (healthChart) healthChart.destroy();
    if (categoryChart) categoryChart.destroy();

    const successCount = rules.filter(r => r.status === 'success').length;
    const errorCount = rules.filter(r => r.status === 'error').length;

    healthChart = new Chart(ctxHealth, {
        type: 'doughnut',
        data: {
            labels: ['Muvaffaqiyatli', 'Xato'],
            datasets: [{
                data: [successCount, errorCount],
                backgroundColor: ['#10b981', '#ef4444'],
                borderWidth: 0
            }]
        },
        options: {
            plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8' } } }
        }
    });

    const categories = [...new Set(rules.map(r => r.category))];
    const catHits = categories.map(cat =>
        rules.filter(r => r.category === cat).reduce((acc, r) => acc + r.hits, 0)
    );

    categoryChart = new Chart(ctxCat, {
        type: 'bar',
        data: {
            labels: categories,
            datasets: [{
                label: 'Hits count',
                data: catHits,
                backgroundColor: '#6366f1',
                borderRadius: 8
            }]
        },
        options: {
            scales: {
                y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8' } },
                x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function setupEventListeners() {
    // Tab switching
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.onclick = () => {
            document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const tab = btn.getAttribute('data-tab');
            const dashboardTab = document.getElementById('dashboard-tab');
            const rulesTab = document.getElementById('rules-tab');

            if (tab === 'dashboard') {
                dashboardTab.classList.add('active');
                rulesTab.classList.remove('active');
            } else {
                dashboardTab.classList.remove('active');
                rulesTab.classList.add('active');
                renderRules(allRules, tab === 'gdpr' ? 'GDPR' : 'PCI-DSS');
            }
        };
    });

    // Modal close
    document.querySelector('.close-modal').onclick = () => {
        document.getElementById('rule-modal').style.display = 'none';
    };

    window.onclick = (event) => {
        if (event.target == document.getElementById('rule-modal')) {
            document.getElementById('rule-modal').style.display = 'none';
        }
    };

    // Search
    document.getElementById('rule-search').oninput = (e) => {
        const term = e.target.value.toLowerCase();
        const activeTab = document.querySelector('.nav-item.active').getAttribute('data-tab');
        let filtered = allRules;
        if (activeTab !== 'dashboard') {
            filtered = allRules.filter(r => r.source === (activeTab === 'gdpr' ? 'GDPR' : 'PCI-DSS'));
        }
        const searchResult = filtered.filter(r =>
            r.title.toLowerCase().includes(term) ||
            r.rule_id.toLowerCase().includes(term) ||
            r.mapping.toLowerCase().includes(term)
        );
        renderRules(searchResult, activeTab === 'dashboard' ? null : (activeTab === 'gdpr' ? 'GDPR' : 'PCI-DSS'));
    };

    // Real Test Run
    document.getElementById('run-test').onclick = async () => {
        const btn = document.getElementById('run-test');
        const originalText = btn.innerHTML;
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Testing Rules...';
        btn.disabled = true;

        // Reset hit counters for visual refresh
        allRules.forEach(r => { r.status = 'idle'; r.hits = 0; });
        updateDashboard(allRules);
        renderRules(allRules);

        for (let i = 0; i < allRules.length; i++) {
            const rule = allRules[i];

            try {
                const response = await fetch('/api/test_rule', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query: rule.query })
                });
                const result = await response.json();

                // Add a small delay to avoid overwhelming the server
                await new Promise(resolve => setTimeout(resolve, 200));

                if (result.status === 'success') {
                    rule.status = 'success';
                    rule.hits = result.hits;
                    rule.error_msg = null;
                } else {
                    rule.status = 'error';
                    rule.error_msg = result.message || 'Unknown SIEM error';
                }
            } catch (err) {
                rule.status = 'error';
                rule.error_msg = err.message;
            }

            // Periodically update UI every 5 rules
            if (i % 5 === 0 || i === allRules.length - 1) {
                updateDashboard(allRules);
                setupCharts(allRules);
                const activeTab = document.querySelector('.nav-item.active').getAttribute('data-tab');
                if (activeTab !== 'dashboard') {
                    renderRules(allRules, activeTab === 'gdpr' ? 'GDPR' : 'PCI-DSS');
                }
            }
        }

        btn.innerHTML = originalText;
        btn.disabled = false;
    };
}
