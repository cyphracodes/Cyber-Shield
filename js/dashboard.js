/**
 * CYBER SHIELD — Dashboard Analytics
 * Tracks anonymous session statistics for demonstration.
 */

const Dashboard = (() => {
    let stats = {
        totalScans: 0,
        highRisk: 0,
        mediumRisk: 0,
        lowRisk: 0,
        categories: {},
        flags: {},
        history: []
    };

    function addScan(result, text) {
        stats.totalScans++;

        if (result.level === 'high') stats.highRisk++;
        else if (result.level === 'medium') stats.mediumRisk++;
        else stats.lowRisk++;

        // Track categories
        if (result.categoryKey) {
            stats.categories[result.category] = (stats.categories[result.category] || 0) + 1;
        }

        // Track all categories found
        if (result.allCategories) {
            result.allCategories.forEach(cat => {
                stats.categories[cat.name] = (stats.categories[cat.name] || 0) + 1;
            });
        }

        // Track flags
        result.flags.forEach(flag => {
            stats.flags[flag.flag] = (stats.flags[flag.flag] || 0) + 1;
        });

        // Add to history
        stats.history.unshift({
            time: new Date().toLocaleTimeString(),
            text: text.substring(0, 80) + (text.length > 80 ? '...' : ''),
            level: result.level,
            score: result.score,
            category: result.category || 'Unknown'
        });

        // Keep history to last 20
        if (stats.history.length > 20) {
            stats.history = stats.history.slice(0, 20);
        }

        updateDashboard();
    }

    function updateDashboard() {
        // Update stat cards
        document.getElementById('totalScans').textContent = stats.totalScans;
        document.getElementById('highRiskCount').textContent = stats.highRisk;
        document.getElementById('mediumRiskCount').textContent = stats.mediumRisk;
        document.getElementById('lowRiskCount').textContent = stats.lowRisk;

        // Update category chart
        renderBarChart('categoryChart', stats.categories, 'blue');

        // Update flags chart
        renderBarChart('flagsChart', stats.flags, 'red');

        // Update history
        renderHistory();
    }

    function renderBarChart(containerId, data, colorClass) {
        const container = document.getElementById(containerId);
        const entries = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 8);

        if (entries.length === 0) {
            container.innerHTML = '<p class="chart-empty">No data yet</p>';
            return;
        }

        const maxValue = Math.max(...entries.map(e => e[1]));
        const colors = ['blue', 'red', 'orange', 'green', 'purple'];

        container.innerHTML = entries.map(([label, value], index) => {
            const percentage = Math.max(8, (value / maxValue) * 100);
            const color = colors[index % colors.length];
            return `
                <div class="chart-bar">
                    <div class="chart-bar-label" title="${label}">${label.length > 18 ? label.substring(0, 18) + '…' : label}</div>
                    <div class="chart-bar-track">
                        <div class="chart-bar-fill ${color}" style="width: ${percentage}%">${value}</div>
                    </div>
                </div>
            `;
        }).join('');
    }

    function renderHistory() {
        const container = document.getElementById('scanHistory');

        if (stats.history.length === 0) {
            container.innerHTML = '<p class="chart-empty">No scans yet. Analyze a message to get started.</p>';
            return;
        }

        container.innerHTML = stats.history.map(item => `
            <div class="scan-item">
                <span class="scan-risk-badge ${item.level}">${item.level} (${item.score})</span>
                <span class="scan-text" title="${item.text}">${item.text}</span>
                <span class="scan-time">${item.time}</span>
            </div>
        `).join('');
    }

    function getStats() {
        return { ...stats };
    }

    return {
        addScan,
        updateDashboard,
        getStats
    };
})();