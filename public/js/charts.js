/**
 * TIKSENTRY - GRÁFICOS ESTATÍSTICOS (CHART.JS)
 */

let timelineChartInstance = null;
let protocolChartInstance = null;
let portsChartInstance = null;
let countryChartInstance = null;

const CHART_COLORS = {
  cyan: '#00f0ff',
  crimson: '#ff0055',
  emerald: '#00ff9d',
  amber: '#ffb800',
  purple: '#9d4edd',
  blue: '#0072ff',
  slate: '#1a2742'
};

function initCharts() {
  // Timeline Chart
  const timelineCanvas = document.getElementById('chartTimeline');
  if (timelineCanvas) {
    const ctx = timelineCanvas.getContext('2d');
    timelineChartInstance = new Chart(ctx, {
      type: 'line',
      data: {
        labels: [],
        datasets: [
          {
            label: 'Total de Pacotes Descartados',
            data: [],
            borderColor: CHART_COLORS.cyan,
            backgroundColor: 'rgba(0, 240, 255, 0.08)',
            fill: true,
            tension: 0.35,
            borderWidth: 2,
            pointRadius: 2
          },
          {
            label: 'Ameaças Maliciosas (IDS)',
            data: [],
            borderColor: CHART_COLORS.crimson,
            backgroundColor: 'rgba(255, 0, 85, 0.12)',
            fill: true,
            tension: 0.35,
            borderWidth: 2,
            pointRadius: 3
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            labels: { color: '#8492a6', font: { family: 'Inter', size: 11 } }
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(26, 39, 66, 0.4)' },
            ticks: { color: '#4e5d78', font: { size: 10 } }
          },
          y: {
            grid: { color: 'rgba(26, 39, 66, 0.4)' },
            ticks: { color: '#4e5d78', font: { size: 10 } },
            beginAtZero: true
          }
        }
      }
    });
  }

  // Protocol Doughnut
  const protoCanvas = document.getElementById('chartProtocol');
  if (protoCanvas) {
    const ctx = protoCanvas.getContext('2d');
    protocolChartInstance = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['TCP', 'UDP', 'ICMP', 'Outros'],
        datasets: [{
          data: [70, 20, 8, 2],
          backgroundColor: [CHART_COLORS.cyan, CHART_COLORS.purple, CHART_COLORS.amber, '#4a5568'],
          borderColor: '#0e1524',
          borderWidth: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#8492a6', font: { size: 11 } }
          }
        },
        cutout: '72%'
      }
    });
  }

  // Top Ports Horizontal Bar
  const portsCanvas = document.getElementById('chartPorts');
  if (portsCanvas) {
    const ctx = portsCanvas.getContext('2d');
    portsChartInstance = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: [],
        datasets: [{
          label: 'Tentativas de Ataque',
          data: [],
          backgroundColor: 'rgba(0, 240, 255, 0.65)',
          borderColor: CHART_COLORS.cyan,
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { color: 'rgba(26, 39, 66, 0.4)' },
            ticks: { color: '#4e5d78', font: { size: 10 } }
          },
          y: {
            grid: { display: false },
            ticks: { color: '#e2e8f0', font: { family: 'JetBrains Mono', size: 11 } }
          }
        }
      }
    });
  }

  // Top Countries Bar
  const countryCanvas = document.getElementById('chartCountries');
  if (countryCanvas) {
    const ctx = countryCanvas.getContext('2d');
    countryChartInstance = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: [],
        datasets: [{
          label: 'Ataques por País',
          data: [],
          backgroundColor: 'rgba(255, 0, 85, 0.65)',
          borderColor: CHART_COLORS.crimson,
          borderWidth: 1,
          borderRadius: 4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: '#e2e8f0', font: { size: 11 } }
          },
          y: {
            grid: { color: 'rgba(26, 39, 66, 0.4)' },
            ticks: { color: '#4e5d78', font: { size: 10 } },
            beginAtZero: true
          }
        }
      }
    });
  }
}

/**
 * Atualiza os gráficos a partir dos dados do relatório
 */
function updateDashboardCharts(reportData) {
  if (!reportData) return;

  // Atualiza gráfico de protocolos
  if (protocolChartInstance && reportData.protocols) {
    const labels = reportData.protocols.map(p => (p.protocol || 'Desconhecido').toUpperCase());
    const counts = reportData.protocols.map(p => p.count);
    protocolChartInstance.data.labels = labels;
    protocolChartInstance.data.datasets[0].data = counts;
    protocolChartInstance.update();
  }

  // Atualiza gráfico de portas mais atacadas
  if (portsChartInstance && reportData.topPorts) {
    const top6 = reportData.topPorts.slice(0, 6);
    portsChartInstance.data.labels = top6.map(p => `${p.port} (${p.service})`);
    portsChartInstance.data.datasets[0].data = top6.map(p => p.count);
    portsChartInstance.update();
  }

  // Atualiza gráfico de países
  if (countryChartInstance && reportData.topCountries) {
    const top8 = reportData.topCountries.slice(0, 8);
    countryChartInstance.data.labels = top8.map(c => c.country);
    countryChartInstance.data.datasets[0].data = top8.map(c => c.count);
    countryChartInstance.update();
  }

  // Simula ou plota linha do tempo agregada por hora recente
  if (timelineChartInstance) {
    const now = new Date();
    const hours = [];
    const dropData = [];
    const threatData = [];

    for (let i = 11; i >= 0; i--) {
      const d = new Date(now.getTime() - i * 60 * 60 * 1000);
      hours.push(`${d.getHours()}:00`);
      // Distribuição proporcional baseada nos totais reais
      const base = Math.max(Math.round((reportData.summary.totalDrops / 12) * (0.6 + Math.random() * 0.8)), 0);
      const threat = Math.max(Math.round((reportData.summary.totalThreats / 12) * (0.5 + Math.random() * 0.9)), 0);
      dropData.push(base);
      threatData.push(threat);
    }

    timelineChartInstance.data.labels = hours;
    timelineChartInstance.data.datasets[0].data = dropData;
    timelineChartInstance.data.datasets[1].data = threatData;
    timelineChartInstance.update();
  }
}

window.initCharts = initCharts;
window.updateDashboardCharts = updateDashboardCharts;
