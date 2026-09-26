const $ = (id) => document.getElementById(id);
const esc = (val) =>
  String(val ?? '').replace(
    /[&<>"']/g,
    (char) =>
      ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;',
      }[char])
  );
function cls(risk) {
  return risk >= 75 ? 'red' : risk >= 50 ? 'amber' : 'green';
}
function tm(timeString) {
  try {
    return new Date(timeString).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return '--:--:--';
  }
}

// Fetch telemetry and update dashboard components
async function refresh() {
  const data = await (await fetch('/api/dashboard')).json();

  // Update Summary Counters
  $('events').textContent = data.stats.events;
  $('incidents').textContent = data.stats.incidents;
  $('critical').textContent = data.stats.critical;
  $('contained').textContent = data.stats.contained;

  // Render Timeline
  $('timeline').innerHTML =
    data.events
      .slice(0, 12)
      .map((e) => {
        const incident = data.incidents.find(
          (x) => x.source_ip === e.source_ip && x.user === e.username
        );
        const risk = incident ? incident.risk : 0;

        return `
          <div class="event">
            <div class="time">${tm(e.timestamp)}</div>
            <div>
              <div class="event-title">${esc(e.action)} · ${esc(e.endpoint)}</div>
              <div class="event-meta">${esc(e.username)} from ${esc(e.source_ip)} · ${esc(e.country)}</div>
            </div>
            <span class="badge ${cls(risk)}">${risk ? 'RISK ' + risk : 'NORMAL'}</span>
          </div>
        `;
      })
      .join('') || '<p style="color:#7890a3">Waiting for telemetry...</p>';

  // Render Source IPs
  $('sources').innerHTML =
    [...new Set(data.events.map((x) => x.source_ip))]
      .slice(0, 8)
      .map((x) => `<span class="source">${esc(x)}</span>`)
      .join('') || '<span class="source">No sources</span>';

  // Render Decision Engine Reasoning
  const latestIncident = data.incidents[0];
  if (latestIncident) {
    $('reasoning').innerHTML = `
      <div class="reason">
        <div class="reason-grid">
          <div>
            <span class="kicker">RISK</span>
            <div class="risk-number">${latestIncident.risk}</div>
            <span class="badge ${cls(latestIncident.risk)}">${esc(latestIncident.decision)}</span>
          </div>
          <div>
            <b>${esc(latestIncident.summary)}</b>
            <div class="riskbar">
              <div class="riskfill ${cls(latestIncident.risk)}" style="width:${latestIncident.risk}%"></div>
            </div>
            <p>${esc(latestIncident.explanation)}</p>
          </div>
        </div>
        ${latestIncident.findings
          .map(
            (f) => `
          <div class="finding">
            <b>${esc(f.rule)} ·${esc(f.title)}</b>
            <span>${Math.round(f.confidence * 100)}% confidence</span>
            <small>${esc(f.evidence)} · ATT&CK ${esc(f.mitre)}</small>
          </div>
        `
          )
          .join('')}
      </div>
    `;
  } else {
    $('reasoning').innerHTML =
      '<p style="color:#7890a3">Run the incident replay to see explainable reasoning.</p>';
  }

  // Render Response Log
  $('responses').innerHTML =
    data.responses
      .slice(0, 8)
      .map(
        (r) => `
        <div class="response">
          <b>${esc(r.action)}</b>
          <small>${esc(r.target)} · ${tm(r.timestamp)}</small>
          <p>${esc(r.result)}</p>
        </div>
      `
      )
      .join('') || '<p style="color:#7890a3">No automated responses yet.</p>';
}

// Event Listeners
$('simulate').onclick = async () => {$('simulate').disabled = true;
  $('simulate').textContent = 'Replaying incident...';

  await fetch('/api/demo', { method: 'POST' });
  await refresh();

  $('simulate').disabled = false;
  $('simulate').textContent = '▶ Run incident replay';
};

$('reset').onclick = async () => {
  await fetch('/api/reset', { method: 'POST' });
  await refresh();
};

// Application Initialization
refresh();
setInterval(refresh, 2500);