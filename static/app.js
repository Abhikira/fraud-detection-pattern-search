const $ = selector => document.querySelector(selector);
const csrfToken = $('meta[name="csrf-token"]').content;
const escapeHtml = value => String(value).replace(/[&<>"]/g, char => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'
}[char]));
const badge = risk => `<span class="badge ${risk}">${risk}</span>`;
const SAMPLE = {
  account_ref: 'ACC-1002',
  description: 'URGENT WIRE TRANSFER needed - buy gift card and send code now'
};
const reportDialog = $('#report-dialog');

async function api(url, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes((options.method || 'GET').toUpperCase())) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  const response = await fetch(url, { ...options, headers });
  let data;
  try {
    data = await response.json();
  } catch {
    throw new Error(response.ok ? 'The server returned an invalid response.' : `Request failed (${response.status}).`);
  }
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
}

function setTab(tabName) {
  document.querySelectorAll('.tab').forEach(tab => {
    const active = tab.dataset.tab === tabName;
    tab.classList.toggle('active', active);
    tab.setAttribute('aria-pressed', String(active));
  });
  document.querySelectorAll('.panel').forEach(panel => {
    const active = panel.id === tabName;
    panel.classList.toggle('active', active);
    panel.hidden = !active;
  });
  if (tabName === 'dash') loadDashboard();
  if (tabName === 'pats') loadPatterns();
  if (tabName === 'users') loadUsers();
}

document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => setTab(tab.dataset.tab));
});

$('#sample').addEventListener('click', () => {
  $('#account_ref').value = SAMPLE.account_ref;
  $('#txt').value = SAMPLE.description;
});
$('#refresh-dash').addEventListener('click', loadDashboard);
$('#close-report').addEventListener('click', () => reportDialog.close());
reportDialog.addEventListener('click', event => {
  if (event.target === reportDialog) reportDialog.close();
});

function highlight(text, matches) {
  const spans = matches.flatMap(match => match.positions.map(position => [position, position + match.length]))
    .sort((a, b) => a[0] - b[0]);
  let html = '';
  let index = 0;
  for (const [start, end] of spans) {
    if (start < index) continue;
    html += `${escapeHtml(text.slice(index, start))}<mark>${escapeHtml(text.slice(start, end))}</mark>`;
    index = end;
  }
  return html + escapeHtml(text.slice(index));
}

function showResults(data) {
  $('#out').innerHTML = `<div class="card table-card"><div class="table-heading"><div><p class="eyebrow">Scan complete</p><h3>Results · ${escapeHtml(data.algorithm.replace('_', '-'))}</h3></div><span>${data.results.length} transaction(s)</span></div>` +
    data.results.map(result => `
      <article class="result-card">
        <div class="result-heading"><span>#${result.id} · ${escapeHtml(result.account_ref)}</span>${badge(escapeHtml(result.risk))}</div>
        <p class="result-description">${highlight(result.description, result.matches)}</p>
        <div class="chips">${result.matches.map(match =>
          `<span class="chip">${escapeHtml(match.pattern)} · ${escapeHtml(match.category)} · ${match.count} match(es) at [${escapeHtml(match.positions.join(', '))}] · ${badge(escapeHtml(match.severity))}</span>`
        ).join('') || '<span class="chip">No library phrases matched</span>'}</div>
      </article>`).join('') + '</div>';
  reportDialog.showModal();
}

function selectedAlgorithm() {
  return document.querySelector('input[name="algo"]:checked').value;
}

$('#scan-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('#err').textContent = '';
  const transactions = [{
    account_ref: $('#account_ref').value.trim(),
    description: $('#txt').value.trim()
  }];
  try {
    showResults(await api('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ algorithm: selectedAlgorithm(), transactions })
    }));
  } catch (error) {
    $('#err').textContent = error.message;
  }
});

$('#upload-form').addEventListener('submit', async event => {
  event.preventDefault();
  $('#err').textContent = '';
  const file = $('#file').files[0];
  if (!file) {
    $('#err').textContent = 'Choose a CSV file first.';
    return;
  }
  const formData = new FormData();
  formData.append('file', file);
  formData.append('algorithm', selectedAlgorithm());
  try {
    showResults(await api('/api/analyze', { method: 'POST', body: formData }));
  } catch (error) {
    $('#err').textContent = error.message;
  }
});

async function loadDashboard() {
  $('#dash-error').textContent = '';
  try {
    const [stats, transactions, detections] = await Promise.all([
      api('/api/stats'), api('/api/transactions'), api('/api/detections')
    ]);
    $('#stats').innerHTML = [
      ['Transactions', stats.transactions], ['Flagged', stats.flagged],
      ['Detections', stats.detections], ['Patterns', stats.patterns]
    ].map(([label, value]) => `<div class="stat"><strong>${escapeHtml(value)}</strong><span>${label}</span></div>`).join('');
    $('#tx').innerHTML = transactions.map(row =>
      `<tr><td>${escapeHtml(row.id)}</td><td><strong>${escapeHtml(row.account_ref)}</strong><br>${escapeHtml(row.description)}</td><td>${escapeHtml(row.created_at)}</td><td>${escapeHtml(row.hits)}</td><td>${badge(escapeHtml(row.risk))}</td></tr>`
    ).join('') || '<tr><td colspan="5">No stored transactions.</td></tr>';
    $('#det').innerHTML = detections.map(row =>
      `<tr><td>${escapeHtml(row.transaction_id)}</td><td>${escapeHtml(row.pattern_text)}</td><td>${escapeHtml(row.category)}</td><td>${escapeHtml(row.algorithm)}</td><td>${escapeHtml(row.match_count)}</td><td>${escapeHtml(row.positions)}</td><td>${badge(escapeHtml(row.risk_level))}</td><td>${escapeHtml(row.detected_at)}</td></tr>`
    ).join('') || '<tr><td colspan="8">No detection history.</td></tr>';
  } catch (error) {
    $('#dash-error').textContent = error.message;
  }
}

async function loadPatterns() {
  $('#patterns-error').textContent = '';
  try {
    const patterns = await api('/api/patterns');
    $('#pl').innerHTML = patterns.map(pattern =>
      `<tr><td>${escapeHtml(pattern.pattern_text)}</td><td>${escapeHtml(pattern.category)}</td><td>${badge(escapeHtml(pattern.severity))}</td><td><button class="button button-secondary button-small edit-pattern" type="button" data-id="${escapeHtml(pattern.id)}" data-pattern-text="${escapeHtml(pattern.pattern_text)}" data-category="${escapeHtml(pattern.category)}" data-severity="${escapeHtml(pattern.severity)}">Edit</button> <button class="button button-secondary button-small delete-pattern" type="button" data-id="${escapeHtml(pattern.id)}">Delete</button></td></tr>`
    ).join('') || '<tr><td colspan="4">No patterns have been added.</td></tr>';
  } catch (error) {
    $('#patterns-error').textContent = error.message;
  }
}

if ($('#pattern-form')) {
  const form = $('#pattern-form');

  function resetPatternEditor() {
    form.reset();
    delete form.dataset.editId;
    $('#ps').value = 'MEDIUM';
    $('#pattern-form-heading').textContent = 'Add a matching phrase';
    $('#pattern-submit').innerHTML = 'Add pattern <span aria-hidden="true">&rarr;</span>';
    $('#pattern-cancel').hidden = true;
  }

  $('#pattern-form').addEventListener('submit', async event => {
    event.preventDefault();
    $('#perr').textContent = '';
    const editId = form.dataset.editId;
    try {
      await api(editId ? `/api/patterns/${encodeURIComponent(editId)}` : '/api/patterns', {
        method: editId ? 'PATCH' : 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          pattern_text: $('#pt').value,
          category: $('#pc').value,
          severity: $('#ps').value
        })
      });
      resetPatternEditor();
      await loadPatterns();
    } catch (error) {
      $('#perr').textContent = error.message;
    }
  });

  $('#pattern-cancel').addEventListener('click', resetPatternEditor);

  $('#pl').addEventListener('click', async event => {
    const button = event.target.closest('button');
    if (!button) return;
    if (button.matches('.edit-pattern')) {
      form.dataset.editId = button.dataset.id;
      $('#pt').value = button.dataset.patternText;
      $('#pc').value = button.dataset.category;
      $('#ps').value = button.dataset.severity;
      $('#pattern-form-heading').textContent = 'Edit matching phrase';
      $('#pattern-submit').innerHTML = 'Save changes <span aria-hidden="true">&rarr;</span>';
      $('#pattern-cancel').hidden = false;
      $('#pt').focus();
      return;
    }
    if (!button.matches('.delete-pattern')) return;
    $('#patterns-error').textContent = '';
    try {
      await api(`/api/patterns/${encodeURIComponent(button.dataset.id)}`, { method: 'DELETE' });
      await loadPatterns();
    } catch (error) {
      $('#patterns-error').textContent = error.message;
    }
  });
}

async function loadUsers() {
  $('#users-error').textContent = '';
  try {
    const users = await api('/api/users');
    $('#user-list').innerHTML = users.map(user => {
      const active = Boolean(user.is_active);
      const action = active ? 'Suspend' : 'Reactivate';
      return `<tr><td>${escapeHtml(user.id)}</td><td>${escapeHtml(user.email)}</td><td>${escapeHtml(user.role)}</td><td>${active ? 'Active' : 'Suspended'}</td><td>${user.role === 'USER' ? `<button class="button button-secondary toggle-user" type="button" data-id="${escapeHtml(user.id)}" data-active="${!active}">${action}</button>` : ''}</td></tr>`;
    }).join('') || '<tr><td colspan="5">No users found.</td></tr>';
  } catch (error) {
    $('#users-error').textContent = error.message;
  }
}

if ($('#user-list')) {
  $('#user-list').addEventListener('click', async event => {
    const button = event.target.closest('.toggle-user');
    if (!button) return;
    $('#users-error').textContent = '';
    try {
      await api(`/api/users/${encodeURIComponent(button.dataset.id)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_active: button.dataset.active === 'true' })
      });
      await loadUsers();
    } catch (error) {
      $('#users-error').textContent = error.message;
    }
  });
}
