(() => {
  'use strict';

  const state = { token: '', jobs: new Map(), filter: 'all', settings: {}, events: null, output: '', draftTimer: null, pendingLaunch: null, activeMode: 'check_only', selectedJob: null };
  const $ = (id) => document.getElementById(id);
  const statusLabels = { queued: 'ĐANG CHỜ', running: 'ĐANG CHẠY', success: 'THÀNH CÔNG', error: 'LỖI', cancelled: 'ĐÃ DỪNG' };
  const errorLabels = {
    account_die: 'TÀI KHOẢN DIE',
    invalid_credentials: 'SAI MẬT KHẨU / 2FA',
    technical_error: 'LỖI KỸ THUẬT',
  };
  const MODE_LABELS = {
    check_only: { short: 'CHỈ CHECK', title: 'Kiểm tra tài khoản', icon: '✓', description: 'Chỉ kiểm tra Live, Free/Plus. Không thay đổi bất kỳ thứ gì.' },
    change_2fa: { short: 'ĐỔI 2FA', title: 'Đổi khóa 2FA', icon: '⟳', description: 'Kiểm tra Live, sau đó thay khóa TOTP và đăng nhập lại xác minh.' },
    change_password: { short: 'ĐỔI PASS', title: 'Đổi mật khẩu', icon: '🔑', description: 'Đổi mật khẩu ngẫu nhiên, giữ nguyên 2FA, xác minh đăng nhập lại.' },
    change_password_and_2fa: { short: 'PASS + 2FA', title: 'Đổi Password & 2FA', icon: '⬡', description: 'Đổi mật khẩu trước, rồi đổi khóa TOTP — cả hai đều được xác minh.' },
  };

  function planLabel(job) {
    return job.plan ? String(job.plan).toUpperCase() : 'CHƯA RÕ';
  }

  function statusLabel(job) {
    if (job.status === 'success') return `THÀNH CÔNG · ${planLabel(job)}`;
    if (job.status === 'error' && job.error_kind) return errorLabels[job.error_kind] || 'LỖI';
    return statusLabels[job.status] || job.status;
  }

  function accountCheck(job) {
    if (job.account_state === 'die') return { label: 'DIE', className: 'die', detail: job.error || 'Tài khoản đã bị vô hiệu hóa' };
    if (job.account_state === 'live') return { label: `LIVE · ${planLabel(job)}`, className: 'live', detail: `Gói kiểm tra từ ${job.plan_source || 'session'}` };
    if (job.error_kind === 'invalid_credentials') return { label: 'CHƯA XÁC MINH', className: 'unknown', detail: job.error || 'Thông tin đăng nhập hoặc 2FA không đúng' };
    return { label: 'CHƯA RÕ', className: 'unknown', detail: job.error || 'Chưa kiểm tra xong tài khoản' };
  }

  async function api(path, options = {}) {
    const headers = { ...(options.headers || {}), 'X-Auth-Token': state.token };
    if (options.body) headers['Content-Type'] = 'application/json';
    const response = await fetch(path, { ...options, headers });
    if (!response.ok) {
      let message = `HTTP ${response.status}`;
      try { message = (await response.json()).detail || message; } catch (_) { /* plain error */ }
      throw new Error(message);
    }
    return response.headers.get('content-type')?.includes('json') ? response.json() : response.text();
  }

  function toast(message, type = '') {
    const node = document.createElement('div');
    node.className = `toast ${type}`;
    node.textContent = message;
    $('toast-stack').appendChild(node);
    setTimeout(() => node.remove(), 3800);
  }

  function updateEditor() {
    const value = $('combo-input').value;
    const count = value.trim() ? value.split(/\r?\n/).filter(Boolean).length : 0;
    $('line-count').textContent = `${count} dòng`;
    $('line-numbers').textContent = Array.from({ length: Math.max(1, value.split(/\r?\n/).length) }, (_, i) => i + 1).join('\n');
    document.querySelector('.cursor-hint').style.display = value ? 'none' : 'block';
  }

  function modeValue() {
    return state.activeMode;
  }

  function renderMode() {
    document.querySelectorAll('.mode-btn').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.mode === state.activeMode);
    });
  }

  function scheduleDraftSave() {
    updateEditor();
    clearTimeout(state.draftTimer);
    state.draftTimer = setTimeout(async () => {
      state.settings['twofa.input_draft'] = $('combo-input').value;
      try {
        const data = await api('/api/settings', { method: 'PUT', body: JSON.stringify(settingsPayload()) });
        state.settings = data.settings;
      } catch (error) {
        toast(`Không lưu được danh sách nháp: ${error.message}`, 'error');
      }
    }, 450);
  }

  function counts() {
    const jobs = [...state.jobs.values()];
    const running = jobs.filter((job) => ['queued', 'running'].includes(job.status)).length;
    const success = jobs.filter((job) => job.status === 'success').length;
    const error = jobs.filter((job) => ['error', 'cancelled'].includes(job.status)).length;
    const retryableErrors = jobs.filter((job) => ['error', 'cancelled'].includes(job.status) && job.retryable !== false).length;
    $('metric-running').textContent = running;
    $('metric-success').textContent = success;
    $('metric-errors').textContent = error;
    $('count-all').textContent = jobs.length;
    $('count-running').textContent = running;
    $('count-success').textContent = success;
    $('count-error').textContent = error;
    $('retry-failed-count').textContent = retryableErrors;
    $('retry-failed').disabled = retryableErrors === 0;
  }

  function filteredJobs() {
    const jobs = [...state.jobs.values()].sort((a, b) => a.created_at - b.created_at);
    if (state.filter === 'running') return jobs.filter((j) => ['queued', 'running'].includes(j.status));
    if (state.filter === 'error') return jobs.filter((j) => ['error', 'cancelled'].includes(j.status));
    if (state.filter === 'success') return jobs.filter((j) => j.status === 'success');
    return jobs;
  }

  function render() {
    counts();
    const jobs = filteredJobs();
    $('empty-state').style.display = jobs.length ? 'none' : 'grid';
    $('job-list').innerHTML = jobs.map((job) => {
      const check = accountCheck(job);
      const modeShort = (MODE_LABELS[job.mode] || { short: job.mode.toUpperCase() }).short;
      const checkpoint = job.mode === 'check_only' && job.status === 'success'
        ? 'ĐÃ CHECK LIVE · KHÔNG ĐỔI'
        : job.login_verified
          ? 'ĐÃ XÁC MINH THÀNH CÔNG'
          : job.rotated_pending_verify
            ? 'ĐÃ LƯU · CHỜ VERIFY'
            : check.detail;
      const canRetry = ['error', 'cancelled'].includes(job.status) && job.retryable !== false;
      const canStop = ['queued', 'running'].includes(job.status);
      const selected = state.selectedJob === job.id ? ' selected' : '';
      return `<tr data-id="${job.id}" class="job-row${selected}" title="${escapeHtml(job.error || '')}">
        <td class="account"><strong>${escapeHtml(job.email)}</strong><span>${job.id.slice(0, 10).toUpperCase()} · <b class="job-mode mode-${job.mode}">${escapeHtml(modeShort)}</b></span></td>
        <td><span class="status ${job.status} ${job.plan ? `plan-${escapeHtml(job.plan)}` : ''}">${escapeHtml(statusLabel(job))}</span></td>
        <td><div class="account-result"><span class="account-badge ${check.className}">${escapeHtml(check.label)}</span><small>${escapeHtml(checkpoint)}</small></div></td>
        <td>${job.retry_count}</td>
        <td><div class="row-actions">
          ${canRetry ? '<button class="action-btn retry-btn" data-action="retry">↻ Retry</button>' : ''}
          ${canStop ? '<button class="action-btn stop-btn" data-action="stop">■ Dừng</button>' : ''}
          ${!canStop ? '<button class="action-btn delete-btn" data-action="delete">× Xóa</button>' : ''}
        </div></td></tr>`;
    }).join('');
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>'"]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[char]));
  }

  function renderOutput() {
    const lines = state.output.trim() ? state.output.trim().split(/\r?\n/) : [];
    $('success-output').value = lines.join('\n');
    $('output-count').textContent = `${lines.length} tài khoản`;
    $('output-empty').style.display = lines.length ? 'none' : 'flex';
    $('success-output').style.visibility = lines.length ? 'visible' : 'hidden';
    $('copy-output').disabled = !lines.length;
    $('export-output').disabled = !lines.length;
  }

  async function refreshOutput() {
    try {
      state.output = await api('/api/output');
      renderOutput();
    } catch (error) {
      toast(`Không tải được output: ${error.message}`, 'error');
    }
  }

  async function copyOutput() {
    if (!state.output.trim()) return;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(state.output.trim());
      } else {
        $('success-output').select();
        document.execCommand('copy');
        window.getSelection()?.removeAllRanges();
      }
      toast('Đã copy toàn bộ tài khoản thành công.');
    } catch (_) {
      toast('Không thể copy tự động. Hãy chọn nội dung và copy thủ công.', 'error');
    }
  }

  function openLaunchConfirmation() {
    const lines = $('combo-input').value.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    if (!lines.length) return toast('Hãy nhập ít nhất một combo.', 'error');
    const mode = modeValue();
    const info = MODE_LABELS[mode] || { title: mode, icon: '?', description: '' };
    const isDestructive = mode !== 'check_only';
    state.pendingLaunch = { lines, mode };
    $('confirm-accent').className = `confirm-accent ${isDestructive ? 'is-change' : 'is-check'}`;
    $('confirm-icon').textContent = info.icon;
    $('confirm-title').textContent = info.title;
    $('confirm-message').textContent = info.description;
    $('confirm-count').textContent = lines.length;
    $('confirm-concurrency').textContent = $('quick-concurrency').value;
    $('confirm-action').textContent = info.short;
    $('confirm-launch').className = `button ${isDestructive ? 'confirm-change' : 'confirm-check'}`;
    $('confirm-launch').textContent = isDestructive ? `Xác nhận — ${info.title}` : 'Đúng, chỉ kiểm tra';
    $('launch-confirm').showModal();
  }

  async function launch() {
    if (!state.pendingLaunch) return;
    const { lines, mode } = state.pendingLaunch;
    state.pendingLaunch = null;
    $('launch-confirm').close();
    $('launch-batch').disabled = true;
    try {
      const data = await api('/api/jobs', { method: 'POST', body: JSON.stringify({ lines, mode }) });
      data.jobs.forEach((job) => state.jobs.set(job.id, job));
      render();
      const info = MODE_LABELS[mode] || { title: mode };
      toast(`Đã nạp ${data.jobs.length} tài khoản — ${info.title}.`);
      $('queue').scrollIntoView({ behavior: 'smooth' });
    } catch (error) { toast(error.message, 'error'); }
    finally { $('launch-batch').disabled = false; }
  }

  async function jobAction(id, action) {
    try {
      if (action === 'logs') return openLogs(id);
      if (action === 'retry' || action === 'stop') {
        const data = await api(`/api/jobs/${id}/${action}`, { method: 'POST' });
        state.jobs.set(id, data.job); render();
      } else if (action === 'delete') {
        await api(`/api/jobs/${id}`, { method: 'DELETE' });
        state.jobs.delete(id); render();
      }
    } catch (error) { toast(error.message, 'error'); }
  }

  async function openLogs(id) {
    const job = state.jobs.get(id);
    if (!job) return;
    if (state.selectedJob === id) {
      closeInlineLog();
      return;
    }
    state.selectedJob = id;
    render();
    const panel = $('inline-log-panel');
    panel.style.display = 'flex';
    $('inline-log-title').textContent = job.email;
    $('inline-log-status').innerHTML = `<span class="status ${job.status}">${escapeHtml(statusLabel(job))}</span>`;
    $('inline-log-content').textContent = 'Đang tải log...';
    try {
      const data = await api(`/api/jobs/${id}/logs`);
      $('inline-log-content').textContent = data.logs.join('\n') || 'Chưa có log.';
      $('inline-log-content').scrollTop = $('inline-log-content').scrollHeight;
    } catch (error) { $('inline-log-content').textContent = error.message; }
  }

  function closeInlineLog() {
    $('inline-log-panel').style.display = 'none';
    state.selectedJob = null;
    render();
  }

  function openDrawer(id) {
    closeDrawers();
    $(id).classList.add('open'); $(id).setAttribute('aria-hidden', 'false');
    $('drawer-backdrop').classList.add('open');
  }

  function closeDrawers() {
    document.querySelectorAll('.drawer').forEach((drawer) => { drawer.classList.remove('open'); drawer.setAttribute('aria-hidden', 'true'); });
    $('drawer-backdrop').classList.remove('open');
  }

  function loadSettingsForm() {
    const concurrency = state.settings['twofa.max_concurrent'];
    $('setting-concurrency').value = concurrency;
    $('quick-concurrency').value = concurrency;
    $('setting-timeout').value = state.settings['twofa.job_timeout'];
    $('setting-auto-retry').checked = state.settings['twofa.auto_retry'];
    $('setting-retry-max').value = state.settings['twofa.auto_retry_max'];
    $('setting-retry-delay').value = state.settings['twofa.auto_retry_delay'];
    renderMode();
  }

  function settingsPayload(maxConcurrent = state.settings['twofa.max_concurrent']) {
    return {
      max_concurrent: Number(maxConcurrent),
      job_timeout: Number(state.settings['twofa.job_timeout']),
      auto_retry: Boolean(state.settings['twofa.auto_retry']),
      auto_retry_max: Number(state.settings['twofa.auto_retry_max']),
      auto_retry_delay: Number(state.settings['twofa.auto_retry_delay']),
      change_enabled: Boolean(state.settings['twofa.change_enabled']),
      input_draft: $('combo-input').value,
    };
  }

  async function saveQuickConcurrency() {
    const input = $('quick-concurrency');
    const value = Number(input.value);
    if (!Number.isInteger(value) || value < 1 || value > 10) {
      input.value = state.settings['twofa.max_concurrent'];
      throw new Error('Số luồng phải từ 1 đến 10.');
    }
    if (value === Number(state.settings['twofa.max_concurrent'])) return;
    const data = await api('/api/settings', { method: 'PUT', body: JSON.stringify(settingsPayload(value)) });
    state.settings = data.settings;
    loadSettingsForm();
    toast(`Đã đổi sang ${value} luồng chạy đồng thời.`);
  }

  async function retryFailed() {
    const failed = [...state.jobs.values()].filter((job) => ['error', 'cancelled'].includes(job.status) && job.retryable !== false);
    if (!failed.length) return;
    const button = $('retry-failed');
    button.disabled = true;
    let retried = 0;
    try {
      for (const job of failed) {
        try {
          const data = await api(`/api/jobs/${job.id}/retry`, { method: 'POST' });
          state.jobs.set(job.id, data.job);
          retried += 1;
          render();
        } catch (error) {
          toast(`${job.email}: ${error.message}`, 'error');
        }
      }
      toast(`Đã đưa ${retried}/${failed.length} tài khoản lỗi vào chạy lại.`);
    } finally {
      render();
    }
  }

  async function saveSettings(event) {
    event.preventDefault();
    try {
      const payload = {
        max_concurrent: Number($('setting-concurrency').value),
        job_timeout: Number($('setting-timeout').value),
        auto_retry: $('setting-auto-retry').checked,
        auto_retry_max: Number($('setting-retry-max').value),
        auto_retry_delay: Number($('setting-retry-delay').value),
        change_enabled: Boolean(state.settings['twofa.change_enabled']),
        input_draft: $('combo-input').value,
      };
      const data = await api('/api/settings', { method: 'PUT', body: JSON.stringify(payload) });
      state.settings = data.settings;
      loadSettingsForm();
      closeDrawers(); toast('Đã lưu cấu hình runtime vào SQLite.');
    } catch (error) { toast(error.message, 'error'); }
  }

  async function exportOutput() {
    try {
      const response = await fetch('/api/output', { headers: { 'X-Auth-Token': state.token } });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'twofa-success.txt'; anchor.click();
      URL.revokeObjectURL(url);
    } catch (error) { toast(error.message, 'error'); }
  }

  function connectEvents() {
    state.events?.close();
    state.events = new EventSource(`/api/events?token=${encodeURIComponent(state.token)}`);
    state.events.onopen = () => { $('connection-label').textContent = 'LOCAL ONLINE'; };
    state.events.onerror = () => { $('connection-label').textContent = 'RECONNECTING'; };
    state.events.onmessage = ({ data }) => {
      const payload = JSON.parse(data);
      if (payload.type === 'snapshot') {
        state.jobs.clear(); payload.jobs.forEach((job) => state.jobs.set(job.id, job));
      } else if (payload.type === 'job') state.jobs.set(payload.job.id, payload.job);
      else if (payload.type === 'removed') state.jobs.delete(payload.id);
      render();
      refreshOutput();
    };
  }

  async function init() {
    try {
      const data = await fetch('/api/bootstrap').then((response) => response.json());
      state.token = data.token; state.settings = data.settings;
      $('combo-input').value = String(state.settings['twofa.input_draft'] || '');
      data.jobs.forEach((job) => state.jobs.set(job.id, job));
      loadSettingsForm(); updateEditor(); render(); renderOutput(); connectEvents(); await refreshOutput();
    } catch (_) { $('connection-label').textContent = 'SERVER OFFLINE'; toast('Không kết nối được localhost :5033', 'error'); }
  }

  $('combo-input').addEventListener('input', scheduleDraftSave);
  $('combo-input').addEventListener('scroll', () => { $('line-numbers').scrollTop = $('combo-input').scrollTop; });
  document.querySelectorAll('.mode-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      state.activeMode = btn.dataset.mode;
      renderMode();
    });
  });
  $('quick-concurrency').addEventListener('change', async () => {
    try { await saveQuickConcurrency(); } catch (error) { toast(error.message, 'error'); }
  });
  $('launch-batch').addEventListener('click', async () => {
    try { await saveQuickConcurrency(); openLaunchConfirmation(); } catch (error) { toast(error.message, 'error'); }
  });
  $('confirm-launch').addEventListener('click', launch);
  $('cancel-launch').addEventListener('click', () => { state.pendingLaunch = null; $('launch-confirm').close(); });
  $('retry-failed').addEventListener('click', retryFailed);
  $('job-list').addEventListener('click', (event) => {
    const button = event.target.closest('[data-action]');
    const row = event.target.closest('tr');
    if (button && row) return jobAction(row.dataset.id, button.dataset.action);
    if (row && row.dataset.id) openLogs(row.dataset.id);
  });
  $('close-inline-log').addEventListener('click', closeInlineLog);
  document.querySelectorAll('.filter').forEach((button) => button.addEventListener('click', () => {
    document.querySelectorAll('.filter').forEach((item) => item.classList.remove('active'));
    button.classList.add('active'); state.filter = button.dataset.filter; render();
  }));
  document.querySelectorAll('[data-target]').forEach((button) => button.addEventListener('click', () => $(button.dataset.target).scrollIntoView({ behavior: 'smooth' })));
  $('open-settings').addEventListener('click', () => { loadSettingsForm(); openDrawer('settings-drawer'); });
  $('close-detail').addEventListener('click', closeDrawers); $('close-settings').addEventListener('click', closeDrawers); $('drawer-backdrop').addEventListener('click', closeDrawers);
  $('settings-form').addEventListener('submit', saveSettings);
  $('copy-output').addEventListener('click', copyOutput);
  $('export-output').addEventListener('click', exportOutput);
  $('nav-output').addEventListener('click', () => $('output-panel').scrollIntoView({ behavior: 'smooth' }));
  $('stop-all').addEventListener('click', async () => { try { await api('/api/jobs/stop-all', { method: 'POST' }); toast('Đã gửi lệnh dừng toàn bộ.'); } catch (error) { toast(error.message, 'error'); } });
  $('clear-all').addEventListener('click', async () => { try { await api('/api/jobs', { method: 'DELETE' }); state.jobs.clear(); render(); await refreshOutput(); toast('Đã dọn danh sách.'); } catch (error) { toast(error.message, 'error'); } });
  updateEditor(); renderOutput(); init();
})();
