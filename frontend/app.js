const state = {
  sessionId: `session-${Date.now()}`,
  workflowId: null,
  isAuthenticated: false,
};

const PROVIDER_META = {
  openai: {
    label: 'OpenAI',
    hint: '适用官方 OpenAI 接口或兼容代理。',
    defaultBaseUrl: '',
    models: ['gpt-4o', 'gpt-4o-mini', 'o3-mini', 'o1-mini'],
  },
  zhipu: {
    label: '智谱AI',
    hint: '国内网络优先建议，推荐 GLM-4 系列模型。',
    defaultBaseUrl: '',
    models: ['glm-4-plus', 'glm-4-air', 'glm-4-flash'],
  },
  deepseek: {
    label: 'DeepSeek',
    hint: '默认地址已内置，可直接填写 Key 与模型。',
    defaultBaseUrl: 'https://api.deepseek.com',
    models: ['deepseek-chat', 'deepseek-reasoner'],
  },
  custom: {
    label: '自定义端点',
    hint: '用于 OpenAI 兼容接口，需填写 Base URL 与模型名。',
    defaultBaseUrl: '',
    models: ['自定义输入'],
  },
};

const el = {
  landingView: document.getElementById('landingView'),
  workspaceView: document.getElementById('workspaceView'),
  authStatusText: document.getElementById('authStatusText'),
  logoutBtn: document.getElementById('logoutBtn'),
  openSettingsBtn: document.getElementById('openSettingsBtn'),
  closeSettingsBtn: document.getElementById('closeSettingsBtn'),
  settingsDialog: document.getElementById('settingsDialog'),
  workflowFab: document.getElementById('workflowFab'),
  openWorkflowPanel: document.getElementById('openWorkflowPanel'),
  closeWorkflowPanel: document.getElementById('closeWorkflowPanel'),
  workflowDrawer: document.getElementById('workflowDrawer'),

  loginForm: document.getElementById('loginForm'),
  probeLoginBtn: document.getElementById('probeLogin'),
  loginProbeResult: document.getElementById('loginProbeResult'),
  loginResult: document.getElementById('loginResult'),

  providerType: document.getElementById('providerType'),
  providerApiKey: document.getElementById('providerApiKey'),
  providerBaseUrl: document.getElementById('providerBaseUrl'),
  providerBaseUrlRow: document.getElementById('providerBaseUrlRow'),
  providerModel: document.getElementById('providerModel'),
  providerCustomModelRow: document.getElementById('providerCustomModelRow'),
  providerCustomModel: document.getElementById('providerCustomModel'),
  providerHint: document.getElementById('providerHint'),
  providerResult: document.getElementById('providerResult'),
  providerList: document.getElementById('providerList'),

  chatForm: document.getElementById('chatForm'),
  chatMessage: document.getElementById('chatMessage'),
  chatStream: document.getElementById('chatStream'),

  workflowList: document.getElementById('workflowList'),
  approvalList: document.getElementById('approvalList'),
  wfResult: document.getElementById('wfResult'),

  dangerDialog: document.getElementById('dangerDialog'),
  dangerText: document.getElementById('dangerText'),
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    data = { raw: text };
  }
  if (!response.ok) {
    throw new Error(data.detail || data.message || text || '请求失败');
  }
  return data;
}

function setHint(target, message, type = '') {
  target.textContent = message || '';
  target.classList.remove('success', 'error');
  if (type) target.classList.add(type);
}

function setAuthState(authenticated, statusText = '') {
  state.isAuthenticated = authenticated;
  el.landingView.classList.toggle('hidden', authenticated);
  el.workspaceView.classList.toggle('hidden', !authenticated);
  if (!authenticated) {
    setWorkflowDrawer(false);
    closeDialog(el.settingsDialog);
  }
  if (authenticated) {
    el.authStatusText.textContent = statusText || '认证通过，已连接 XDR 平台。';
  }
}

function setWorkflowDrawer(open) {
  el.workflowDrawer.classList.toggle('hidden', !open);
  el.workflowDrawer.setAttribute('aria-hidden', open ? 'false' : 'true');
}

function openDialog(dialog) {
  if (!dialog) return;
  try {
    if (typeof dialog.showModal === 'function') {
      dialog.showModal();
      return;
    }
  } catch {
    // fallback below
  }
  dialog.classList.add('open');
  dialog.setAttribute('open', 'open');
}

function closeDialog(dialog) {
  if (!dialog) return;
  try {
    if (typeof dialog.close === 'function' && dialog.open) {
      dialog.close();
      return;
    }
  } catch {
    // fallback below
  }
  dialog.classList.remove('open');
  dialog.removeAttribute('open');
}

function collectLoginPayload() {
  return {
    base_url: document.getElementById('baseUrl').value.trim(),
    auth_code: document.getElementById('authCode').value.trim() || null,
    access_key: document.getElementById('accessKey').value.trim() || null,
    secret_key: document.getElementById('secretKey').value.trim() || null,
    verify_ssl: document.getElementById('verifySsl').checked,
  };
}

function providerLabel(provider) {
  return PROVIDER_META[provider]?.label || provider;
}

function initProviderUI() {
  const provider = el.providerType.value;
  const meta = PROVIDER_META[provider];

  el.providerHint.textContent = meta?.hint || '';
  el.providerModel.innerHTML = '';
  (meta?.models || []).forEach((model) => {
    const option = document.createElement('option');
    option.value = model;
    option.textContent = model;
    el.providerModel.appendChild(option);
  });

  if (provider === 'deepseek' && !el.providerBaseUrl.value) {
    el.providerBaseUrl.value = meta.defaultBaseUrl;
  }

  const showBaseUrl = provider === 'custom' || provider === 'deepseek' || provider === 'openai';
  el.providerBaseUrlRow.classList.toggle('hidden', !showBaseUrl);

  const customModel = provider === 'custom' || el.providerModel.value === '自定义输入';
  el.providerCustomModelRow.classList.toggle('hidden', !customModel);

  el.providerApiKey.placeholder = '按供应商填写对应密钥';
}

function getProviderPayload() {
  const provider = el.providerType.value;
  const selectedModel = el.providerModel.value;
  const modelName = selectedModel === '自定义输入' ? el.providerCustomModel.value.trim() : selectedModel;

  return {
    provider,
    api_key: el.providerApiKey.value.trim() || null,
    base_url: el.providerBaseUrl.value.trim() || null,
    model_name: modelName || null,
    enabled: true,
  };
}

function appendCard(node) {
  el.chatStream.appendChild(node);
  el.chatStream.scrollTop = el.chatStream.scrollHeight;
}

function cardTemplate(title, className = '') {
  const card = document.createElement('div');
  card.className = `chat-card ${className}`;
  if (title) {
    const h = document.createElement('strong');
    h.textContent = title;
    card.appendChild(h);
  }
  return card;
}

function renderPayload(payload) {
  if (payload.type === 'text') {
    const card = cardTemplate(payload.data.title || '系统消息', payload.data.dangerous ? 'approval-card' : '');
    const pre = document.createElement('pre');
    pre.textContent = payload.data.text || '';
    card.appendChild(pre);
    appendCard(card);
    return;
  }

  if (payload.type === 'table') {
    const card = cardTemplate(payload.data.title || '表格结果');
    const wrap = document.createElement('div');
    wrap.className = 'table-wrap';
    const table = document.createElement('table');
    const thead = document.createElement('thead');
    const trh = document.createElement('tr');
    (payload.data.columns || []).forEach((c) => {
      const th = document.createElement('th');
      th.textContent = c.label;
      trh.appendChild(th);
    });
    thead.appendChild(trh);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    (payload.data.rows || []).forEach((row) => {
      const tr = document.createElement('tr');
      (payload.data.columns || []).forEach((c) => {
        const td = document.createElement('td');
        const value = row[c.key];
        td.textContent = Array.isArray(value) ? value.join(', ') : String(value ?? '');
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);
    card.appendChild(wrap);
    appendCard(card);
    return;
  }

  if (payload.type === 'echarts_graph') {
    const card = cardTemplate(payload.data.title || '图表结果');
    const chart = document.createElement('div');
    chart.style.height = '260px';
    card.appendChild(chart);
    const summary = document.createElement('p');
    summary.textContent = payload.data.summary || '';
    card.appendChild(summary);
    appendCard(card);
    const instance = echarts.init(chart);
    instance.setOption(payload.data.option || {});
    window.addEventListener('resize', () => instance.resize());
    return;
  }

  if (payload.type === 'approval_card') {
    const card = cardTemplate(payload.data.title || '审批确认', 'approval-card');
    const pre = document.createElement('pre');
    pre.textContent = payload.data.summary || '';
    card.appendChild(pre);
    const actions = document.createElement('div');
    actions.className = 'action-row';

    const ok = document.createElement('button');
    ok.className = 'danger-btn';
    ok.textContent = '确认执行';
    ok.onclick = () => {
      openDangerConfirm(payload.data.summary || '', async () => {
        await sendChat('确认');
      });
    };

    const cancel = document.createElement('button');
    cancel.className = 'secondary-btn';
    cancel.textContent = '取消';
    cancel.onclick = async () => sendChat('取消');

    actions.appendChild(ok);
    actions.appendChild(cancel);
    card.appendChild(actions);
    appendCard(card);
    return;
  }

  if (payload.type === 'form_card') {
    const card = cardTemplate(payload.data.title || '参数表单');
    const desc = document.createElement('p');
    desc.textContent = payload.data.description || '';
    card.appendChild(desc);

    const form = document.createElement('form');
    form.className = 'grid-form';

    const fields = payload.data.fields || [];
    fields.forEach((field) => {
      const wrap = document.createElement('label');
      wrap.textContent = field.label || field.key;
      let inputEl;

      if (field.type === 'select') {
        inputEl = document.createElement('select');
        (field.options || []).forEach((option) => {
          const opt = document.createElement('option');
          opt.value = option.value;
          opt.textContent = option.label;
          inputEl.appendChild(opt);
        });
        if (field.value != null) inputEl.value = String(field.value);
      } else {
        inputEl = document.createElement('input');
        inputEl.type = field.type === 'number' ? 'number' : 'text';
        if (field.placeholder) inputEl.placeholder = field.placeholder;
        if (field.value != null) inputEl.value = String(field.value);
      }

      inputEl.name = field.key;
      if (field.required) inputEl.required = true;
      wrap.appendChild(inputEl);
      form.appendChild(wrap);
    });

    const actionRow = document.createElement('div');
    actionRow.className = 'action-row';
    const submitBtn = document.createElement('button');
    submitBtn.type = 'submit';
    submitBtn.textContent = payload.data.submitLabel || '提交';
    actionRow.appendChild(submitBtn);
    form.appendChild(actionRow);

    form.onsubmit = async (event) => {
      event.preventDefault();
      const fd = new FormData(form);
      const params = {};
      fields.forEach((field) => {
        const raw = (fd.get(field.key) || '').toString().trim();
        if (!raw) return;
        if (field.key === 'views') {
          params[field.key] = raw;
          return;
        }
        if (field.type === 'number') {
          const num = Number(raw);
          if (!Number.isNaN(num)) params[field.key] = num;
          return;
        }
        params[field.key] = raw;
      });

      await sendChat(
        `__FORM_SUBMIT__:${JSON.stringify({
          token: payload.data.token,
          intent: payload.data.intent,
          params,
        })}`,
      );
    };

    card.appendChild(form);
    appendCard(card);
  }
}

async function readSSEStream(response) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let pending = '';
  let tempPre = null;

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    pending += decoder.decode(value, { stream: true });
    const parts = pending.split('\n\n');
    pending = parts.pop() || '';

    for (const part of parts) {
      if (!part.startsWith('data: ')) continue;
      const raw = part.slice(6).trim();
      if (raw === '[DONE]') return;
      const event = JSON.parse(raw);

      if (event.type === 'text_start') {
        const p = event.payload;
        const tempCard = cardTemplate(p.data.title || '系统消息', p.data.dangerous ? 'approval-card' : '');
        tempPre = document.createElement('pre');
        tempCard.appendChild(tempPre);
        appendCard(tempCard);
      } else if (event.type === 'text_delta') {
        if (tempPre) tempPre.textContent += event.delta;
      } else if (event.type === 'payload') {
        renderPayload(event.payload);
      }
    }
  }
}

function openDangerConfirm(text, onConfirm) {
  el.dangerText.textContent = text;
  openDialog(el.dangerDialog);
  const confirmBtn = document.getElementById('dangerConfirm');
  const cancelBtn = document.getElementById('dangerCancel');

  confirmBtn.onclick = async () => {
    closeDialog(el.dangerDialog);
    await onConfirm();
  };
  cancelBtn.onclick = () => {
    closeDialog(el.dangerDialog);
  };
}

function renderList(container, items, render) {
  container.innerHTML = '';
  if (!items.length) {
    container.textContent = '暂无数据';
    return;
  }
  items.forEach((item) => {
    const line = document.createElement('div');
    line.style.padding = '6px 0';
    line.style.borderBottom = '1px solid rgba(255,255,255,0.08)';
    line.innerHTML = render(item);
    container.appendChild(line);
  });
}

async function refreshProviders() {
  const items = await api('/api/config/providers');
  renderList(
    el.providerList,
    items,
    (i) => `${providerLabel(i.provider)} · ${i.model_name || '-'} · ${i.enabled ? '启用' : '禁用'} · ${i.base_url || '默认地址'}`,
  );
}

async function refreshWorkflows() {
  const items = await api('/api/workflows');
  renderList(
    el.workflowList,
    items,
    (i) => `#${i.id} ${i.name} | Cron:${i.cron_expr} | 等级:${(i.levels || []).join(',')} | ${i.enabled ? '开启' : '关闭'}`,
  );
  if (items.length && !state.workflowId) state.workflowId = items[0].id;
}

async function refreshApprovals() {
  const items = await api('/api/workflows/approvals');
  renderList(el.approvalList, items, (i) => {
    const disabled = i.status !== 'Pending' ? 'disabled' : '';
    return `
      <div><strong>#${i.id}</strong> ${i.title}（${i.status}）</div>
      <div class="action-row" style="margin-top:6px;">
        <button ${disabled} data-approve="${i.id}" class="danger-btn">批准</button>
        <button ${disabled} data-reject="${i.id}" class="secondary-btn">拒绝</button>
      </div>
    `;
  });

  el.approvalList.querySelectorAll('button[data-approve]').forEach((btn) => {
    btn.onclick = async () => {
      const id = btn.getAttribute('data-approve');
      await api(`/api/workflows/approvals/${id}/decision`, {
        method: 'POST',
        body: JSON.stringify({ decision: 'approve', reviewer: '安全分析员' }),
      });
      await refreshApprovals();
    };
  });

  el.approvalList.querySelectorAll('button[data-reject]').forEach((btn) => {
    btn.onclick = async () => {
      const id = btn.getAttribute('data-reject');
      await api(`/api/workflows/approvals/${id}/decision`, {
        method: 'POST',
        body: JSON.stringify({ decision: 'reject', reviewer: '安全分析员', comment: '人工驳回' }),
      });
      await refreshApprovals();
    };
  });
}

async function sendChat(message) {
  if (!state.isAuthenticated) {
    setHint(el.loginResult, '请先登录成功后再进入对话。', 'error');
    setAuthState(false);
    return;
  }

  const req = { session_id: state.sessionId, message };
  const response = await fetch('/api/chat/stream', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
  if (!response.ok) {
    const text = await response.text();
    const card = cardTemplate('错误');
    const pre = document.createElement('pre');
    pre.textContent = text;
    card.appendChild(pre);
    appendCard(card);
    return;
  }
  await readSSEStream(response);
}

async function bootWorkspace() {
  await Promise.all([
    refreshProviders().catch((err) => {
      setHint(el.providerResult, err.message || '供应商配置加载失败，可稍后重试。', 'error');
    }),
    refreshWorkflows().catch((err) => {
      setHint(el.wfResult, err.message || '流程列表加载失败，可稍后重试。', 'error');
    }),
    refreshApprovals().catch((err) => {
      setHint(el.wfResult, err.message || '审批列表加载失败，可稍后重试。', 'error');
    }),
  ]);
}

async function checkAuthStatus() {
  try {
    const status = await api('/api/auth/status');
    if (status.authenticated) {
      const url = status.base_url || '已配置平台';
      setAuthState(true, `当前已连接平台：${url}`);
      await bootWorkspace();
    } else {
      setAuthState(false);
    }
  } catch {
    setAuthState(false);
  }
}

el.probeLoginBtn.onclick = async () => {
  try {
    const payload = collectLoginPayload();
    await api('/api/auth/probe', { method: 'POST', body: JSON.stringify(payload) });
    setHint(el.loginProbeResult, '连通性探测成功，可以继续登录。', 'success');
  } catch (err) {
    setHint(el.loginProbeResult, err.message, 'error');
  }
};

el.loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    const payload = collectLoginPayload();
    const result = await api('/api/auth/login', { method: 'POST', body: JSON.stringify(payload) });
    setHint(el.loginResult, result.message, 'success');
    setAuthState(true, `已登录平台：${payload.base_url}`);
    await bootWorkspace();
  } catch (err) {
    setHint(el.loginResult, err.message, 'error');
    setAuthState(false);
  }
});

el.logoutBtn.onclick = () => {
  state.sessionId = `session-${Date.now()}`;
  el.chatStream.innerHTML = '';
  setHint(el.loginResult, '已退出到登录页（本地会话已重置）。', 'success');
  setAuthState(false);
};

el.openSettingsBtn.onclick = async () => {
  if (!state.isAuthenticated) {
    setHint(el.loginResult, '请先登录后再打开系统设置。', 'error');
    return;
  }
  openDialog(el.settingsDialog);
  try {
    await refreshProviders();
  } catch (err) {
    setHint(el.providerResult, err.message || '供应商配置加载失败', 'error');
  }
};

el.closeSettingsBtn.onclick = () => {
  closeDialog(el.settingsDialog);
};

el.settingsDialog.addEventListener('click', (event) => {
  const rect = el.settingsDialog.getBoundingClientRect();
  const isOutside =
    event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom;
  if (isOutside) closeDialog(el.settingsDialog);
});

const openWorkflowDrawer = async () => {
  if (!state.isAuthenticated) {
    setHint(el.loginResult, '请先登录后再打开流程面板。', 'error');
    return;
  }
  setWorkflowDrawer(true);
  try {
    await Promise.all([refreshWorkflows(), refreshApprovals()]);
    setHint(el.wfResult, '');
  } catch (err) {
    setHint(el.wfResult, err.message || '流程面板加载失败', 'error');
  }
};

el.workflowFab.onclick = openWorkflowDrawer;
el.openWorkflowPanel.onclick = openWorkflowDrawer;
el.closeWorkflowPanel.onclick = () => setWorkflowDrawer(false);

el.providerType.addEventListener('change', initProviderUI);
el.providerModel.addEventListener('change', initProviderUI);

document.getElementById('saveProvider').onclick = async () => {
  try {
    if (!state.isAuthenticated) {
      setHint(el.providerResult, '请先登录平台。', 'error');
      return;
    }
    const payload = getProviderPayload();
    await api('/api/config/providers', { method: 'POST', body: JSON.stringify(payload) });
    setHint(el.providerResult, '供应商配置已保存。', 'success');
    await refreshProviders();
  } catch (err) {
    setHint(el.providerResult, err.message, 'error');
  }
};

document.getElementById('testProvider').onclick = async () => {
  try {
    if (!state.isAuthenticated) {
      setHint(el.providerResult, '请先登录平台。', 'error');
      return;
    }
    const payload = getProviderPayload();
    const data = await api('/api/config/providers/test', { method: 'POST', body: JSON.stringify(payload) });
    setHint(el.providerResult, data.message, data.success ? 'success' : 'error');
  } catch (err) {
    setHint(el.providerResult, err.message, 'error');
  }
};

el.chatForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const message = el.chatMessage.value.trim();
  if (!message) return;
  el.chatMessage.value = '';

  const userCard = cardTemplate('你');
  const pre = document.createElement('pre');
  pre.textContent = message;
  userCard.appendChild(pre);
  appendCard(userCard);

  await sendChat(message);
});

document.getElementById('saveWorkflow').onclick = async () => {
  try {
    if (!state.isAuthenticated) {
      setHint(el.wfResult, '请先登录平台。', 'error');
      return;
    }

    const levels = document
      .getElementById('wfLevels')
      .value.split(',')
      .map((x) => Number(x.trim()))
      .filter(Boolean);

    const payload = {
      name: document.getElementById('wfName').value,
      cron_expr: document.getElementById('wfCron').value,
      levels,
      enabled: true,
      require_approval: document.getElementById('wfApproval').checked,
      webhook_url: document.getElementById('wfWebhook').value || null,
    };
    const data = await api('/api/workflows', { method: 'POST', body: JSON.stringify(payload) });
    state.workflowId = data.id;
    setHint(el.wfResult, `流程已保存：#${data.id}`, 'success');
    await refreshWorkflows();
  } catch (err) {
    setHint(el.wfResult, err.message, 'error');
  }
};

document.getElementById('runWorkflow').onclick = async () => {
  try {
    if (!state.isAuthenticated) {
      setHint(el.wfResult, '请先登录平台。', 'error');
      return;
    }
    if (!state.workflowId) {
      setHint(el.wfResult, '请先保存流程配置。', 'error');
      return;
    }
    const data = await api('/api/workflows/run', {
      method: 'POST',
      body: JSON.stringify({ workflow_id: state.workflowId }),
    });
    setHint(el.wfResult, `流程已触发，状态：${data.status}`, 'success');
    await refreshApprovals();
  } catch (err) {
    setHint(el.wfResult, err.message, 'error');
  }
};

document.getElementById('refreshApprovals').onclick = refreshApprovals;

function runParticleBackground() {
  const canvas = document.getElementById('particleCanvas');
  const ctx = canvas.getContext('2d');
  const dots = Array.from({ length: 76 }, () => ({
    x: Math.random() * window.innerWidth,
    y: Math.random() * window.innerHeight,
    vx: (Math.random() - 0.5) * 0.55,
    vy: (Math.random() - 0.5) * 0.55,
    r: Math.random() * 1.8 + 0.6,
  }));

  const resize = () => {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  };

  const frame = () => {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = 'rgba(34,211,238,0.75)';
    dots.forEach((d) => {
      d.x += d.vx;
      d.y += d.vy;
      if (d.x <= 0 || d.x >= canvas.width) d.vx *= -1;
      if (d.y <= 0 || d.y >= canvas.height) d.vy *= -1;
      ctx.beginPath();
      ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
      ctx.fill();
    });

    for (let i = 0; i < dots.length; i++) {
      for (let j = i + 1; j < dots.length; j++) {
        const a = dots[i];
        const b = dots[j];
        const dist = Math.hypot(a.x - b.x, a.y - b.y);
        if (dist < 120) {
          ctx.strokeStyle = `rgba(34, 211, 238, ${0.14 - dist / 860})`;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }
    }

    requestAnimationFrame(frame);
  };

  resize();
  window.addEventListener('resize', resize);
  frame();
}

(async function init() {
  runParticleBackground();
  initProviderUI();
  await checkAuthStatus();
})();
