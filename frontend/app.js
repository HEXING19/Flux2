const state = {
  sessionId: `session-${Date.now()}`,
  isAuthenticated: false,
  playbookTemplates: [],
};

const DEFAULT_PLAYBOOK_SCENES = [
  {
    id: 'routine_check',
    name: '今日安全早报',
    button_label: '☕ 生成今日安全早报',
    description: '自动聚合过去24小时日志总量、未处置高危事件和样本证据，生成值班晨报。',
    hint: '适合每天交接班时快速掌握整体安全态势。',
    default_params: { window_hours: 24, sample_size: 3 },
  },
  {
    id: 'alert_triage',
    name: '单点告警深度研判',
    button_label: '🔍 一键深度研判',
    description: '围绕指定事件做实体画像、外部情报和内部影响计数，输出封禁/观察建议。',
    hint: '可在“事件查询”后按序号研判，或直接输入事件 UUID。',
    default_params: { window_days: 7, mode: 'analyze' },
  },
  {
    id: 'threat_hunting',
    name: '攻击者活动轨迹',
    button_label: '🕵️ 攻击者活动轨迹生成',
    description: '默认回溯90天并最多扫描2000条事件，生成攻击故事线和关键证据。',
    hint: '适合针对某个可疑 IP 做溯源汇报。',
    default_params: { window_days: 90, max_scan: 2000, evidence_limit: 20 },
  },
];

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
  playbookCards: document.getElementById('playbookCards'),
  playbookHint: document.getElementById('playbookHint'),
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

function setAuthState(authenticated, statusText = '', isConnected = true) {
  state.isAuthenticated = authenticated;
  el.landingView.classList.toggle('hidden', authenticated);
  el.workspaceView.classList.toggle('hidden', !authenticated);
  const mainNav = document.getElementById('mainNav');
  if (mainNav) mainNav.classList.toggle('hidden', !authenticated);
  if (!authenticated) {
    closeDialog(el.settingsDialog);
  }
  if (authenticated) {
    el.authStatusText.textContent = statusText || '认证通过，已连接 XDR 平台。';
    if (!isConnected) {
      el.authStatusText.style.color = 'var(--status-fault)';
      document.querySelector('.status-dot').style.background = 'var(--status-fault)';
      document.querySelector('.status-dot').style.boxShadow = '0 0 8px var(--status-fault)';
    } else {
      el.authStatusText.style.color = 'var(--text-muted)';
      document.querySelector('.status-dot').style.background = 'var(--status-online)';
      document.querySelector('.status-dot').style.boxShadow = '0 0 8px var(--status-online)';
    }
  }
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
    verify_ssl: false,
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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function playbookButtonClass(style) {
  if (style === 'danger') return 'danger-btn';
  if (style === 'secondary') return 'secondary-btn';
  return 'primary-btn';
}

function renderNextActions(actions) {
  if (!actions || !actions.length) return;
  const card = cardTemplate('下一步动作推荐');
  const row = document.createElement('div');
  row.className = 'action-row playbook-next-actions';

  actions.forEach((action) => {
    const btn = document.createElement('button');
    btn.className = playbookButtonClass(action.style);
    btn.textContent = action.label || action.id || '执行';
    btn.onclick = async () => {
      try {
        btn.disabled = true;
        await runPlaybook(action.template_id, action.params || {}, action.label || action.template_id);
      } catch (err) {
        const errorCard = cardTemplate('Playbook 执行失败');
        const pre = document.createElement('pre');
        pre.textContent = err.message || '未知错误';
        errorCard.appendChild(pre);
        appendCard(errorCard);
      } finally {
        btn.disabled = false;
      }
    };
    row.appendChild(btn);
  });

  card.appendChild(row);
  appendCard(card);
}

function createPlaybookProgressCard(runId, templateId) {
  const card = cardTemplate(`Playbook 运行中 · ${templateId}`);
  card.dataset.playbookRunId = String(runId);
  const pre = document.createElement('pre');
  pre.textContent = `run_id=${runId}\n初始化中...`;
  card.appendChild(pre);
  appendCard(card);
  return { card, pre };
}

function updatePlaybookProgress(preEl, runData) {
  const nodeStatus = runData?.context?.node_status || {};
  const progress = runData?.context?.progress || {};
  const lines = [];
  lines.push(`状态: ${runData.status}`);
  lines.push(`run_id: ${runData.run_id}`);
  lines.push(`进度: ${progress.finished || 0}/${progress.total || Object.keys(nodeStatus).length || 0}`);
  Object.entries(nodeStatus).forEach(([nodeId, info]) => {
    const status = info?.status || 'Pending';
    const error = info?.error ? ` (error: ${info.error})` : '';
    lines.push(`- ${nodeId}: ${status}${error}`);
  });
  preEl.textContent = lines.join('\n');
}

function renderPlaybookResult(runData) {
  const result = runData?.result || {};
  const summary = result.summary || runData?.error || '';
  if (summary) {
    renderPayload({
      type: 'text',
      data: { title: `Playbook 结果 · ${runData.template_id}`, text: summary, dangerous: false },
    });
  }

  (result.cards || []).forEach((cardPayload) => renderPayload(cardPayload));
  renderNextActions(result.next_actions || []);
}

function buildSceneParams(scene) {
  const base = { ...(scene.default_params || {}) };
  if (scene.id === 'alert_triage') {
    const raw = window.prompt('请输入事件序号（如 1）或事件UUID（incident-xxx）：', '');
    const value = (raw || '').trim();
    if (!value) return null;
    if (/^incident-/.test(value)) {
      return { ...base, incident_uuid: value };
    }
    const idx = Number(value);
    if (!Number.isNaN(idx) && idx > 0) {
      return { ...base, event_index: idx };
    }
    throw new Error('输入格式错误，请填写事件序号或 incident UUID。');
  }

  if (scene.id === 'threat_hunting') {
    const raw = window.prompt('请输入要追踪的攻击者IP：', '');
    const value = (raw || '').trim();
    if (!value) return null;
    return { ...base, ip: value };
  }

  return base;
}

function renderPlaybookCards(templates) {
  if (!el.playbookCards) return;
  el.playbookCards.innerHTML = '';

  const byId = new Map((templates || []).map((tpl) => [tpl.id, tpl]));
  const scenes = DEFAULT_PLAYBOOK_SCENES.map((scene) => {
    const remote = byId.get(scene.id) || {};
    return {
      ...scene,
      ...remote,
      default_params: { ...scene.default_params, ...(remote.default_params || {}) },
    };
  });

  scenes.forEach((scene) => {
    const card = document.createElement('article');
    card.className = 'playbook-card-item';

    const title = document.createElement('h4');
    title.textContent = scene.name || scene.id;
    card.appendChild(title);

    const desc = document.createElement('p');
    desc.className = 'scene-desc';
    desc.textContent = scene.description || '';
    card.appendChild(desc);

    const hint = document.createElement('p');
    hint.className = 'scene-hint';
    hint.textContent = scene.hint || '';
    card.appendChild(hint);

    const action = document.createElement('div');
    action.className = 'scene-action';
    const btn = document.createElement('button');
    btn.className = 'primary-btn playbook-btn';
    btn.textContent = scene.button_label || scene.name || scene.id;
    btn.onclick = async () => {
      try {
        btn.disabled = true;
        const params = buildSceneParams(scene);
        if (!params) return;
        await runPlaybook(scene.id, params, scene.name || scene.id);
      } catch (err) {
        setHint(el.playbookHint, err.message || '场景执行失败', 'error');
      } finally {
        btn.disabled = false;
      }
    };
    action.appendChild(btn);
    card.appendChild(action);
    el.playbookCards.appendChild(card);
  });
}

async function refreshPlaybookTemplates() {
  if (!state.isAuthenticated) return;
  try {
    const templates = await api('/api/playbooks/templates');
    state.playbookTemplates = templates;
    renderPlaybookCards(templates);
    setHint(el.playbookHint, `已加载 ${templates.length} 个场景模板。`, 'success');
  } catch (err) {
    state.playbookTemplates = [];
    renderPlaybookCards([]);
    setHint(el.playbookHint, err.message || 'Playbook 模板加载失败', 'error');
  }
}

async function pollPlaybookRun(runId, progressUi) {
  const maxPoll = 120;
  for (let i = 0; i < maxPoll; i += 1) {
    const runData = await api(`/api/playbooks/runs/${runId}`);
    updatePlaybookProgress(progressUi.pre, runData);
    if (runData.status === 'Finished' || runData.status === 'Failed') {
      return runData;
    }
    await sleep(1000);
  }
  throw new Error(`Playbook 运行超时，run_id=${runId}`);
}

async function runPlaybook(templateId, params = {}, triggerLabel = '') {
  if (!state.isAuthenticated) {
    setHint(el.playbookHint, '请先登录平台后再执行场景。', 'error');
    return;
  }

  if (!templateId) {
    throw new Error('缺少 template_id');
  }

  const requestPayload = {
    template_id: templateId,
    params,
    session_id: state.sessionId,
  };

  const introCard = cardTemplate('你', 'user');
  const introPre = document.createElement('pre');
  introPre.textContent = `触发场景: ${triggerLabel || templateId}`;
  introCard.appendChild(introPre);
  appendCard(introCard);

  const runInfo = await api('/api/playbooks/run', {
    method: 'POST',
    body: JSON.stringify(requestPayload),
  });
  const progressUi = createPlaybookProgressCard(runInfo.run_id, templateId);
  if (runInfo.partial_context) {
    updatePlaybookProgress(progressUi.pre, {
      run_id: runInfo.run_id,
      template_id: templateId,
      status: runInfo.status,
      context: runInfo.partial_context,
    });
  }

  const runData = await pollPlaybookRun(runInfo.run_id, progressUi);
  renderPlaybookResult(runData);
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
  await refreshProviders().catch((err) => {
    setHint(el.providerResult, err.message || '供应商配置加载失败，可稍后重试。', 'error');
  });
  await refreshPlaybookTemplates();
}

async function checkAuthStatus() {
  try {
    const status = await api('/api/auth/status');
    if (status.authenticated) {
      const url = status.base_url || '已配置平台';
      const isConnected = status.connected !== false;

      if (isConnected) {
        setAuthState(true, `当前已连接平台：${url}`, true);
        await bootWorkspace();
      } else {
        setAuthState(true, `当前平台配置：${url} (连接断开/网络异常)`, false);
      }
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
  state.playbookTemplates = [];
  el.chatStream.innerHTML = '';
  if (el.playbookCards) el.playbookCards.innerHTML = '';
  if (el.playbookHint) setHint(el.playbookHint, '');
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
    await window.refreshSafetyRules?.();
  } catch (err) {
    setHint(el.providerResult, err.message || '配置加载失败', 'error');
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

async function refreshSafetyRules() {
  const containerList = document.getElementById('safetyRuleList');
  const containerBuiltin = document.getElementById('builtinSafetyRules');
  try {
    const items = await api('/api/config/safety_gate');

    const builtinItems = items.filter(i => i.is_builtin);
    const customItems = items.filter(i => !i.is_builtin);

    containerBuiltin.innerHTML = '';
    builtinItems.forEach(i => {
      const span = document.createElement('span');
      span.className = 'badge-tag';
      span.title = i.description || '';
      span.textContent = i.target;
      containerBuiltin.appendChild(span);
    });

    renderList(containerList, customItems, (i) => {
      const typeLabel = i.rule_type === 'ip' ? 'IP' : i.rule_type === 'cidr' ? '网段' : '域名';
      return `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <div>
            <strong style="color:var(--sec-medium);">${i.target}</strong> <span style="font-size:0.85em; opacity:0.7">(${typeLabel})</span>
            <div style="font-size:0.85em; margin-top:4px; color:var(--text-main);">${i.description || '无备注'}</div>
          </div>
          <button data-delete-rule="${i.id}" class="secondary-btn" style="padding:4px 8px; font-size:0.85em;">删除红线</button>
        </div>
      `;
    });

    containerList.querySelectorAll('button[data-delete-rule]').forEach((btn) => {
      btn.onclick = async () => {
        const id = btn.getAttribute('data-delete-rule');
        try {
          await api(`/api/config/safety_gate/${id}`, { method: 'DELETE' });
          await refreshSafetyRules();
        } catch (err) {
          setHint(document.getElementById('safetyRuleResult'), err.message, 'error');
        }
      };
    });
  } catch (err) {
    containerList.textContent = '加载失败';
  }
}

// Sidebar Tab Switching
document.querySelectorAll('.settings-tab').forEach(tab => {
  tab.onclick = () => {
    document.querySelectorAll('.settings-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.settings-section').forEach(s => s.classList.remove('active'));
    tab.classList.add('active');
    const targetId = tab.getAttribute('data-tab');
    document.getElementById(targetId).classList.add('active');
  };
});

document.getElementById('safetyRuleForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const resultHint = document.getElementById('safetyRuleResult');
  try {
    if (!state.isAuthenticated) {
      setHint(resultHint, '请先登录平台。', 'error');
      return;
    }
    const payload = {
      rule_type: document.getElementById('safetyRuleType').value,
      target: document.getElementById('safetyRuleTarget').value.trim(),
      description: document.getElementById('safetyRuleDesc').value.trim() || undefined
    };

    await api('/api/config/safety_gate', { method: 'POST', body: JSON.stringify(payload) });
    setHint(resultHint, '安全防卫红线已添加。', 'success');
    document.getElementById('safetyRuleTarget').value = '';
    document.getElementById('safetyRuleDesc').value = '';
    await refreshSafetyRules();
  } catch (err) {
    setHint(resultHint, err.message, 'error');
  }
});


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

window.refreshSafetyRules = refreshSafetyRules;

el.chatForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const message = el.chatMessage.value.trim();
  if (!message) return;
  el.chatMessage.value = '';

  const userCard = cardTemplate('你', 'user');
  const pre = document.createElement('pre');
  pre.textContent = message;
  userCard.appendChild(pre);
  appendCard(userCard);

  await sendChat(message);
});


(async function init() {
  initProviderUI();
  renderPlaybookCards([]);
  await checkAuthStatus();
})();
