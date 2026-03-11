const state = {
  sessionId: `session-${Date.now()}`,
  isAuthenticated: false,
  xdrBaseUrl: '',
  playbookTemplates: [],
  coreAssets: [],
  activePlaybookRunId: null,
  playbookRunCache: {},
  routineBlockDraft: null,
  slashVisible: false,
  slashActiveIndex: 0,
  slashFiltered: [],
};

const DEFAULT_PLAYBOOK_SCENES = [
  {
    id: 'routine_check',
    name: '今日安全早报',
    button_label: '☕ 今日安全早报',
    description: '自动聚合过去24小时日志总量、未处置高危事件和样本证据，生成值班晨报。',
    hint: '适合每天交接班时快速掌握整体安全态势。',
    default_params: { window_hours: 24, sample_size: 3 },
  },
  {
    id: 'alert_triage',
    name: '单点告警深度研判',
    button_label: '🔎 单点告警深度研判',
    description: '围绕指定事件做实体画像、外部情报和内部影响计数，输出封禁/观察建议。',
    hint: '可在“事件查询”后按序号研判，或直接输入事件 UUID。',
    default_params: { window_days: 7, mode: 'analyze' },
  },
  {
    id: 'threat_hunting',
    name: '攻击者活动轨迹',
    button_label: '🎯 攻击者活动轨迹',
    description: '默认回溯90天并最多扫描1万条告警，生成攻击故事线和关键证据。',
    hint: '适合针对某个可疑 IP 做溯源汇报。',
    default_params: { window_days: 90, max_scan: 10000, evidence_limit: 20 },
  },
  {
    id: 'asset_guard',
    name: '核心资产防线透视',
    button_label: '🛡️ 核心资产防线透视',
    description: '围绕核心资产IP进行双向态势体检，输出管理层可读的风险摘要和建议动作。',
    hint: '适合给业务负责人做核心资产每日/每周态势汇报。',
    default_params: { window_hours: 24, top_external_ip: 5 },
  },
];

const SLASH_COMMANDS = [
  {
    id: 'routine_check',
    command: '/今日安全早报',
    aliases: ['/routine_check', '/早报'],
    description: '启动今日安全早报自动编排。',
  },
  {
    id: 'alert_triage',
    command: '/单点告警深度研判',
    aliases: ['/alert_triage', '/研判'],
    description: '围绕指定事件做深度研判并给出处置建议。',
  },
  {
    id: 'threat_hunting',
    command: '/攻击者活动轨迹',
    aliases: ['/threat_hunting', '/轨迹'],
    description: '生成攻击者活动轨迹与关键证据。',
  },
  {
    id: 'asset_guard',
    command: '/核心资产防线透视',
    aliases: ['/asset_guard', '/核心资产'],
    description: '围绕核心资产输出风险态势报告。',
  },
];

const PLAYBOOK_STAGE_META = {
  routine_check: {
    node_1_log_count_24h: { title: '统计日志总量', desc: '统计过去窗口期日志体量' },
    node_2_unhandled_high_events_24h: { title: '检索高危未处置事件', desc: '筛选需要优先关注的高危告警' },
    node_3_sample_detail_parallel: { title: '并行拉取样本证据', desc: '补充样本事件证据和实体信息' },
    node_4_llm_briefing: { title: '生成早报结论', desc: '输出面向值班交接的结论与建议' },
  },
  alert_triage: {
    analyze: {
      node_1_resolve_target: { title: '定位目标事件', desc: '解析事件ID/序号并锁定目标' },
      node_2_entity_profile: { title: '生成实体画像', desc: '抽取事件关联IP与画像信息' },
      node_3_external_intel: { title: '外部情报查询', desc: '补充ThreatBook或本地情报结果' },
      node_4_internal_impact_count_parallel: { title: '统计内部影响', desc: '计算影响面与风险得分' },
      node_5_llm_triage_summary: { title: '输出研判结论', desc: '给出处置建议和优先动作' },
    },
    block_ip: {
      node_1_resolve_target_ip: { title: '解析待封禁IP', desc: '从参数或事件实体定位目标IP' },
      node_2_build_block_approval: { title: '生成审批卡', desc: '进入高危操作人工审批链路' },
    },
  },
  threat_hunting: {
    node_1_external_profile: { title: '查询外部画像', desc: '获取目标IP外部威胁画像' },
    node_2_event_scan_paginated: { title: '双向扫描告警', desc: '回溯窗口内按源/目的IP检索相关告警' },
    node_3_evidence_enrichment_parallel: { title: '并行补充证据', desc: '拉取时间线和关联实体信息' },
    node_4_internal_activity_count: { title: '统计内部活动', desc: '按窗口统计源/目的活动量' },
    node_5_llm_timeline_story: { title: '生成活动轨迹故事线', desc: '输出侦察到影响的结构化叙事' },
  },
  asset_guard: {
    node_1_events_dst_asset: { title: '统计入向告警', desc: '分析以资产为目的的事件' },
    node_2_events_src_asset: { title: '统计出向告警', desc: '分析以资产为源的事件' },
    node_3_logs_dst_asset: { title: '统计入向访问', desc: '计算资产作为目的IP的访问量' },
    node_4_logs_src_asset: { title: '统计出向访问', desc: '计算资产作为源IP的访问量' },
    node_5_top_external_ip: { title: '提取外部Top实体', desc: '识别高频外部访问IP' },
    node_6_external_intel_enrich: { title: '情报画像增强', desc: '对外部Top实体执行情报查询' },
    node_7_llm_asset_briefing: { title: '生成管理层结论', desc: '输出核心资产态势结论与建议' },
  },
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

const IPV4_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const CVE_REGEX = /\bCVE-\d{4}-\d{4,7}\b/gi;
const RISK_SEVERITY_RANK = {
  严重: 4,
  高危: 3,
  中危: 2,
  低危: 1,
  信息: 0,
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
  threatbookApiKey: document.getElementById('threatbookApiKey'),
  threatbookEnabled: document.getElementById('threatbookEnabled'),
  threatbookTestIp: document.getElementById('threatbookTestIp'),
  threatbookResult: document.getElementById('threatbookResult'),
  coreAssetForm: document.getElementById('coreAssetForm'),
  coreAssetName: document.getElementById('coreAssetName'),
  coreAssetIp: document.getElementById('coreAssetIp'),
  coreAssetOwner: document.getElementById('coreAssetOwner'),
  coreAssetMeta: document.getElementById('coreAssetMeta'),
  coreAssetResult: document.getElementById('coreAssetResult'),
  coreAssetList: document.getElementById('coreAssetList'),

  chatForm: document.getElementById('chatForm'),
  chatMessage: document.getElementById('chatMessage'),
  chatStream: document.getElementById('chatStream'),
  slashCommandMenu: document.getElementById('slashCommandMenu'),
  playbookWorkspacePanel: document.getElementById('playbookWorkspacePanel'),
  playbookWorkspaceBody: document.getElementById('playbookWorkspaceBody'),
  closePlaybookWorkspaceBtn: document.getElementById('closePlaybookWorkspace'),
  playbookCards: document.getElementById('playbookCards'),
  playbookHint: document.getElementById('playbookHint'),
  dangerDialog: document.getElementById('dangerDialog'),
  dangerText: document.getElementById('dangerText'),
  routineBlockDialog: document.getElementById('routineBlockDialog'),
  routineBlockTitle: document.getElementById('routineBlockTitle'),
  routineBlockTargetList: document.getElementById('routineBlockTargetList'),
  routineBlockSkipped: document.getElementById('routineBlockSkipped'),
  routineBlockIntelBody: document.getElementById('routineBlockIntelBody'),
  routineBlockDevice: document.getElementById('routineBlockDevice'),
  routineBlockHours: document.getElementById('routineBlockHours'),
  routineBlockReason: document.getElementById('routineBlockReason'),
  routineBlockRuleName: document.getElementById('routineBlockRuleName'),
  routineBlockHint: document.getElementById('routineBlockHint'),
  routineBlockCancel: document.getElementById('routineBlockCancel'),
  routineBlockConfirm: document.getElementById('routineBlockConfirm'),
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
  if (!authenticated) {
    setPlaybookWorkspaceOpen(false);
    clearPlaybookWorkspace();
    state.activePlaybookRunId = null;
    state.playbookRunCache = {};
    hideSlashCommandMenu();
  }
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

function setPlaybookWorkspaceOpen(open) {
  if (!el.playbookWorkspacePanel || !el.workspaceView) return;
  el.playbookWorkspacePanel.classList.toggle('hidden', !open);
  el.workspaceView.classList.toggle('panel-open', open);
}

function clearPlaybookWorkspace() {
  if (!el.playbookWorkspaceBody) return;
  el.playbookWorkspaceBody.innerHTML = '';
  const empty = document.createElement('div');
  empty.className = 'playbook-workspace-empty';
  empty.textContent = '触发 Playbook 后将在此展示任务进度与完整报告。';
  el.playbookWorkspaceBody.appendChild(empty);
}

function appendPlaybookWorkspaceCard(node) {
  if (!el.playbookWorkspaceBody) return;
  const empty = el.playbookWorkspaceBody.querySelector('.playbook-workspace-empty');
  if (empty) empty.remove();
  el.playbookWorkspaceBody.appendChild(node);
  el.playbookWorkspaceBody.scrollTop = el.playbookWorkspaceBody.scrollHeight;
}

function getPlaybookDisplayName(templateId, fallback = '') {
  const fallbackName = String(fallback || '').trim();
  if (fallbackName) return fallbackName;
  const local = DEFAULT_PLAYBOOK_SCENES.find((scene) => scene.id === templateId)?.name;
  if (local) return local;
  const remote = state.playbookTemplates.find((tpl) => tpl.id === templateId)?.name;
  return remote || templateId || 'Playbook';
}

function renderPlaybookLaunchFeedback(templateId, triggerLabel = '', runId = null) {
  const displayName = getPlaybookDisplayName(templateId, triggerLabel);
  const card = cardTemplate('', 'playbook-launch-card');
  if (runId != null) {
    card.dataset.playbookRunId = String(runId);
  }

  const icon = document.createElement('div');
  icon.className = 'playbook-launch-icon';
  icon.textContent = '🖥️';
  card.appendChild(icon);

  const body = document.createElement('div');
  body.className = 'playbook-launch-body';

  const title = document.createElement('div');
  title.className = 'playbook-launch-title';
  title.textContent = `已为您启动“${displayName}”任务，请在右侧查看进度。`;
  body.appendChild(title);

  const desc = document.createElement('div');
  desc.className = 'playbook-launch-desc';
  desc.textContent = '您可以继续在此向我提问，不会打断任务执行。';
  body.appendChild(desc);
  card.appendChild(body);

  if (runId != null) {
    card.onclick = async () => {
      try {
        await openPlaybookRunById(runId, templateId, { resetWorkspace: true });
      } catch (err) {
        setHint(el.playbookHint, err.message || '加载 Playbook 运行状态失败', 'error');
      }
    };
  }

  appendCard(card);
}

async function openPlaybookRunById(runId, templateId = '', opts = {}) {
  if (!runId) return null;
  state.activePlaybookRunId = runId;
  setPlaybookWorkspaceOpen(true);
  if (opts.resetWorkspace !== false && el.playbookWorkspaceBody) {
    el.playbookWorkspaceBody.innerHTML = '';
  }

  const runData = await api(`/api/playbooks/runs/${runId}`);
  state.playbookRunCache[runId] = runData;
  const resolvedTemplateId = runData.template_id || templateId || 'unknown';
  const progressUi = createPlaybookProgressCard(runId, resolvedTemplateId);
  updatePlaybookProgress(progressUi, runData);

  if (runData.status === 'Finished' || runData.status === 'Failed') {
    renderPlaybookResult(runData);
    return runData;
  }

  const finalRun = await pollPlaybookRun(runId, progressUi, resolvedTemplateId);
  state.playbookRunCache[runId] = finalRun;
  if (state.activePlaybookRunId === runId) {
    renderPlaybookResult(finalRun);
  }
  return finalRun;
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
    card.appendChild(createMarkdownBlock(payload.data.text || ''));
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
    card.appendChild(createMarkdownBlock(payload.data.summary || ''));
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
  const displayName = getPlaybookDisplayName(templateId);
  const card = cardTemplate(`Playbook 运行中 · ${templateId}`);
  card.dataset.playbookRunId = String(runId);
  card.classList.add('playbook-progress-card', 'workspace-panel-card');
  card.dataset.playbookTemplate = templateId || '';

  const header = document.createElement('div');
  header.className = 'playbook-progress-header';
  const toggleBtn = document.createElement('button');
  toggleBtn.type = 'button';
  toggleBtn.className = 'playbook-progress-toggle';
  toggleBtn.textContent = '收起';
  header.appendChild(toggleBtn);
  card.appendChild(header);

  const sub = document.createElement('div');
  sub.className = 'playbook-progress-template';
  sub.textContent = displayName;
  card.appendChild(sub);

  const runMeta = document.createElement('div');
  runMeta.className = 'playbook-progress-meta';
  runMeta.textContent = `run_id: ${runId}`;
  card.appendChild(runMeta);

  const barWrap = document.createElement('div');
  barWrap.className = 'playbook-progress-bar';
  const barFill = document.createElement('div');
  barFill.className = 'playbook-progress-fill';
  barFill.style.width = '0%';
  barWrap.appendChild(barFill);
  card.appendChild(barWrap);

  const progressText = document.createElement('p');
  progressText.className = 'playbook-progress-text';
  progressText.textContent = '初始化中...';
  card.appendChild(progressText);

  const detailsWrap = document.createElement('div');
  detailsWrap.className = 'playbook-progress-details';
  card.appendChild(detailsWrap);

  const stageList = document.createElement('div');
  stageList.className = 'playbook-stage-list';
  detailsWrap.appendChild(stageList);

  const details = document.createElement('details');
  details.className = 'playbook-tech-details';
  const summary = document.createElement('summary');
  summary.textContent = '技术详情';
  details.appendChild(summary);
  const pre = document.createElement('pre');
  pre.textContent = `run_id=${runId}\n初始化中...`;
  details.appendChild(pre);
  detailsWrap.appendChild(details);

  const progressUi = {
    card,
    pre,
    stageList,
    progressText,
    barFill,
    detailsWrap,
    toggleBtn,
    userCollapsed: false,
    autoCollapsed: false,
  };

  toggleBtn.onclick = () => {
    const nextCollapsed = !detailsWrap.classList.contains('collapsed');
    progressUi.userCollapsed = nextCollapsed;
    progressUi.autoCollapsed = false;
    detailsWrap.classList.toggle('collapsed', nextCollapsed);
    toggleBtn.textContent = nextCollapsed ? '展开详情' : '收起';
  };

  appendPlaybookWorkspaceCard(card);
  return progressUi;
}

function getStageMeta(templateId, runData) {
  const input = runData?.input?.params || {};
  if (templateId === 'alert_triage') {
    const mode = input.mode === 'block_ip' ? 'block_ip' : 'analyze';
    return PLAYBOOK_STAGE_META.alert_triage[mode] || {};
  }
  return PLAYBOOK_STAGE_META[templateId] || {};
}

function mapNodeStatus(status) {
  const normalized = String(status || 'Pending');
  if (normalized === 'Running') return { text: '执行中', className: 'running' };
  if (normalized === 'Finished') return { text: '已完成', className: 'finished' };
  if (normalized === 'Failed') return { text: '失败', className: 'failed' };
  return { text: '等待中', className: 'pending' };
}

function simplifyError(errorText) {
  if (!errorText) return '';
  const text = String(errorText).trim();
  if (text.includes("'nodes'")) return '依赖节点尚未就绪';
  if (text === '0') return '接口返回数据格式异常（缺少预期字段）';
  if (text.length <= 80) return text;
  return `${text.slice(0, 80)}...`;
}

function updatePlaybookProgress(progressUi, runData) {
  const nodeStatus = runData?.context?.node_status || {};
  const progress = runData?.context?.progress || {};
  const total = progress.total || Object.keys(nodeStatus).length || 0;
  const finished = progress.finished || 0;
  const percent = total > 0 ? Math.round((finished / total) * 100) : 0;
  progressUi.barFill.style.width = `${Math.max(0, Math.min(100, percent))}%`;

  const statusText = mapNodeStatus(runData?.status).text;
  progressUi.progressText.textContent = `状态：${statusText} · 进度：${finished}/${total}`;
  const completed = runData?.status === 'Finished' || runData?.status === 'Failed';
  if (completed && !progressUi.userCollapsed && !progressUi.autoCollapsed) {
    progressUi.autoCollapsed = true;
    progressUi.detailsWrap.classList.add('collapsed');
    progressUi.toggleBtn.textContent = '展开详情';
  } else if (!completed && !progressUi.userCollapsed) {
    progressUi.autoCollapsed = false;
    progressUi.detailsWrap.classList.remove('collapsed');
    progressUi.toggleBtn.textContent = '收起';
  }

  const stageMeta = getStageMeta(runData?.template_id, runData);
  const orderedNodeIds = Object.keys(stageMeta).length ? Object.keys(stageMeta) : Object.keys(nodeStatus);
  Object.keys(nodeStatus).forEach((nodeId) => {
    if (!orderedNodeIds.includes(nodeId)) orderedNodeIds.push(nodeId);
  });
  progressUi.stageList.innerHTML = '';
  orderedNodeIds.forEach((nodeId) => {
    const info = nodeStatus[nodeId] || {};
    const statusInfo = mapNodeStatus(info.status);
    const stage = document.createElement('div');
    stage.className = `playbook-stage-item stage-${statusInfo.className}`;

    const left = document.createElement('div');
    left.className = 'playbook-stage-main';
    const title = document.createElement('div');
    title.className = 'playbook-stage-title';
    title.textContent = stageMeta[nodeId]?.title || '后台任务';
    const desc = document.createElement('div');
    desc.className = 'playbook-stage-desc';
    desc.textContent = stageMeta[nodeId]?.desc || nodeId;
    left.appendChild(title);
    left.appendChild(desc);

    if (info?.error) {
      const err = document.createElement('div');
      err.className = 'playbook-stage-error';
      err.textContent = `失败原因：${simplifyError(info.error)}`;
      left.appendChild(err);
    }

    const badge = document.createElement('span');
    badge.className = `playbook-stage-badge badge-${statusInfo.className}`;
    badge.textContent = statusInfo.text;

    stage.appendChild(left);
    stage.appendChild(badge);
    progressUi.stageList.appendChild(stage);
  });

  const lines = [`状态: ${runData.status}`, `run_id: ${runData.run_id}`, `进度: ${finished}/${total}`];
  Object.entries(nodeStatus).forEach(([nodeId, info]) => {
    const rawStatus = info?.status || 'Pending';
    const rawError = info?.error ? ` (error: ${info.error})` : '';
    lines.push(`- ${nodeId}: ${rawStatus}${rawError}`);
  });
  progressUi.pre.textContent = lines.join('\n');
}

function payloadText(payload) {
  return payload?.type === 'text' ? String(payload?.data?.text || '').trim() : '';
}

function isSummaryDuplicated(summary, cards) {
  if (!summary || !cards?.length) return false;
  const firstText = payloadText(cards[0]);
  return !!firstText && firstText === String(summary).trim();
}

function escapeHtml(raw) {
  return String(raw ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatInlineMarkdown(text) {
  let html = escapeHtml(text);
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  return html;
}

function markdownToHtml(text) {
  const normalized = String(text || '')
    .replace(/\r\n/g, '\n')
    .replace(/([^\n])\n([：:]\s+)/g, '$1 $2')
    .replace(/^\s*[。]\s+/gm, '- ');
  const lines = normalized.split('\n');
  const html = [];
  let inUl = false;
  let inOl = false;

  function closeLists() {
    if (inUl) {
      html.push('</ul>');
      inUl = false;
    }
    if (inOl) {
      html.push('</ol>');
      inOl = false;
    }
  }

  lines.forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) {
      closeLists();
      return;
    }
    if (trimmed === ':' || trimmed === '：') {
      return;
    }

    if (trimmed === '---') {
      closeLists();
      html.push('<hr />');
      return;
    }

    const heading = trimmed.match(/^(#{1,6})\s+(.+)$/);
    if (heading) {
      closeLists();
      const level = heading[1].length;
      html.push(`<h${level}>${formatInlineMarkdown(heading[2])}</h${level}>`);
      return;
    }

    const quote = trimmed.match(/^>\s?(.+)$/);
    if (quote) {
      closeLists();
      html.push(`<blockquote>${formatInlineMarkdown(quote[1])}</blockquote>`);
      return;
    }

    const ul = trimmed.match(/^[-*•●◦▪]\s+(.+)$/);
    if (ul) {
      if (!inUl) {
        if (inOl) {
          html.push('</ol>');
          inOl = false;
        }
        html.push('<ul>');
        inUl = true;
      }
      html.push(`<li>${formatInlineMarkdown(ul[1])}</li>`);
      return;
    }

    const colonContinuation = trimmed.match(/^[:：]\s*(.+)$/);
    if (colonContinuation) {
      closeLists();
      html.push(`<p>${formatInlineMarkdown(colonContinuation[1])}</p>`);
      return;
    }

    const ol = trimmed.match(/^\d+\.\s+(.+)$/);
    if (ol) {
      if (!inOl) {
        if (inUl) {
          html.push('</ul>');
          inUl = false;
        }
        html.push('<ol>');
        inOl = true;
      }
      html.push(`<li>${formatInlineMarkdown(ol[1])}</li>`);
      return;
    }

    closeLists();
    html.push(`<p>${formatInlineMarkdown(trimmed)}</p>`);
  });

  closeLists();
  return html.join('');
}

function createMarkdownBlock(text) {
  const block = document.createElement('div');
  block.className = 'markdown-block';
  block.innerHTML = markdownToHtml(text);
  return block;
}

function createUnifiedTable(payload, customRows = null) {
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
  const rows = Array.isArray(customRows) ? customRows : (payload.data.rows || []);
  rows.forEach((row) => {
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
  return wrap;
}

function mountDeferredCharts(container) {
  const charts = container.querySelectorAll('[data-echarts-deferred="1"]');
  charts.forEach((chart) => {
    if (chart.__echartsInstance) return;
    const instance = echarts.init(chart);
    instance.setOption(chart.__echartsOption || {});
    chart.__echartsInstance = instance;
    window.addEventListener('resize', () => instance.resize());
  });
}

function createPlaybookActionButton(action) {
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
      appendPlaybookWorkspaceCard(errorCard);
    } finally {
      btn.disabled = false;
    }
  };
  return btn;
}

function toMetricNumber(value) {
  const num = Number(value);
  if (!Number.isFinite(num)) return 0;
  return Math.max(0, Math.round(num));
}

function formatMetric(value) {
  return toMetricNumber(value).toLocaleString('zh-CN');
}

function dedupText(values) {
  const arr = Array.isArray(values) ? values : [];
  const cleaned = arr.map((item) => String(item || '').trim()).filter(Boolean);
  return [...new Set(cleaned)];
}

function isValidIpv4(ip) {
  const parts = String(ip || '').trim().split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d+$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function isPrivateIpv4(ip) {
  if (!isValidIpv4(ip)) return false;
  const [a, b] = String(ip).split('.').map((n) => Number(n));
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

function extractIpv4List(text) {
  const found = String(text || '').match(IPV4_REGEX) || [];
  return dedupText(found.filter((ip) => isValidIpv4(ip)));
}

function extractCveList(...texts) {
  const list = [];
  texts.forEach((text) => {
    const found = String(text || '').match(CVE_REGEX) || [];
    found.forEach((cve) => list.push(String(cve).toUpperCase()));
  });
  return dedupText(list);
}

function normalizeSeverity(value) {
  const text = String(value || '').trim();
  if (text.includes('严重')) return '严重';
  if (text.includes('高危') || text === '高') return '高危';
  if (text.includes('中危') || text === '中') return '中危';
  if (text.includes('低危') || text === '低') return '低危';
  return '信息';
}

function severityRank(value) {
  return RISK_SEVERITY_RANK[normalizeSeverity(value)] ?? 0;
}

function classifyRiskType(row, cves) {
  const text = `${row?.name || ''} ${row?.description || ''}`.toLowerCase();
  if (cves.length) return '漏洞利用';
  if (text.includes('webshell') || text.includes('后门') || text.includes('冰蝎')) return '后门植入';
  if (text.includes('反序列化')) return '反序列化攻击';
  if (text.includes('java')) return 'Java 应用攻击';
  if (text.includes('rce') || text.includes('远程代码执行')) return 'RCE 远程代码执行';
  if (text.includes('扫描')) return '扫描攻击';
  return '异常攻击行为';
}

function parseHighEventTotal(cards, fallback = 0) {
  const textCards = (cards || []).filter((card) => card?.type === 'text');
  for (const card of textCards) {
    const text = String(card?.data?.text || '');
    const match = text.match(/总数[：:]\s*(?:\*\*)?(\d+)/);
    if (match) return toMetricNumber(match[1]);
  }
  return toMetricNumber(fallback);
}

function parseLogTotal(cards, summary = '') {
  const chart = (cards || []).find((card) => card?.type === 'echarts_graph');
  const fromChartSummary = String(chart?.data?.summary || '').match(/(\d[\d,]*)/);
  if (fromChartSummary) return toMetricNumber(fromChartSummary[1].replace(/,/g, ''));
  const fromSummary = String(summary || '').match(/安全日志\s*([\d,]+)/);
  if (fromSummary) return toMetricNumber(fromSummary[1].replace(/,/g, ''));
  return 0;
}

function buildRoutineCheckViewModel(runData) {
  const result = runData?.result || {};
  const cards = Array.isArray(result.cards) ? result.cards : [];
  const summary = String(result.summary || '').trim();
  const tableCard = cards.find(
    (card) => card?.type === 'table' && String(card?.data?.title || '').includes('未处置高危事件'),
  ) || cards.find((card) => card?.type === 'table');
  const chartCard = cards.find((card) => card?.type === 'echarts_graph');
  const rows = Array.isArray(tableCard?.data?.rows) ? tableCard.data.rows : [];
  const resultBlockTargets = result?.block_targets || {};

  const highEventTotal = parseHighEventTotal(cards, rows.length);
  const logTotal = parseLogTotal(cards, summary);

  const assetCount = new Map();
  rows.forEach((row) => {
    const ip = String(row?.hostIp || '').trim();
    if (!isValidIpv4(ip)) return;
    assetCount.set(ip, (assetCount.get(ip) || 0) + 1);
  });
  const affectedAssets = assetCount.size;

  const trendRawValues = Array.isArray(chartCard?.data?.option?.series?.[0]?.data)
    ? chartCard.data.option.series[0].data
    : [];
  const trendRawLabels = Array.isArray(chartCard?.data?.option?.xAxis?.data)
    ? chartCard.data.option.xAxis.data
    : [];
  const trendValues = trendRawValues.slice(-7).map((value) => toMetricNumber(value));
  const trendLabels = trendRawLabels.slice(-7).map((label) => String(label || '').slice(5, 10));
  while (trendValues.length < 7) trendValues.unshift(0);
  while (trendLabels.length < 7) trendLabels.unshift('--');

  const avgAssetCount = affectedAssets ? rows.length / affectedAssets : 0;
  const topAssets = [...assetCount.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([ip, count]) => {
      const diff = avgAssetCount > 0 ? Math.round(((count - avgAssetCount) / avgAssetCount) * 100) : 0;
      const trend = `${diff >= 0 ? '+' : ''}${diff}%`;
      return { ip, count, trend };
    });

  const grouped = new Map();
  rows.forEach((row) => {
    const key = String(row?.name || row?.uuId || '').trim() || `risk-${grouped.size + 1}`;
    const cves = extractCveList(row?.name, row?.description);
    const current = grouped.get(key) || {
      id: key,
      title: row?.name || '未知风险',
      severity: normalizeSeverity(row?.incidentSeverity),
      type: classifyRiskType(row, cves),
      desc: String(row?.description || '').trim(),
      assets: [],
      cves: [],
      count: 0,
    };
    current.count += 1;
    current.severity = severityRank(row?.incidentSeverity) > severityRank(current.severity)
      ? normalizeSeverity(row?.incidentSeverity)
      : current.severity;
    const hostIp = String(row?.hostIp || '').trim();
    if (isValidIpv4(hostIp)) current.assets.push(hostIp);
    current.cves = dedupText([...(current.cves || []), ...cves]);
    if (!current.desc) current.desc = String(row?.description || '').trim();
    grouped.set(key, current);
  });

  const risks = [...grouped.values()]
    .map((risk, index) => ({
      ...risk,
      id: `R${index + 1}`,
      assets: dedupText(risk.assets).slice(0, 6),
      cve: risk.cves[0] || '',
      desc: risk.desc || '该风险暂无补充描述，请在 XDR 平台查看完整事件详情。',
    }))
    .sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || b.count - a.count)
    .slice(0, 3);

  const hostIps = new Set([...assetCount.keys()]);
  const sourceCandidates = [];
  const outboundCandidates = [];
  rows.forEach((row) => {
    const srcIp = String(row?.srcIp || '').trim();
    const dstIp = String(row?.dstIp || '').trim();
    if (isValidIpv4(srcIp)) {
      sourceCandidates.push(srcIp);
    }
    if (isValidIpv4(dstIp)) {
      outboundCandidates.push(dstIp);
    }
    extractIpv4List(`${row?.name || ''} ${row?.description || ''}`).forEach((ip) => sourceCandidates.push(ip));
  });
  (result.next_actions || []).forEach((action) => {
    const params = action?.params || {};
    if (isValidIpv4(params?.ip)) sourceCandidates.push(params.ip);
    (params?.ips || []).forEach((ip) => sourceCandidates.push(ip));
  });
  const sourceIpsFromResult = dedupText(resultBlockTargets?.source_ips || []).filter((ip) => isValidIpv4(ip));
  let sourceIps = dedupText(sourceCandidates).filter((ip) => isValidIpv4(ip) && !hostIps.has(ip) && !isPrivateIpv4(ip));
  if (!sourceIps.length) {
    sourceIps = dedupText(sourceCandidates).filter((ip) => isValidIpv4(ip) && !hostIps.has(ip));
  }
  if (sourceIpsFromResult.length) {
    sourceIps = sourceIpsFromResult;
  }
  sourceIps = sourceIps.slice(0, 3);

  const outboundIpsFromResult = dedupText(resultBlockTargets?.outbound_ips || []).filter((ip) => isValidIpv4(ip));
  let outboundIps = dedupText(outboundCandidates).filter((ip) => isValidIpv4(ip) && !hostIps.has(ip) && !isPrivateIpv4(ip));
  if (!outboundIps.length) {
    outboundIps = dedupText(outboundCandidates).filter((ip) => isValidIpv4(ip) && !hostIps.has(ip));
  }
  if (outboundIpsFromResult.length) {
    outboundIps = outboundIpsFromResult;
  }
  outboundIps = outboundIps.slice(0, 3);

  const isolateHosts = risks
    .filter((risk) => severityRank(risk.severity) >= severityRank('高危'))
    .flatMap((risk) => risk.assets)
    .filter((ip) => isValidIpv4(ip));
  const fallbackIsolate = [...hostIps];
  const isolateItems = dedupText(isolateHosts.length ? isolateHosts : fallbackIsolate).slice(0, 3);

  const vulnItems = [];
  risks.forEach((risk) => {
    if (!risk.cve) return;
    (risk.assets || []).forEach((ip) => vulnItems.push(`${ip} (${risk.cve})`));
  });
  if (!vulnItems.length) {
    rows.slice(0, 3).forEach((row) => {
      const cve = extractCveList(row?.name, row?.description)[0];
      const ip = String(row?.hostIp || '').trim();
      if (cve && isValidIpv4(ip)) vulnItems.push(`${ip} (${cve})`);
    });
  }

  const dayText = (() => {
    const t = runData?.finished_at || runData?.started_at;
    const date = t ? new Date(t) : new Date();
    if (Number.isNaN(date.getTime())) return new Date().toISOString().slice(0, 10);
    return date.toISOString().slice(0, 10);
  })();

  return {
    dayText,
    summary,
    logTotal,
    highEventTotal,
    affectedAssets,
    trendLabels,
    trendValues,
    topAssets,
    risks,
    sourceIps,
    outboundIps,
    isolateItems,
    vulnItems: dedupText(vulnItems).slice(0, 3),
    nextActions: Array.isArray(result.next_actions) ? result.next_actions : [],
  };
}

async function copyTextCompat(value) {
  const text = String(value || '').trim();
  if (!text) return false;
  if (navigator?.clipboard?.writeText && window.isSecureContext) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // fallback below
    }
  }
  try {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.setAttribute('readonly', 'readonly');
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    textarea.style.left = '-9999px';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    const ok = document.execCommand('copy');
    textarea.remove();
    return !!ok;
  } catch {
    return false;
  }
}

async function handleCopyText(value) {
  const ok = await copyTextCompat(value);
  if (ok) {
    setHint(el.playbookHint, `已复制：${value}`, 'success');
    return;
  }
  setHint(el.playbookHint, '复制失败，请手动复制。', 'error');
}

function createRoutineCopyTag(text) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'routine-copy-tag';
  const value = String(text || '').trim();
  btn.textContent = value;
  btn.title = `点击复制 ${value}`;
  btn.onclick = async () => {
    await handleCopyText(value);
  };
  return btn;
}

function createRoutineCopyMiniButton(text) {
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'routine-copy-mini-btn';
  btn.textContent = '复制';
  const value = String(text || '').trim();
  btn.title = `复制 ${value}`;
  btn.onclick = async (event) => {
    event.preventDefault();
    event.stopPropagation();
    await handleCopyText(value);
  };
  return btn;
}

function buildRoutineActionItem(action) {
  const wrapper = document.createElement('div');
  wrapper.className = 'routine-action-item';

  const head = document.createElement('div');
  head.className = 'routine-action-head';
  const title = document.createElement('p');
  title.className = 'routine-action-title';
  title.textContent = action.title;
  const type = document.createElement('span');
  type.className = 'routine-action-type';
  type.textContent = action.type;
  head.appendChild(title);
  head.appendChild(type);
  wrapper.appendChild(head);

  const impact = document.createElement('div');
  impact.className = 'routine-action-impact';
  impact.textContent = `影响：${action.impact}`;
  wrapper.appendChild(impact);

  const listTitle = document.createElement('p');
  listTitle.className = 'routine-action-list-title';
  listTitle.textContent = '拟处理/排查对象清单';
  wrapper.appendChild(listTitle);

  const list = document.createElement('div');
  list.className = 'routine-action-list';
  (action.items || []).forEach((item) => {
    const line = document.createElement('div');
    line.className = 'routine-action-list-item';
    const textNode = document.createElement('span');
    textNode.className = 'routine-action-list-text';
    textNode.textContent = item;
    line.appendChild(textNode);
    const ips = extractIpv4List(item);
    if (ips.length) {
      line.classList.add('has-copy');
      line.appendChild(createRoutineCopyMiniButton(ips[0]));
    }
    list.appendChild(line);
  });
  wrapper.appendChild(list);

  if (action.buttonText) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'routine-action-btn';
    btn.textContent = action.buttonText;
    if (action.disabled) btn.disabled = true;
    if (typeof action.onClick === 'function') {
      btn.onclick = async () => {
        if (action.disabled) return;
        btn.disabled = true;
        try {
          await action.onClick();
        } finally {
          btn.disabled = !!action.disabled;
        }
      };
    }
    wrapper.appendChild(btn);
  }
  return wrapper;
}

async function executeRoutineBlockSources(ips, opts = {}) {
  if (!ips.length) {
    throw new Error('未识别到可处置的目标 IP。');
  }
  const payload = {
    session_id: state.sessionId,
    ips,
    block_type: opts.blockType || 'SRC_IP',
    reason: opts.reason || '由安全早报一键处置触发',
    duration_hours: Math.max(1, Math.min(360, Number(opts.durationHours) || 24)),
    device_id: opts.deviceId || null,
    rule_name: opts.ruleName || null,
  };
  const response = await api('/api/playbooks/routine-check/block-sources', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
  return response;
}

async function fetchRoutineBlockPreview(ips, blockType = 'SRC_IP') {
  return api('/api/playbooks/routine-check/block-preview', {
    method: 'POST',
    body: JSON.stringify({
      session_id: state.sessionId,
      ips,
      block_type: blockType,
    }),
  });
}

function resetRoutineBlockDialog() {
  if (el.routineBlockTargetList) el.routineBlockTargetList.innerHTML = '';
  if (el.routineBlockIntelBody) el.routineBlockIntelBody.innerHTML = '';
  if (el.routineBlockDevice) el.routineBlockDevice.innerHTML = '';
  if (el.routineBlockSkipped) {
    el.routineBlockSkipped.classList.add('hidden');
    el.routineBlockSkipped.textContent = '';
  }
  if (el.routineBlockHint) {
    el.routineBlockHint.classList.remove('success', 'error');
    el.routineBlockHint.textContent = '';
  }
}

function setRoutineBlockHint(message, type = '') {
  if (!el.routineBlockHint) return;
  el.routineBlockHint.textContent = message || '';
  el.routineBlockHint.classList.remove('success', 'error');
  if (type) el.routineBlockHint.classList.add(type);
}

function removeRoutineBlockIp(ip) {
  if (!state.routineBlockDraft) return;
  state.routineBlockDraft.selectedIps = (state.routineBlockDraft.selectedIps || []).filter((item) => item !== ip);
  renderRoutineBlockDialogContent();
}

function createRoutineTargetChip(ip) {
  const chip = document.createElement('div');
  chip.className = 'routine-block-target-chip';
  const text = document.createElement('span');
  text.className = 'routine-block-target-text';
  text.textContent = ip;
  chip.appendChild(text);
  chip.appendChild(createRoutineCopyMiniButton(ip));
  const removeBtn = document.createElement('button');
  removeBtn.type = 'button';
  removeBtn.className = 'routine-block-remove-btn';
  removeBtn.textContent = '移除';
  removeBtn.onclick = (event) => {
    event.preventDefault();
    event.stopPropagation();
    removeRoutineBlockIp(ip);
  };
  chip.appendChild(removeBtn);
  return chip;
}

function renderRoutineBlockDialogContent() {
  const draft = state.routineBlockDraft;
  if (!draft) return;
  const selectedIps = draft.selectedIps || [];
  if (el.routineBlockTitle) {
    el.routineBlockTitle.textContent = `${draft.actionTitle || '一键处置'}（${selectedIps.length}个目标）`;
  }
  if (el.routineBlockTargetList) {
    el.routineBlockTargetList.innerHTML = '';
    selectedIps.forEach((ip) => {
      el.routineBlockTargetList.appendChild(createRoutineTargetChip(ip));
    });
    if (!selectedIps.length) {
      const empty = document.createElement('span');
      empty.className = 'routine-block-empty';
      empty.textContent = '暂无待下发目标，请至少保留一个IP。';
      el.routineBlockTargetList.appendChild(empty);
    }
  }
  if (el.routineBlockIntelBody) {
    el.routineBlockIntelBody.innerHTML = '';
    selectedIps.forEach((ip) => {
      const row = (draft.intelRowsByIp || {})[ip] || {};
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>${ip}</td>
        <td>${row.severity || '-'}</td>
        <td>${row.confidence || '-'}</td>
        <td>${row.tags || '-'}</td>
        <td>${row.source || '-'}</td>
        <td>${row.suggestion || '建议观察'}</td>
        <td><button type="button" class="routine-table-remove-btn">移除</button></td>
      `;
      const removeBtn = tr.querySelector('.routine-table-remove-btn');
      if (removeBtn) {
        removeBtn.onclick = () => {
          removeRoutineBlockIp(ip);
        };
      }
      el.routineBlockIntelBody.appendChild(tr);
    });
    if (!selectedIps.length) {
      const tr = document.createElement('tr');
      tr.innerHTML = '<td colspan="7">暂无待下发目标，请先保留至少一个IP。</td>';
      el.routineBlockIntelBody.appendChild(tr);
    }
  }

  const hasOnlineDevice = Array.isArray(draft.deviceOptions) && draft.deviceOptions.length > 0;
  if (el.routineBlockConfirm) {
    el.routineBlockConfirm.disabled = !hasOnlineDevice || !selectedIps.length;
  }
  if (!selectedIps.length) {
    setRoutineBlockHint('请至少保留一个目标IP后再下发。', 'error');
  } else if (!hasOnlineDevice) {
    setRoutineBlockHint('当前没有在线AF联动设备，暂无法直接下发。', 'error');
  } else {
    setRoutineBlockHint('请核对威胁情报、设备与封禁时长后下发。', '');
  }
}

function buildDefaultRuleName(prefix = 'routine') {
  const now = new Date();
  const pad = (v) => String(v).padStart(2, '0');
  const ts = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}${pad(now.getHours())}${pad(now.getMinutes())}`;
  return `Flux_${prefix}_${ts}`;
}

async function openRoutineBlockDialog(config) {
  if (!el.routineBlockDialog) return;
  const ips = Array.isArray(config?.ips) ? config.ips : [];
  if (!ips.length) {
    setHint(el.playbookHint, config?.emptyMessage || '当前没有可下发封禁的目标 IP。', 'error');
    return;
  }

  try {
    resetRoutineBlockDialog();
    setRoutineBlockHint('正在加载在线设备与威胁情报...', '');
    const preview = await fetchRoutineBlockPreview(ips, config.blockType || 'SRC_IP');
    const targets = preview?.ips || [];
    if (!targets.length) {
      setHint(el.playbookHint, '目标 IP 均已被安全防线保护，无法下发封禁。', 'error');
      return;
    }

    const intelRows = preview?.intel_rows || [];
    const intelRowsByIp = {};
    intelRows.forEach((row) => {
      const ip = String(row?.ip || '').trim();
      if (!ip) return;
      intelRowsByIp[ip] = row;
    });
    const devices = preview?.device_options || [];

    state.routineBlockDraft = {
      actionTitle: config.actionTitle || '一键处置',
      resultTitle: config.resultTitle || '网侧封禁结果',
      blockType: preview.block_type || config.blockType || 'SRC_IP',
      allIps: [...targets],
      selectedIps: [...targets],
      skippedIps: preview.skipped_ips || [],
      deviceOptions: devices,
      intelRowsByIp,
    };

    const skipped = preview?.skipped_ips || [];
    if (el.routineBlockSkipped && skipped.length) {
      el.routineBlockSkipped.classList.remove('hidden');
      el.routineBlockSkipped.textContent = `已自动过滤受保护IP：${skipped.join('、')}`;
    }

    if (el.routineBlockDevice) {
      el.routineBlockDevice.innerHTML = '';
      devices.forEach((item) => {
        const option = document.createElement('option');
        option.value = item.device_id;
        option.textContent = `${item.device_name} (${item.device_id})`;
        el.routineBlockDevice.appendChild(option);
      });
      if (!devices.length) {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = '暂无在线AF设备';
        el.routineBlockDevice.appendChild(option);
      }
    }

    if (el.routineBlockHours) el.routineBlockHours.value = '24';
    if (el.routineBlockReason) {
      el.routineBlockReason.value = config.defaultReason || '由安全早报一键处置触发';
    }
    if (el.routineBlockRuleName) {
      el.routineBlockRuleName.value = buildDefaultRuleName(config.blockType === 'DST_IP' ? 'outbound' : 'source');
    }
    renderRoutineBlockDialogContent();
    openDialog(el.routineBlockDialog);
  } catch (err) {
    setHint(el.playbookHint, err.message || '加载封禁预览失败', 'error');
  }
}

async function submitRoutineBlockDialog() {
  if (!state.routineBlockDraft) return;
  const selectedIps = state.routineBlockDraft.selectedIps || [];
  if (!selectedIps.length) {
    setRoutineBlockHint('请至少保留一个目标IP后再下发。', 'error');
    return;
  }
  const deviceId = String(el.routineBlockDevice?.value || '').trim();
  if (!deviceId) {
    setRoutineBlockHint('请选择在线联动设备。', 'error');
    return;
  }
  const hours = Math.max(1, Math.min(360, Number(el.routineBlockHours?.value) || 24));
  const reason = String(el.routineBlockReason?.value || '').trim() || '由安全早报一键处置触发';
  const ruleName = String(el.routineBlockRuleName?.value || '').trim() || null;
  if (el.routineBlockConfirm) el.routineBlockConfirm.disabled = true;
  try {
    const data = await executeRoutineBlockSources(selectedIps, {
      blockType: state.routineBlockDraft.blockType,
      reason,
      durationHours: hours,
      deviceId,
      ruleName,
    });
    closeDialog(el.routineBlockDialog);
    setHint(el.playbookHint, data.message || '封禁执行成功。', 'success');
    const resultCard = cardTemplate(state.routineBlockDraft.resultTitle || '网侧封禁结果');
    const selectedText = selectedIps.length ? `\n\n已下发目标IP：${selectedIps.join('、')}` : '';
    const filteredText = (state.routineBlockDraft.skippedIps || []).length
      ? `\n\n已自动跳过受保护IP：${state.routineBlockDraft.skippedIps.join('、')}`
      : '';
    resultCard.appendChild(createMarkdownBlock(`${data.message || '已完成下发。'}${selectedText}${filteredText}`));
    appendPlaybookWorkspaceCard(resultCard);
    state.routineBlockDraft = null;
  } catch (err) {
    setRoutineBlockHint(err.message || '下发失败，请检查参数。', 'error');
  } finally {
    if (el.routineBlockConfirm && state.routineBlockDraft) {
      const hasOnlineDevice = Array.isArray(state.routineBlockDraft.deviceOptions) && state.routineBlockDraft.deviceOptions.length > 0;
      const selectedIpsNow = state.routineBlockDraft.selectedIps || [];
      el.routineBlockConfirm.disabled = !hasOnlineDevice || !selectedIpsNow.length;
    }
  }
}

function renderRoutineFollowupCard(nextActions) {
  if (!nextActions || !nextActions.length) return;
  const card = cardTemplate('', '');
  card.classList.add('playbook-task-card', 'workspace-panel-card', 'routine-followup-card');

  const title = document.createElement('h4');
  title.className = 'routine-followup-title';
  title.textContent = '下一步动作推荐';
  card.appendChild(title);

  const row = document.createElement('div');
  row.className = 'action-row playbook-next-actions';
  nextActions.forEach((action) => row.appendChild(createPlaybookActionButton(action)));
  card.appendChild(row);

  appendPlaybookWorkspaceCard(card);
}

function renderRoutineCheckCard(runData) {
  const vm = buildRoutineCheckViewModel(runData);
  const card = cardTemplate('', '');
  card.classList.add('playbook-unified-report', 'playbook-task-card', 'workspace-panel-card', 'routine-report-card');

  const header = document.createElement('div');
  header.className = 'routine-report-header';
  const titleWrap = document.createElement('div');
  const title = document.createElement('h3');
  title.className = 'routine-report-title';
  title.textContent = 'Playbook 安全日报';
  const dateBadge = document.createElement('span');
  dateBadge.className = 'routine-report-date';
  dateBadge.textContent = vm.dayText;
  title.appendChild(dateBadge);
  titleWrap.appendChild(title);
  const subtitle = document.createElement('p');
  subtitle.className = 'routine-report-subtitle';
  subtitle.textContent = '根据最新威胁情报生成的自动化处置建议';
  titleWrap.appendChild(subtitle);
  header.appendChild(titleWrap);
  card.appendChild(header);

  const stats = document.createElement('div');
  stats.className = 'routine-stats-grid';
  [
    { label: '需要优先关注的事件', value: formatMetric(vm.highEventTotal), className: 'risk' },
    { label: '今日安全日志', value: formatMetric(vm.logTotal), className: 'log' },
    { label: '受影响资产数', value: formatMetric(vm.affectedAssets), className: 'asset' },
  ].forEach((item) => {
    const stat = document.createElement('div');
    stat.className = `routine-stat-card ${item.className}`;
    const label = document.createElement('p');
    label.className = 'routine-stat-label';
    label.textContent = item.label;
    const value = document.createElement('p');
    value.className = 'routine-stat-value';
    value.textContent = item.value;
    stat.appendChild(label);
    stat.appendChild(value);
    stats.appendChild(stat);
  });
  card.appendChild(stats);

  const mainGrid = document.createElement('div');
  mainGrid.className = 'routine-main-grid';
  const left = document.createElement('div');
  left.className = 'routine-left-column';
  const right = document.createElement('div');
  right.className = 'routine-right-column';
  mainGrid.appendChild(left);
  mainGrid.appendChild(right);
  card.appendChild(mainGrid);

  const trendBox = document.createElement('section');
  trendBox.className = 'routine-panel';
  const trendTitle = document.createElement('h4');
  trendTitle.className = 'routine-panel-title';
  trendTitle.textContent = '近期安全态势趋势 (近7段)';
  trendBox.appendChild(trendTitle);
  const bars = document.createElement('div');
  bars.className = 'routine-trend-bars';
  const maxVal = Math.max(...vm.trendValues, 1);
  vm.trendValues.forEach((value, index) => {
    const col = document.createElement('div');
    col.className = 'routine-trend-col';
    const bar = document.createElement('div');
    bar.className = `routine-trend-bar ${index === vm.trendValues.length - 1 ? 'current' : ''}`;
    const ratio = Math.max(6, Math.round((value / maxVal) * 100));
    bar.style.height = `${ratio}%`;
    bar.title = String(value);
    col.appendChild(bar);
    bars.appendChild(col);
  });
  trendBox.appendChild(bars);
  const trendLabels = document.createElement('div');
  trendLabels.className = 'routine-trend-labels';
  vm.trendLabels.forEach((label, index) => {
    const span = document.createElement('span');
    span.textContent = index === vm.trendLabels.length - 1 ? '今天' : label;
    trendLabels.appendChild(span);
  });
  trendBox.appendChild(trendLabels);
  left.appendChild(trendBox);

  const assetsBox = document.createElement('section');
  assetsBox.className = 'routine-panel';
  const assetsTitle = document.createElement('h4');
  assetsTitle.className = 'routine-panel-title';
  assetsTitle.textContent = '受攻击最频繁资产 (TOP 3)';
  assetsBox.appendChild(assetsTitle);
  const assetsGrid = document.createElement('div');
  assetsGrid.className = 'routine-assets-grid';
  (vm.topAssets.length ? vm.topAssets : [{ ip: '-', count: 0, trend: '+0%' }]).forEach((asset) => {
    const node = document.createElement('div');
    node.className = 'routine-asset-card';
    const ipRow = document.createElement('div');
    ipRow.className = 'routine-asset-ip-row';
    const ipNode = document.createElement('p');
    ipNode.className = 'routine-asset-ip';
    ipNode.textContent = asset.ip;
    ipRow.appendChild(ipNode);
    if (isValidIpv4(asset.ip)) {
      ipRow.appendChild(createRoutineCopyMiniButton(asset.ip));
    }
    node.appendChild(ipRow);
    const countNode = document.createElement('p');
    countNode.className = 'routine-asset-count';
    countNode.textContent = formatMetric(asset.count);
    node.appendChild(countNode);
    const trendNode = document.createElement('p');
    trendNode.className = 'routine-asset-trend';
    trendNode.textContent = `较平均 ${asset.trend}`;
    node.appendChild(trendNode);
    assetsGrid.appendChild(node);
  });
  assetsBox.appendChild(assetsGrid);
  left.appendChild(assetsBox);

  const riskWrap = document.createElement('div');
  riskWrap.className = 'routine-risk-wrap';
  const riskTitle = document.createElement('h4');
  riskTitle.className = 'routine-risk-title';
  riskTitle.textContent = '关键风险清单';
  riskWrap.appendChild(riskTitle);
  const riskRows = vm.risks.length ? vm.risks : [{
    id: 'R1',
    severity: '中危',
    type: '暂无',
    title: '暂无风险样本',
    desc: '当前未提取到高危事件样本，请稍后重试。',
    assets: [],
    cve: '',
  }];
  riskRows.forEach((risk) => {
    const item = document.createElement('article');
    item.className = 'routine-risk-item';
    item.style.borderLeftColor = severityRank(risk.severity) >= severityRank('严重') ? '#ef4444' : '#f59e0b';

    const top = document.createElement('div');
    top.className = 'routine-risk-head';
    const leftMeta = document.createElement('div');
    const metaLine = document.createElement('div');
    metaLine.className = 'routine-risk-meta';
    const sev = document.createElement('span');
    sev.className = `routine-risk-severity ${severityRank(risk.severity) >= severityRank('严重') ? 'high' : 'medium'}`;
    sev.textContent = risk.severity;
    const typ = document.createElement('span');
    typ.className = 'routine-risk-type';
    typ.textContent = risk.type;
    metaLine.appendChild(sev);
    metaLine.appendChild(typ);
    const riskName = document.createElement('h5');
    riskName.className = 'routine-risk-name';
    riskName.textContent = risk.title;
    leftMeta.appendChild(metaLine);
    leftMeta.appendChild(riskName);
    top.appendChild(leftMeta);

    if (risk.cve) {
      const cveLink = document.createElement('a');
      cveLink.className = 'routine-risk-cve';
      cveLink.href = `https://nvd.nist.gov/vuln/detail/${risk.cve.toLowerCase()}`;
      cveLink.target = '_blank';
      cveLink.rel = 'noopener noreferrer';
      cveLink.textContent = risk.cve;
      top.appendChild(cveLink);
    }
    item.appendChild(top);

    const desc = document.createElement('p');
    desc.className = 'routine-risk-desc';
    desc.textContent = risk.desc;
    item.appendChild(desc);

    const assets = document.createElement('div');
    assets.className = 'routine-risk-assets';
    const label = document.createElement('span');
    label.className = 'routine-risk-assets-label';
    label.textContent = '涉及资产:';
    assets.appendChild(label);
    const tagWrap = document.createElement('div');
    tagWrap.className = 'routine-risk-tags';
    (risk.assets || []).forEach((ip) => tagWrap.appendChild(createRoutineCopyTag(ip)));
    assets.appendChild(tagWrap);
    item.appendChild(assets);
    riskWrap.appendChild(item);
  });
  left.appendChild(riskWrap);

  const actionPanel = document.createElement('section');
  actionPanel.className = 'routine-action-panel';
  const actionTitle = document.createElement('h4');
  actionTitle.className = 'routine-action-panel-title';
  actionTitle.textContent = '处置建议方案';
  actionPanel.appendChild(actionTitle);

  const openManualIsolation = async () => {
    const guide = '主机隔离接口暂未完全打通，请先手动前往 XDR 平台执行主机网络隔离。';
    setHint(el.playbookHint, guide, 'error');
    const manualCard = cardTemplate('主机隔离提示');
    const hostText = vm.isolateItems.length ? vm.isolateItems.join('、') : '请在平台按风险清单逐台确认';
    manualCard.appendChild(createMarkdownBlock(`${guide}\n\n建议优先隔离主机：${hostText}`));
    appendPlaybookWorkspaceCard(manualCard);
    if (state.xdrBaseUrl) {
      window.open(state.xdrBaseUrl, '_blank', 'noopener,noreferrer');
    }
  };

  const blockSources = async () => {
    await openRoutineBlockDialog({
      actionTitle: '封禁恶意攻击源',
      resultTitle: '网侧封禁结果',
      blockType: 'SRC_IP',
      ips: vm.sourceIps,
      defaultReason: '由安全早报一键处置触发（攻击源封禁）',
      emptyMessage: '当前未提取到可封禁的攻击源 IP，请先执行深度研判后再处置。',
    });
  };

  const blockOutboundIps = async () => {
    await openRoutineBlockDialog({
      actionTitle: '封锁恶意外联IP',
      resultTitle: '外联封锁结果',
      blockType: 'DST_IP',
      ips: vm.outboundIps,
      defaultReason: '由安全早报一键处置触发（恶意外联封锁）',
      emptyMessage: '当前未提取到可封锁的恶意外联 IP。',
    });
  };

  const actions = [
    {
      id: 'isolate',
      title: '风险主机网络隔离',
      type: '隔离',
      impact: '高：主机业务将中断',
      items: vm.isolateItems.length ? vm.isolateItems : ['暂无可提取主机'],
      buttonText: '确认并一键隔离',
      onClick: openManualIsolation,
    },
    {
      id: 'block',
      title: '封禁恶意攻击源',
      type: '拦截',
      impact: '中：需确认业务合法出口 IP',
      items: vm.sourceIps.length ? vm.sourceIps : ['暂无可提取攻击源'],
      buttonText: '确认并一键处置',
      disabled: !vm.sourceIps.length,
      onClick: blockSources,
    },
    {
      id: 'block_outbound',
      title: '封锁恶意外联IP',
      type: '拦截',
      impact: '中：需确认目的地址确为恶意外联',
      items: vm.outboundIps.length ? vm.outboundIps : ['暂无可提取恶意外联IP'],
      buttonText: '确认并一键封锁',
      disabled: !vm.outboundIps.length,
      onClick: blockOutboundIps,
    },
    {
      id: 'scan',
      title: '针对性漏洞一键排查',
      type: '巡检',
      impact: '低：轻量扫描流量',
      items: vm.vulnItems.length ? vm.vulnItems : ['暂无可提取漏洞巡检目标'],
      buttonText: '',
      onClick: null,
    },
  ];
  actions.forEach((action) => actionPanel.appendChild(buildRoutineActionItem(action)));
  right.appendChild(actionPanel);

  appendPlaybookWorkspaceCard(card);
  renderRoutineFollowupCard(vm.nextActions);
}

function createFormNode(payload) {
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

  return form;
}

function createUnifiedPayloadSection(payload, index) {
  const section = document.createElement('div');
  section.className = 'report-section';

  const title = document.createElement('h4');
  title.className = 'report-section-title';
  title.textContent = payload?.data?.title || `区块 ${index + 1}`;
  section.appendChild(title);

  if (payload?.type === 'text') {
    section.appendChild(createMarkdownBlock(payload?.data?.text || ''));
    return section;
  }
  if (payload?.type === 'table') {
    const tableTitle = String(payload?.data?.title || '');
    const allRows = payload?.data?.rows || [];
    const rowCount = allRows.length;
    if (tableTitle.includes('未处置高危事件')) {
      const defaultRows = allRows.slice(0, 5);
      const cappedRows = allRows.slice(0, 50);
      const remainingRows = cappedRows.slice(5);
      section.appendChild(createUnifiedTable(payload, defaultRows));
      if (remainingRows.length) {
        const details = document.createElement('details');
        details.className = 'report-collapsible';
        const summaryNode = document.createElement('summary');
        summaryNode.textContent = `展开查看其余 ${remainingRows.length} 条（最多展示前50条）`;
        details.appendChild(summaryNode);
        details.appendChild(createUnifiedTable(payload, remainingRows));
        section.appendChild(details);
      }
      if (allRows.length > 50) {
        const tip = document.createElement('p');
        tip.className = 'report-chart-summary';
        tip.textContent = `当前共 ${allRows.length} 条，仅展示前 50 条。`;
        section.appendChild(tip);
      }
      return section;
    }
    const tableNode = createUnifiedTable(payload);
    const shouldCollapse =
      tableTitle.includes('命中事件清单') || tableTitle.includes('命中告警清单') || rowCount >= 12;
    if (shouldCollapse) {
      const details = document.createElement('details');
      details.className = 'report-collapsible';
      const summaryNode = document.createElement('summary');
      summaryNode.textContent = `展开/收起明细（共 ${rowCount} 条）`;
      details.appendChild(summaryNode);
      details.appendChild(tableNode);
      section.appendChild(details);
    } else {
      section.appendChild(tableNode);
    }
    return section;
  }
  if (payload?.type === 'echarts_graph') {
    const chart = document.createElement('div');
    chart.style.height = '260px';
    chart.dataset.echartsDeferred = '1';
    chart.__echartsOption = payload?.data?.option || {};
    section.appendChild(chart);
    if (payload?.data?.summary) {
      const p = document.createElement('p');
      p.className = 'report-chart-summary';
      p.textContent = payload.data.summary;
      section.appendChild(p);
    }
    return section;
  }
  if (payload?.type === 'approval_card') {
    section.appendChild(createMarkdownBlock(payload?.data?.summary || ''));
    const actions = document.createElement('div');
    actions.className = 'action-row';
    const ok = document.createElement('button');
    ok.className = 'danger-btn';
    ok.textContent = '确认执行';
    ok.onclick = () => {
      openDangerConfirm(payload?.data?.summary || '', async () => {
        await sendChat('确认');
      });
    };
    const cancel = document.createElement('button');
    cancel.className = 'secondary-btn';
    cancel.textContent = '取消';
    cancel.onclick = async () => sendChat('取消');
    actions.appendChild(ok);
    actions.appendChild(cancel);
    section.appendChild(actions);
    return section;
  }
  if (payload?.type === 'form_card') {
    const desc = document.createElement('p');
    desc.textContent = payload?.data?.description || '';
    section.appendChild(desc);
    section.appendChild(createFormNode(payload));
    return section;
  }

  const pre = document.createElement('pre');
  pre.textContent = JSON.stringify(payload?.data || {}, null, 2);
  section.appendChild(pre);
  return section;
}

function buildPayloadExportHtml(payloads, bundleTitle = '任务报告', metaText = '') {
  const sections = [];
  (payloads || []).forEach((payload, index) => {
    const title = escapeHtml(payload?.data?.title || `区块 ${index + 1}`);
    if (payload?.type === 'text') {
      sections.push(`<section><h2>${title}</h2>${markdownToHtml(payload?.data?.text || '')}</section>`);
      return;
    }
    if (payload?.type === 'table') {
      const columns = payload?.data?.columns || [];
      const rows = payload?.data?.rows || [];
      const th = columns.map((c) => `<th>${escapeHtml(c.label)}</th>`).join('');
      const tr = rows
        .map((row) => {
          const tds = columns
            .map((c) => {
              const value = row[c.key];
              const text = Array.isArray(value) ? value.join(', ') : String(value ?? '');
              return `<td>${escapeHtml(text)}</td>`;
            })
            .join('');
          return `<tr>${tds}</tr>`;
        })
        .join('');
      sections.push(`<section><h2>${title}</h2><table><thead><tr>${th}</tr></thead><tbody>${tr}</tbody></table></section>`);
      return;
    }
    if (payload?.type === 'echarts_graph') {
      const chartSummary = escapeHtml(payload?.data?.summary || '图表结果');
      sections.push(`<section><h2>${title}</h2><p>${chartSummary}</p></section>`);
      return;
    }
    if (payload?.type === 'approval_card') {
      sections.push(`<section><h2>${title}</h2>${markdownToHtml(payload?.data?.summary || '')}</section>`);
      return;
    }
    if (payload?.type === 'form_card') {
      sections.push(`<section><h2>${title}</h2><p>${escapeHtml(payload?.data?.description || '')}</p></section>`);
      return;
    }
    sections.push(`<section><h2>${title}</h2><pre>${escapeHtml(JSON.stringify(payload?.data || {}, null, 2))}</pre></section>`);
  });

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(bundleTitle)}</title>
  <style>
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;max-width:1080px;margin:24px auto;padding:0 14px;line-height:1.72;color:#dbe7ff;background:#081226}
    h1{margin:0 0 8px;font-size:28px;color:#f3f7ff}
    .meta{color:#9db2d8;margin-bottom:18px}
    section{border:1px solid rgba(93,134,212,.55);border-radius:14px;padding:14px 16px;margin-bottom:14px;background:#0c1a3b}
    h2{margin:0 0 10px;font-size:19px;color:#e7efff}
    table{width:100%;border-collapse:collapse;font-size:13px}
    th,td{border:1px solid rgba(98,137,208,.45);padding:8px 10px;text-align:left;vertical-align:top}
    th{background:rgba(24,44,87,.9);color:#cfe0ff}
    code{background:rgba(255,255,255,.08);padding:2px 6px;border-radius:5px}
    pre{white-space:pre-wrap;word-break:break-word;background:rgba(255,255,255,.05);padding:10px;border-radius:8px}
  </style>
</head>
<body>
  <h1>${escapeHtml(bundleTitle)}</h1>
  <div class="meta">${escapeHtml(metaText || `导出时间: ${new Date().toLocaleString()}`)}</div>
  ${sections.join('\n')}
</body>
</html>`;
}

function triggerHtmlDownload(html, filename) {
  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function downloadPayloadReport(payloads, filenamePrefix = 'task-report', bundleTitle = '任务报告') {
  const html = buildPayloadExportHtml(payloads, bundleTitle);
  triggerHtmlDownload(html, `${filenamePrefix}-${Date.now()}.html`);
}

function buildReportHeader(title, buttonText = '', onClick = null) {
  const header = document.createElement('div');
  header.className = 'report-header';

  const titleNode = document.createElement('h3');
  titleNode.className = 'report-header-title';
  titleNode.textContent = title || '任务执行结果';
  header.appendChild(titleNode);

  if (buttonText && typeof onClick === 'function') {
    const actionBtn = document.createElement('button');
    actionBtn.type = 'button';
    actionBtn.className = 'secondary-btn';
    actionBtn.textContent = buttonText;
    actionBtn.addEventListener('click', async (event) => {
      event.preventDefault();
      event.stopPropagation();
      actionBtn.disabled = true;
      try {
        await onClick(event);
      } finally {
        actionBtn.disabled = false;
      }
    });
    header.appendChild(actionBtn);
  }
  return header;
}

function renderUnifiedPayloadCard(cardTitle, payloads, opts = {}) {
  const card = cardTemplate('', '');
  card.classList.add('playbook-unified-report', 'playbook-task-card');
  card.appendChild(
    buildReportHeader(
      cardTitle || '任务执行结果',
      opts.downloadable ? (opts.downloadLabel || '下载内容（HTML）') : '',
      opts.downloadable
        ? () => downloadPayloadReport(payloads, opts.filenamePrefix || 'task-report', cardTitle || '任务执行结果')
        : null,
    ),
  );

  (payloads || []).forEach((payload, index) => {
    card.appendChild(createUnifiedPayloadSection(payload, index));
  });

  appendCard(card);
  requestAnimationFrame(() => mountDeferredCharts(card));
}

function buildPlaybookExportHtml(runData) {
  const result = runData?.result || {};
  const cards = Array.isArray(result.cards) ? result.cards : [];
  const summary = String(result.summary || runData?.error || '').trim();
  const payloadsForExport = [];
  if (summary) {
    payloadsForExport.push({ type: 'text', data: { title: '摘要', text: summary } });
  }
  payloadsForExport.push(...cards);

  const actionLabels = (result.next_actions || []).map((action) => action.label || action.id || '执行动作');
  if (actionLabels.length) {
    payloadsForExport.push({
      type: 'text',
      data: { title: '下一步动作推荐', text: actionLabels.map((label) => `- ${label}`).join('\n') },
    });
  }
  return buildPayloadExportHtml(
    payloadsForExport,
    `Playbook 报告 ${runData?.run_id || ''}`,
    `template: ${runData?.template_id || '-'} · run_id: ${runData?.run_id || '-'} · status: ${runData?.status || '-'}`
  );
}

async function downloadPlaybookReport(runData) {
  const runId = runData?.run_id;
  let latestRunData = runData;
  if (runId) {
    latestRunData = await api(`/api/playbooks/runs/${runId}`);
    state.playbookRunCache[runId] = latestRunData;
  }
  const html = buildPlaybookExportHtml(latestRunData);
  triggerHtmlDownload(html, `playbook-${latestRunData?.template_id || 'report'}-run-${latestRunData?.run_id || Date.now()}.html`);
  setHint(el.playbookHint, `报告已生成并开始下载（run_id: ${latestRunData?.run_id || '-'}）。`, 'success');
}

function renderPlaybookUnifiedCard(runData) {
  const result = runData?.result || {};
  const summary = String(result.summary || runData?.error || '').trim();
  const cards = Array.isArray(result.cards) ? result.cards : [];
  const nextActions = Array.isArray(result.next_actions) ? result.next_actions : [];
  const displayName = getPlaybookDisplayName(runData?.template_id || '');

  const card = cardTemplate('', '');
  card.classList.add('playbook-unified-report', 'playbook-task-card', 'workspace-panel-card');
  card.appendChild(
    buildReportHeader(`Playbook 报告 · ${displayName}`, '下载报告（HTML）', async () => {
      try {
        await downloadPlaybookReport(runData);
      } catch (err) {
        setHint(el.playbookHint, err.message || '报告下载失败', 'error');
      }
    }),
  );

  if (summary) {
    const section = document.createElement('div');
    section.className = 'report-section';
    const title = document.createElement('h4');
    title.className = 'report-section-title';
    title.textContent = '摘要';
    section.appendChild(title);
    section.appendChild(createMarkdownBlock(summary));
    card.appendChild(section);
  }

  cards.forEach((payload, index) => {
    if (payload?.type === 'text' && payloadText(payload) === summary) return;
    card.appendChild(createUnifiedPayloadSection(payload, index));
  });

  if (nextActions.length) {
    const section = document.createElement('div');
    section.className = 'report-section';
    const title = document.createElement('h4');
    title.className = 'report-section-title';
    title.textContent = '下一步动作推荐';
    section.appendChild(title);
    const row = document.createElement('div');
    row.className = 'action-row playbook-next-actions';
    nextActions.forEach((action) => row.appendChild(createPlaybookActionButton(action)));
    section.appendChild(row);
    card.appendChild(section);
  }

  appendPlaybookWorkspaceCard(card);
  requestAnimationFrame(() => mountDeferredCharts(card));
}

function renderPlaybookResult(runData) {
  if (runData?.template_id === 'routine_check') {
    renderRoutineCheckCard(runData);
    return;
  }
  renderPlaybookUnifiedCard(runData);
}

function buildSceneParams(scene) {
  const base = { ...(scene.default_params || {}) };
  if (scene.id === 'alert_triage') {
    const raw = window.prompt('请输入事件序号（如 1）或事件UUID（incident-xxx）：', '');
    const value = (raw || '').trim();
    if (!value) return null;
    if (!/^\d+$/.test(value)) {
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

  if (scene.id === 'asset_guard') {
    const defaultAsset = state.coreAssets[0];
    const defaultPromptValue = defaultAsset ? `${defaultAsset.asset_name || ''} ${defaultAsset.asset_ip}`.trim() : '';
    const raw = window.prompt('请输入核心资产IP（可输入“资产名 空格 IP”）：', defaultPromptValue);
    const value = (raw || '').trim();
    if (!value) return null;

    let assetIp = '';
    let assetName = '';
    const ipMatch = value.match(/(?:\d{1,3}\.){3}\d{1,3}/);
    if (ipMatch) {
      assetIp = ipMatch[0];
      assetName = value.replace(assetIp, '').trim();
    } else {
      throw new Error('请输入合法的核心资产IP。');
    }
    return { ...base, asset_ip: assetIp, asset_name: assetName || undefined };
  }

  return base;
}

function formatTriggerLabel(templateId, triggerLabel, params) {
  const baseLabel = triggerLabel || templateId;
  if (templateId === 'alert_triage') {
    if (params?.incident_uuid) return `触发场景: ${baseLabel}（${params.incident_uuid}）`;
    if (Array.isArray(params?.incident_uuids) && params.incident_uuids.length) {
      if (params.incident_uuids.length === 1) return `触发场景: ${baseLabel}（${params.incident_uuids[0]}）`;
      return `触发场景: ${baseLabel}（${params.incident_uuids[0]} 等${params.incident_uuids.length}条）`;
    }
    if (params?.event_index) return `触发场景: ${baseLabel}（序号${params.event_index}）`;
    if (Array.isArray(params?.event_indexes) && params.event_indexes.length) {
      return `触发场景: ${baseLabel}（序号${params.event_indexes[0]} 等${params.event_indexes.length}条）`;
    }
  }
  if (templateId === 'asset_guard' && params?.asset_ip) {
    return `触发场景: ${baseLabel}（${params.asset_ip}）`;
  }
  return `触发场景: ${baseLabel}`;
}

function resolvePlaybookScenes(templates = state.playbookTemplates) {
  const byId = new Map((templates || []).map((tpl) => [tpl.id, tpl]));
  return DEFAULT_PLAYBOOK_SCENES.map((scene) => {
    const remote = byId.get(scene.id) || {};
    return {
      ...scene,
      ...remote,
      default_params: { ...scene.default_params, ...(remote.default_params || {}) },
    };
  });
}

function getSceneById(sceneId) {
  return resolvePlaybookScenes().find((scene) => scene.id === sceneId) || null;
}

function renderPlaybookCards(templates) {
  if (!el.playbookCards) return;
  el.playbookCards.innerHTML = '';

  const scenes = resolvePlaybookScenes(templates);

  scenes.forEach((scene) => {
    const card = document.createElement('article');
    card.className = 'playbook-card-item';
    card.dataset.scene = scene.id;

    const btn = document.createElement('button');
    btn.className = 'playbook-btn';
    btn.type = 'button';
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
    card.appendChild(btn);

    if (scene.description || scene.hint) {
      const tooltip = document.createElement('div');
      tooltip.className = 'scene-tooltip';

      const ttTitle = document.createElement('div');
      ttTitle.className = 'scene-tooltip-title';
      ttTitle.textContent = scene.name || scene.id;
      tooltip.appendChild(ttTitle);

      if (scene.description) {
        const ttDesc = document.createElement('div');
        ttDesc.className = 'scene-tooltip-desc';
        ttDesc.textContent = scene.description;
        tooltip.appendChild(ttDesc);
      }
      if (scene.hint) {
        const ttHint = document.createElement('div');
        ttHint.className = 'scene-tooltip-hint';
        ttHint.textContent = `提示：${scene.hint}`;
        tooltip.appendChild(ttHint);
      }
      card.appendChild(tooltip);
    }

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
    updateSlashMenuFromInput();
  } catch (err) {
    state.playbookTemplates = [];
    renderPlaybookCards([]);
    setHint(el.playbookHint, err.message || 'Playbook 模板加载失败', 'error');
    updateSlashMenuFromInput();
  }
}

function resolveSlashCommands() {
  const sceneById = new Map(resolvePlaybookScenes().map((scene) => [scene.id, scene]));
  return SLASH_COMMANDS.map((item) => {
    const scene = sceneById.get(item.id) || {};
    return {
      ...item,
      sceneName: scene.name || item.id,
      buttonLabel: scene.button_label || scene.name || item.id,
      hint: scene.hint || '',
    };
  });
}

function hideSlashCommandMenu() {
  state.slashVisible = false;
  state.slashActiveIndex = 0;
  state.slashFiltered = [];
  if (el.slashCommandMenu) {
    el.slashCommandMenu.classList.add('hidden');
    el.slashCommandMenu.innerHTML = '';
  }
}

function renderSlashCommandMenu(items) {
  if (!el.slashCommandMenu) return;
  if (!items.length) {
    hideSlashCommandMenu();
    return;
  }
  state.slashVisible = true;
  state.slashFiltered = items;
  if (state.slashActiveIndex >= items.length) {
    state.slashActiveIndex = 0;
  }

  el.slashCommandMenu.classList.remove('hidden');
  el.slashCommandMenu.innerHTML = '';

  items.forEach((item, index) => {
    const option = document.createElement('button');
    option.type = 'button';
    option.className = 'slash-command-item';
    option.dataset.commandId = item.id;
    option.dataset.commandIndex = String(index);
    option.setAttribute('role', 'option');
    const left = document.createElement('div');
    left.className = 'slash-command-main';
    const cmd = document.createElement('div');
    cmd.className = 'slash-command';
    cmd.textContent = item.command;
    const desc = document.createElement('div');
    desc.className = 'slash-command-desc';
    desc.textContent = item.description || item.hint || item.sceneName;
    left.appendChild(cmd);
    left.appendChild(desc);
    option.appendChild(left);

    const badge = document.createElement('span');
    badge.className = 'slash-command-badge';
    badge.textContent = item.sceneName || item.id;
    option.appendChild(badge);

    option.addEventListener('mouseenter', () => {
      setSlashActiveIndex(index);
    });
    option.addEventListener('mousedown', (event) => {
      event.preventDefault();
    });
    option.addEventListener('click', async () => {
      await executeSlashCommand(item);
    });
    el.slashCommandMenu.appendChild(option);
  });

  paintSlashActiveOption();
}

function filterSlashCommands(inputText) {
  const text = String(inputText || '').trim();
  if (!text.startsWith('/')) return [];
  const query = text.slice(1).trim().toLowerCase();
  const commands = resolveSlashCommands();
  if (!query) return commands;
  return commands.filter((item) => {
    const haystack = [item.command, item.sceneName, item.description, ...(item.aliases || [])].join(' ').toLowerCase();
    return haystack.includes(query);
  });
}

function updateSlashMenuFromInput() {
  const inputValue = el.chatMessage?.value || '';
  const filtered = filterSlashCommands(inputValue);
  if (filtered.length) {
    renderSlashCommandMenu(filtered);
  } else {
    hideSlashCommandMenu();
  }
}

function paintSlashActiveOption() {
  if (!el.slashCommandMenu) return;
  const items = el.slashCommandMenu.querySelectorAll('.slash-command-item');
  items.forEach((node) => {
    const idx = Number(node.dataset.commandIndex || -1);
    const active = idx === state.slashActiveIndex;
    node.classList.toggle('active', active);
    node.setAttribute('aria-selected', active ? 'true' : 'false');
  });
}

function setSlashActiveIndex(index) {
  if (!state.slashFiltered.length) return;
  const max = state.slashFiltered.length;
  state.slashActiveIndex = ((index % max) + max) % max;
  paintSlashActiveOption();
}

function moveSlashActive(step) {
  if (!state.slashFiltered.length) return;
  setSlashActiveIndex(state.slashActiveIndex + step);
}

function getActiveSlashCommand() {
  if (!state.slashFiltered.length) return null;
  return state.slashFiltered[state.slashActiveIndex] || state.slashFiltered[0] || null;
}

function resolveSlashCommand(rawText) {
  const text = String(rawText || '').trim();
  if (!text.startsWith('/')) return null;
  const commands = resolveSlashCommands();
  const lower = text.toLowerCase();
  return (
    commands.find((item) => item.command.toLowerCase() === lower)
    || commands.find((item) => (item.aliases || []).some((alias) => alias.toLowerCase() === lower))
    || (text === '/' ? commands[0] : null)
  );
}

async function executeSlashCommand(command) {
  if (!command) return;
  const scene = getSceneById(command.id);
  if (!scene) {
    setHint(el.playbookHint, `未找到场景：${command.id}`, 'error');
    return;
  }
  hideSlashCommandMenu();
  if (el.chatMessage) {
    el.chatMessage.value = '';
    el.chatMessage.focus();
  }
  try {
    const params = buildSceneParams(scene);
    if (!params) return;
    await runPlaybook(scene.id, params, scene.name || scene.id);
  } catch (err) {
    setHint(el.playbookHint, err.message || '快捷指令执行失败', 'error');
  }
}

function getPlaybookPollTimeoutMs(templateId) {
  if (templateId === 'threat_hunting') return 15 * 60 * 1000;
  if (templateId === 'asset_guard') return 10 * 60 * 1000;
  return 5 * 60 * 1000;
}

async function pollPlaybookRun(runId, progressUi, templateId) {
  const timeoutMs = getPlaybookPollTimeoutMs(templateId);
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const runData = await api(`/api/playbooks/runs/${runId}`);
    state.playbookRunCache[runId] = runData;
    updatePlaybookProgress(progressUi, runData);
    if (runData.status === 'Finished' || runData.status === 'Failed') {
      return runData;
    }
    await sleep(1000);
  }
  throw new Error(`Playbook 运行超时，run_id=${runId}（>${Math.floor(timeoutMs / 1000)}s）`);
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

  const introCard = cardTemplate('', 'user playbook-trigger-card');
  const introBubble = document.createElement('div');
  introBubble.className = 'playbook-trigger-pill';
  introBubble.textContent = formatTriggerLabel(templateId, triggerLabel, params);
  const introAvatar = document.createElement('div');
  introAvatar.className = 'playbook-trigger-avatar';
  introAvatar.textContent = '👤';
  introCard.appendChild(introBubble);
  introCard.appendChild(introAvatar);
  appendCard(introCard);

  const runInfo = await api('/api/playbooks/run', {
    method: 'POST',
    body: JSON.stringify(requestPayload),
  });
  introCard.dataset.playbookRunId = String(runInfo.run_id);
  introCard.onclick = async () => {
    try {
      await openPlaybookRunById(runInfo.run_id, templateId, { resetWorkspace: true });
    } catch (err) {
      setHint(el.playbookHint, err.message || '加载 Playbook 运行状态失败', 'error');
    }
  };
  renderPlaybookLaunchFeedback(templateId, triggerLabel, runInfo.run_id);
  state.activePlaybookRunId = runInfo.run_id;
  await openPlaybookRunById(runInfo.run_id, templateId, { resetWorkspace: true });
}

async function readSSEStream(response) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let pending = '';
  let currentTextPayload = null;
  const batchPayloads = [];

  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    pending += decoder.decode(value, { stream: true });
    const parts = pending.split('\n\n');
    pending = parts.pop() || '';

    for (const part of parts) {
      if (!part.startsWith('data: ')) continue;
      const raw = part.slice(6).trim();
      if (raw === '[DONE]') {
        if (currentTextPayload) {
          batchPayloads.push(currentTextPayload);
          currentTextPayload = null;
        }
        if (batchPayloads.length > 1) {
          const primaryTitle = batchPayloads[0]?.data?.title || '任务执行结果';
          renderUnifiedPayloadCard(`${primaryTitle} · 执行详情`, batchPayloads, {
            downloadable: true,
            downloadLabel: '下载任务内容（HTML）',
            filenamePrefix: 'chat-task-report',
          });
        } else if (batchPayloads.length === 1) {
          renderPayload(batchPayloads[0]);
        }
        return;
      }
      const event = JSON.parse(raw);

      if (event.type === 'text_start') {
        const p = event.payload || {};
        currentTextPayload = {
          ...p,
          data: {
            ...(p.data || {}),
            text: '',
          },
        };
      } else if (event.type === 'text_delta') {
        if (currentTextPayload) {
          currentTextPayload.data.text += event.delta || '';
        }
      } else if (event.type === 'text_end') {
        if (currentTextPayload) {
          if (!currentTextPayload.data.text) {
            currentTextPayload.data.text = event.text || '';
          }
          batchPayloads.push(currentTextPayload);
          currentTextPayload = null;
        }
      } else if (event.type === 'payload') {
        batchPayloads.push(event.payload);
      } else if (event.type === 'payload_batch') {
        batchPayloads.push(...(event.payloads || []));
      }
    }
  }

  if (currentTextPayload) {
    batchPayloads.push(currentTextPayload);
  }
  if (batchPayloads.length > 1) {
    const primaryTitle = batchPayloads[0]?.data?.title || '任务执行结果';
    renderUnifiedPayloadCard(`${primaryTitle} · 执行详情`, batchPayloads, {
      downloadable: true,
      downloadLabel: '下载任务内容（HTML）',
      filenamePrefix: 'chat-task-report',
    });
  } else if (batchPayloads.length === 1) {
    renderPayload(batchPayloads[0]);
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

async function loadThreatbookConfig() {
  if (!el.threatbookApiKey) return;
  const data = await api('/api/config/threatbook');
  el.threatbookApiKey.value = '';
  if (el.threatbookEnabled) el.threatbookEnabled.checked = data.enabled !== false;
  if (data.masked_key) {
    el.threatbookApiKey.placeholder = `已保存：${data.masked_key}`;
  } else {
    el.threatbookApiKey.placeholder = '输入 ThreatBook API Key';
  }
}

async function saveThreatbookConfig() {
  if (!el.threatbookApiKey || !el.threatbookEnabled) return;
  const payload = {
    api_key: el.threatbookApiKey.value.trim() || null,
    enabled: !!el.threatbookEnabled.checked,
  };
  await api('/api/config/threatbook', { method: 'POST', body: JSON.stringify(payload) });
  setHint(el.threatbookResult, 'ThreatBook 配置已保存。', 'success');
  await loadThreatbookConfig();
}

async function testThreatbookConfig() {
  if (!el.threatbookApiKey || !el.threatbookTestIp) return;
  const payload = {
    api_key: el.threatbookApiKey.value.trim() || null,
    test_ip: el.threatbookTestIp.value.trim() || '8.8.8.8',
  };
  const result = await api('/api/config/threatbook/test', { method: 'POST', body: JSON.stringify(payload) });
  setHint(el.threatbookResult, result.message || '测试完成', result.success ? 'success' : 'error');
}

async function refreshCoreAssets() {
  if (!el.coreAssetList) return;
  const items = await api('/api/config/core-assets');
  state.coreAssets = items;
  renderList(el.coreAssetList, items, (item) => {
    const metadata = item.metadata && Object.keys(item.metadata).length ? JSON.stringify(item.metadata) : '-';
    return `
      <div style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
        <div>
          <strong style="color:var(--sec-medium);">${item.asset_name || '未命名资产'}</strong>
          <div style="font-size:0.9em; margin-top:4px;">IP: ${item.asset_ip}</div>
          <div style="font-size:0.85em; opacity:0.85; margin-top:4px;">负责人: ${item.biz_owner || '-'} · 备注: ${metadata}</div>
        </div>
        <button data-delete-asset="${item.id}" class="secondary-btn" style="padding:4px 8px; font-size:0.85em;">删除</button>
      </div>
    `;
  });

  el.coreAssetList.querySelectorAll('button[data-delete-asset]').forEach((btn) => {
    btn.onclick = async () => {
      const id = btn.getAttribute('data-delete-asset');
      try {
        await api(`/api/config/core-assets/${id}`, { method: 'DELETE' });
        await refreshCoreAssets();
      } catch (err) {
        setHint(el.coreAssetResult, err.message || '删除失败', 'error');
      }
    };
  });
}


async function sendChat(message) {
  if (!state.isAuthenticated) {
    setHint(el.loginResult, '请先登录成功后再进入对话。', 'error');
    setAuthState(false);
    return;
  }

  const req = {
    session_id: state.sessionId,
    message,
    active_playbook_run_id: state.activePlaybookRunId || null,
  };
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
  await loadThreatbookConfig().catch((err) => {
    setHint(el.threatbookResult, err.message || 'ThreatBook 配置加载失败，可稍后重试。', 'error');
  });
  await refreshCoreAssets().catch((err) => {
    setHint(el.coreAssetResult, err.message || '核心资产列表加载失败，可稍后重试。', 'error');
  });
  await refreshPlaybookTemplates();
}

async function checkAuthStatus() {
  setAuthState(false);
  try {
    const status = await api('/api/auth/status');
    if (!status.authenticated) return;
    const url = status.base_url || '';
    state.xdrBaseUrl = url;
    const baseUrlInput = document.getElementById('baseUrl');
    if (baseUrlInput && !baseUrlInput.value && url) {
      baseUrlInput.value = url;
    }
    setHint(el.loginResult, '检测到已保存凭证，请重新登录后进入工作台。', '');
  } catch {}
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
    state.xdrBaseUrl = payload.base_url;
    setAuthState(true, `已登录平台：${payload.base_url}`);
    await bootWorkspace();
  } catch (err) {
    setHint(el.loginResult, err.message, 'error');
    setAuthState(false);
  }
});

el.logoutBtn.onclick = () => {
  state.sessionId = `session-${Date.now()}`;
  state.xdrBaseUrl = '';
  state.playbookTemplates = [];
  state.activePlaybookRunId = null;
  state.playbookRunCache = {};
  state.routineBlockDraft = null;
  el.chatStream.innerHTML = '';
  if (el.playbookCards) el.playbookCards.innerHTML = '';
  if (el.playbookHint) setHint(el.playbookHint, '');
  closeDialog(el.routineBlockDialog);
  clearPlaybookWorkspace();
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
    await loadThreatbookConfig();
    await refreshCoreAssets();
  } catch (err) {
    setHint(el.providerResult, err.message || '配置加载失败', 'error');
  }
};

el.closeSettingsBtn.onclick = () => {
  closeDialog(el.settingsDialog);
};

if (el.closePlaybookWorkspaceBtn) {
  el.closePlaybookWorkspaceBtn.onclick = () => {
    setPlaybookWorkspaceOpen(false);
  };
}

if (el.routineBlockCancel) {
  el.routineBlockCancel.onclick = () => {
    state.routineBlockDraft = null;
    closeDialog(el.routineBlockDialog);
  };
}

if (el.routineBlockConfirm) {
  el.routineBlockConfirm.onclick = async () => {
    await submitRoutineBlockDialog();
  };
}

el.settingsDialog.addEventListener('click', (event) => {
  const rect = el.settingsDialog.getBoundingClientRect();
  const isOutside =
    event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom;
  if (isOutside) closeDialog(el.settingsDialog);
});

if (el.routineBlockDialog) {
  el.routineBlockDialog.addEventListener('click', (event) => {
    const rect = el.routineBlockDialog.getBoundingClientRect();
    const isOutside =
      event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom;
    if (isOutside) {
      state.routineBlockDraft = null;
      closeDialog(el.routineBlockDialog);
    }
  });
}


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

const saveThreatbookBtn = document.getElementById('saveThreatbook');
if (saveThreatbookBtn) {
  saveThreatbookBtn.onclick = async () => {
    try {
      if (!state.isAuthenticated) {
        setHint(el.threatbookResult, '请先登录平台。', 'error');
        return;
      }
      await saveThreatbookConfig();
    } catch (err) {
      setHint(el.threatbookResult, err.message || '保存失败', 'error');
    }
  };
}

const testThreatbookBtn = document.getElementById('testThreatbook');
if (testThreatbookBtn) {
  testThreatbookBtn.onclick = async () => {
    try {
      if (!state.isAuthenticated) {
        setHint(el.threatbookResult, '请先登录平台。', 'error');
        return;
      }
      await testThreatbookConfig();
    } catch (err) {
      setHint(el.threatbookResult, err.message || '测试失败', 'error');
    }
  };
}

if (el.coreAssetForm) {
  el.coreAssetForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      if (!state.isAuthenticated) {
        setHint(el.coreAssetResult, '请先登录平台。', 'error');
        return;
      }
      const payload = {
        asset_name: el.coreAssetName.value.trim(),
        asset_ip: el.coreAssetIp.value.trim(),
        biz_owner: el.coreAssetOwner.value.trim() || null,
        metadata: el.coreAssetMeta.value.trim() || null,
      };
      await api('/api/config/core-assets', { method: 'POST', body: JSON.stringify(payload) });
      setHint(el.coreAssetResult, '核心资产已保存。', 'success');
      el.coreAssetName.value = '';
      el.coreAssetIp.value = '';
      el.coreAssetOwner.value = '';
      el.coreAssetMeta.value = '';
      await refreshCoreAssets();
    } catch (err) {
      setHint(el.coreAssetResult, err.message || '保存失败', 'error');
    }
  });
}

window.refreshSafetyRules = refreshSafetyRules;
window.refreshCoreAssets = refreshCoreAssets;

if (el.chatMessage) {
  el.chatMessage.addEventListener('input', () => {
    updateSlashMenuFromInput();
  });
  el.chatMessage.addEventListener('focus', () => {
    updateSlashMenuFromInput();
  });
  el.chatMessage.addEventListener('keyup', () => {
    updateSlashMenuFromInput();
  });
  el.chatMessage.addEventListener('keydown', async (event) => {
    if (event.key === '/') {
      setTimeout(() => {
        updateSlashMenuFromInput();
      }, 0);
    }
    if (!state.slashVisible) return;
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      moveSlashActive(1);
      return;
    }
    if (event.key === 'ArrowUp') {
      event.preventDefault();
      moveSlashActive(-1);
      return;
    }
    if (event.key === 'Escape') {
      event.preventDefault();
      hideSlashCommandMenu();
      return;
    }
    if (event.key === 'Enter') {
      const trimmed = (el.chatMessage.value || '').trim();
      if (trimmed.startsWith('/')) {
        event.preventDefault();
        const command = resolveSlashCommand(trimmed) || getActiveSlashCommand();
        if (command) {
          await executeSlashCommand(command);
        }
      }
    }
  });
}

if (el.slashCommandMenu) {
  el.slashCommandMenu.addEventListener('mousedown', (event) => {
    event.preventDefault();
  });
}

document.addEventListener('click', (event) => {
  if (!state.slashVisible) return;
  const target = event.target;
  if (target === el.chatMessage) return;
  if (el.slashCommandMenu && el.slashCommandMenu.contains(target)) return;
  hideSlashCommandMenu();
});

el.chatForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const message = el.chatMessage.value.trim();
  if (!message) return;
  if (message.startsWith('/')) {
    const command = resolveSlashCommand(message) || getActiveSlashCommand();
    if (command) {
      await executeSlashCommand(command);
      return;
    }
    setHint(el.playbookHint, '未匹配到快捷指令，可输入 / 选择四个核心场景。', 'error');
    return;
  }
  hideSlashCommandMenu();
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
