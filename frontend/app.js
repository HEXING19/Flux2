const state = {
  sessionId: '',
  conversationScopeKey: '',
  conversations: [],
  activeConversationId: null,
  isAuthenticated: false,
  xdrBaseUrl: '',
  playbookTemplates: [],
  coreAssets: [],
  activePlaybookRunId: null,
  playbookRunCache: {},
  playbookOpenTokens: {},
  routineBlockDraft: null,
  routineBlockAutoCloseTimer: null,
  slashVisible: false,
  slashActiveIndex: 0,
  slashFiltered: [],
  semanticRuleMeta: null,
  semanticRules: [],
  chatRequest: createIdleChatRequestState(),
};

const CONVERSATION_STORAGE_KEY = 'flux_conversations_v1';
const CONVERSATION_STORAGE_VERSION = 1;
const FORM_SUBMIT_PREFIX = '__FORM_SUBMIT__:';
const CHAT_WELCOME_TITLE = '系统向导';
const CHAT_WELCOME_TEXT = `协议握手完成。Flux 智能安全助手已就绪。

推荐这样提问，更容易命中系统能力：
1. 💡 事件查询：例如“查看近24小时的安全事件”、“查询最近7天高危事件”
2. 🔎 事件详情：例如“查看第2个事件的详细举证”
3. 🚨 告警查询：例如“查看近7天的安全告警信息”
4. 📊 统计分析：例如“总结最近7天的告警趋势”、“最近7天安全告警分类情况”
5. 🛡️ 封禁管理：例如“查看 1.2.3.4 的封禁状态”、“封禁 1.2.3.4 24小时”

推荐模板：时间范围 + 对象 + 动作，例如“近24小时 + 告警 + 查看”。
针对封禁等高危操作，系统将会触发安全红线校验与二次人工确认。请描述您的安全运营需求...`;

const CHAT_PHASE_META = {
  thinking: {
    text: '正在思考中，正在查询相关数据...',
  },
  generating: {
    text: '正在生成回复中...',
  },
};

const CHAT_BUSY_NOTICE = '上一条回复仍在处理中，请稍候...';

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
    node_2_unhandled_high_events_24h: { title: '检索需要优先关注的威胁', desc: '筛选需要优先关注的时间' },
    node_3_sample_detail_parallel: { title: '并行拉取样本证据', desc: '补充样本事件证据和实体信息' },
    node_4_llm_briefing: { title: '生成早报结论', desc: '输出安全态势的结论与建议' },
  },
  alert_triage: {
    analyze: {
      node_1_resolve_target: { title: '定位目标事件', desc: '解析事件ID/序号并锁定目标' },
      node_2_entity_profile: { title: '生成实体画像', desc: '抽取事件关联IP与画像信息' },
      node_3_proof_enrich: { title: '提取举证特征', desc: '聚合MITRE、漏洞与Payload证据' },
      node_4_external_intel: { title: '外部情报查询', desc: '补充ThreatBook或本地情报结果' },
      node_5_internal_impact_count_parallel: { title: '统计内部影响', desc: '计算影响面与风险得分' },
      node_6_asset_profile: { title: '补全受害画像', desc: '从资产接口提取主机名、角色与价值' },
      node_7_llm_triage_summary: { title: '输出研判结论', desc: '给出处置建议和优先动作' },
    },
    block_ip: {
      node_1_resolve_target_ip: { title: '解析待封禁IP', desc: '从参数或事件实体定位目标IP' },
      node_2_build_block_approval: { title: '生成审批卡', desc: '进入高危操作人工审批链路' },
    },
  },
  threat_hunting: {
    node_1_attack_surface_recon: { title: '线索锁定与攻击面探明', desc: '先按源IP检索，必要时补目的IP并完成攻击面聚合' },
    node_2_breakthrough_identify: { title: '突破口确认', desc: '从告警中定位高置信突破记录与 Victim A' },
    node_3_victim_lateral_movement: { title: '横向移动追踪', desc: '基于 Victim A 检测重点端口与异常端口扩散行为' },
    node_4_outbound_behavior_analysis: { title: '出站行为分析', desc: '聚合失陷主机外联目标与最近活跃证据' },
    node_5_kill_chain_finalize: { title: '生成杀伤链闭环', desc: '拼接侦察、利用、横向、结果四阶段证据' },
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
  semanticRuleForm: document.getElementById('semanticRuleForm'),
  semanticRuleId: document.getElementById('semanticRuleId'),
  semanticRuleDomain: document.getElementById('semanticRuleDomain'),
  semanticRuleSlot: document.getElementById('semanticRuleSlot'),
  semanticRuleMatchMode: document.getElementById('semanticRuleMatchMode'),
  semanticRuleActionType: document.getElementById('semanticRuleActionType'),
  semanticRulePhrase: document.getElementById('semanticRulePhrase'),
  semanticRuleValueLabel: document.getElementById('semanticRuleValueLabel'),
  semanticRuleValueHelp: document.getElementById('semanticRuleValueHelp'),
  semanticRuleValueEditor: document.getElementById('semanticRuleValueEditor'),
  semanticRulePriority: document.getElementById('semanticRulePriority'),
  semanticRuleDesc: document.getElementById('semanticRuleDesc'),
  semanticRuleEnabled: document.getElementById('semanticRuleEnabled'),
  semanticRuleResult: document.getElementById('semanticRuleResult'),
  semanticRuleList: document.getElementById('semanticRuleList'),
  resetSemanticRuleFormBtn: document.getElementById('resetSemanticRuleForm'),
  saveSemanticRuleBtn: document.getElementById('saveSemanticRule'),

  newConversationBtn: document.getElementById('newConversationBtn'),
  conversationList: document.getElementById('conversationList'),
  activeConversationLabel: document.getElementById('activeConversationLabel'),
  chatForm: document.getElementById('chatForm'),
  chatMessage: document.getElementById('chatMessage'),
  chatSubmitBtn: document.getElementById('chatSubmitBtn'),
  chatStream: document.getElementById('chatStream'),
  chatStatusBar: document.getElementById('chatStatusBar'),
  chatStatusText: document.getElementById('chatStatusText'),
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
  routineBlockTargetLabel: document.getElementById('routineBlockTargetLabel'),
  routineBlockTargetList: document.getElementById('routineBlockTargetList'),
  routineBlockSkipped: document.getElementById('routineBlockSkipped'),
  routineBlockIntelBody: document.getElementById('routineBlockIntelBody'),
  routineBlockDevice: document.getElementById('routineBlockDevice'),
  routineBlockHours: document.getElementById('routineBlockHours'),
  routineBlockReason: document.getElementById('routineBlockReason'),
  routineBlockRuleName: document.getElementById('routineBlockRuleName'),
  routineBlockDirection: document.getElementById('routineBlockDirection'),
  routineBlockContextNote: document.getElementById('routineBlockContextNote'),
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

function createRuntimeId(prefix = 'id') {
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
}

function safeIsoTimestamp(value) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) {
    return new Date().toISOString();
  }
  return date.toISOString();
}

function padTimePart(value) {
  return String(value).padStart(2, '0');
}

function formatTimeLabel(value) {
  const date = value ? new Date(value) : new Date();
  if (Number.isNaN(date.getTime())) return '--:--';
  return `${padTimePart(date.getHours())}:${padTimePart(date.getMinutes())}`;
}

function normalizeConversationScope(baseUrl) {
  const normalized = String(baseUrl || '').trim().replace(/\/+$/, '').toLowerCase();
  return normalized || 'default';
}

function truncateConversationText(text, maxLength = 22) {
  const normalized = String(text || '').trim().replace(/\s+/g, ' ');
  if (!normalized) return '';
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, maxLength).trimEnd()}...`;
}

function summarizePayloadBatch(payloads) {
  const normalizedPayloads = Array.isArray(payloads) ? payloads.filter(Boolean) : [];
  if (!normalizedPayloads.length) return '系统返回了空结果。';
  if (normalizedPayloads.length === 1) {
    const payload = normalizedPayloads[0];
    if (payload?.type === 'text') {
      const text = truncateConversationText(payload?.data?.text || '', 40);
      if (text) return text;
    }
    return truncateConversationText(payload?.data?.title || '系统消息', 40) || '系统消息';
  }
  const firstTitle = truncateConversationText(normalizedPayloads[0]?.data?.title || '任务执行结果', 22);
  return `${firstTitle} 等 ${normalizedPayloads.length} 项结果`;
}

function normalizeConversationEntry(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const type = String(entry.type || '').trim();
  const createdAt = safeIsoTimestamp(entry.createdAt);

  if (type === 'user_message') {
    const message = String(entry.message || '').trim();
    if (!message) return null;
    return { type, message, createdAt };
  }

  if (type === 'assistant_payload_batch') {
    const payloads = Array.isArray(entry.payloads) ? entry.payloads.filter(Boolean) : [];
    if (!payloads.length) return null;
    return { type, payloads, createdAt };
  }

  if (type === 'playbook_trigger') {
    const templateId = String(entry.templateId || '').trim();
    const triggerLabel = String(entry.triggerLabel || '').trim();
    const params = entry.params && typeof entry.params === 'object' ? entry.params : {};
    const runId = Number(entry.runId);
    if (!templateId && !triggerLabel) return null;
    return {
      type,
      templateId,
      triggerLabel,
      params,
      runId: Number.isFinite(runId) && runId > 0 ? runId : null,
      createdAt,
    };
  }

  if (type === 'error') {
    const message = String(entry.message || '').trim();
    if (!message) return null;
    return {
      type,
      title: String(entry.title || '错误').trim() || '错误',
      message,
      createdAt,
    };
  }

  return null;
}

function deriveConversationTitle(entries, createdAt) {
  const firstUserMessage = (entries || []).find((entry) => entry?.type === 'user_message' && entry?.message);
  if (firstUserMessage?.message) {
    return truncateConversationText(firstUserMessage.message, 24);
  }
  return `新会话 ${formatTimeLabel(createdAt)}`;
}

function deriveConversationPreview(entries) {
  const lastEntry = Array.isArray(entries) && entries.length ? entries[entries.length - 1] : null;
  if (!lastEntry) return '等待新的安全运营指令';
  if (lastEntry.type === 'user_message') return truncateConversationText(lastEntry.message, 42);
  if (lastEntry.type === 'assistant_payload_batch') return summarizePayloadBatch(lastEntry.payloads);
  if (lastEntry.type === 'playbook_trigger') {
    const displayName = getPlaybookDisplayName(lastEntry.templateId, lastEntry.triggerLabel);
    return `已启动 ${displayName}`;
  }
  if (lastEntry.type === 'error') return `错误：${truncateConversationText(lastEntry.message, 34)}`;
  return '等待新的安全运营指令';
}

function normalizeConversationRecord(record) {
  if (!record || typeof record !== 'object') return null;
  const entries = Array.isArray(record.entries)
    ? record.entries.map(normalizeConversationEntry).filter(Boolean)
    : [];
  const createdAt = safeIsoTimestamp(record.createdAt);
  const updatedAt = safeIsoTimestamp(record.updatedAt || createdAt);
  const activePlaybookRunId = Number(record.activePlaybookRunId);
  return {
    id: String(record.id || createRuntimeId('conv')).trim(),
    sessionId: String(record.sessionId || createRuntimeId('session')).trim(),
    entries,
    createdAt,
    updatedAt,
    activePlaybookRunId: Number.isFinite(activePlaybookRunId) && activePlaybookRunId > 0 ? activePlaybookRunId : null,
    title: deriveConversationTitle(entries, createdAt),
    preview: deriveConversationPreview(entries),
  };
}

function createConversationRecord(seed = {}) {
  return normalizeConversationRecord({
    id: seed.id || createRuntimeId('conv'),
    sessionId: seed.sessionId || createRuntimeId('session'),
    entries: Array.isArray(seed.entries) ? seed.entries : [],
    createdAt: seed.createdAt || new Date().toISOString(),
    updatedAt: seed.updatedAt || seed.createdAt || new Date().toISOString(),
    activePlaybookRunId: seed.activePlaybookRunId || null,
  });
}

function sortConversations(conversations) {
  return [...(conversations || [])].sort((left, right) => {
    const leftTs = new Date(left?.updatedAt || 0).getTime();
    const rightTs = new Date(right?.updatedAt || 0).getTime();
    return rightTs - leftTs;
  });
}

function readConversationStore() {
  try {
    const raw = window.localStorage.getItem(CONVERSATION_STORAGE_KEY);
    if (!raw) {
      return { version: CONVERSATION_STORAGE_VERSION, scopes: {} };
    }
    const parsed = JSON.parse(raw);
    const scopes = parsed?.scopes && typeof parsed.scopes === 'object' ? parsed.scopes : {};
    return {
      version: CONVERSATION_STORAGE_VERSION,
      scopes,
    };
  } catch {
    return { version: CONVERSATION_STORAGE_VERSION, scopes: {} };
  }
}

function writeConversationStore(store) {
  try {
    window.localStorage.setItem(
      CONVERSATION_STORAGE_KEY,
      JSON.stringify({
        version: CONVERSATION_STORAGE_VERSION,
        scopes: store?.scopes && typeof store.scopes === 'object' ? store.scopes : {},
      }),
    );
  } catch {
    // Ignore localStorage failures and keep the UI usable.
  }
}

function getConversationById(conversationId) {
  return state.conversations.find((conversation) => conversation.id === conversationId) || null;
}

function getActiveConversation() {
  return getConversationById(state.activeConversationId);
}

function persistConversationScope() {
  if (!state.conversationScopeKey) return;
  const store = readConversationStore();
  store.scopes[state.conversationScopeKey] = {
    activeConversationId: state.activeConversationId,
    conversations: state.conversations.map((conversation) => ({
      id: conversation.id,
      sessionId: conversation.sessionId,
      title: conversation.title,
      preview: conversation.preview,
      createdAt: conversation.createdAt,
      updatedAt: conversation.updatedAt,
      entries: conversation.entries,
      activePlaybookRunId: conversation.activePlaybookRunId,
    })),
  };
  writeConversationStore(store);
}

function syncActiveConversationRuntime(conversation) {
  state.activeConversationId = conversation?.id || null;
  state.sessionId = conversation?.sessionId || '';
  state.activePlaybookRunId = conversation?.activePlaybookRunId || null;
  if (el.activeConversationLabel) {
    el.activeConversationLabel.textContent = conversation?.title || '未选择会话';
  }
}

function upsertConversationRecord(conversation) {
  const normalized = normalizeConversationRecord(conversation);
  if (!normalized) return null;
  const nextList = state.conversations.filter((item) => item.id !== normalized.id);
  nextList.push(normalized);
  state.conversations = sortConversations(nextList);
  if (!state.activeConversationId) {
    state.activeConversationId = normalized.id;
  }
  if (state.activeConversationId === normalized.id) {
    syncActiveConversationRuntime(normalized);
  }
  persistConversationScope();
  renderConversationList();
  return normalized;
}

function updateConversationRecord(conversationId, updater) {
  const current = getConversationById(conversationId);
  if (!current) return null;
  const patch = typeof updater === 'function' ? updater(current) : updater;
  const next = normalizeConversationRecord({
    ...current,
    ...(patch || {}),
    id: current.id,
    sessionId: current.sessionId,
  });
  return upsertConversationRecord(next);
}

function addConversationEntry(entry, conversationId = state.activeConversationId) {
  const normalizedEntry = normalizeConversationEntry(entry);
  if (!normalizedEntry || !conversationId) return null;
  return updateConversationRecord(conversationId, (conversation) => ({
    entries: [...conversation.entries, normalizedEntry],
    updatedAt: normalizedEntry.createdAt,
  }));
}

function setConversationPlaybookRun(conversationId, runId, opts = {}) {
  if (!conversationId) return null;
  return updateConversationRecord(conversationId, (conversation) => ({
    activePlaybookRunId: runId || null,
    updatedAt: opts.touch === true ? new Date().toISOString() : conversation.updatedAt,
  }));
}

function buildConversationItem(conversation) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'conversation-item';
  button.dataset.conversationId = conversation.id;
  if (conversation.id === state.activeConversationId) {
    button.classList.add('active');
  }
  button.disabled = isChatRequestInFlight() || !state.isAuthenticated;

  const title = document.createElement('span');
  title.className = 'conversation-item-title';
  title.textContent = conversation.title;
  button.appendChild(title);

  const preview = document.createElement('span');
  preview.className = 'conversation-item-preview';
  preview.textContent = conversation.preview || '等待新的安全运营指令';
  button.appendChild(preview);

  const meta = document.createElement('div');
  meta.className = 'conversation-item-meta';
  const updatedAt = document.createElement('span');
  updatedAt.textContent = formatTimeLabel(conversation.updatedAt);
  meta.appendChild(updatedAt);
  const badge = document.createElement('span');
  badge.className = 'conversation-item-badge';
  badge.textContent = conversation.entries.length ? `${conversation.entries.length} 条记录` : '空会话';
  meta.appendChild(badge);
  button.appendChild(meta);

  button.onclick = async () => {
    if (conversation.id === state.activeConversationId) return;
    if (isChatRequestInFlight()) {
      flashChatBusyNotice();
      return;
    }
    await activateConversation(conversation.id);
  };

  return button;
}

function renderConversationList() {
  if (!el.conversationList) return;
  el.conversationList.innerHTML = '';
  state.conversations.forEach((conversation) => {
    el.conversationList.appendChild(buildConversationItem(conversation));
  });
  if (el.newConversationBtn) {
    el.newConversationBtn.disabled = isChatRequestInFlight() || !state.isAuthenticated;
  }
}

function createWelcomeCard() {
  const card = cardTemplate(CHAT_WELCOME_TITLE);
  const pre = document.createElement('pre');
  pre.textContent = CHAT_WELCOME_TEXT;
  card.appendChild(pre);
  return card;
}

function createUserMessageCard(message) {
  const userCard = cardTemplate('你', 'user');
  const pre = document.createElement('pre');
  pre.textContent = message;
  userCard.appendChild(pre);
  return userCard;
}

function createErrorMessageCard(message, title = '错误') {
  const card = cardTemplate(title, 'error-card');
  const pre = document.createElement('pre');
  pre.textContent = message || '请求失败，请稍后重试。';
  card.appendChild(pre);
  return card;
}

function renderConversationEmptyState() {
  if (!el.chatStream) return;
  el.chatStream.innerHTML = '';
  appendCard(createWelcomeCard());
}

function clearWelcomePlaceholder(conversationId = state.activeConversationId) {
  const conversation = getConversationById(conversationId);
  if (!conversation || conversation.entries.length || !el.chatStream) return;
  el.chatStream.innerHTML = '';
}

function renderStoredErrorEntry(entry) {
  appendCard(createErrorMessageCard(entry.message, entry.title || '错误'));
}

function renderPayloadBatch(payloads, opts = {}) {
  const requestState = opts.requestState || null;
  const normalizedPayloads = Array.isArray(payloads) ? payloads.filter(Boolean) : [];
  if (!normalizedPayloads.length) {
    if (requestState) {
      removeChatPendingCard(requestState);
    }
    return;
  }

  if (requestState && (!isActiveChatRequest(requestState) && !requestState?.placeholderCard?.isConnected)) {
    return;
  }

  if (normalizedPayloads.length === 1 && normalizedPayloads[0].type === 'text') {
    if (requestState) {
      replacePendingCardWithText(requestState, normalizedPayloads[0]);
    } else {
      renderPayload(normalizedPayloads[0]);
    }
    return;
  }

  if (requestState) {
    removeChatPendingCard(requestState);
  }
  if (normalizedPayloads.length > 1) {
    const primaryTitle = normalizedPayloads[0]?.data?.title || '任务执行结果';
    renderUnifiedPayloadCard(`${primaryTitle} · 执行详情`, normalizedPayloads);
    return;
  }
  renderPayload(normalizedPayloads[0]);
}

function createPlaybookTriggerCard(templateId, triggerLabel, params, runId = null) {
  const introCard = cardTemplate('', 'user playbook-trigger-card');
  if (runId != null) {
    introCard.dataset.playbookRunId = String(runId);
    introCard.onclick = async () => {
      try {
        await openPlaybookRunById(runId, templateId, { resetWorkspace: true });
      } catch (err) {
        setHint(el.playbookHint, err.message || '加载 Playbook 运行状态失败', 'error');
      }
    };
  }
  const introBubble = document.createElement('div');
  introBubble.className = 'playbook-trigger-pill';
  introBubble.textContent = formatTriggerLabel(templateId, triggerLabel, params);
  const introAvatar = document.createElement('div');
  introAvatar.className = 'playbook-trigger-avatar';
  introAvatar.textContent = '👤';
  introCard.appendChild(introBubble);
  introCard.appendChild(introAvatar);
  return introCard;
}

function replayConversationEntry(entry) {
  if (!entry) return;
  if (entry.type === 'user_message') {
    appendCard(createUserMessageCard(entry.message));
    return;
  }
  if (entry.type === 'assistant_payload_batch') {
    renderPayloadBatch(entry.payloads);
    return;
  }
  if (entry.type === 'playbook_trigger') {
    appendCard(createPlaybookTriggerCard(entry.templateId, entry.triggerLabel, entry.params, entry.runId));
    renderPlaybookLaunchFeedback(entry.templateId, entry.triggerLabel, entry.runId);
    return;
  }
  if (entry.type === 'error') {
    renderStoredErrorEntry(entry);
  }
}

function renderConversationEntries(entries) {
  if (!el.chatStream) return;
  el.chatStream.innerHTML = '';
  const normalizedEntries = Array.isArray(entries) ? entries : [];
  if (!normalizedEntries.length) {
    renderConversationEmptyState();
    return;
  }
  normalizedEntries.forEach(replayConversationEntry);
  scrollChatToBottom();
}

async function restoreConversation(conversation, opts = {}) {
  syncActiveConversationRuntime(conversation);
  persistConversationScope();
  renderConversationList();
  renderConversationEntries(conversation?.entries || []);
  hideSlashCommandMenu();

  if (conversation?.activePlaybookRunId) {
    try {
      await openPlaybookRunById(conversation.activePlaybookRunId, '', { resetWorkspace: true });
    } catch (err) {
      clearPlaybookWorkspace();
      setPlaybookWorkspaceOpen(false);
      setHint(el.playbookHint, err.message || '恢复 Playbook 运行状态失败。', 'error');
    }
  } else {
    clearPlaybookWorkspace();
    setPlaybookWorkspaceOpen(false);
  }

  if (opts.focusInput !== false && el.chatMessage) {
    el.chatMessage.focus();
  }
}

async function activateConversation(conversationId, opts = {}) {
  const conversation = getConversationById(conversationId);
  if (!conversation) return;
  state.activeConversationId = conversation.id;
  await restoreConversation(conversation, opts);
}

async function createNewConversation(opts = {}) {
  const conversation = createConversationRecord();
  upsertConversationRecord(conversation);
  await activateConversation(conversation.id, opts);
  return conversation;
}

async function ensureConversationScope(baseUrl) {
  const scopeKey = normalizeConversationScope(baseUrl);
  const store = readConversationStore();
  const rawScope = store.scopes?.[scopeKey];
  const conversations = sortConversations(
    (Array.isArray(rawScope?.conversations) ? rawScope.conversations : [])
      .map(normalizeConversationRecord)
      .filter(Boolean),
  );

  state.conversationScopeKey = scopeKey;
  state.conversations = conversations;

  if (!state.conversations.length) {
    await createNewConversation({ focusInput: false });
    return;
  }

  const requestedId = String(rawScope?.activeConversationId || '').trim();
  const activeConversation =
    state.conversations.find((conversation) => conversation.id === requestedId) || state.conversations[0];
  state.activeConversationId = activeConversation.id;
  await restoreConversation(activeConversation, { focusInput: false });
}

function clearConversationRuntimeState() {
  state.sessionId = '';
  state.conversationScopeKey = '';
  state.conversations = [];
  state.activeConversationId = null;
  if (el.conversationList) {
    el.conversationList.innerHTML = '';
  }
  if (el.activeConversationLabel) {
    el.activeConversationLabel.textContent = '';
  }
  if (el.chatStream) {
    el.chatStream.innerHTML = '';
  }
}

function createFormSubmitMessage(payload, params) {
  const labelMap = new Map((payload?.data?.fields || []).map((field) => [field.key, field.label || field.key]));
  const detail = Object.entries(params || {})
    .slice(0, 3)
    .map(([key, value]) => `${labelMap.get(key) || key}=${Array.isArray(value) ? value.join(',') : String(value)}`)
    .join('，');
  return detail ? `提交表单：${detail}` : `提交表单：${payload?.data?.title || '参数补充'}`;
}

async function submitChatMessage(message, opts = {}) {
  const rawMessage = String(message || '').trim();
  if (!rawMessage) return false;

  if (!state.isAuthenticated) {
    return sendChat(rawMessage);
  }
  if (isChatRequestInFlight()) {
    flashChatBusyNotice();
    return false;
  }

  const conversationId = opts.conversationId || state.activeConversationId;
  const displayText = String(opts.displayText || rawMessage).trim();
  clearWelcomePlaceholder(conversationId);
  if (opts.recordUser !== false && displayText) {
    addConversationEntry({ type: 'user_message', message: displayText, createdAt: new Date().toISOString() }, conversationId);
  }
  if (opts.renderUserCard !== false && displayText) {
    appendCard(createUserMessageCard(displayText));
  }

  if (el.chatMessage && opts.clearInput) {
    el.chatMessage.value = '';
  }
  return sendChat(rawMessage);
}

const CHART_TEXT_PRIMARY = '#e7eefc';
const CHART_TEXT_SECONDARY = '#b7c6df';
const CHART_GRID_LINE = 'rgba(151, 172, 211, 0.24)';
const CHART_AXIS_LINE = 'rgba(143, 164, 201, 0.38)';
const CHART_TOOLTIP_BG = 'rgba(9, 16, 34, 0.94)';

function cloneChartOption(option) {
  if (!option || typeof option !== 'object') return {};
  if (typeof structuredClone === 'function') return structuredClone(option);
  return JSON.parse(JSON.stringify(option));
}

function themeChartTitle(title) {
  if (Array.isArray(title)) return title.map((item) => themeChartTitle(item));
  if (!title || typeof title !== 'object') return title;
  return {
    ...title,
    textStyle: {
      color: CHART_TEXT_PRIMARY,
      fontWeight: 700,
      ...(title.textStyle || {}),
    },
    subtextStyle: {
      color: CHART_TEXT_SECONDARY,
      ...(title.subtextStyle || {}),
    },
  };
}

function themeChartLegend(legend) {
  if (Array.isArray(legend)) return legend.map((item) => themeChartLegend(item));
  if (!legend || typeof legend !== 'object') return legend;
  return {
    ...legend,
    textStyle: {
      color: CHART_TEXT_SECONDARY,
      ...(legend.textStyle || {}),
    },
  };
}

function themeChartAxis(axis, axisType = 'value') {
  if (Array.isArray(axis)) return axis.map((item) => themeChartAxis(item, axisType));
  if (!axis || typeof axis !== 'object') return axis;
  const themed = {
    ...axis,
    axisLabel: {
      color: CHART_TEXT_SECONDARY,
      ...(axis.axisLabel || {}),
    },
    axisLine: {
      ...(axis.axisLine || {}),
      lineStyle: {
        color: CHART_AXIS_LINE,
        ...((axis.axisLine && axis.axisLine.lineStyle) || {}),
      },
    },
    nameTextStyle: {
      color: CHART_TEXT_SECONDARY,
      ...(axis.nameTextStyle || {}),
    },
    axisPointer: {
      ...((axis.axisPointer && typeof axis.axisPointer === 'object') ? axis.axisPointer : {}),
      label: {
        color: CHART_TEXT_PRIMARY,
        backgroundColor: 'rgba(33, 60, 112, 0.92)',
        ...(((axis.axisPointer && axis.axisPointer.label) || {})),
      },
    },
  };
  if (axisType === 'category') return themed;
  return {
    ...themed,
    splitLine: {
      ...(axis.splitLine || {}),
      lineStyle: {
        color: CHART_GRID_LINE,
        ...((axis.splitLine && axis.splitLine.lineStyle) || {}),
      },
    },
  };
}

function themeChartSeries(series) {
  if (!Array.isArray(series)) return [];
  return series.map((item) => {
    if (!item || typeof item !== 'object') return item;
    if (String(item.type || '').toLowerCase() === 'pie') {
      return {
        ...item,
        label: {
          show: true,
          color: '#f8fbff',
          fontWeight: 700,
          backgroundColor: 'rgba(7, 14, 30, 0.88)',
          borderColor: 'rgba(125, 160, 226, 0.26)',
          borderWidth: 1,
          borderRadius: 999,
          padding: [4, 8],
          textBorderColor: 'rgba(3, 8, 22, 0.9)',
          textBorderWidth: 3,
          ...((item.label && typeof item.label === 'object') ? item.label : {}),
        },
        labelLine: {
          show: true,
          length: 16,
          length2: 10,
          ...((item.labelLine && typeof item.labelLine === 'object') ? item.labelLine : {}),
          lineStyle: {
            color: '#93b5ee',
            width: 1.5,
            ...(((item.labelLine || {}).lineStyle) || {}),
          },
        },
        emphasis: {
          ...((item.emphasis && typeof item.emphasis === 'object') ? item.emphasis : {}),
          label: {
            color: '#ffffff',
            fontWeight: 800,
            backgroundColor: 'rgba(16, 29, 58, 0.96)',
            borderRadius: 999,
            padding: [5, 9],
            ...(((item.emphasis && item.emphasis.label) || {})),
          },
        },
      };
    }
    return {
      ...item,
      label: {
        color: CHART_TEXT_PRIMARY,
        ...((item.label && typeof item.label === 'object') ? item.label : {}),
      },
      emphasis: {
        ...((item.emphasis && typeof item.emphasis === 'object') ? item.emphasis : {}),
        label: {
          color: CHART_TEXT_PRIMARY,
          ...(((item.emphasis && item.emphasis.label) || {})),
        },
      },
    };
  });
}

function inferAxisKind(axis, fallback = 'value') {
  if (Array.isArray(axis)) return axis.map((item) => inferAxisKind(item, fallback));
  if (!axis || typeof axis !== 'object') return fallback;
  const axisType = String(axis.type || '').trim().toLowerCase();
  return axisType || fallback;
}

function buildReadableChartOption(option) {
  const themed = cloneChartOption(option);
  return {
    ...themed,
    backgroundColor: 'transparent',
    textStyle: {
      color: CHART_TEXT_PRIMARY,
      ...(themed.textStyle || {}),
    },
    title: themeChartTitle(themed.title),
    legend: themeChartLegend(themed.legend),
    tooltip: {
      ...((themed.tooltip && typeof themed.tooltip === 'object') ? themed.tooltip : {}),
      backgroundColor: CHART_TOOLTIP_BG,
      borderColor: 'rgba(94, 132, 211, 0.46)',
      textStyle: {
        color: CHART_TEXT_PRIMARY,
        ...(themed.tooltip && themed.tooltip.textStyle ? themed.tooltip.textStyle : {}),
      },
    },
    xAxis: Array.isArray(themed.xAxis)
      ? themed.xAxis.map((axis, index) => themeChartAxis(axis, inferAxisKind(axis, index === 0 ? 'category' : 'value')))
      : themeChartAxis(themed.xAxis, inferAxisKind(themed.xAxis, 'category')),
    yAxis: Array.isArray(themed.yAxis)
      ? themed.yAxis.map((axis, index) => themeChartAxis(axis, inferAxisKind(axis, index === 0 ? 'value' : 'category')))
      : themeChartAxis(themed.yAxis, inferAxisKind(themed.yAxis, 'value')),
    radar: themed.radar ? {
      ...themed.radar,
      axisName: {
        color: CHART_TEXT_SECONDARY,
        ...((themed.radar.axisName && typeof themed.radar.axisName === 'object') ? themed.radar.axisName : {}),
      },
      splitLine: {
        ...(themed.radar.splitLine || {}),
        lineStyle: {
          color: CHART_GRID_LINE,
          ...(((themed.radar.splitLine || {}).lineStyle || {})),
        },
      },
      axisLine: {
        ...(themed.radar.axisLine || {}),
        lineStyle: {
          color: CHART_AXIS_LINE,
          ...(((themed.radar.axisLine || {}).lineStyle || {})),
        },
      },
      splitArea: {
        ...(themed.radar.splitArea || {}),
        areaStyle: {
          color: ['rgba(13, 23, 48, 0.22)', 'rgba(13, 23, 48, 0.08)'],
          ...(((themed.radar.splitArea || {}).areaStyle || {})),
        },
      },
    } : themed.radar,
    series: themeChartSeries(themed.series),
  };
}

function setHint(target, message, type = '') {
  target.textContent = message || '';
  target.classList.remove('success', 'error');
  if (type) target.classList.add(type);
}

function finishBootTransition() {
  document.body.classList.remove('booting');
  const bootScreen = document.getElementById('appBootScreen');
  if (!bootScreen) return;
  window.setTimeout(() => {
    bootScreen.remove();
  }, 260);
}

function setAuthState(authenticated, statusText = '', isConnected = true) {
  state.isAuthenticated = authenticated;
  el.landingView.classList.toggle('hidden', authenticated);
  el.workspaceView.classList.toggle('hidden', !authenticated);
  if (!authenticated) {
    resetChatRequestState();
    setPlaybookWorkspaceOpen(false);
    clearPlaybookWorkspace();
    state.activePlaybookRunId = null;
    state.playbookRunCache = {};
    state.playbookOpenTokens = {};
    hideSlashCommandMenu();
    clearConversationRuntimeState();
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
  scrollChatToBottom();
}

function scrollChatToBottom() {
  if (!el.chatStream) return;
  el.chatStream.scrollTop = el.chatStream.scrollHeight;
}

function createIdleChatRequestState() {
  return {
    inFlight: false,
    conversationId: null,
    sessionId: '',
    phase: 'idle',
    startedAt: null,
    placeholderCard: null,
    placeholderTitleNode: null,
    placeholderStatusRow: null,
    placeholderStatusNode: null,
    previewNode: null,
    previewText: '',
    previewFrame: null,
    statusRestoreTimer: null,
    statusOverride: '',
  };
}

function getChatPhaseText(phase) {
  return CHAT_PHASE_META[phase]?.text || '';
}

function isChatRequestInFlight() {
  return !!state.chatRequest?.inFlight;
}

function isActiveChatRequest(requestState) {
  return !!requestState && state.chatRequest === requestState && !!requestState.inFlight;
}

function clearChatStatusRestoreTimer(requestState) {
  if (!requestState?.statusRestoreTimer) return;
  clearTimeout(requestState.statusRestoreTimer);
  requestState.statusRestoreTimer = null;
}

function cancelChatPreviewFrame(requestState) {
  if (requestState?.previewFrame == null) return;
  cancelAnimationFrame(requestState.previewFrame);
  requestState.previewFrame = null;
}

function syncChatRequestUi() {
  const requestState = state.chatRequest;
  const inFlight = !!requestState?.inFlight;
  const phase = requestState?.phase || 'idle';
  const statusText = requestState?.statusOverride || getChatPhaseText(phase);

  if (el.chatStream) {
    el.chatStream.setAttribute('aria-busy', inFlight ? 'true' : 'false');
  }
  if (el.chatForm) {
    el.chatForm.classList.toggle('busy', inFlight);
  }
  if (el.chatMessage) {
    el.chatMessage.disabled = inFlight;
  }
  if (el.chatSubmitBtn) {
    el.chatSubmitBtn.disabled = inFlight;
    el.chatSubmitBtn.textContent = inFlight ? '处理中...' : '执行';
  }
  if (el.chatStatusBar) {
    el.chatStatusBar.classList.toggle('hidden', !inFlight);
    el.chatStatusBar.classList.toggle('is-thinking', inFlight && phase === 'thinking');
    el.chatStatusBar.classList.toggle('is-generating', inFlight && phase === 'generating');
  }
  if (el.chatStatusText) {
    el.chatStatusText.textContent = statusText;
  }
  renderConversationList();
}

function createChatPendingCard(phase = 'thinking') {
  const card = cardTemplate('助手', 'assistant-pending-card');
  card.dataset.pendingAssistant = 'true';

  const statusRow = document.createElement('div');
  statusRow.className = `assistant-pending-status assistant-pending-status--${phase}`;

  const spinner = document.createElement('span');
  spinner.className = 'assistant-pending-spinner';
  spinner.setAttribute('aria-hidden', 'true');
  statusRow.appendChild(spinner);

  const statusNode = document.createElement('span');
  statusNode.className = 'assistant-pending-status-text';
  statusNode.textContent = getChatPhaseText(phase);
  statusRow.appendChild(statusNode);
  card.appendChild(statusRow);

  const preview = document.createElement('pre');
  preview.className = 'assistant-pending-preview';
  preview.textContent = getChatPhaseText(phase);
  card.appendChild(preview);

  return {
    card,
    titleNode: card.querySelector('strong'),
    statusRow,
    statusNode,
    preview,
  };
}

function mountChatPendingCard(requestState) {
  if (!isActiveChatRequest(requestState)) return;
  const pendingUi = createChatPendingCard(requestState.phase);
  requestState.placeholderCard = pendingUi.card;
  requestState.placeholderTitleNode = pendingUi.titleNode;
  requestState.placeholderStatusRow = pendingUi.statusRow;
  requestState.placeholderStatusNode = pendingUi.statusNode;
  requestState.previewNode = pendingUi.preview;
  appendCard(pendingUi.card);
}

function updateChatPendingTitle(requestState, title) {
  if (!isActiveChatRequest(requestState) || !requestState.placeholderTitleNode) return;
  requestState.placeholderTitleNode.textContent = title || '系统消息';
}

function updateChatPendingPhase(requestState, phase) {
  if (!isActiveChatRequest(requestState)) return;
  clearChatStatusRestoreTimer(requestState);
  requestState.statusOverride = '';
  requestState.phase = phase;
  const phaseText = getChatPhaseText(phase);
  if (requestState.placeholderStatusRow) {
    requestState.placeholderStatusRow.classList.toggle('assistant-pending-status--thinking', phase === 'thinking');
    requestState.placeholderStatusRow.classList.toggle('assistant-pending-status--generating', phase === 'generating');
  }
  if (requestState.placeholderStatusNode) {
    requestState.placeholderStatusNode.textContent = phaseText;
  }
  if (requestState.previewNode && !requestState.previewText) {
    requestState.previewNode.textContent = phaseText;
  }
  syncChatRequestUi();
}

function scheduleChatPreviewRender(requestState) {
  if (!isActiveChatRequest(requestState) || !requestState.previewNode || requestState.previewFrame != null) return;
  requestState.previewFrame = requestAnimationFrame(() => {
    requestState.previewFrame = null;
    if (!isActiveChatRequest(requestState) || !requestState.previewNode) return;
    requestState.previewNode.textContent = requestState.previewText || getChatPhaseText(requestState.phase);
    scrollChatToBottom();
  });
}

function setChatPreviewText(requestState, text) {
  if (!isActiveChatRequest(requestState)) return;
  requestState.previewText = text || '';
  scheduleChatPreviewRender(requestState);
}

function removeChatPendingCard(requestState) {
  cancelChatPreviewFrame(requestState);
  if (requestState?.placeholderCard?.isConnected) {
    requestState.placeholderCard.remove();
  }
  requestState.placeholderCard = null;
  requestState.placeholderTitleNode = null;
  requestState.placeholderStatusRow = null;
  requestState.placeholderStatusNode = null;
  requestState.previewNode = null;
  requestState.previewText = '';
}

function replacePendingCardWithText(requestState, payload) {
  const textPayload = payload || { type: 'text', data: {} };
  if (!isActiveChatRequest(requestState) && !requestState?.placeholderCard?.isConnected) return;
  if (!requestState?.placeholderCard || !requestState.placeholderCard.isConnected) {
    renderPayload(textPayload);
    return;
  }

  cancelChatPreviewFrame(requestState);
  const card = requestState.placeholderCard;
  card.className = 'chat-card';
  card.removeAttribute('data-pending-assistant');
  if (textPayload.data?.dangerous) {
    card.classList.add('approval-card');
  }
  card.innerHTML = '';

  const title = document.createElement('strong');
  title.textContent = textPayload.data?.title || '系统消息';
  card.appendChild(title);
  card.appendChild(createMarkdownBlock(textPayload.data?.text || ''));

  requestState.placeholderCard = null;
  requestState.placeholderTitleNode = null;
  requestState.placeholderStatusRow = null;
  requestState.placeholderStatusNode = null;
  requestState.previewNode = null;
  requestState.previewText = '';
  scrollChatToBottom();
}

function renderChatRequestError(requestState, message) {
  if (!isActiveChatRequest(requestState) && !requestState?.placeholderCard?.isConnected) return;
  const safeMessage = message || '请求失败，请稍后重试。';
  if (!requestState?.placeholderCard || !requestState.placeholderCard.isConnected) {
    const card = cardTemplate('错误', 'error-card');
    const pre = document.createElement('pre');
    pre.textContent = safeMessage;
    card.appendChild(pre);
    appendCard(card);
    return;
  }

  cancelChatPreviewFrame(requestState);
  const card = requestState.placeholderCard;
  card.className = 'chat-card error-card';
  card.removeAttribute('data-pending-assistant');
  card.innerHTML = '';

  const title = document.createElement('strong');
  title.textContent = '错误';
  card.appendChild(title);
  const pre = document.createElement('pre');
  pre.textContent = safeMessage;
  card.appendChild(pre);

  requestState.placeholderCard = null;
  requestState.placeholderTitleNode = null;
  requestState.placeholderStatusRow = null;
  requestState.placeholderStatusNode = null;
  requestState.previewNode = null;
  requestState.previewText = '';
  scrollChatToBottom();
}

function finalizeChatPayloadBatch(payloads, requestState) {
  if (!isActiveChatRequest(requestState) && !requestState?.placeholderCard?.isConnected) return;
  const normalizedPayloads = Array.isArray(payloads) ? payloads.filter(Boolean) : [];
  if (normalizedPayloads.length) {
    addConversationEntry(
      {
        type: 'assistant_payload_batch',
        payloads: normalizedPayloads,
        createdAt: new Date().toISOString(),
      },
      requestState?.conversationId || state.activeConversationId,
    );
  }
  renderPayloadBatch(normalizedPayloads, { requestState });
}

function flashChatBusyNotice(message = CHAT_BUSY_NOTICE) {
  const requestState = state.chatRequest;
  if (!requestState?.inFlight) return;
  clearChatStatusRestoreTimer(requestState);
  requestState.statusOverride = message;
  syncChatRequestUi();
  requestState.statusRestoreTimer = window.setTimeout(() => {
    if (!isActiveChatRequest(requestState)) return;
    requestState.statusOverride = '';
    requestState.statusRestoreTimer = null;
    syncChatRequestUi();
  }, 2200);
}

function beginChatRequest() {
  const requestState = createIdleChatRequestState();
  requestState.inFlight = true;
  requestState.conversationId = state.activeConversationId;
  requestState.sessionId = state.sessionId;
  requestState.phase = 'thinking';
  requestState.startedAt = Date.now();
  state.chatRequest = requestState;
  mountChatPendingCard(requestState);
  syncChatRequestUi();
  return requestState;
}

function finishChatRequest(requestState) {
  if (!isActiveChatRequest(requestState)) return;
  clearChatStatusRestoreTimer(requestState);
  cancelChatPreviewFrame(requestState);
  state.chatRequest = createIdleChatRequestState();
  syncChatRequestUi();
}

function resetChatRequestState() {
  clearChatStatusRestoreTimer(state.chatRequest);
  removeChatPendingCard(state.chatRequest);
  state.chatRequest = createIdleChatRequestState();
  syncChatRequestUi();
}

function setPlaybookWorkspaceOpen(open) {
  if (!el.playbookWorkspacePanel || !el.workspaceView) return;
  el.playbookWorkspacePanel.classList.toggle('hidden', !open);
  el.workspaceView.classList.toggle('panel-open', open);
}

function setPlaybookWorkspaceMode(mode = 'default') {
  if (!el.playbookWorkspacePanel || !el.playbookWorkspaceBody) return;
  const triage = mode === 'triage';
  el.playbookWorkspacePanel.classList.toggle('triage-mode', triage);
  el.playbookWorkspaceBody.classList.toggle('triage-mode', triage);
}

function clearPlaybookWorkspace() {
  if (!el.playbookWorkspaceBody) return;
  setPlaybookWorkspaceMode('default');
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
  const runId = String(node?.dataset?.playbookRunId || '').trim();
  const cardType = String(node?.dataset?.playbookCardType || '').trim();
  if (runId && cardType) {
    const existingCards = Array.from(
      el.playbookWorkspaceBody.querySelectorAll('.chat-card[data-playbook-run-id][data-playbook-card-type]')
    ).filter((item) => item.dataset.playbookRunId === runId && item.dataset.playbookCardType === cardType);
    if (existingCards.length) {
      existingCards[0].replaceWith(node);
      existingCards.slice(1).forEach((item) => item.remove());
      return;
    }
  }
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
  const conversationId = opts.conversationId || state.activeConversationId;
  const runKey = String(runId);
  const openToken = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  state.playbookOpenTokens[runKey] = openToken;
  state.activePlaybookRunId = runId;
  setConversationPlaybookRun(conversationId, runId);
  setPlaybookWorkspaceOpen(true);
  if (opts.resetWorkspace !== false && el.playbookWorkspaceBody) {
    el.playbookWorkspaceBody.innerHTML = '';
  }

  const runData = await api(`/api/playbooks/runs/${runId}`);
  if (state.playbookOpenTokens[runKey] !== openToken) {
    return runData;
  }
  state.playbookRunCache[runId] = runData;
  const resolvedTemplateId = runData.template_id || templateId || 'unknown';
  const progressUi = createPlaybookProgressCard(runId, resolvedTemplateId);
  updatePlaybookProgress(progressUi, runData);

  if (runData.status === 'Finished' || runData.status === 'Failed') {
    if (state.playbookOpenTokens[runKey] === openToken) {
      renderPlaybookResult(runData);
    }
    return runData;
  }

  const finalRun = await pollPlaybookRun(runId, progressUi, resolvedTemplateId);
  if (state.playbookOpenTokens[runKey] !== openToken) {
    return finalRun;
  }
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
    const table = createConfiguredTable(payload.data.columns || []);
    const thead = document.createElement('thead');
    const trh = document.createElement('tr');
    (payload.data.columns || []).forEach((c) => {
      const th = document.createElement('th');
      th.textContent = c.label;
      applyColumnCellStyle(th, c);
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
        td.title = td.textContent;
        applyColumnCellStyle(td, c);
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
    chart.className = 'chart-canvas';
    chart.style.height = '260px';
    card.appendChild(chart);
    const summary = document.createElement('p');
    summary.className = 'chart-summary';
    summary.textContent = payload.data.summary || '';
    card.appendChild(summary);
    appendCard(card);
    const instance = echarts.init(chart);
    instance.setOption(buildReadableChartOption(payload.data.option || {}));
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
        await submitChatMessage('确认');
      });
    };

    const cancel = document.createElement('button');
    cancel.className = 'secondary-btn';
    cancel.textContent = '取消';
    cancel.onclick = async () => submitChatMessage('取消');

    actions.appendChild(ok);
    actions.appendChild(cancel);
    card.appendChild(actions);
    appendCard(card);
    return;
  }

  if (payload.type === 'quick_actions') {
    const card = cardTemplate(payload.data.title || '快捷操作', 'quick-action-card');
    const desc = document.createElement('p');
    desc.textContent = payload.data.text || '';
    card.appendChild(desc);

    const actions = document.createElement('div');
    actions.className = 'action-row quick-action-row';
    (payload.data.actions || []).forEach((action) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = action.style === 'primary' ? 'primary-btn quick-action-btn' : 'secondary-btn quick-action-btn';
      btn.textContent = action.label || '继续';
      btn.onclick = async () => {
        if (!action.message) return;
        btn.disabled = true;
        try {
          await submitChatMessage(String(action.message));
        } finally {
          btn.disabled = false;
        }
      };
      actions.appendChild(btn);
    });

    if (actions.childNodes.length) {
      card.appendChild(actions);
    }
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
      if (field.pattern) inputEl.pattern = field.pattern;
      if (field.min != null) inputEl.min = String(field.min);
      if (field.max != null) inputEl.max = String(field.max);
      if (field.step != null) inputEl.step = String(field.step);
      if (field.inputmode) inputEl.inputMode = field.inputmode;
      if (field.title) inputEl.title = field.title;
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
      if (!form.reportValidity()) return;
      const fd = new FormData(form);
      const params = {};
      fields.forEach((field) => {
        const raw = (fd.get(field.key) || '').toString().trim();
        if (!raw) return;
        if (field.key === 'views') {
          validateBlockTargetValues(raw, (fd.get('block_type') || '').toString().trim());
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

      await submitChatMessage(
        `${FORM_SUBMIT_PREFIX}${JSON.stringify({
          token: payload.data.token,
          intent: payload.data.intent,
          params,
        })}`,
        {
          displayText: createFormSubmitMessage(payload, params),
        },
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
  setPlaybookWorkspaceMode('default');
  const displayName = getPlaybookDisplayName(templateId);
  const card = cardTemplate(`Playbook 运行中 · ${templateId}`);
  card.dataset.playbookRunId = String(runId);
  card.dataset.playbookCardType = 'progress';
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
  const columns = payload.data.columns || [];
  const table = createConfiguredTable(columns);
  const thead = document.createElement('thead');
  const trh = document.createElement('tr');
  columns.forEach((c) => {
    const th = document.createElement('th');
    th.textContent = c.label;
    applyColumnCellStyle(th, c);
    trh.appendChild(th);
  });
  thead.appendChild(trh);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  const rows = Array.isArray(customRows) ? customRows : (payload.data.rows || []);
  rows.forEach((row) => {
    const tr = document.createElement('tr');
    columns.forEach((c) => {
      const td = document.createElement('td');
      const value = row[c.key];
      td.textContent = Array.isArray(value) ? value.join(', ') : String(value ?? '');
      td.title = td.textContent;
      applyColumnCellStyle(td, c);
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

function createConfiguredTable(columns) {
  const table = document.createElement('table');
  const hasColumnWidth = columns.some((column) => column && (column.width || column.minWidth));
  if (hasColumnWidth) {
    table.classList.add('table-fixed-layout');
    const colgroup = document.createElement('colgroup');
    columns.forEach((column) => {
      const col = document.createElement('col');
      if (column.width) col.style.width = column.width;
      if (column.minWidth) col.style.minWidth = column.minWidth;
      colgroup.appendChild(col);
    });
    table.appendChild(colgroup);
  }
  return table;
}

function applyColumnCellStyle(node, column) {
  if (!node || !column) return;
  if (column.width) node.style.width = column.width;
  if (column.minWidth) node.style.minWidth = column.minWidth;
  if (column.nowrap) {
    node.style.whiteSpace = 'nowrap';
  }
}

function mountDeferredCharts(container) {
  const charts = container.querySelectorAll('[data-echarts-deferred="1"]');
  charts.forEach((chart) => {
    if (chart.__echartsInstance) return;
    const instance = echarts.init(chart);
    instance.setOption(buildReadableChartOption(chart.__echartsOption || {}));
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

function isValidIncidentUuid(value) {
  return /^incident-[A-Za-z0-9-]{6,}$/.test(String(value || '').trim());
}

function isValidDomainName(value) {
  return /^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$/.test(String(value || '').trim());
}

function isValidUrlTarget(value) {
  const text = String(value || '').trim();
  if (!text) return false;
  if (/^https?:\/\//i.test(text)) {
    try {
      const parsed = new URL(text);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  }
  const slashIndex = text.indexOf('/');
  if (slashIndex <= 0) return false;
  const host = text.slice(0, slashIndex);
  return isValidIpv4(host) || isValidDomainName(host);
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

function splitTargetValues(value) {
  return dedupText(String(value || '').split(/[\s,，]+/).map((item) => item.trim()).filter(Boolean));
}

function validateBlockTargetValues(rawValue, blockType) {
  const values = splitTargetValues(rawValue);
  if (!values.length) {
    throw new Error('请输入至少一个封禁对象。');
  }
  const normalizedType = String(blockType || '').trim().toUpperCase();
  const validatorMap = {
    SRC_IP: { fn: isValidIpv4, label: 'IPv4 地址' },
    DST_IP: { fn: isValidIpv4, label: 'IPv4 地址' },
    DNS: { fn: isValidDomainName, label: '域名' },
    URL: { fn: isValidUrlTarget, label: 'URL' },
  };
  const validator = validatorMap[normalizedType];
  if (!validator) {
    throw new Error('封禁对象类型不合法。');
  }
  const invalid = values.find((item) => !validator.fn(item));
  if (invalid) {
    throw new Error(`封禁对象 ${invalid} 不是合法的${validator.label}。`);
  }
  return values;
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
  const trendLabels = trendRawLabels.slice(-7).map((label) => {
    const text = String(label || '').trim();
    if (!text) return '--';
    const dayText = text.split(' ')[0];
    const matched = dayText.match(/(\d{2}-\d{2})$/);
    return matched ? matched[1] : dayText.slice(-5);
  });
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
  if (state.routineBlockAutoCloseTimer) {
    window.clearInterval(state.routineBlockAutoCloseTimer);
    state.routineBlockAutoCloseTimer = null;
  }
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

function closeRoutineBlockDialog() {
  if (state.routineBlockAutoCloseTimer) {
    window.clearInterval(state.routineBlockAutoCloseTimer);
    state.routineBlockAutoCloseTimer = null;
  }
  state.routineBlockDraft = null;
  closeDialog(el.routineBlockDialog);
}

function setRoutineBlockHint(message, type = '') {
  if (!el.routineBlockHint) return;
  el.routineBlockHint.textContent = message || '';
  el.routineBlockHint.classList.remove('success', 'error');
  if (type) el.routineBlockHint.classList.add(type);
}

function getRoutineBlockModeMeta(blockType) {
  if (String(blockType || '').toUpperCase() === 'DST_IP') {
    return {
      directionValue: '目的IP',
      modeLabel: '目的IP封禁',
      targetLabel: '待封锁目的IP',
      confirmLabel: '确认并封锁目的IP',
      contextNote: '当前模式：目的IP封禁，仅支持深信服 AF 设备联动。',
    };
  }
  return {
    directionValue: '源IP',
    modeLabel: '源IP封禁',
    targetLabel: '待封禁源IP',
    confirmLabel: '确认并封禁源IP',
    contextNote: '当前模式：源IP封禁，仅支持深信服 AF 设备联动。',
  };
}

function removeRoutineBlockIp(ip) {
  if (!state.routineBlockDraft) return;
  state.routineBlockDraft.selectedIps = (state.routineBlockDraft.selectedIps || []).filter((item) => item !== ip);
  renderRoutineBlockDialogContent();
}

function createRoutineTargetChip(ip) {
  const isLocked = !!state.routineBlockDraft?.successState;
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
  removeBtn.disabled = isLocked;
  removeBtn.onclick = (event) => {
    event.preventDefault();
    event.stopPropagation();
    if (isLocked) return;
    removeRoutineBlockIp(ip);
  };
  chip.appendChild(removeBtn);
  return chip;
}

function renderRoutineBlockDialogContent() {
  const draft = state.routineBlockDraft;
  if (!draft) return;
  const selectedIps = draft.selectedIps || [];
  const modeMeta = draft.modeMeta || getRoutineBlockModeMeta(draft.blockType);
  const successState = draft.successState || null;
  if (el.routineBlockTitle) {
    el.routineBlockTitle.textContent = `${draft.actionTitle || '一键处置'}（${selectedIps.length}个目标）`;
  }
  if (el.routineBlockTargetLabel) el.routineBlockTargetLabel.textContent = modeMeta.targetLabel;
  if (el.routineBlockDirection) el.routineBlockDirection.value = modeMeta.directionValue || '-';
  if (el.routineBlockContextNote) el.routineBlockContextNote.textContent = modeMeta.contextNote;
  if (el.routineBlockConfirm) {
    el.routineBlockConfirm.textContent = successState ? '封禁已完成' : modeMeta.confirmLabel;
  }
  if (el.routineBlockCancel) {
    el.routineBlockCancel.textContent = successState ? '立即关闭' : '取消';
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
        removeBtn.disabled = !!successState;
        removeBtn.onclick = () => {
          if (successState) return;
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
  const deviceMessage = String(draft.deviceMessage || '').trim();
  if (el.routineBlockDevice) el.routineBlockDevice.disabled = !!successState;
  if (el.routineBlockHours) el.routineBlockHours.disabled = !!successState;
  if (el.routineBlockRuleName) el.routineBlockRuleName.disabled = !!successState;
  if (el.routineBlockDirection) el.routineBlockDirection.disabled = true;
  if (el.routineBlockReason) el.routineBlockReason.disabled = !!successState;
  if (el.routineBlockConfirm) {
    el.routineBlockConfirm.disabled = !!successState || !hasOnlineDevice || !selectedIps.length;
  }
  if (successState) {
    const countdown = Math.max(0, Number(successState.countdown) || 0);
    setRoutineBlockHint(`${successState.message || '封禁执行成功。'} ${countdown}秒后自动关闭弹窗，你也可以手动关闭。`, 'success');
    return;
  }
  if (!selectedIps.length) {
    setRoutineBlockHint('请至少保留一个目标IP后再下发。', 'error');
  } else if (!hasOnlineDevice) {
    setRoutineBlockHint(deviceMessage || '当前没有可联动 AF 设备，暂无法直接下发。', 'error');
  } else {
    setRoutineBlockHint(deviceMessage || '已找到可联动 AF 设备，请核对威胁情报、设备与封禁时长后下发。', '');
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
    const deviceStatus = String(preview?.device_status || '').trim();
    const deviceMessage = String(preview?.device_message || '').trim();
    const defaultDeviceId = String(preview?.default_device_id || (devices[0]?.device_id || '')).trim();
    const resolvedBlockType = preview.block_type || config.blockType || 'SRC_IP';
    const modeMeta = getRoutineBlockModeMeta(resolvedBlockType);

    state.routineBlockDraft = {
      actionTitle: config.actionTitle || '一键处置',
      resultTitle: config.resultTitle || '网侧封禁结果',
      blockType: resolvedBlockType,
      modeMeta,
      allIps: [...targets],
      selectedIps: [...targets],
      skippedIps: preview.skipped_ips || [],
      deviceOptions: devices,
      deviceStatus,
      deviceMessage,
      defaultDeviceId,
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
      if (defaultDeviceId) {
        el.routineBlockDevice.value = defaultDeviceId;
      }
      if (!devices.length) {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = deviceStatus === 'query_error'
          ? 'AF设备查询失败'
          : '暂无可联动AF设备';
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
    setHint(el.playbookHint, data.message || '封禁执行成功。', 'success');
    const resultCard = cardTemplate(state.routineBlockDraft.resultTitle || '网侧封禁结果');
    const selectedText = selectedIps.length ? `\n\n已下发目标IP：${selectedIps.join('、')}` : '';
    const filteredText = (state.routineBlockDraft.skippedIps || []).length
      ? `\n\n已自动跳过受保护IP：${state.routineBlockDraft.skippedIps.join('、')}`
      : '';
    resultCard.appendChild(createMarkdownBlock(`${data.message || '已完成下发。'}${selectedText}${filteredText}`));
    appendPlaybookWorkspaceCard(resultCard);
    state.routineBlockDraft.successState = {
      message: data.message || '封禁执行成功。',
      countdown: 3,
    };
    renderRoutineBlockDialogContent();
    state.routineBlockAutoCloseTimer = window.setInterval(() => {
      if (!state.routineBlockDraft?.successState) {
        if (state.routineBlockAutoCloseTimer) {
          window.clearInterval(state.routineBlockAutoCloseTimer);
          state.routineBlockAutoCloseTimer = null;
        }
        return;
      }
      state.routineBlockDraft.successState.countdown -= 1;
      if (state.routineBlockDraft.successState.countdown <= 0) {
        closeRoutineBlockDialog();
        return;
      }
      renderRoutineBlockDialogContent();
    }, 1000);
  } catch (err) {
    setRoutineBlockHint(err.message || '下发失败，请检查参数。', 'error');
  } finally {
    if (el.routineBlockConfirm && state.routineBlockDraft) {
      const hasOnlineDevice = Array.isArray(state.routineBlockDraft.deviceOptions) && state.routineBlockDraft.deviceOptions.length > 0;
      const selectedIpsNow = state.routineBlockDraft.selectedIps || [];
      el.routineBlockConfirm.disabled = !!state.routineBlockDraft.successState || !hasOnlineDevice || !selectedIpsNow.length;
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
  setPlaybookWorkspaceMode('default');
  const vm = buildRoutineCheckViewModel(runData);
  const card = cardTemplate('', '');
  if (runData?.run_id != null) {
    card.dataset.playbookRunId = String(runData.run_id);
  }
  card.dataset.playbookCardType = 'routine-report';
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
  trendTitle.textContent = '近期安全态势趋势 (近7天)';
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

function parseThreatSummaryStats(summary) {
  const text = String(summary || '');
  const matched = text.match(/命中\s*(\d+)\s*条告警/);
  const src = text.match(/源IP告警\s*(\d+)/);
  const dst = text.match(/目的IP告警\s*(\d+)/);
  const windowDays = text.match(/(\d+)\s*天/);
  return {
    matchedTotal: matched ? toMetricNumber(matched[1]) : 0,
    srcTotal: src ? toMetricNumber(src[1]) : 0,
    dstTotal: dst ? toMetricNumber(dst[1]) : 0,
    windowDays: windowDays ? toMetricNumber(windowDays[1]) : 90,
  };
}

function parseThreatStoryStageCards(storyText) {
  const text = String(storyText || '');
  if (!text) return [];
  const cards = [];
  const sections = text.matchAll(/####\s*(侦察|利用|横向|结果)\s*([\s\S]*?)(?=####\s*(侦察|利用|横向|结果)|$)/g);
  for (const item of sections) {
    const stageName = item[1];
    const body = String(item[2] || '').trim();
    const alertIds = dedupText((body.match(/(?:incident|alert)-[a-zA-Z0-9-]+/g) || []).map((id) => id.trim())).slice(0, 6);
    cards.push({
      stage_name: stageName,
      stage_badge: `${stageName}阶段`,
      title: '阶段证据',
      attack_phase: '',
      summary: body || '暂无阶段证据说明。',
      observed: true,
      alert_ids: alertIds,
      tags: [],
      entities: [],
    });
  }
  return cards;
}

function buildThreatHuntingViewModel(runData) {
  const ALERT_TABLE_DISPLAY_LIMIT = 10;
  const result = runData?.result || {};
  const cards = Array.isArray(result.cards) ? result.cards : [];
  const threatView = result?.threat_view || {};
  const summary = String(result.summary || '').trim();
  const summaryStats = parseThreatSummaryStats(summary);

  const targetIp = String(
    threatView?.target_ip
    || runData?.input?.params?.ip
    || (summary.match(IPV4_REGEX) || [])[0]
    || '-',
  ).trim() || '-';
  const targetType = String(threatView?.target_type || (isPrivateIpv4(targetIp) ? '内部终端' : '外部IP'));

  const stats = {
    matchedTotal: toMetricNumber(threatView?.stats?.matched_total ?? summaryStats.matchedTotal),
    srcTotal: toMetricNumber(threatView?.stats?.src_alert_total ?? summaryStats.srcTotal),
    dstTotal: toMetricNumber(threatView?.stats?.dst_alert_total ?? summaryStats.dstTotal),
    windowDays: toMetricNumber(threatView?.window_days ?? summaryStats.windowDays ?? 90),
  };

  const riskLevel = String(threatView?.risk?.level || (summary.match(/风险等级\s*([高中低])/)?.[1] || '中')).trim() || '中';
  const riskLabelMap = {
    低: '低风险 (Low)',
    中: '中风险 (Medium)',
    高: '高风险 (High)',
  };
  const riskDetailMap = {
    低: '当前窗口未观测到持续性高危攻击行为',
    中: '存在持续攻击迹象，建议加强监测',
    高: '存在实质性攻击行为，建议立即处置',
  };

  const decisionCard = cards.find((item) => item?.type === 'text' && String(item?.data?.title || '').includes('处置结论'));
  const actionDecision = String(
    threatView?.risk?.action_decision
    || decisionCard?.data?.text
    || '建议继续观察',
  ).replace(/\*/g, '').trim();
  const actionHint = String(threatView?.risk?.action_hint || (actionDecision.includes('立即封禁') ? '建议立即执行微隔离/封禁' : '建议持续观察并加强监测')).trim();

  const stageMeta = {
    侦察: { title: '初步侦察', attack: 'ATT&CK Reconnaissance', cardTitle: '扫描与探测脆弱点', style: 'recon' },
    利用: { title: '漏洞利用', attack: 'ATT&CK Initial Access / Execution', cardTitle: '漏洞利用与执行', style: 'exploit' },
    横向: { title: '横向与控制', attack: 'ATT&CK Lateral Movement / Command and Control', cardTitle: '建立控制与横向移动', style: 'lateral' },
    结果: { title: '结果', attack: 'ATT&CK Exfiltration / Impact', cardTitle: '影响与结果评估', style: 'impact' },
  };
  const orderedStages = ['侦察', '利用', '横向', '结果'];

  const rawStageCards = Array.isArray(threatView?.stage_evidence_cards) && threatView.stage_evidence_cards.length
    ? threatView.stage_evidence_cards
    : parseThreatStoryStageCards(threatView?.story || cards.find((item) => item?.type === 'text' && String(item?.data?.title || '').includes('攻击故事线'))?.data?.text || '');
  const stageCardByName = new Map(
    (rawStageCards || [])
      .map((item) => [String(item?.stage_name || '').trim(), item])
      .filter(([name]) => orderedStages.includes(name)),
  );
  const stageCards = orderedStages.map((stageName) => {
    const raw = stageCardByName.get(stageName) || {};
    return {
      stageName,
      stageBadge: raw?.stage_badge || `${stageName}阶段`,
      title: raw?.title || stageMeta[stageName].cardTitle,
      attackPhase: raw?.attack_phase || stageMeta[stageName].attack,
      summary: String(raw?.summary || '当前窗口未观测到该阶段的高置信度告警证据。'),
      observed: Boolean(raw?.observed),
      alertIds: dedupText(raw?.alert_ids || []),
      tags: dedupText(raw?.tags || []),
      entities: dedupText(raw?.entities || []),
      style: stageMeta[stageName].style,
    };
  });

  const rawChain = Array.isArray(threatView?.kill_chain_stages) ? threatView.kill_chain_stages : [];
  const rawChainMap = new Map(
    rawChain
      .map((item) => [String(item?.stage_name || '').trim(), item])
      .filter(([name]) => orderedStages.includes(name)),
  );
  const killChain = orderedStages.map((stageName) => {
    const raw = rawChainMap.get(stageName) || {};
    const fallbackCard = stageCardByName.get(stageName) || {};
    return {
      stageName,
      title: raw?.title || stageMeta[stageName].title,
      attackPhase: raw?.attack_phase || stageMeta[stageName].attack,
      observed: typeof raw?.observed === 'boolean' ? raw.observed : Boolean(fallbackCard?.observed),
      time: String(raw?.time || ''),
      highlight: String(raw?.highlight || ''),
      style: stageMeta[stageName].style,
    };
  });

  const fallbackTableCard = cards.find((item) => item?.type === 'table' && String(item?.data?.title || '').includes('命中告警清单'));
  const fallbackTableRows = Array.isArray(fallbackTableCard?.data?.rows) ? fallbackTableCard.data.rows : [];
  const normalizeDirection = (rawDirection) => {
    const raw = String(rawDirection || '').trim();
    if (raw === '0') return '无';
    if (raw === '1') return '内对外';
    if (raw === '2') return '外对内';
    if (raw === '3') return '内对内';
    if (raw === '源') {
      return isPrivateIpv4(targetIp) ? '内部 -> 外部' : '外部 -> 内部';
    }
    if (raw === '目的') {
      return isPrivateIpv4(targetIp) ? '外部 -> 内部' : '内部 -> 外部';
    }
    if (raw === '源/目的' || raw === '双向') {
      return '-';
    }
    return raw || '-';
  };
  const rawAlertRows = Array.isArray(threatView?.alert_table_rows) && threatView.alert_table_rows.length
    ? threatView.alert_table_rows
    : fallbackTableRows.map((row) => ({
      recent_time: row?.endTime || '-',
      direction: normalizeDirection(row?.direction),
      alert_name: row?.name || '-',
      alert_id: row?.alertId || row?.threatId || row?.uuId || '-',
      severity: row?.incidentSeverity || '-',
      status: row?.dealStatus || '-',
    }));
  const alertRows = rawAlertRows.slice(0, ALERT_TABLE_DISPLAY_LIMIT).map((row, idx) => ({
    index: idx + 1,
    recentTime: String(row?.recent_time || '-'),
    direction: normalizeDirection(row?.direction),
    alertName: String(row?.alert_name || '-'),
    alertId: String(row?.alert_id || row?.alertId || row?.threat_id || row?.uuId || '-'),
    severity: String(row?.severity || '-'),
    status: String(row?.status || '-'),
  }));

  const nextActions = Array.isArray(result?.next_actions) ? result.next_actions : [];
  const dangerAction = nextActions.find((action) => action?.style === 'danger')
    || nextActions.find((action) => String(action?.label || '').includes('封禁'))
    || null;
  const actionLabel = dangerAction?.label || `执行 IP ${targetIp} 封禁 (提交流程)`;

  const finishedAt = runData?.finished_at || runData?.started_at;
  let finishedAtText = '-';
  if (finishedAt) {
    const dt = new Date(finishedAt);
    if (!Number.isNaN(dt.getTime())) {
      const y = dt.getFullYear();
      const m = String(dt.getMonth() + 1).padStart(2, '0');
      const d = String(dt.getDate()).padStart(2, '0');
      const h = String(dt.getHours()).padStart(2, '0');
      const mm = String(dt.getMinutes()).padStart(2, '0');
      const s = String(dt.getSeconds()).padStart(2, '0');
      finishedAtText = `${y}-${m}-${d} ${h}:${mm}:${s}`;
    }
  }

  return {
    targetIp,
    targetType,
    finishedAtText,
    stats,
    risk: {
      level: riskLevel,
      levelLabel: String(threatView?.risk?.level_label || riskLabelMap[riskLevel] || riskLabelMap['中']),
      levelDetail: String(threatView?.risk?.level_detail || riskDetailMap[riskLevel] || riskDetailMap['中']),
      actionDecision,
      actionHint,
    },
    killChain,
    stageCards,
    alertRows,
    alertTableTotal: toMetricNumber(threatView?.alert_table_total ?? stats.matchedTotal ?? alertRows.length),
    alertTableCoreCount: alertRows.length,
    actionLabel,
    dangerAction,
    nextActions,
  };
}

function showThreatCardToast(card, message) {
  const toast = card.querySelector('.threat-report-toast');
  const text = card.querySelector('.threat-report-toast-text');
  if (!toast || !text) {
    setHint(el.playbookHint, message, 'success');
    return;
  }
  text.textContent = message;
  toast.classList.add('show');
  const timer = Number(card.dataset.toastTimer || '0');
  if (timer) {
    clearTimeout(timer);
  }
  const timeoutId = window.setTimeout(() => {
    toast.classList.remove('show');
    card.dataset.toastTimer = '0';
  }, 1800);
  card.dataset.toastTimer = String(timeoutId);
}

function renderThreatHuntingCard(runData) {
  setPlaybookWorkspaceMode('default');
  const vm = buildThreatHuntingViewModel(runData);
  const card = cardTemplate('', '');
  if (runData?.run_id != null) {
    card.dataset.playbookRunId = String(runData.run_id);
  }
  card.dataset.playbookCardType = 'threat-report';
  card.classList.add('playbook-unified-report', 'playbook-task-card', 'workspace-panel-card', 'threat-report-card');

  const header = document.createElement('div');
  header.className = 'threat-report-header';
  const titleWrap = document.createElement('div');
  const title = document.createElement('h3');
  title.className = 'threat-report-title';
  title.textContent = 'Playbook 报告 · 攻击者活动轨迹';
  const subtitle = document.createElement('p');
  subtitle.className = 'threat-report-subtitle';
  subtitle.textContent = `溯源分析完成时间: ${vm.finishedAtText}`;
  titleWrap.appendChild(title);
  titleWrap.appendChild(subtitle);
  header.appendChild(titleWrap);
  card.appendChild(header);

  const summaryGrid = document.createElement('div');
  summaryGrid.className = 'threat-summary-grid';

  const targetStat = document.createElement('div');
  targetStat.className = 'threat-summary-card';
  targetStat.innerHTML = '<div class="label">目标溯源 IP</div>';
  const ipRow = document.createElement('div');
  ipRow.className = 'threat-ip-value-row';
  const ipValue = document.createElement('div');
  ipValue.className = 'value mono';
  ipValue.textContent = vm.targetIp;
  const ipCopyBtn = document.createElement('button');
  ipCopyBtn.type = 'button';
  ipCopyBtn.className = 'threat-copy-icon-btn';
  ipCopyBtn.textContent = '复制';
  ipCopyBtn.title = `复制 ${vm.targetIp}`;
  ipCopyBtn.onclick = async () => {
    const ok = await copyTextCompat(vm.targetIp);
    if (ok) {
      showThreatCardToast(card, `IP 已复制: ${vm.targetIp}`);
    } else {
      setHint(el.playbookHint, '复制失败，请手动复制。', 'error');
    }
  };
  ipRow.appendChild(ipValue);
  ipRow.appendChild(ipCopyBtn);
  targetStat.appendChild(ipRow);
  const targetMeta = document.createElement('div');
  targetMeta.className = 'meta';
  targetMeta.innerHTML = `<span>${escapeHtml(vm.targetType)}</span>`;
  targetStat.appendChild(targetMeta);
  summaryGrid.appendChild(targetStat);

  const countStat = document.createElement('div');
  countStat.className = 'threat-summary-card';
  countStat.innerHTML = `<div class="label">${escapeHtml(String(vm.stats.windowDays))}天内命中告警</div><div class="value">${escapeHtml(formatMetric(vm.stats.matchedTotal))} <span class="unit">条</span></div><div class="meta"><span>源: ${escapeHtml(formatMetric(vm.stats.srcTotal))}</span><span class="sep">|</span><span>目的: ${escapeHtml(formatMetric(vm.stats.dstTotal))}</span></div>`;
  summaryGrid.appendChild(countStat);

  const riskStat = document.createElement('div');
  riskStat.className = 'threat-summary-card risk';
  riskStat.innerHTML = `<div class="label">综合风险评级</div><div class="value">${escapeHtml(vm.risk.levelLabel)}</div><div class="meta">${escapeHtml(vm.risk.levelDetail)}</div>`;
  summaryGrid.appendChild(riskStat);

  const actionStat = document.createElement('div');
  actionStat.className = 'threat-summary-card action';
  actionStat.innerHTML = `<div class="label">智能处置建议</div><div class="value">${escapeHtml(vm.risk.actionHint)}</div><div class="meta">${escapeHtml(vm.risk.actionDecision)}</div>`;
  summaryGrid.appendChild(actionStat);
  card.appendChild(summaryGrid);

  const chain = document.createElement('section');
  chain.className = 'threat-chain-wrap';
  const chainTitle = document.createElement('h4');
  chainTitle.className = 'threat-section-title';
  chainTitle.textContent = '攻击故事线全景图';
  chain.appendChild(chainTitle);

  const track = document.createElement('div');
  track.className = 'threat-chain-track';
  const baseLine = document.createElement('div');
  baseLine.className = 'threat-chain-line-base';
  track.appendChild(baseLine);
  const progressLine = document.createElement('div');
  progressLine.className = 'threat-chain-line-progress';
  const lastObserved = (() => {
    const idx = [...vm.killChain].reverse().findIndex((item) => item.observed);
    if (idx < 0) return -1;
    return vm.killChain.length - idx - 1;
  })();
  const ratio = lastObserved < 0 ? 0 : Math.max(0, Math.min(1, lastObserved / (vm.killChain.length - 1)));
  progressLine.style.width = `${Math.round(ratio * 100)}%`;
  track.appendChild(progressLine);
  const nodes = document.createElement('div');
  nodes.className = 'threat-chain-nodes';
  vm.killChain.forEach((stage) => {
    const node = document.createElement('div');
    node.className = `threat-chain-node ${stage.style} ${stage.observed ? 'observed' : 'muted'}`;
    const dot = document.createElement('div');
    dot.className = 'threat-chain-dot';
    dot.textContent = stage.observed ? '●' : '○';
    const name = document.createElement('div');
    name.className = 'threat-chain-name';
    name.textContent = stage.title;
    const meta = document.createElement('div');
    meta.className = 'threat-chain-meta';
    meta.textContent = stage.observed ? (stage.time || stage.highlight || stage.attackPhase) : '未观测到';
    node.appendChild(dot);
    node.appendChild(name);
    node.appendChild(meta);
    nodes.appendChild(node);
  });
  track.appendChild(nodes);
  chain.appendChild(track);
  card.appendChild(chain);

  const evidenceWrap = document.createElement('section');
  evidenceWrap.className = 'threat-evidence-wrap';
  const evidenceTitle = document.createElement('h4');
  evidenceTitle.className = 'threat-section-title';
  evidenceTitle.textContent = '行为阶段详细分析';
  evidenceWrap.appendChild(evidenceTitle);
  vm.stageCards.forEach((stage) => {
    const item = document.createElement('article');
    item.className = `threat-stage-card ${stage.style} ${stage.observed ? '' : 'muted'}`.trim();

    const line1 = document.createElement('div');
    line1.className = 'threat-stage-head';
    const badge = document.createElement('span');
    badge.className = 'threat-stage-badge';
    badge.textContent = stage.stageBadge;
    const titleNode = document.createElement('h5');
    titleNode.className = 'threat-stage-title';
    titleNode.textContent = stage.title;
    line1.appendChild(badge);
    line1.appendChild(titleNode);
    item.appendChild(line1);

    const attack = document.createElement('p');
    attack.className = 'threat-stage-attack';
    attack.textContent = stage.attackPhase;
    item.appendChild(attack);

    const summaryNode = document.createElement('p');
    summaryNode.className = 'threat-stage-summary';
    summaryNode.textContent = stage.summary;
    item.appendChild(summaryNode);

    const chips = document.createElement('div');
    chips.className = 'threat-stage-chips';
    stage.alertIds.forEach((alertId) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'threat-copy-chip';
      btn.title = `点击复制完整告警ID: ${alertId}`;
      btn.textContent = `${alertId.slice(0, 18)}...`;
      btn.onclick = async () => {
        const ok = await copyTextCompat(alertId);
        if (ok) {
          showThreatCardToast(card, `告警 ID 已复制: ${alertId.slice(0, 18)}...`);
        } else {
          setHint(el.playbookHint, '复制失败，请手动复制。', 'error');
        }
      };
      chips.appendChild(btn);
    });
    stage.tags.forEach((tag) => {
      const tagNode = document.createElement('span');
      tagNode.className = 'threat-tag-chip';
      tagNode.textContent = `标签: ${tag}`;
      chips.appendChild(tagNode);
    });
    stage.entities.forEach((entity) => {
      const entityNode = document.createElement('button');
      entityNode.type = 'button';
      entityNode.className = 'threat-entity-chip';
      entityNode.textContent = entity;
      entityNode.title = `点击复制IP: ${entity}`;
      entityNode.onclick = async () => {
        const ok = await copyTextCompat(entity);
        if (ok) {
          showThreatCardToast(card, `IP 已复制: ${entity}`);
        } else {
          setHint(el.playbookHint, '复制失败，请手动复制。', 'error');
        }
      };
      chips.appendChild(entityNode);
    });
    if (chips.childNodes.length) {
      item.appendChild(chips);
    }
    evidenceWrap.appendChild(item);
  });
  card.appendChild(evidenceWrap);

  const alertPanel = document.createElement('section');
  alertPanel.className = 'threat-alert-panel';
  const collapseHead = document.createElement('button');
  collapseHead.type = 'button';
  collapseHead.className = 'threat-alert-head';
  const headingText = document.createElement('span');
  headingText.textContent = `命中告警清单 (已聚合重复扫描，共 ${formatMetric(vm.alertTableCoreCount)} 条核心证据)`;
  const chevron = document.createElement('span');
  chevron.className = 'threat-alert-chevron';
  chevron.textContent = '▾';
  collapseHead.appendChild(headingText);
  collapseHead.appendChild(chevron);
  alertPanel.appendChild(collapseHead);

  const alertBody = document.createElement('div');
  alertBody.className = 'threat-alert-body';
  const tableWrap = document.createElement('div');
  tableWrap.className = 'table-wrap';
  const table = document.createElement('table');
  table.className = 'threat-alert-table';
  table.innerHTML = '<thead><tr><th>最近发生时间</th><th>方向</th><th>告警名称</th><th>告警ID</th></tr></thead>';
  const tbody = document.createElement('tbody');
  vm.alertRows.forEach((row) => {
    const tr = document.createElement('tr');
    const tdTime = document.createElement('td');
    tdTime.textContent = row.recentTime;
    const tdDirection = document.createElement('td');
    tdDirection.textContent = row.direction;
    const tdName = document.createElement('td');
    tdName.textContent = row.alertName;
    const tdId = document.createElement('td');
    const idBtn = document.createElement('button');
    idBtn.type = 'button';
    idBtn.className = 'threat-alert-copy-btn mono';
    idBtn.textContent = row.alertId;
    idBtn.title = `点击复制告警ID: ${row.alertId}`;
    idBtn.onclick = async () => {
      const ok = await copyTextCompat(row.alertId);
      if (ok) {
        showThreatCardToast(card, `告警 ID 已复制: ${row.alertId.slice(0, 18)}...`);
      } else {
        setHint(el.playbookHint, '复制失败，请手动复制。', 'error');
      }
    };
    tdId.appendChild(idBtn);
    tr.appendChild(tdTime);
    tr.appendChild(tdDirection);
    tr.appendChild(tdName);
    tr.appendChild(tdId);
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  tableWrap.appendChild(table);
  alertBody.appendChild(tableWrap);

  const panelFooter = document.createElement('div');
  panelFooter.className = 'threat-alert-footer';
  panelFooter.textContent = `当前共命中 ${formatMetric(vm.alertTableTotal)} 条，列表展示前 ${formatMetric(vm.alertRows.length)} 条。`;
  alertBody.appendChild(panelFooter);
  alertPanel.appendChild(alertBody);
  card.appendChild(alertPanel);

  let alertOpen = true;
  collapseHead.onclick = () => {
    alertOpen = !alertOpen;
    alertBody.classList.toggle('hidden', !alertOpen);
    chevron.classList.toggle('collapsed', !alertOpen);
  };

  const actionBar = document.createElement('section');
  actionBar.className = 'threat-action-bar';
  const infoText = document.createElement('p');
  infoText.className = 'threat-action-info';
  infoText.textContent = vm.risk.level === '高'
    ? '结合内部主机恶意活动，确认攻击已造成实质性危害，需立即介入。'
    : '已检测到可疑攻击行为，建议持续观察并结合业务风险人工确认。';
  actionBar.appendChild(infoText);
  const actionRow = document.createElement('div');
  actionRow.className = 'threat-action-buttons';
  if (vm.dangerAction) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'threat-danger-btn';
    btn.textContent = vm.actionLabel;
    btn.onclick = async () => {
      try {
        btn.disabled = true;
        const params = vm.dangerAction?.params || {};
        const blockTypeRaw = String(params.block_type || params.blockType || 'SRC_IP').toUpperCase();
        const blockType = blockTypeRaw === 'DST_IP' ? 'DST_IP' : 'SRC_IP';
        const ips = [];
        if (isValidIpv4(params.ip)) ips.push(params.ip);
        if (Array.isArray(params.ips)) {
          params.ips.forEach((ip) => {
            if (isValidIpv4(ip)) ips.push(ip);
          });
        }
        const dedupIps = dedupText(ips).filter((ip) => isValidIpv4(ip));
        if (dedupIps.length) {
          await openRoutineBlockDialog({
            actionTitle: blockType === 'DST_IP' ? '封锁恶意外联IP' : '封禁恶意攻击源',
            resultTitle: blockType === 'DST_IP' ? '外联封锁结果' : '网侧封禁结果',
            blockType,
            ips: dedupIps,
            defaultReason: '由攻击者活动轨迹一键处置触发',
            emptyMessage: '当前未提取到可下发封禁的目标 IP。',
          });
          return;
        }
        await runPlaybook(vm.dangerAction.template_id, params, vm.dangerAction.label || vm.dangerAction.id);
      } catch (err) {
        setHint(el.playbookHint, err.message || '执行动作失败', 'error');
      } finally {
        btn.disabled = false;
      }
    };
    actionRow.appendChild(btn);
  } else {
    vm.nextActions.forEach((action) => actionRow.appendChild(createPlaybookActionButton(action)));
  }
  actionBar.appendChild(actionRow);
  card.appendChild(actionBar);

  const toast = document.createElement('div');
  toast.className = 'threat-report-toast';
  const toastText = document.createElement('span');
  toastText.className = 'threat-report-toast-text';
  toastText.textContent = '已复制';
  toast.appendChild(toastText);
  card.appendChild(toast);

  appendPlaybookWorkspaceCard(card);
}

function parseMetricPercent(value, fallback = 0) {
  const raw = String(value ?? '').trim();
  if (!raw) return fallback;
  const num = Number(raw.replace('%', ''));
  if (!Number.isFinite(num)) return fallback;
  return Math.max(0, Math.min(100, Math.round(num)));
}

function buildAlertTriageViewModel(runData) {
  const result = runData?.result || {};
  const triageView = result?.triage_view || {};
  const header = triageView?.header || {};
  const risk = triageView?.risk || {};
  const attacker = triageView?.attacker || {};
  const victim = triageView?.victim || {};
  const impact = triageView?.impact || {};
  const tactics = triageView?.tactics || {};
  const payload = triageView?.payload || {};
  const actionBlock = triageView?.actions || {};
  const nextActions = Array.isArray(actionBlock?.next_actions) ? actionBlock.next_actions : (Array.isArray(result?.next_actions) ? result.next_actions : []);
  const dangerAction = actionBlock?.danger_action || nextActions.find((action) => action?.style === 'danger') || null;
  const supportActions = nextActions.filter((action) => action && action.style !== 'danger' && (!dangerAction || action.id !== dangerAction.id));
  const incidentUuid = String(
    header?.incident_uuid
    || runData?.input?.params?.incident_uuid
    || (Array.isArray(runData?.input?.params?.incident_uuids) ? runData.input.params.incident_uuids[0] : '')
    || '-',
  ).trim() || '-';
  const incidentName = String(header?.incident_name || runData?.input?.params?.incident_name || '未知事件').trim() || '未知事件';
  const summary = String(result?.summary || '').replace(/\*\*/g, '').trim();
  const confidence = parseMetricPercent(attacker?.confidence, 0);
  const payloadLines = dedupText(payload?.lines || []);
  const rawPayloadText = String(payload?.raw_text || payloadLines.join('\n') || '未提取到高置信度原始 Payload 片段。').trim();
  const attackerTags = dedupText(attacker?.tags || []);
  const riskTags = dedupText(tactics?.risk_tags || []);
  const mitreTags = dedupText(tactics?.mitre || []);
  const title = String(header?.title || 'Playbook 报告 · 单点告警深度研判').trim();
  const severityLabel = String(header?.severity_label || '深度研判').trim();
  const conclusionTitle = String(risk?.conclusion_title || '系统研判结论').trim();
  const conclusionText = String(risk?.conclusion_text || '研判已完成。').replace(/\*\*/g, '').trim();
  const keyEvidence = String(risk?.key_evidence || '').trim();
  const dangerLabel = isValidIpv4(attacker?.ip) ? `一键封禁源 IP (${attacker.ip})` : (dangerAction?.label || '执行处置');
  const attackerHistory = String(attacker?.history_summary || '近7天未检索到同源高危攻击记录').trim();
  const assetRole = String(victim?.asset_role || victim?.asset_name || '-').trim() || '-';
  const recommendation = String(risk?.recommendation || '').trim();
  const authenticityScore = Number(risk?.authenticity_score || 0);
  const conclusionTone = String(risk?.tone || '').trim() || (authenticityScore >= 88 || recommendation.includes('立即') ? 'critical' : (authenticityScore >= 72 ? 'high' : (authenticityScore >= 40 ? 'medium' : 'low')));

  return {
    title,
    incidentName,
    incidentUuid,
    severityLabel,
    conclusionTitle,
    conclusionText,
    conclusionTone,
    keyEvidence,
    summary,
    recommendation,
    breachLabel: String(risk?.recommendation_label || '尚未确认边界突破').trim(),
    lateralLabel: String(risk?.lateral_label || '当前未观测到高置信横向扩散证据').trim(),
    boundaryBreached: Boolean(risk?.boundary_breached),
    lateralMovement: Boolean(risk?.lateral_movement),
    attacker: {
      ip: String(attacker?.ip || '-').trim() || '-',
      location: String(attacker?.location || '未知').trim() || '未知',
      confidence,
      tags: attackerTags,
      history: attackerHistory,
      severity: String(attacker?.severity || '未知').trim() || '未知',
    },
    victim: {
      ip: String(victim?.ip || '-').trim() || '-',
      hostName: String(victim?.host_name || '-').trim() || '-',
      assetRole,
    },
    impact: {
      windowDays: toMetricNumber(impact?.window_days || 7) || 7,
      totalVisits: toMetricNumber(impact?.total_visits || 0),
      highRiskVisits: toMetricNumber(impact?.high_risk_visits || 0),
      successCount: toMetricNumber(impact?.success_count || 0),
      lateralMovement: Boolean(impact?.lateral_movement),
    },
    tactics: {
      mitre: mitreTags,
      riskTags,
      aiResult: String(tactics?.ai_result || '').trim(),
    },
    payload: {
      title: String(payload?.title || '提取的关键恶意 Payload 片段（仅支持WAF类型告警）').trim(),
      rawText: rawPayloadText,
    },
    dangerAction,
    dangerLabel,
    supportActions,
  };
}

function createAlertTriageActionModal(ip) {
  const overlay = document.createElement('div');
  overlay.className = 'alert-triage-block-modal';
  overlay.innerHTML = `
    <div class="alert-triage-block-modal-card">
      <h4>执行 SOAR 处置剧本</h4>
      <p>正在通过现有处置链路提交针对源 IP ${escapeHtml(ip || '-')} 的封禁动作，请稍候...</p>
      <div class="alert-triage-block-progress">
        <div class="alert-triage-block-progress-bar"></div>
      </div>
      <div class="alert-triage-block-progress-text">剧本执行中</div>
    </div>
  `;
  return overlay;
}

function renderAlertTriageCard(runData) {
  const result = runData?.result || {};
  if (!result?.triage_view && !result?.summary) {
    renderPlaybookUnifiedCard(runData);
    return;
  }
  setPlaybookWorkspaceMode('triage');
  const vm = buildAlertTriageViewModel(runData);
  const card = cardTemplate('', '');
  if (runData?.run_id != null) {
    card.dataset.playbookRunId = String(runData.run_id);
  }
  card.dataset.playbookCardType = 'triage-report';
  card.classList.add('playbook-unified-report', 'playbook-task-card', 'workspace-panel-card', 'alert-triage-card');

  const header = document.createElement('div');
  header.className = 'alert-triage-header';
  const headerInfo = document.createElement('div');
  const title = document.createElement('h3');
  title.className = 'alert-triage-title';
  title.textContent = vm.title;
  headerInfo.appendChild(title);
  const metaRow = document.createElement('div');
  metaRow.className = 'alert-triage-meta-row';
  const badge = document.createElement('span');
  badge.className = `alert-triage-badge tone-${vm.conclusionTone}`;
  badge.textContent = vm.severityLabel;
  metaRow.appendChild(badge);
  headerInfo.appendChild(metaRow);
  const incidentName = document.createElement('div');
  incidentName.className = 'alert-triage-event-name';
  incidentName.textContent = `事件名称: ${vm.incidentName}`;
  headerInfo.appendChild(incidentName);
  const uuid = document.createElement('div');
  uuid.className = 'alert-triage-uuid';
  uuid.textContent = `UUID: ${vm.incidentUuid}`;
  headerInfo.appendChild(uuid);
  header.appendChild(headerInfo);

  if (vm.dangerAction) {
    const actionBtn = document.createElement('button');
    actionBtn.type = 'button';
    actionBtn.className = 'alert-triage-danger-btn';
    actionBtn.textContent = vm.dangerLabel;
    actionBtn.onclick = async () => {
      const modal = createAlertTriageActionModal(vm.attacker.ip);
      document.body.appendChild(modal);
      try {
        actionBtn.disabled = true;
        await runPlaybook(vm.dangerAction.template_id, vm.dangerAction.params || {}, vm.dangerAction.label || vm.dangerAction.id || '执行动作');
      } catch (err) {
        setHint(el.playbookHint, err.message || '执行动作失败', 'error');
      } finally {
        actionBtn.disabled = false;
        modal.remove();
      }
    };
    header.appendChild(actionBtn);
  }
  card.appendChild(header);

  const conclusion = document.createElement('section');
  conclusion.className = `alert-triage-conclusion tone-${vm.conclusionTone}`;
  conclusion.innerHTML = `
    <div class="alert-triage-conclusion-icon">${vm.conclusionTone === 'critical' ? '!' : (vm.conclusionTone === 'low' ? 'i' : '△')}</div>
    <div class="alert-triage-conclusion-body">
      <h4>${escapeHtml(vm.conclusionTitle)}</h4>
      <p>${escapeHtml(vm.conclusionText)}</p>
      ${vm.keyEvidence ? `<div class="alert-triage-key-evidence">关键证据：${escapeHtml(vm.keyEvidence)}</div>` : ''}
      <div class="alert-triage-conclusion-flags"></div>
    </div>
  `;
  const flagWrap = conclusion.querySelector('.alert-triage-conclusion-flags');
  [
    vm.breachLabel,
    vm.lateralLabel,
  ].filter(Boolean).forEach((text, idx) => {
    const item = document.createElement('span');
    item.className = `alert-triage-flag ${idx === 0 ? 'critical' : 'warning'}`;
    item.textContent = text;
    flagWrap.appendChild(item);
  });
  card.appendChild(conclusion);

  const grid = document.createElement('div');
  grid.className = 'alert-triage-grid';

  const attackerPanel = document.createElement('section');
  attackerPanel.className = 'alert-triage-panel attacker';
  attackerPanel.innerHTML = `
    <div class="alert-triage-panel-title">攻击源画像</div>
    <div class="alert-triage-ip">${escapeHtml(vm.attacker.ip)}</div>
    <div class="alert-triage-sub">${escapeHtml(vm.attacker.location)}</div>
    <div class="alert-triage-meter">
      <div class="alert-triage-meter-head">
        <span>情报置信度</span>
        <strong>${vm.attacker.confidence}%</strong>
      </div>
      <div class="alert-triage-meter-track"><div class="alert-triage-meter-bar" style="width:${vm.attacker.confidence}%"></div></div>
    </div>
    <div class="alert-triage-chip-wrap"></div>
    <div class="alert-triage-note">${escapeHtml(vm.attacker.history)}</div>
  `;
  const attackerChipWrap = attackerPanel.querySelector('.alert-triage-chip-wrap');
  vm.attacker.tags.forEach((tag) => {
    const chip = document.createElement('span');
    chip.className = 'alert-triage-chip attacker';
    chip.textContent = tag;
    attackerChipWrap.appendChild(chip);
  });
  if (!vm.attacker.tags.length) {
    const empty = document.createElement('span');
    empty.className = 'alert-triage-chip muted';
    empty.textContent = vm.attacker.severity || '暂无情报标签';
    attackerChipWrap.appendChild(empty);
  }
  grid.appendChild(attackerPanel);

  const victimPanel = document.createElement('section');
  victimPanel.className = 'alert-triage-panel victim';
  victimPanel.innerHTML = `
    <div class="alert-triage-panel-title">受害目标画像</div>
    <div class="alert-triage-kv-block">
      <div class="label">受害资产 IP</div>
      <div class="value">${escapeHtml(vm.victim.ip)}</div>
    </div>
    <div class="alert-triage-victim-grid">
      <div><span>主机名</span><strong>${escapeHtml(vm.victim.hostName)}</strong></div>
      <div><span>资产角色</span><strong>${escapeHtml(vm.victim.assetRole)}</strong></div>
    </div>
  `;
  grid.appendChild(victimPanel);

  const impactPanel = document.createElement('section');
  impactPanel.className = 'alert-triage-panel impact';
  impactPanel.innerHTML = `
    <div class="alert-triage-panel-title">内部影响面</div>
    <div class="alert-triage-impact-grid">
      <div class="alert-triage-impact-item">
        <span>近${vm.impact.windowDays}天总访问量</span>
        <strong>${formatMetric(vm.impact.totalVisits)}</strong>
      </div>
      <div class="alert-triage-impact-item">
        <span>高危攻击量</span>
        <strong class="warn">${formatMetric(vm.impact.highRiskVisits)}</strong>
      </div>
      <div class="alert-triage-impact-item emphasis">
        <span>有效攻击次数 (攻击成功)</span>
        <strong>${formatMetric(vm.impact.successCount)}</strong>
      </div>
    </div>
  `;
  grid.appendChild(impactPanel);
  card.appendChild(grid);

  const tacticsPanel = document.createElement('section');
  tacticsPanel.className = 'alert-triage-tactics';
  const tacticsHeader = document.createElement('div');
  tacticsHeader.className = 'alert-triage-tactics-tab';
  tacticsHeader.textContent = '攻击手法特征';
  tacticsPanel.appendChild(tacticsHeader);

  const tacticsBody = document.createElement('div');
  tacticsBody.className = 'alert-triage-tactics-body';
  const mitreBlock = document.createElement('div');
  const mitreTitle = document.createElement('h4');
  mitreTitle.textContent = '命中 MITRE ATT&CK 战术';
  mitreBlock.appendChild(mitreTitle);
  const mitreWrap = document.createElement('div');
  mitreWrap.className = 'alert-triage-chip-wrap';
  vm.tactics.mitre.forEach((tag) => {
    const chip = document.createElement('span');
    chip.className = 'alert-triage-chip mitre';
    chip.textContent = tag;
    mitreWrap.appendChild(chip);
  });
  vm.tactics.riskTags.forEach((tag) => {
    const chip = document.createElement('span');
    chip.className = 'alert-triage-chip risk';
    chip.textContent = tag;
    mitreWrap.appendChild(chip);
  });
  if (!vm.tactics.mitre.length && !vm.tactics.riskTags.length) {
    const chip = document.createElement('span');
    chip.className = 'alert-triage-chip muted';
    chip.textContent = '暂无攻击手法标签';
    mitreWrap.appendChild(chip);
  }
  mitreBlock.appendChild(mitreWrap);
  tacticsBody.appendChild(mitreBlock);

  const payloadBlock = document.createElement('div');
  const payloadTitle = document.createElement('h4');
  payloadTitle.textContent = vm.payload.title;
  payloadBlock.appendChild(payloadTitle);
  const payloadPre = document.createElement('div');
  payloadPre.className = 'alert-triage-payload-block';
  payloadPre.innerHTML = `
    <div class="alert-triage-payload-comment">// 提取的关键恶意 Payload 片段</div>
    <pre>${escapeHtml(vm.payload.rawText)}</pre>
  `;
  payloadBlock.appendChild(payloadPre);
  tacticsBody.appendChild(payloadBlock);

  if (vm.tactics.aiResult) {
    const aiBlock = document.createElement('p');
    aiBlock.className = 'alert-triage-ai-note';
    aiBlock.textContent = `AI举证摘要：${vm.tactics.aiResult}`;
    tacticsBody.appendChild(aiBlock);
  }
  tacticsPanel.appendChild(tacticsBody);
  card.appendChild(tacticsPanel);

  if (vm.supportActions.length) {
    const footer = document.createElement('div');
    footer.className = 'alert-triage-footer-actions';
    vm.supportActions.forEach((action) => footer.appendChild(createPlaybookActionButton(action)));
    card.appendChild(footer);
  }

  appendPlaybookWorkspaceCard(card);
}

function parseAssetGuardTags(value) {
  if (Array.isArray(value)) return dedupText(value);
  const text = String(value || '').trim();
  if (!text) return [];
  return dedupText(text.split(/[、,，]/));
}

function normalizeAssetGuardSeverity(value) {
  const raw = String(value || '未知').trim();
  if (raw === '严重') return { label: '严重', tone: 'critical' };
  if (raw === '高' || raw === '高危') return { label: '高危', tone: 'high' };
  if (raw === '中' || raw === '中危') return { label: '中危', tone: 'medium' };
  if (raw === '低' || raw === '低危') return { label: '低危', tone: 'low' };
  return { label: raw || '未知', tone: 'muted' };
}

function buildAssetGuardViewModel(runData) {
  const result = runData?.result || {};
  const cards = Array.isArray(result?.cards) ? result.cards : [];
  const asset = result?.asset || {};
  const nextActions = Array.isArray(result?.next_actions) ? result.next_actions : [];
  const dangerAction = nextActions.find((action) => action?.style === 'danger') || null;
  const statsCard = cards.find((card) => card?.data?.namespace === 'asset_guard_stats') || {};
  const intelCard = cards.find((card) => card?.data?.namespace === 'asset_guard_intel') || {};
  const chartCard = cards.find((card) => card?.type === 'echarts_graph' && String(card?.data?.title || '').includes('流量威胁双向评估')) || {};
  const actionCard = cards.find((card) => card?.type === 'text' && String(card?.data?.title || '') === '建议动作') || {};
  const statsRows = Array.isArray(statsCard?.data?.rows) ? statsCard.data.rows : [];
  const intelRowsRaw = Array.isArray(intelCard?.data?.rows) ? intelCard.data.rows : [];
  const inboundRow = statsRows.find((row) => String(row?.direction || '').includes('入向')) || {};
  const outboundRow = statsRows.find((row) => String(row?.direction || '').includes('出向')) || {};
  const trend = result?.asset_guard_view?.trend || {};
  const trendLabels = Array.isArray(trend?.labels) && trend.labels.length
    ? trend.labels
    : (Array.isArray(chartCard?.data?.option?.xAxis?.data) ? chartCard.data.option.xAxis.data : []);
  const trendInbound = trendLabels.map((_, idx) => toMetricNumber(Array.isArray(trend?.inbound) ? trend.inbound[idx] : 0));
  const trendOutbound = trendLabels.map((_, idx) => toMetricNumber(Array.isArray(trend?.outbound) ? trend.outbound[idx] : 0));
  const trendMax = Math.max(1, ...trendInbound, ...trendOutbound);
  const blockIps = dedupText(
    Array.isArray(dangerAction?.params?.ips)
      ? dangerAction.params.ips
      : intelRowsRaw.map((row) => row?.ip),
  ).filter((ip) => isValidIpv4(ip));
  const summary = String(result?.summary || '').replace(/\*\*/g, '').trim();
  const insightText = String(
    trend?.insight
    || chartCard?.data?.summary
    || summary,
  ).replace(/^AI\s*透视结论[:：]?\s*/i, '').trim();
  const actionText = String(actionCard?.data?.text || '建议优先对 Top 外部访问实体执行封禁审批；并对封禁前后关联高危告警进行人工复核。')
    .replace(/^建议动作[:：]?\s*/, '')
    .trim();
  const eventMax = Math.max(
    1,
    toMetricNumber(inboundRow?.event_count || 0),
    toMetricNumber(outboundRow?.event_count || 0),
  );
  const logMax = Math.max(
    1,
    toMetricNumber(inboundRow?.log_count || 0),
    toMetricNumber(outboundRow?.log_count || 0),
  );
  const intelRows = intelRowsRaw.map((row) => {
    const severity = normalizeAssetGuardSeverity(row?.severity);
    const confidenceValue = parseMetricPercent(row?.confidence, 0);
    return {
      ip: String(row?.ip || '-').trim() || '-',
      severityLabel: severity.label,
      severityTone: severity.tone,
      confidenceText: `${confidenceValue}%`,
      confidenceValue,
      tags: parseAssetGuardTags(row?.tags),
      source: String(row?.source || '未知').trim() || '未知',
      hits: toMetricNumber(row?.hits || 0),
    };
  });

  return {
    title: 'Playbook 报告 · 核心资产防线透视',
    subtitle: '面向业务负责人及管理层的自动化安全评估视图',
    assetIp: String(asset?.asset_ip || runData?.input?.params?.asset_ip || '-').trim() || '-',
    assetName: String(asset?.asset_name || runData?.input?.params?.asset_name || '').trim(),
    windowHours: toMetricNumber(asset?.window_hours || runData?.input?.params?.window_hours || 24) || 24,
    summary,
    insightText: insightText || '近 7 天未发现明显的双向异常峰值，可继续维持常规关注。',
    actionText,
    metrics: {
      inbound: {
        eventCount: toMetricNumber(inboundRow?.event_count || 0),
        logCount: toMetricNumber(inboundRow?.log_count || 0),
      },
      outbound: {
        eventCount: toMetricNumber(outboundRow?.event_count || 0),
        logCount: toMetricNumber(outboundRow?.log_count || 0),
      },
      eventMax,
      logMax,
    },
    trend: {
      labels: trendLabels,
      inbound: trendInbound,
      outbound: trendOutbound,
      max: trendMax,
    },
    intelRows,
    blockIps,
    dangerAction,
  };
}

function buildAssetGuardTrendChart(vm) {
  const chartWrap = document.createElement('div');
  chartWrap.className = 'asset-guard-chart-wrap';

  const axis = document.createElement('div');
  axis.className = 'asset-guard-chart-axis';
  ['1.0', '0.8', '0.6', '0.4', '0.2', '0'].forEach((label) => {
    const item = document.createElement('span');
    item.textContent = label;
    axis.appendChild(item);
  });
  chartWrap.appendChild(axis);

  const plot = document.createElement('div');
  plot.className = 'asset-guard-chart-plot';
  const maxValue = Math.max(1, vm.trend.max);
  (vm.trend.labels.length ? vm.trend.labels : ['-', '-', '-', '-', '-', '-', '-']).forEach((label, idx) => {
    const inboundValue = toMetricNumber(vm.trend.inbound[idx] || 0);
    const outboundValue = toMetricNumber(vm.trend.outbound[idx] || 0);
    const inboundPct = Math.max(0, Math.min(100, Math.round((inboundValue / maxValue) * 100)));
    const outboundPct = Math.max(0, Math.min(100, Math.round((outboundValue / maxValue) * 100)));
    const col = document.createElement('div');
    col.className = 'asset-guard-chart-col';
    col.innerHTML = `
      <div class="asset-guard-chart-tooltip">入向 ${formatMetric(inboundValue)} / 出向 ${formatMetric(outboundValue)}</div>
      <div class="asset-guard-chart-bars">
        <div class="asset-guard-chart-bar outbound" style="height:${outboundPct}%"></div>
        <div class="asset-guard-chart-bar inbound" style="height:${inboundPct}%"></div>
      </div>
      <div class="asset-guard-chart-label">${escapeHtml(label)}</div>
    `;
    plot.appendChild(col);
  });
  chartWrap.appendChild(plot);
  return chartWrap;
}

function renderAssetGuardCard(runData) {
  const result = runData?.result || {};
  if (!result?.cards?.length && !result?.summary) {
    renderPlaybookUnifiedCard(runData);
    return;
  }
  setPlaybookWorkspaceMode('default');
  const vm = buildAssetGuardViewModel(runData);
  const card = cardTemplate('', '');
  if (runData?.run_id != null) {
    card.dataset.playbookRunId = String(runData.run_id);
  }
  card.dataset.playbookCardType = 'asset-guard-report';
  card.classList.add('playbook-unified-report', 'playbook-task-card', 'workspace-panel-card', 'asset-guard-card');

  const header = document.createElement('header');
  header.className = 'asset-guard-header';
  header.innerHTML = `
    <div>
      <h3 class="asset-guard-title">${escapeHtml(vm.title)}</h3>
      <p class="asset-guard-subtitle">${escapeHtml(vm.subtitle)}</p>
    </div>
  `;
  card.appendChild(header);

  const summaryGrid = document.createElement('section');
  summaryGrid.className = 'asset-guard-summary-grid';
  summaryGrid.innerHTML = `
    <article class="asset-guard-stat-card">
      <div class="asset-guard-stat-label-row">
        <span class="asset-guard-stat-icon neutral">▣</span>
        <span class="asset-guard-stat-label">核心资产</span>
      </div>
      <div class="asset-guard-stat-main mono">${escapeHtml(vm.assetIp)}</div>
      <div class="asset-guard-stat-sub">评估周期: 最近 ${formatMetric(vm.windowHours)} 小时内</div>
    </article>
    <article class="asset-guard-stat-card tone-inbound">
      <div class="asset-guard-tone-bar"></div>
      <div class="asset-guard-stat-label-row">
        <span class="asset-guard-stat-icon inbound">↙</span>
        <span class="asset-guard-stat-label">入向威胁 (目标为资产)</span>
      </div>
      <div class="asset-guard-metric-single">
        <strong class="asset-guard-metric-value inbound">${formatMetric(vm.metrics.inbound.eventCount)}</strong>
        <span class="asset-guard-metric-unit">告警</span>
      </div>
    </article>
    <article class="asset-guard-stat-card tone-outbound">
      <div class="asset-guard-tone-bar"></div>
      <div class="asset-guard-stat-label-row">
        <span class="asset-guard-stat-icon outbound">↗</span>
        <span class="asset-guard-stat-label">出向威胁 (源为资产)</span>
      </div>
      <div class="asset-guard-metric-single">
        <strong class="asset-guard-metric-value outbound">${formatMetric(vm.metrics.outbound.eventCount)}</strong>
        <span class="asset-guard-metric-unit">告警</span>
      </div>
    </article>
  `;
  card.appendChild(summaryGrid);

  const chartSection = document.createElement('section');
  chartSection.className = 'asset-guard-panel';
  const chartTitle = document.createElement('h4');
  chartTitle.className = 'asset-guard-panel-title with-icon';
  chartTitle.innerHTML = '<span class="asset-guard-panel-icon">▤</span>流量威胁双向评估 (近7天)';
  chartSection.appendChild(chartTitle);
  chartSection.appendChild(buildAssetGuardTrendChart(vm));
  const insightBox = document.createElement('div');
  insightBox.className = 'asset-guard-insight-box';
  const insightMark = document.createElement('div');
  insightMark.className = 'asset-guard-insight-mark';
  insightMark.textContent = '✦';
  const insightBody = document.createElement('div');
  const insightHeading = document.createElement('h5');
  insightHeading.textContent = 'AI 透视结论';
  const insightParagraph = document.createElement('p');
  const insightText = vm.insightText || '';
  const assetIp = vm.assetIp && vm.assetIp !== '-' ? vm.assetIp : '';
  if (assetIp && insightText.includes(assetIp)) {
    const [before, after] = insightText.split(assetIp, 2);
    if (before) insightParagraph.appendChild(document.createTextNode(before));
    const code = document.createElement('code');
    code.className = 'asset-guard-inline-code';
    code.textContent = assetIp;
    insightParagraph.appendChild(code);
    if (after) insightParagraph.appendChild(document.createTextNode(after));
  } else {
    insightParagraph.textContent = insightText;
  }
  insightBody.appendChild(insightHeading);
  insightBody.appendChild(insightParagraph);
  insightBox.appendChild(insightMark);
  insightBox.appendChild(insightBody);
  chartSection.appendChild(insightBox);
  card.appendChild(chartSection);

  const intelSection = document.createElement('section');
  intelSection.className = 'asset-guard-panel asset-guard-intel-section';
  const intelTitle = document.createElement('h4');
  intelTitle.className = 'asset-guard-panel-title with-icon';
  intelTitle.innerHTML = '<span class="asset-guard-panel-icon warn">◈</span>Top 5 外部访问实体情报';
  intelSection.appendChild(intelTitle);
  const intelTableWrap = document.createElement('div');
  intelTableWrap.className = 'asset-guard-table-wrap';
  const intelTable = document.createElement('table');
  intelTable.className = 'asset-guard-table';
  intelTable.innerHTML = `
    <thead>
      <tr>
        <th>IP 地址</th>
        <th>威胁等级</th>
        <th>置信度</th>
        <th>情报标签</th>
        <th>数据来源</th>
      </tr>
    </thead>
    <tbody></tbody>
  `;
  const intelBody = intelTable.querySelector('tbody');
  (vm.intelRows.length ? vm.intelRows : [{
    ip: '-',
    severityLabel: '未知',
    severityTone: 'muted',
    confidenceText: '0%',
    confidenceValue: 0,
    tags: ['未知'],
    source: '未知',
  }]).forEach((row) => {
    const tr = document.createElement('tr');
    const tagsHtml = (row.tags.length ? row.tags : ['未知'])
      .map((tag) => `<span class="asset-guard-tag">${escapeHtml(tag)}</span>`)
      .join('');
    tr.innerHTML = `
      <td class="mono">${escapeHtml(row.ip)}</td>
      <td><span class="asset-guard-severity ${row.severityTone}">${escapeHtml(row.severityLabel)}</span></td>
      <td>
        <div class="asset-guard-confidence">
          <span>${escapeHtml(row.confidenceText)}</span>
          <div class="asset-guard-confidence-bar">
            <div class="asset-guard-confidence-fill ${row.severityTone}" style="width:${row.confidenceValue}%"></div>
          </div>
        </div>
      </td>
      <td><div class="asset-guard-tag-list">${tagsHtml}</div></td>
      <td class="muted">${escapeHtml(row.source)}</td>
    `;
    intelBody.appendChild(tr);
  });
  intelTableWrap.appendChild(intelTable);
  intelSection.appendChild(intelTableWrap);
  card.appendChild(intelSection);

  const actionSection = document.createElement('section');
  actionSection.className = 'asset-guard-action-card';
  actionSection.innerHTML = `
    <div class="asset-guard-action-icon-wrap"><span class="asset-guard-action-icon">⛨</span></div>
    <div class="asset-guard-action-body">
      <h4 class="asset-guard-action-title">建议响应动作</h4>
      <p class="asset-guard-action-desc">${escapeHtml(vm.actionText)}</p>
      <div class="asset-guard-batch-box">
        <div class="asset-guard-batch-head">
          <h5 class="asset-guard-batch-title"></h5>
          <span class="asset-guard-batch-tip">点击 ✕ 可移出本次封禁任务</span>
        </div>
        <div class="asset-guard-batch-list"></div>
      </div>
      <div class="asset-guard-action-footer">
        <button type="button" class="asset-guard-danger-btn"></button>
        <span class="asset-guard-action-note">点击后将进入工单流程，不会立即阻断业务</span>
      </div>
    </div>
  `;
  const batchTitle = actionSection.querySelector('.asset-guard-batch-title');
  const batchList = actionSection.querySelector('.asset-guard-batch-list');
  const actionBtn = actionSection.querySelector('.asset-guard-danger-btn');
  const selectedIps = [...vm.blockIps];

  const renderBatchTargets = () => {
    batchTitle.textContent = `批量封禁目标名单 (${selectedIps.length} 个 IP)`;
    batchList.innerHTML = '';
    if (!selectedIps.length) {
      const empty = document.createElement('div');
      empty.className = 'asset-guard-empty';
      empty.textContent = '已清空封禁名单，无动作执行。';
      batchList.appendChild(empty);
    } else {
      selectedIps.forEach((ip) => {
        const chip = document.createElement('div');
        chip.className = 'asset-guard-ip-chip';
        chip.innerHTML = `<span class="asset-guard-ip-chip-text">${escapeHtml(ip)}</span>`;
        const removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.className = 'asset-guard-ip-chip-remove';
        removeBtn.textContent = '✕';
        removeBtn.title = '移出名单';
        removeBtn.onclick = () => {
          const index = selectedIps.indexOf(ip);
          if (index >= 0) {
            selectedIps.splice(index, 1);
            renderBatchTargets();
          }
        };
        chip.appendChild(removeBtn);
        batchList.appendChild(chip);
      });
    }
    actionBtn.textContent = `发起批量封禁审批 (${selectedIps.length} 个目标)`;
    actionBtn.disabled = !selectedIps.length || !vm.dangerAction;
  };

  actionBtn.onclick = async () => {
    if (!vm.dangerAction || !selectedIps.length) return;
    const params = vm.dangerAction.params || {};
    const blockTypeRaw = String(params.block_type || params.blockType || 'SRC_IP').toUpperCase();
    const blockType = blockTypeRaw === 'DST_IP' ? 'DST_IP' : 'SRC_IP';
    try {
      actionBtn.disabled = true;
      await openRoutineBlockDialog({
        actionTitle: blockType === 'DST_IP' ? '封锁恶意外联IP' : '封禁恶意攻击源',
        resultTitle: blockType === 'DST_IP' ? '外联封锁结果' : '网侧封禁结果',
        blockType,
        ips: [...selectedIps],
        defaultReason: '由核心资产防线透视建议动作触发',
        emptyMessage: '当前未提取到可下发封禁的目标 IP。',
      });
    } catch (err) {
      setHint(el.playbookHint, err.message || '执行动作失败', 'error');
    } finally {
      renderBatchTargets();
    }
  };

  renderBatchTargets();
  card.appendChild(actionSection);

  appendPlaybookWorkspaceCard(card);
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
    if (field.pattern) inputEl.pattern = field.pattern;
    if (field.min != null) inputEl.min = String(field.min);
    if (field.max != null) inputEl.max = String(field.max);
    if (field.step != null) inputEl.step = String(field.step);
    if (field.inputmode) inputEl.inputMode = field.inputmode;
    if (field.title) inputEl.title = field.title;
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
    if (!form.reportValidity()) return;
    const fd = new FormData(form);
    const params = {};
    fields.forEach((field) => {
      const raw = (fd.get(field.key) || '').toString().trim();
      if (!raw) return;
      if (field.key === 'views') {
        validateBlockTargetValues(raw, (fd.get('block_type') || '').toString().trim());
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

    await submitChatMessage(
      `${FORM_SUBMIT_PREFIX}${JSON.stringify({
        token: payload.data.token,
        intent: payload.data.intent,
        params,
      })}`,
      {
        displayText: createFormSubmitMessage(payload, params),
      },
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
    chart.className = 'chart-canvas';
    chart.style.height = '260px';
    chart.dataset.echartsDeferred = '1';
    chart.__echartsOption = buildReadableChartOption(payload?.data?.option || {});
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
        await submitChatMessage('确认');
      });
    };
    const cancel = document.createElement('button');
    cancel.className = 'secondary-btn';
    cancel.textContent = '取消';
    cancel.onclick = async () => submitChatMessage('取消');
    actions.appendChild(ok);
    actions.appendChild(cancel);
    section.appendChild(actions);
    return section;
  }
  if (payload?.type === 'quick_actions') {
    if (payload?.data?.text) {
      const p = document.createElement('p');
      p.textContent = payload.data.text;
      section.appendChild(p);
    }
    const actions = payload?.data?.actions || [];
    if (actions.length) {
      const row = document.createElement('div');
      row.className = 'action-row quick-action-row';
      actions.forEach((action) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = action.style === 'primary' ? 'primary-btn quick-action-btn' : 'secondary-btn quick-action-btn';
        btn.textContent = action.label || '继续';
        btn.onclick = async () => {
          if (!action.message) return;
          btn.disabled = true;
          try {
            await submitChatMessage(String(action.message));
          } finally {
            btn.disabled = false;
          }
        };
        row.appendChild(btn);
      });
      section.appendChild(row);
    }
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
    if (payload?.type === 'quick_actions') {
      const text = escapeHtml(payload?.data?.text || '');
      const actions = (payload?.data?.actions || [])
        .map((action) => `<span style="display:inline-block;margin:6px 8px 0 0;padding:6px 10px;border-radius:999px;border:1px solid rgba(98,137,208,.45);background:rgba(28,97,231,.12);color:#e7efff;">${escapeHtml(action.label || '继续')}</span>`)
        .join('');
      sections.push(`<section><h2>${title}</h2><p>${text}</p><div>${actions}</div></section>`);
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
  setPlaybookWorkspaceMode('default');
  const result = runData?.result || {};
  const summary = String(result.summary || runData?.error || '').trim();
  const cards = Array.isArray(result.cards) ? result.cards : [];
  const nextActions = Array.isArray(result.next_actions) ? result.next_actions : [];
  const displayName = getPlaybookDisplayName(runData?.template_id || '');

  const card = cardTemplate('', '');
  if (runData?.run_id != null) {
    card.dataset.playbookRunId = String(runData.run_id);
  }
  card.dataset.playbookCardType = 'generic-report';
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

function renderPlaybookFailedCard(runData) {
  const card = cardTemplate('Playbook 执行失败');
  if (runData?.run_id != null) {
    card.dataset.playbookRunId = String(runData.run_id);
  }
  card.dataset.playbookCardType = 'playbook-failed';
  card.classList.add('workspace-panel-card');
  const detail = String(runData?.error || '后台任务执行失败，请查看节点详情或稍后重试。').trim();
  card.appendChild(createMarkdownBlock(detail));
  appendPlaybookWorkspaceCard(card);
}

function renderPlaybookResult(runData) {
  if (runData?.status === 'Failed') {
    renderPlaybookFailedCard(runData);
    return;
  }
  if (runData?.template_id === 'routine_check') {
    renderRoutineCheckCard(runData);
    return;
  }
  if (runData?.template_id === 'alert_triage') {
    renderAlertTriageCard(runData);
    return;
  }
  if (runData?.template_id === 'asset_guard') {
    renderAssetGuardCard(runData);
    return;
  }
  if (runData?.template_id === 'threat_hunting') {
    renderThreatHuntingCard(runData);
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
      if (!isValidIncidentUuid(value)) {
        throw new Error('输入格式错误，请填写事件序号或合法的 incident UUID。');
      }
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
    if (!isValidIpv4(value)) {
      throw new Error('请输入合法的 IPv4 地址。');
    }
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
      if (!isValidIpv4(assetIp)) {
        throw new Error('请输入合法的核心资产 IPv4。');
      }
    } else {
      throw new Error('请输入合法的核心资产IP。');
    }
    return { ...base, asset_ip: assetIp, asset_name: assetName || undefined };
  }

  return base;
}

function validatePlaybookParams(templateId, params = {}) {
  const next = { ...(params || {}) };
  if (templateId === 'alert_triage') {
    if (next.incident_uuid && !isValidIncidentUuid(next.incident_uuid)) {
      throw new Error('incident_uuid 格式不正确。');
    }
    if (Array.isArray(next.incident_uuids)) {
      next.incident_uuids.forEach((item) => {
        if (!isValidIncidentUuid(item)) {
          throw new Error(`incident_uuid ${item} 格式不正确。`);
        }
      });
    }
    if (next.event_index != null && (!(Number(next.event_index) > 0) || !Number.isInteger(Number(next.event_index)))) {
      throw new Error('event_index 必须是正整数。');
    }
    if (Array.isArray(next.event_indexes)) {
      next.event_indexes.forEach((item) => {
        if (!(Number(item) > 0) || !Number.isInteger(Number(item))) {
          throw new Error('event_indexes 必须全部是正整数。');
        }
      });
    }
    if (next.ip && !isValidIpv4(next.ip)) {
      throw new Error('ip 必须是合法的 IPv4 地址。');
    }
    if (Array.isArray(next.ips)) {
      next.ips.forEach((item) => {
        if (!isValidIpv4(item)) {
          throw new Error(`IP ${item} 不是合法的 IPv4 地址。`);
        }
      });
    }
  }
  if (templateId === 'threat_hunting') {
    if (!isValidIpv4(next.ip)) {
      throw new Error('攻击者活动轨迹的目标必须是合法的 IPv4 地址。');
    }
    const startTs = next.startTimestamp == null ? null : Number(next.startTimestamp);
    const endTs = next.endTimestamp == null ? null : Number(next.endTimestamp);
    if (startTs != null && (!Number.isFinite(startTs) || startTs < 0)) {
      throw new Error('startTimestamp 不合法。');
    }
    if (endTs != null && (!Number.isFinite(endTs) || endTs < 0)) {
      throw new Error('endTimestamp 不合法。');
    }
    if (startTs != null && endTs != null && startTs > endTs) {
      throw new Error('startTimestamp 不能晚于 endTimestamp。');
    }
  }
  if (templateId === 'asset_guard' && !isValidIpv4(next.asset_ip)) {
    throw new Error('核心资产体检的 asset_ip 必须是合法的 IPv4 地址。');
  }
  return next;
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

  const safeParams = validatePlaybookParams(templateId, params);
  const conversationId = state.activeConversationId;
  const requestSessionId = state.sessionId;

  const requestPayload = {
    template_id: templateId,
    params: safeParams,
    session_id: requestSessionId,
  };

  clearWelcomePlaceholder(conversationId);
  const introCard = createPlaybookTriggerCard(templateId, triggerLabel, safeParams);
  appendCard(introCard);

  const runInfo = await api('/api/playbooks/run', {
    method: 'POST',
    body: JSON.stringify(requestPayload),
  });
  addConversationEntry(
    {
      type: 'playbook_trigger',
      templateId,
      triggerLabel,
      params: safeParams,
      runId: runInfo.run_id,
      createdAt: new Date().toISOString(),
    },
    conversationId,
  );
  setConversationPlaybookRun(conversationId, runInfo.run_id);
  introCard.dataset.playbookRunId = String(runInfo.run_id);
  introCard.onclick = async () => {
    try {
      await openPlaybookRunById(runInfo.run_id, templateId, { resetWorkspace: true, conversationId });
    } catch (err) {
      setHint(el.playbookHint, err.message || '加载 Playbook 运行状态失败', 'error');
    }
  };
  if (state.activeConversationId !== conversationId) {
    return;
  }
  renderPlaybookLaunchFeedback(templateId, triggerLabel, runInfo.run_id);
  state.activePlaybookRunId = runInfo.run_id;
  await openPlaybookRunById(runInfo.run_id, templateId, { resetWorkspace: true, conversationId });
}

async function readSSEStream(response, requestState) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let pending = '';
  let currentTextPayload = null;
  const batchPayloads = [];
  let doneReceived = false;

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
        doneReceived = true;
        if (currentTextPayload) {
          batchPayloads.push(currentTextPayload);
          currentTextPayload = null;
        }
        finalizeChatPayloadBatch(batchPayloads, requestState);
        return;
      }
      const event = JSON.parse(raw);

      if (event.type === 'text_start') {
        const p = event.payload || {};
        updateChatPendingPhase(requestState, 'generating');
        updateChatPendingTitle(requestState, p.data?.title || '系统消息');
        currentTextPayload = {
          ...p,
          data: {
            ...(p.data || {}),
            text: '',
          },
        };
        setChatPreviewText(requestState, '');
      } else if (event.type === 'text_delta') {
        if (currentTextPayload) {
          currentTextPayload.data.text += event.delta || '';
          setChatPreviewText(requestState, currentTextPayload.data.text);
        }
      } else if (event.type === 'text_end') {
        if (currentTextPayload) {
          if (!currentTextPayload.data.text) {
            currentTextPayload.data.text = event.text || '';
          }
          setChatPreviewText(requestState, currentTextPayload.data.text);
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
  if (doneReceived || batchPayloads.length) {
    finalizeChatPayloadBatch(batchPayloads, requestState);
    return;
  }
  throw new Error('响应流意外结束，请稍后重试。');
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

function getSemanticDomainMeta(domainValue) {
  const domains = state.semanticRuleMeta?.domains || [];
  return domains.find((item) => item.value === domainValue) || null;
}

function getSemanticSlotMeta(domainValue, slotValue) {
  const domain = getSemanticDomainMeta(domainValue);
  if (!domain) return null;
  return (domain.targets || []).find((item) => item.value === slotValue) || null;
}

function coerceSemanticRuleValue(rawValue, slotMeta) {
  if (slotMeta?.value_type === 'int') {
    return Number(rawValue);
  }
  return rawValue;
}

function populateSemanticRuleDomains(selectedDomain = '', selectedSlot = '') {
  if (!el.semanticRuleDomain || !el.semanticRuleSlot) return;
  const domains = state.semanticRuleMeta?.domains || [];
  el.semanticRuleDomain.innerHTML = '';
  domains.forEach((domain) => {
    const option = document.createElement('option');
    option.value = domain.value;
    option.textContent = domain.label || domain.value;
    el.semanticRuleDomain.appendChild(option);
  });
  if (selectedDomain && domains.some((domain) => domain.value === selectedDomain)) {
    el.semanticRuleDomain.value = selectedDomain;
  }
  populateSemanticRuleMatchModes();
  populateSemanticRuleSlots(selectedSlot);
}

function populateSemanticRuleSlots(selectedSlot = '') {
  if (!el.semanticRuleDomain || !el.semanticRuleSlot) return;
  const domain = getSemanticDomainMeta(el.semanticRuleDomain.value);
  const slots = domain?.targets || [];
  el.semanticRuleSlot.innerHTML = '';
  slots.forEach((slot) => {
    const option = document.createElement('option');
    option.value = slot.value;
    option.textContent = slot.label || slot.value;
    el.semanticRuleSlot.appendChild(option);
  });
  if (selectedSlot && slots.some((slot) => slot.value === selectedSlot)) {
    el.semanticRuleSlot.value = selectedSlot;
  }
  populateSemanticRuleActionTypes();
}

function populateSemanticRuleMatchModes(selectedMatchMode = 'contains') {
  if (!el.semanticRuleMatchMode) return;
  const modes = state.semanticRuleMeta?.match_modes || [];
  el.semanticRuleMatchMode.innerHTML = '';
  modes.forEach((mode) => {
    const option = document.createElement('option');
    option.value = mode.value;
    option.textContent = mode.label || mode.value;
    el.semanticRuleMatchMode.appendChild(option);
  });
  if (selectedMatchMode && modes.some((mode) => mode.value === selectedMatchMode)) {
    el.semanticRuleMatchMode.value = selectedMatchMode;
  }
}

function populateSemanticRuleActionTypes(selectedAction = '', selectedRuleValue = undefined) {
  if (!el.semanticRuleActionType) return;
  const slotMeta = getSemanticSlotMeta(el.semanticRuleDomain?.value, el.semanticRuleSlot?.value);
  const actions = slotMeta?.supported_actions || [];
  el.semanticRuleActionType.innerHTML = '';
  actions.forEach((action) => {
    const option = document.createElement('option');
    option.value = action.value;
    option.textContent = action.label || action.value;
    el.semanticRuleActionType.appendChild(option);
  });
  const fallbackAction = slotMeta?.default_action || actions[0]?.value || 'append';
  if (selectedAction && actions.some((action) => action.value === selectedAction)) {
    el.semanticRuleActionType.value = selectedAction;
  } else {
    el.semanticRuleActionType.value = fallbackAction;
  }
  renderSemanticRuleValueEditor(selectedRuleValue);
}

function renderSemanticRuleValueEditor(selectedRuleValue = undefined) {
  if (!el.semanticRuleValueEditor) return;
  const slotMeta = getSemanticSlotMeta(el.semanticRuleDomain?.value, el.semanticRuleSlot?.value);
  const actionType = el.semanticRuleActionType?.value || '';
  el.semanticRuleValueEditor.innerHTML = '';

  if (!slotMeta) {
    if (el.semanticRuleValueHelp) el.semanticRuleValueHelp.textContent = '';
    if (el.semanticRuleValueLabel) el.semanticRuleValueLabel.textContent = '规则值';
    return;
  }

  const currentValue = selectedRuleValue !== undefined ? selectedRuleValue : getSemanticSelectedRuleValue();
  if (el.semanticRuleValueLabel) {
    el.semanticRuleValueLabel.textContent = `${slotMeta.label || '规则值'} 取值`;
  }
  if (el.semanticRuleValueHelp) {
    const actionLabel = (slotMeta.supported_actions || []).find((action) => action.value === actionType)?.label || actionType;
    const placeholder = slotMeta.placeholder ? ` 输入建议：${slotMeta.placeholder}` : '';
    el.semanticRuleValueHelp.textContent = `当前将对参数“${slotMeta.label || slotMeta.value}”执行“${actionLabel}”。${placeholder}`;
  }

  if (slotMeta.editor === 'enum') {
    const values = Array.isArray(currentValue)
      ? currentValue.map((item) => String(item))
      : currentValue == null || currentValue === ''
        ? []
        : [String(currentValue)];
    const grid = document.createElement('div');
    grid.className = 'semantic-option-grid';
    (slotMeta.options || []).forEach((optionMeta) => {
      const label = document.createElement('label');
      label.className = 'semantic-option-item';

      const input = document.createElement('input');
      input.type = slotMeta.multiple ? 'checkbox' : 'radio';
      input.name = 'semanticRuleValueChoice';
      input.value = String(optionMeta.value);
      input.checked = values.includes(String(optionMeta.value));

      const text = document.createElement('span');
      text.textContent = optionMeta.label || String(optionMeta.value);
      label.appendChild(input);
      label.appendChild(text);
      grid.appendChild(label);
    });
    el.semanticRuleValueEditor.appendChild(grid);
    return;
  }

  const input = document.createElement('input');
  input.className = 'semantic-value-input';
  input.name = 'semanticRuleValueInput';
  input.type = slotMeta.editor === 'number' ? 'number' : 'text';
  if (slotMeta.placeholder) input.placeholder = slotMeta.placeholder;
  if (slotMeta.min != null) input.min = String(slotMeta.min);
  if (slotMeta.max != null) input.max = String(slotMeta.max);
  if (currentValue != null && currentValue !== '') input.value = String(currentValue);
  el.semanticRuleValueEditor.appendChild(input);
}

function getSemanticSelectedRuleValue() {
  const slotMeta = getSemanticSlotMeta(el.semanticRuleDomain?.value, el.semanticRuleSlot?.value);
  if (!slotMeta) return null;

  if (slotMeta.editor === 'enum') {
    const checked = Array.from(el.semanticRuleValueEditor?.querySelectorAll('input[name="semanticRuleValueChoice"]:checked') || []);
    if (slotMeta.multiple) {
      return checked.map((input) => coerceSemanticRuleValue(input.value, slotMeta));
    }
    const selected = checked[0];
    return selected ? coerceSemanticRuleValue(selected.value, slotMeta) : null;
  }

  const input = el.semanticRuleValueEditor?.querySelector('input[name="semanticRuleValueInput"]');
  const rawValue = input?.value ?? '';
  if (String(rawValue).trim() === '') return null;
  return coerceSemanticRuleValue(rawValue, slotMeta);
}

function resetSemanticRuleForm() {
  if (!el.semanticRuleForm) return;
  el.semanticRuleForm.reset();
  if (el.semanticRuleId) el.semanticRuleId.value = '';
  if (el.semanticRuleEnabled) el.semanticRuleEnabled.checked = true;
  if (el.semanticRulePriority) el.semanticRulePriority.value = '100';
  populateSemanticRuleDomains();
  if (el.saveSemanticRuleBtn) {
    el.saveSemanticRuleBtn.textContent = '保存规则';
  }
  if (el.resetSemanticRuleFormBtn) {
    el.resetSemanticRuleFormBtn.textContent = '取消编辑';
  }
  setHint(el.semanticRuleResult, '');
}

async function loadSemanticRuleMeta() {
  state.semanticRuleMeta = await api('/api/config/semantic-rules/meta');
  populateSemanticRuleDomains();
}

function buildSemanticRulePayload() {
  const domain = el.semanticRuleDomain?.value || '';
  const slot = el.semanticRuleSlot?.value || '';
  const slotMeta = getSemanticSlotMeta(domain, slot);
  const actionType = el.semanticRuleActionType?.value || slotMeta?.default_action || 'append';
  const ruleValue = getSemanticSelectedRuleValue();
  const priority = Number(el.semanticRulePriority?.value || 100);
  if (
    ruleValue == null ||
    ruleValue === '' ||
    (Array.isArray(ruleValue) && !ruleValue.length)
  ) {
    throw new Error('请先填写规则值。');
  }
  return {
    domain,
    slot_name: slot,
    match_mode: el.semanticRuleMatchMode?.value || 'contains',
    action_type: actionType,
    phrase: el.semanticRulePhrase?.value.trim() || '',
    rule_value: ruleValue,
    description: el.semanticRuleDesc?.value.trim() || null,
    enabled: !!el.semanticRuleEnabled?.checked,
    priority: Number.isFinite(priority) ? priority : 100,
  };
}

function fillSemanticRuleForm(rule) {
  if (!rule || !el.semanticRuleForm) return;
  if (el.semanticRuleId) el.semanticRuleId.value = String(rule.id || '');
  populateSemanticRuleDomains(rule.domain, rule.slot_name);
  populateSemanticRuleMatchModes(rule.match_mode || 'contains');
  populateSemanticRuleActionTypes(rule.action_type || '', rule.rule_value);
  if (el.semanticRulePhrase) el.semanticRulePhrase.value = rule.phrase || '';
  if (el.semanticRuleDesc) el.semanticRuleDesc.value = rule.description || '';
  if (el.semanticRuleEnabled) el.semanticRuleEnabled.checked = rule.enabled !== false;
  if (el.semanticRulePriority) el.semanticRulePriority.value = String(rule.priority ?? 100);
  if (el.saveSemanticRuleBtn) {
    el.saveSemanticRuleBtn.textContent = '保存修改';
  }
  if (el.resetSemanticRuleFormBtn) {
    el.resetSemanticRuleFormBtn.textContent = '退出编辑';
  }
}

async function refreshSemanticRules() {
  if (!el.semanticRuleList) return;
  if (!state.semanticRuleMeta) {
    await loadSemanticRuleMeta();
  }
  const items = await api('/api/config/semantic-rules');
  state.semanticRules = items;
  renderList(el.semanticRuleList, items, (item) => {
    const labels = (item.rule_value_labels || [])
      .map((label) => `<span class="badge-tag semantic-value-tag">${escapeHtml(label)}</span>`)
      .join('');
    return `
      <div class="semantic-rule-row">
        <div class="semantic-rule-main">
          <div class="semantic-rule-title-row">
            <strong style="color:var(--sec-medium);">${escapeHtml(item.phrase || '-')}</strong>
            <span class="semantic-rule-status ${item.enabled ? 'enabled' : 'disabled'}">${item.enabled ? '启用中' : '已停用'}</span>
          </div>
          <div class="semantic-rule-meta">${escapeHtml(item.domain_label || item.domain)} / ${escapeHtml(item.slot_label || item.slot_name)} · ${escapeHtml(item.match_mode_label || item.match_mode)} · ${escapeHtml(item.action_type_label || item.action_type)}</div>
          <div class="semantic-rule-tags">${labels || '<span class="semantic-rule-empty">暂无规则值</span>'}</div>
          <div class="semantic-rule-desc">${escapeHtml(item.description || '无备注')}</div>
        </div>
        <div class="semantic-rule-actions">
          <button data-edit-semantic-rule="${item.id}" class="secondary-btn" style="padding:4px 8px; font-size:0.85em;">编辑</button>
          <button data-toggle-semantic-rule="${item.id}" class="secondary-btn" style="padding:4px 8px; font-size:0.85em;">${item.enabled ? '停用' : '启用'}</button>
          <button data-delete-semantic-rule="${item.id}" class="secondary-btn" style="padding:4px 8px; font-size:0.85em;">删除</button>
        </div>
      </div>
    `;
  });

  el.semanticRuleList.querySelectorAll('button[data-edit-semantic-rule]').forEach((btn) => {
    btn.onclick = () => {
      const ruleId = Number(btn.getAttribute('data-edit-semantic-rule'));
      const rule = state.semanticRules.find((item) => Number(item.id) === ruleId);
      if (!rule) return;
      fillSemanticRuleForm(rule);
      setHint(el.semanticRuleResult, '已载入规则，可直接修改后保存。');
    };
  });

  el.semanticRuleList.querySelectorAll('button[data-toggle-semantic-rule]').forEach((btn) => {
    btn.onclick = async () => {
      const ruleId = Number(btn.getAttribute('data-toggle-semantic-rule'));
      const rule = state.semanticRules.find((item) => Number(item.id) === ruleId);
      if (!rule) return;
      try {
        await api(`/api/config/semantic-rules/${ruleId}`, {
          method: 'PUT',
          body: JSON.stringify({
            domain: rule.domain,
            slot_name: rule.slot_name,
            match_mode: rule.match_mode || 'contains',
            action_type: rule.action_type || 'append',
            phrase: rule.phrase,
            rule_value: rule.rule_value,
            description: rule.description || null,
            enabled: !rule.enabled,
            priority: rule.priority ?? 100,
          }),
        });
        setHint(el.semanticRuleResult, `规则已${rule.enabled ? '停用' : '启用'}。`, 'success');
        await refreshSemanticRules();
      } catch (err) {
        setHint(el.semanticRuleResult, err.message || '更新失败', 'error');
      }
    };
  });

  el.semanticRuleList.querySelectorAll('button[data-delete-semantic-rule]').forEach((btn) => {
    btn.onclick = async () => {
      const ruleId = Number(btn.getAttribute('data-delete-semantic-rule'));
      try {
        await api(`/api/config/semantic-rules/${ruleId}`, { method: 'DELETE' });
        setHint(el.semanticRuleResult, '规则已删除。', 'success');
        if (String(ruleId) === String(el.semanticRuleId?.value || '')) {
          resetSemanticRuleForm();
        }
        await refreshSemanticRules();
      } catch (err) {
        setHint(el.semanticRuleResult, err.message || '删除失败', 'error');
      }
    };
  });
}


async function sendChat(message) {
  if (!state.isAuthenticated) {
    setHint(el.loginResult, '请先登录成功后再进入对话。', 'error');
    setAuthState(false);
    return false;
  }

  if (isChatRequestInFlight()) {
    flashChatBusyNotice();
    return false;
  }

  const requestState = beginChatRequest();
  const req = {
    session_id: state.sessionId,
    message,
    active_playbook_run_id: state.activePlaybookRunId || null,
  };
  try {
    const response = await fetch('/api/chat/stream', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    if (!response.ok) {
      const text = await response.text();
      const safeMessage = text || '请求失败';
      renderChatRequestError(requestState, safeMessage);
      addConversationEntry(
        { type: 'error', title: '错误', message: safeMessage, createdAt: new Date().toISOString() },
        requestState.conversationId,
      );
      return false;
    }
    await readSSEStream(response, requestState);
    return true;
  } catch (err) {
    const safeMessage = err.message || '请求失败，请稍后重试。';
    renderChatRequestError(requestState, safeMessage);
    addConversationEntry(
      { type: 'error', title: '错误', message: safeMessage, createdAt: new Date().toISOString() },
      requestState.conversationId,
    );
    return false;
  } finally {
    finishChatRequest(requestState);
  }
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
  await ensureConversationScope(state.xdrBaseUrl);
}

async function checkAuthStatus() {
  try {
    const status = await api('/api/auth/status');
    if (!status.authenticated) {
      setAuthState(false);
      return;
    }
    const url = status.base_url || '';
    state.xdrBaseUrl = url;
    const baseUrlInput = document.getElementById('baseUrl');
    if (baseUrlInput && !baseUrlInput.value && url) {
      baseUrlInput.value = url;
    }
    setAuthState(true, `已登录平台：${url || '当前平台'}`);
    setHint(el.loginResult, '已自动恢复上次登录状态。', 'success');
    await bootWorkspace();
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
    state.xdrBaseUrl = payload.base_url;
    setAuthState(true, `已登录平台：${payload.base_url}`);
    await bootWorkspace();
  } catch (err) {
    setHint(el.loginResult, err.message, 'error');
    setAuthState(false);
  }
});

el.logoutBtn.onclick = async () => {
  try {
    const result = await api('/api/auth/logout', { method: 'POST' });
    state.xdrBaseUrl = '';
    state.playbookTemplates = [];
    state.activePlaybookRunId = null;
    state.playbookRunCache = {};
    state.playbookOpenTokens = {};
    closeRoutineBlockDialog();
    if (el.playbookCards) el.playbookCards.innerHTML = '';
    if (el.playbookHint) setHint(el.playbookHint, '');
    setHint(el.loginResult, result.message || '已退出到登录页。', 'success');
    setAuthState(false);
  } catch (err) {
    setHint(el.loginResult, err.message || '退出失败，请稍后重试。', 'error');
  }
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
    await refreshSemanticRules();
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
    closeRoutineBlockDialog();
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
      closeRoutineBlockDialog();
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

if (el.semanticRuleDomain) {
  el.semanticRuleDomain.addEventListener('change', () => populateSemanticRuleSlots());
}

if (el.semanticRuleSlot) {
  el.semanticRuleSlot.addEventListener('change', () => populateSemanticRuleActionTypes());
}

if (el.semanticRuleActionType) {
  el.semanticRuleActionType.addEventListener('change', () => renderSemanticRuleValueEditor());
}

if (el.resetSemanticRuleFormBtn) {
  el.resetSemanticRuleFormBtn.onclick = () => {
    resetSemanticRuleForm();
  };
}

if (el.semanticRuleForm) {
  el.semanticRuleForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      if (!state.isAuthenticated) {
        setHint(el.semanticRuleResult, '请先登录平台。', 'error');
        return;
      }
      if (!state.semanticRuleMeta) {
        await loadSemanticRuleMeta();
      }
      const payload = buildSemanticRulePayload();
      const ruleId = String(el.semanticRuleId?.value || '').trim();
      const path = ruleId ? `/api/config/semantic-rules/${ruleId}` : '/api/config/semantic-rules';
      const method = ruleId ? 'PUT' : 'POST';
      await api(path, { method, body: JSON.stringify(payload) });
      setHint(el.semanticRuleResult, ruleId ? '语义规则已更新。' : '语义规则已创建。', 'success');
      resetSemanticRuleForm();
      await refreshSemanticRules();
    } catch (err) {
      setHint(el.semanticRuleResult, err.message || '保存失败', 'error');
    }
  });
}


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
window.refreshSemanticRules = refreshSemanticRules;

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

if (el.newConversationBtn) {
  el.newConversationBtn.onclick = async () => {
    if (isChatRequestInFlight()) {
      flashChatBusyNotice();
      return;
    }
    await createNewConversation();
  };
}

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
  await submitChatMessage(message, { clearInput: true });
});


(async function init() {
  initProviderUI();
  renderPlaybookCards([]);
  try {
    await checkAuthStatus();
  } finally {
    finishBootTransition();
  }
})();
