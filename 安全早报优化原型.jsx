import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  Server, 
  Info, 
  Copy, 
  ExternalLink, 
  AlertTriangle,
  CheckCircle2,
  Lock,
  Target,
  TrendingUp,
  BarChart3,
  ShieldX
} from 'lucide-react';

const App = () => {
  const stats = [
    { label: '需要优先关注的事件', value: '129', color: 'text-red-500', icon: ShieldAlert, bg: 'bg-red-500/10' },
    { label: '今日安全日志', value: '20,371', color: 'text-blue-400', icon: Activity, bg: 'bg-blue-500/10' },
    { label: '受影响资产数', value: '5', color: 'text-amber-400', icon: Server, bg: 'bg-amber-500/10' },
  ];

  const risks = [
    {
      id: 'R3',
      title: 'Webshell 后门威胁',
      severity: '严重',
      type: '后门植入',
      target: '冰蝎 v3.0 JSP',
      desc: '已检测到冰蝎v3.0 JSP Webshell上传成功，表明已有主机可能被植入后门。',
      assets: ['17.238.171.162', '17.31.69.136']
    },
    {
      id: 'R1',
      title: '应用漏洞利用风险突出',
      severity: '高危',
      type: 'RCE 远程代码执行',
      target: 'ECShop, Apache OFBiz',
      cve: 'CVE-2018-8033',
      desc: '攻击者可借此执行任意命令，直接威胁服务器安全。',
      assets: ['17.135.127.50', '17.100.34.190']
    },
    {
      id: 'R2',
      title: 'Java 应用攻击持续',
      severity: '高危',
      type: '反序列化攻击',
      target: '通用 Java 应用',
      desc: '存在通用Java反序列化攻击及远程加载恶意Java文件事件。',
      assets: ['17.67.61.133']
    }
  ];

  const playbooks = [
    { 
      id: 'p3', 
      title: '风险主机网络隔离', 
      type: '隔离',
      impact: '高：主机业务将中断',
      items: ['17.238.171.162', '17.31.69.136'],
      buttonText: '确认并一键隔离'
    },
    { 
      id: 'p2', 
      title: '封禁恶意攻击源', 
      type: '拦截',
      impact: '中：需确认业务合法出口 IP',
      items: ['103.21.4.12', '45.12.89.4', '192.110.3.44'],
      buttonText: '确认并一键处置'
    },
    { 
      id: 'p1', 
      title: '针对性漏洞一键排查', 
      type: '巡检',
      impact: '低：轻量扫描流量',
      items: ['17.135.127.50 (CVE-2018-8033)', '17.67.61.133 (Java反序列化)', '17.238.171.162 (WebShell扫描)'],
      noButton: true
    },
  ];

  const topAssets = [
    { ip: '17.238.171.162', count: 1450, trend: '+12%' },
    { ip: '17.135.127.50', count: 820, trend: '+5%' },
    { ip: '17.31.69.136', count: 430, trend: '-2%' }
  ];

  const CopyableTag = ({ text }) => (
    <span className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 border border-slate-700 text-[11px] text-slate-300 hover:border-blue-500 transition-colors cursor-pointer group">
      {text}
      <Copy size={10} className="opacity-0 group-hover:opacity-100" />
    </span>
  );

  return (
    <div className="min-h-screen bg-[#0a0f1c] text-slate-200 font-sans p-6">
      {/* Header */}
      <div className="max-w-6xl mx-auto flex justify-between items-center mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="text-blue-500" />
            Playbook 安全日报
            <span className="text-xs font-normal px-2 py-1 bg-blue-500/20 text-blue-400 rounded-full ml-2">2026-03-10</span>
          </h1>
          <p className="text-slate-400 text-sm mt-1">根据最新威胁情报生成的自动化处置建议</p>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        {stats.map((stat, idx) => (
          <div key={idx} className="bg-slate-900/50 border border-slate-800 p-5 rounded-xl flex items-center gap-4">
            <div className={`p-3 rounded-lg ${stat.bg}`}>
              <stat.icon className={stat.color} size={24} />
            </div>
            <div>
              <p className="text-slate-400 text-sm">{stat.label}</p>
              <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="max-w-6xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Left Column: Intelligence & Risks */}
        <div className="lg:col-span-2 space-y-6">
          
          {/* Section: Risk Trend */}
          <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 shadow-sm">
            <h2 className="text-sm font-semibold flex items-center gap-2 text-slate-400 uppercase tracking-widest mb-4 font-bold">
              <TrendingUp size={16} className="text-blue-400" />
              近期安全态势趋势 (近7日)
            </h2>
            <div className="flex items-end justify-between h-20 gap-2 px-2">
              {[40, 65, 30, 85, 45, 95, 129].map((val, i) => (
                <div key={i} className="flex-1 group relative">
                  <div 
                    className={`w-full rounded-t-sm transition-all ${i === 6 ? 'bg-red-500 shadow-lg shadow-red-500/20' : 'bg-slate-700 group-hover:bg-slate-600'}`} 
                    style={{ height: `${val}%` }}
                  ></div>
                  <span className="absolute -top-6 left-1/2 -translate-x-1/2 text-[10px] text-slate-500 opacity-0 group-hover:opacity-100 transition-opacity">
                    {val}
                  </span>
                </div>
              ))}
            </div>
            <div className="flex justify-between mt-2 text-[10px] text-slate-600 px-1 font-mono">
              <span>03-04</span><span>03-05</span><span>03-06</span><span>03-07</span><span>03-08</span><span>03-09</span><span className="text-red-500 font-bold">今天</span>
            </div>
          </div>

          {/* Section: Top Attacked Assets */}
          <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 shadow-sm">
            <h2 className="text-sm font-semibold flex items-center gap-2 text-slate-400 uppercase tracking-widest mb-4 font-bold border-b border-slate-800 pb-2">
              <BarChart3 size={16} className="text-amber-500" />
              受攻击最频繁资产 (TOP 3)
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
              {topAssets.map((asset, i) => (
                <div key={i} className="p-4 bg-slate-800/10 rounded-xl border border-slate-800 flex flex-col items-center text-center group hover:border-amber-500/40 transition-all hover:bg-slate-800/20">
                  <div className="mb-2 p-1.5 bg-slate-900 rounded-full border border-slate-800">
                    <ShieldX size={16} className="text-amber-500 group-hover:scale-110 transition-transform" />
                  </div>
                  <p className="text-sm font-mono text-white mb-2 font-bold tracking-tight">{asset.ip}</p>
                  <div className="mt-auto w-full border-t border-slate-800/50 pt-2 text-center">
                    <p className="text-xl font-bold text-red-400 leading-none">{asset.count}</p>
                    <div className="mt-1.5 flex flex-col items-center">
                      <p className="text-[9px] text-slate-600 uppercase font-medium">攻击尝试</p>
                      <p className={`text-[10px] font-bold mt-0.5 ${asset.trend.startsWith('+') ? 'text-red-500/90' : 'text-green-500/90'}`}>
                        <span className="text-[8px] text-slate-500 font-normal mr-1">较昨日</span>
                        {asset.trend}
                      </p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section: Risk List */}
          <div className="space-y-4">
            <div className="flex items-center px-2">
              <h2 className="text-lg font-semibold flex items-center gap-2 text-slate-100 font-bold">
                <AlertTriangle size={18} className="text-amber-500" />
                关键风险清单
              </h2>
            </div>

            {risks.map((risk) => (
              <div key={risk.id} className="bg-slate-900/40 border border-slate-800 rounded-xl p-5 border-l-4 shadow-sm" style={{ borderLeftColor: risk.severity === '严重' ? '#ef4444' : '#f59e0b' }}>
                <div className="flex justify-between items-start mb-2">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                        risk.severity === '严重' ? 'bg-red-500/20 text-red-500' : 'bg-amber-500/20 text-amber-500'
                      }`}>
                        {risk.severity}
                      </span>
                      <span className="text-slate-500 text-[11px] font-medium">{risk.type}</span>
                    </div>
                    <h3 className="text-base font-bold text-white tracking-tight">{risk.title}</h3>
                  </div>
                  {risk.cve && (
                    <div className="text-[11px] text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20 font-mono">
                      {risk.cve}
                    </div>
                  )}
                </div>
                
                <p className="text-slate-400 text-sm mb-4 leading-relaxed">
                  {risk.desc}
                </p>

                <div className="flex flex-wrap items-center gap-2 pt-3 border-t border-slate-800/50">
                  <span className="text-[11px] text-slate-500 flex items-center gap-1">
                    <Server size={10} /> 涉及资产:
                  </span>
                  <div className="flex flex-wrap gap-2">
                    {risk.assets.map(ip => <CopyableTag key={ip} text={ip} />)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Decisions */}
        <div className="space-y-4">
          
          {/* Section: Action Playbooks */}
          <div className="bg-slate-900/50 border border-blue-500/20 rounded-xl p-5 shadow-xl shadow-blue-500/5">
            <h2 className="text-lg font-bold flex items-center gap-2 mb-5 text-slate-100 border-b border-slate-800 pb-3">
              <CheckCircle2 size={18} className="text-green-500" />
              处置建议方案
            </h2>
            
            <div className="space-y-6">
              {playbooks.map((act) => (
                <div key={act.id} className="relative pl-4 border-l-2 border-slate-800 hover:border-blue-500/50 transition-colors">
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-sm font-bold text-blue-400 flex items-center gap-2">
                      <Target size={14} /> {act.title}
                    </p>
                    <span className="text-[10px] text-slate-500 px-1.5 py-0.5 bg-slate-800 rounded uppercase font-mono">{act.type}</span>
                  </div>

                  <div className="flex items-center gap-2 text-[11px] text-amber-500/80 mb-3 bg-amber-500/5 px-2 py-1 rounded">
                    <Info size={10} /> 影响：{act.impact}
                  </div>

                  <div className="space-y-1.5 mb-4">
                    <p className="text-[10px] text-slate-500 uppercase font-bold tracking-tighter mb-1">拟处理/排查对象清单</p>
                    <div className="flex flex-col gap-1.5">
                      {act.items.map((item, i) => (
                        <div key={i} className="text-[11px] font-mono bg-black/40 px-2 py-1.5 rounded border border-slate-800 text-slate-400">
                          {item}
                        </div>
                      ))}
                    </div>
                  </div>

                  {!act.noButton && (
                    <button className="w-full py-2.5 bg-blue-600/10 hover:bg-blue-600 text-blue-400 hover:text-white border border-blue-600/30 rounded text-[11px] font-bold transition-all flex items-center justify-center gap-2 group shadow-lg shadow-blue-900/10">
                      <Lock size={12} className="group-hover:animate-pulse" />
                      {act.buttonText}
                    </button>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

      </div>
    </div>
  );
};

export default App;