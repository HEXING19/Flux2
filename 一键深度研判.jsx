import React, { useState } from 'react';
import { 
  ShieldAlert, Activity, Crosshair, Server, Globe, 
  Terminal, AlertTriangle, CheckCircle, Clock, 
  Download, PlayCircle, ChevronRight, MapPin, Tag
} from 'lucide-react';

const DeepAnalysisDashboard = () => {
  const [showBlockModal, setShowBlockModal] = useState(false);

  // 模拟故事线数据：一个真实的内网核心资产被攻击成功的案例
  const data = {
    incidentId: "incident-7e064803-bbd3-4c83-859d-ecdb059cd29f",
    status: "critical", // critical, high, medium, low
    conclusion: "高危真实攻击！攻击者利用 Weblogic 漏洞成功获取目标服务器权限，并已探测到内网横向移动行为。",
    
    // 维度1：攻击源与情报 (Attacker)
    attacker: {
      ip: "185.220.101.45",
      country: "德国 (Tor 节点)",
      confidence: 98,
      tags: ["C&C服务器", "僵尸网络", "Tor出口"],
      history: "近7天内有 14 次针对本行业的扫描记录"
    },
    
    // 维度2：受害目标 (Victim)
    victim: {
      ip: "10.0.5.112",
      hostname: "PRD-DB-USER-01",
      role: "核心用户数据库",
      value: "极高 (Crown Jewel)",
      vulnerability: "存在未修复的 CVE-2020-14882 (Weblogic RCE)"
    },
    
    // 维度3 & 4：影响面与载荷 (Impact & Payload)
    impact: {
      totalVisits: 1250,
      highRiskVisits: 45,
      successCount: 3, // 关键：有成功的失陷指标
      lateralMovement: true,
      mitre: ["T1190 (利用面向公众的应用)", "T1059 (命令与脚本解释器)"]
    }
  };

  const handleBlockAction = () => {
    setShowBlockModal(true);
    setTimeout(() => {
      setShowBlockModal(false);
      alert("联动 SOAR 成功：已在边界防火墙下发阻断策略！");
    }, 1500);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-300 p-6 font-sans">
      {/* 顶部 Header：告警上下文与全局操作 */}
      <div className="flex justify-between items-center border-b border-slate-800 pb-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            Playbook 报告 · 单点告警深度研判
            <span className="px-2 py-1 text-xs font-semibold bg-red-500/20 text-red-400 border border-red-500/50 rounded flex items-center gap-1">
              <AlertTriangle size={14} /> 紧急研判
            </span>
          </h1>
          <p className="text-sm text-slate-500 mt-1 font-mono">UUID: {data.incidentId}</p>
        </div>
        <div className="flex gap-3">
          <button 
            onClick={handleBlockAction}
            className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded transition-colors text-sm shadow-lg shadow-red-900/50"
          >
            <ShieldAlert size={16} /> 一键封禁源 IP ({data.attacker.ip})
          </button>
        </div>
      </div>

      {/* 研判摘要核心结论区 (结论先行) */}
      <div className="bg-red-950/30 border-l-4 border-red-500 p-4 rounded-r-lg mb-6 flex items-start gap-4">
        <div className="mt-1">
          <AlertTriangle className="text-red-500 animate-pulse" size={24} />
        </div>
        <div>
          <h2 className="text-lg font-bold text-red-400 mb-1">系统研判结论：攻击真实性极高</h2>
          <p className="text-slate-300">{data.conclusion}</p>
          <div className="mt-3 flex gap-4 text-sm">
            <span className="flex items-center gap-1 text-red-400 font-medium">
              <CheckCircle size={14} /> 攻击已穿透边界
            </span>
            <span className="flex items-center gap-1 text-yellow-400 font-medium">
              <Activity size={14} /> 监测到内部横向扩散
            </span>
          </div>
        </div>
      </div>

      {/* 主要数据面板 (网格布局) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        
        {/* 维度1：攻击源实体画像 & 情报 */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col">
          <h3 className="text-white font-semibold flex items-center gap-2 mb-4">
            <Globe className="text-blue-400" size={18} /> 攻击源画像
          </h3>
          <div className="mb-4">
            <div className="text-2xl font-mono text-white">{data.attacker.ip}</div>
            <div className="flex items-center gap-2 text-sm text-slate-400 mt-1">
              <MapPin size={14} /> {data.attacker.country}
            </div>
          </div>
          
          <div className="space-y-4 flex-1">
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-slate-400">情报置信度</span>
                <span className="text-red-400 font-bold">{data.attacker.confidence}%</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2">
                <div className="bg-gradient-to-r from-red-600 to-red-400 h-2 rounded-full" style={{ width: `${data.attacker.confidence}%` }}></div>
              </div>
            </div>
            
            <div>
              <span className="text-sm text-slate-400 block mb-2">威胁标签</span>
              <div className="flex flex-wrap gap-2">
                {data.attacker.tags.map(tag => (
                  <span key={tag} className="px-2 py-1 bg-red-900/40 text-red-300 text-xs rounded border border-red-800/50 flex items-center gap-1">
                    <Tag size={12} /> {tag}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* 维度2：受害目标资产价值 */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col">
          <h3 className="text-white font-semibold flex items-center gap-2 mb-4">
            <Server className="text-purple-400" size={18} /> 受害目标画像
          </h3>
          <div className="flex-1 flex flex-col justify-center gap-6">
            <div>
              <div className="text-slate-400 text-sm mb-1">受害资产 IP</div>
              <div className="text-3xl font-mono text-white">{data.victim.ip}</div>
            </div>
            
            <div className="grid grid-cols-2 gap-4 bg-slate-800/40 p-4 rounded border border-slate-700/50">
              <div>
                <span className="text-slate-400 text-xs block mb-1">主机名</span>
                <span className="text-white font-mono text-sm">{data.victim.hostname}</span>
              </div>
              <div>
                <span className="text-slate-400 text-xs block mb-1">资产角色</span>
                <span className="text-white text-sm">{data.victim.role}</span>
              </div>
            </div>
          </div>
        </div>

        {/* 维度3 & 4：内部影响面统计 (将枯燥表格图表化) */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-col">
          <h3 className="text-white font-semibold flex items-center gap-2 mb-4">
            <Crosshair className="text-orange-400" size={18} /> 内部影响面
          </h3>
          
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div className="bg-slate-800/50 p-3 rounded text-center">
              <div className="text-slate-400 text-xs mb-1">近7天总访问量</div>
              <div className="text-xl font-mono text-white">{data.impact.totalVisits}</div>
            </div>
            <div className="bg-slate-800/50 p-3 rounded text-center">
              <div className="text-slate-400 text-xs mb-1">高危攻击量</div>
              <div className="text-xl font-mono text-orange-400">{data.impact.highRiskVisits}</div>
            </div>
            <div className="bg-red-900/20 border border-red-500/30 p-3 rounded text-center col-span-2">
              <div className="text-red-400 text-xs mb-1 font-semibold">有效攻击次数 (攻击成功)</div>
              <div className="text-3xl font-mono text-red-500 font-bold">{data.impact.successCount}</div>
            </div>
          </div>
        </div>
      </div>

      {/* 底部：攻击手法与特征详情 */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <div className="flex border-b border-slate-800 bg-slate-900/50 px-4">
          <div className="py-3 px-4 text-sm font-medium border-b-2 border-blue-500 text-blue-400">
            攻击手法特征
          </div>
        </div>
        
        <div className="p-5">
          <div className="space-y-4">
            <div>
              <h4 className="text-sm font-medium text-slate-400 mb-2">命中 MITRE ATT&CK 战术</h4>
              <div className="flex gap-2">
                {data.impact.mitre.map(t => (
                  <span key={t} className="px-3 py-1 bg-slate-800 text-slate-300 text-xs rounded-full border border-slate-700">{t}</span>
                ))}
              </div>
            </div>
            <div className="bg-slate-950 p-4 rounded border border-slate-800 font-mono text-sm text-green-400 overflow-x-auto">
              <div className="text-slate-500 mb-2">// 提取的关键恶意 Payload 片段</div>
              GET /console/images/%252E%252E%252Fconsole.portal?_nfpb=true&_pageLabel=HomePage1&handle=com.tangosol.coherence.mvel2.sh.ShellSession(%22java.lang.Runtime.getRuntime().exec('whoami');%22) HTTP/1.1<br/>
              Host: 10.0.5.112:7001<br/>
              User-Agent: curl/7.68.0
            </div>
          </div>
        </div>
      </div>

      {/* 模拟的处置弹窗 */}
      {showBlockModal && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-slate-900 border border-slate-700 p-6 rounded-lg max-w-md w-full shadow-2xl">
            <h3 className="text-lg font-bold text-white mb-2 flex items-center gap-2">
              <PlayCircle className="text-blue-500" /> 执行 SOAR 处置剧本
            </h3>
            <p className="text-slate-400 text-sm mb-6">正在通过 API 联动 Palo Alto 防火墙，下发针对源 IP {data.attacker.ip} 的全局阻断策略...</p>
            <div className="w-full bg-slate-800 rounded-full h-2 mb-2 overflow-hidden">
              <div className="bg-blue-500 h-2 rounded-full animate-[pulse_1s_ease-in-out_infinite]" style={{ width: '60%' }}></div>
            </div>
            <p className="text-xs text-slate-500 text-right">剧本执行中 (60%)</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default DeepAnalysisDashboard;