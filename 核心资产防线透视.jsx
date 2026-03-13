import React, { useState } from 'react';
import { 
  ShieldAlert, Activity, AlertTriangle, 
  Server, ArrowDownRight, ArrowUpRight, Shield, 
  X, Info, Sparkles, AlertOctagon
} from 'lucide-react';

const ExecutiveDashboard = () => {
  // 底部待封禁IP的状态管理，展示交互效果
  const [blockIps, setBlockIps] = useState([
    '1.87.105.112', 
    '123.71.103.143', 
    '214.239.184.97', 
    '179.4.164.130', 
    '155.190.194.249'
  ]);

  const removeIp = (ipToRemove) => {
    setBlockIps(blockIps.filter(ip => ip !== ipToRemove));
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-300 p-6 font-sans">
      <div className="max-w-6xl mx-auto space-y-6">
        
        {/* Header */}
        <header className="pb-4 border-b border-slate-800">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-wide">Playbook 报告 · 核心资产防线透视</h1>
            <p className="text-slate-400 mt-1 text-sm">面向业务负责人及管理层的自动化安全评估视图</p>
          </div>
        </header>

        {/* Executive Summary - Metric Cards */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 shadow-sm">
            <div className="flex items-center gap-3 text-slate-400 mb-3">
              <Server size={18} />
              <span className="font-medium text-sm">核心资产</span>
            </div>
            <div className="text-2xl font-mono text-white mb-1">172.25.138.51</div>
            <div className="text-xs text-slate-500">评估周期: 最近 24 小时内</div>
          </div>

          <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 shadow-sm relative overflow-hidden">
            <div className="absolute top-0 left-0 w-1 h-full bg-red-500"></div>
            <div className="flex items-center gap-3 text-slate-400 mb-3">
              <ArrowDownRight size={18} className="text-red-400" />
              <span className="font-medium text-sm">入向威胁 (目标为资产)</span>
            </div>
            <div className="flex items-baseline gap-4">
              <div>
                <span className="text-3xl font-bold text-red-400">100</span>
                <span className="text-xs text-slate-500 ml-1">告警</span>
              </div>
              <div>
                <span className="text-xl font-semibold text-slate-300">11</span>
                <span className="text-xs text-slate-500 ml-1">次访问</span>
              </div>
            </div>
          </div>

          <div className="bg-slate-900 p-5 rounded-xl border border-slate-800 shadow-sm relative overflow-hidden">
             <div className="absolute top-0 left-0 w-1 h-full bg-orange-500"></div>
            <div className="flex items-center gap-3 text-slate-400 mb-3">
              <ArrowUpRight size={18} className="text-orange-400" />
              <span className="font-medium text-sm">出向威胁 (源为资产)</span>
            </div>
             <div className="flex items-baseline gap-4">
              <div>
                <span className="text-3xl font-bold text-orange-400">100</span>
                <span className="text-xs text-slate-500 ml-1">告警</span>
              </div>
              <div>
                <span className="text-xl font-semibold text-slate-300">0</span>
                <span className="text-xs text-slate-500 ml-1">次访问</span>
              </div>
            </div>
          </div>
        </section>

        {/* Charts & AI Insight */}
        <section className="bg-slate-900 rounded-xl border border-slate-800 p-6">
          <h2 className="text-lg font-semibold text-white mb-6 flex items-center gap-2">
            <Activity size={18} className="text-slate-400" />
            流量威胁双向评估 (近7天)
          </h2>
          
          {/* Mock Chart Area */}
          <div className="h-48 border-b border-l border-slate-700 relative mb-6 flex items-end pt-4 pr-2">
            {/* Y-axis labels mock */}
            <div className="absolute -left-6 top-0 bottom-0 flex flex-col justify-between text-xs text-slate-500 pb-6">
              <span>1.0</span><span>0.8</span><span>0.6</span><span>0.4</span><span>0.2</span><span>0</span>
            </div>
            
            {/* Mock Data Bars */}
            <div className="w-full h-full flex items-end justify-between px-2 gap-2">
              {[10, 25, 15, 40, 30, 85, 95].map((val, idx) => (
                <div key={idx} className="w-1/6 flex flex-col justify-end gap-1 h-full group relative">
                   {/* Hover Tooltip (Mock) */}
                   <div className="opacity-0 group-hover:opacity-100 absolute -top-8 left-1/2 -translate-x-1/2 bg-slate-800 text-xs px-2 py-1 rounded transition-opacity">
                      {val}%
                   </div>
                  {/* Outbound (mock lower) */}
                  <div className="w-full bg-orange-500/30 rounded-t-sm" style={{ height: `${val * 0.3}%` }}></div>
                  {/* Inbound (mock higher) */}
                  <div className="w-full bg-red-500/50 rounded-t-sm" style={{ height: `${val}%` }}></div>
                </div>
              ))}
            </div>
            {/* X-axis labels */}
            <div className="absolute -bottom-6 left-0 right-0 flex justify-between text-xs text-slate-500 px-6">
              <span>周六</span><span>周日</span><span>周一</span><span>周二</span><span>周三</span><span>周四</span><span>周五</span>
            </div>
          </div>

          {/* AI Insight Box */}
          <div className="mt-8 bg-gradient-to-r from-indigo-950/80 to-slate-900 border border-indigo-500/30 rounded-lg p-4 flex gap-4 items-start shadow-inner">
            <div className="bg-indigo-500/20 p-2 rounded-full">
              <Sparkles size={20} className="text-indigo-400" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-indigo-300 mb-1">AI 透视结论</h3>
              <p className="text-sm text-slate-300 leading-relaxed">
                近 7 天出现异常流量峰值，建议优先审查核心资产 <code className="bg-slate-800 px-1 rounded text-slate-400">172.25.138.51</code> 的横向扫描与暴露面策略。
              </p>
            </div>
          </div>
        </section>

        {/* Detailed Tables Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          
          {/* Table 1: Bidirectional Stats */}
          <section className="bg-slate-900 rounded-xl border border-slate-800 p-6 flex flex-col">
            <h2 className="text-lg font-semibold text-white mb-4">资产双向告警统计</h2>
            <div className="overflow-x-auto flex-1">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-slate-400 bg-slate-800/50 uppercase">
                  <tr>
                    <th className="px-4 py-3 rounded-tl-lg">方向</th>
                    <th className="px-4 py-3">告警数</th>
                    <th className="px-4 py-3 rounded-tr-lg">访问量</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  <tr className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-4 font-medium flex items-center gap-2">
                      <ArrowDownRight size={16} className="text-red-400" />
                      入向 <span className="text-slate-500 text-xs">(目标为资产)</span>
                    </td>
                    <td className="px-4 py-4">
                      <div className="flex items-center gap-3">
                        <span className="w-8">100</span>
                        <div className="w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-red-500 w-full"></div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-4">
                      <div className="flex items-center gap-3">
                        <span className="w-8">11</span>
                        <div className="w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-slate-400 w-[11%]"></div>
                        </div>
                      </div>
                    </td>
                  </tr>
                  <tr className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-4 font-medium flex items-center gap-2">
                      <ArrowUpRight size={16} className="text-orange-400" />
                      出向 <span className="text-slate-500 text-xs">(源为资产)</span>
                    </td>
                    <td className="px-4 py-4">
                      <div className="flex items-center gap-3">
                        <span className="w-8">100</span>
                        <div className="w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-orange-500 w-full"></div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-4">
                       <div className="flex items-center gap-3">
                        <span className="w-8">0</span>
                        <div className="w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-slate-400 w-0"></div>
                        </div>
                      </div>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          {/* Table 2: Top 5 Threat IPs */}
          <section className="bg-slate-900 rounded-xl border border-slate-800 p-6 lg:col-span-2">
            <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <AlertOctagon size={18} className="text-slate-400" />
              Top 5 外部访问实体情报
            </h2>
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left">
                <thead className="text-xs text-slate-400 bg-slate-800/50 uppercase">
                  <tr>
                    <th className="px-4 py-3 rounded-tl-lg">IP 地址</th>
                    <th className="px-4 py-3">威胁等级</th>
                    <th className="px-4 py-3">置信度</th>
                    <th className="px-4 py-3">情报标签</th>
                    <th className="px-4 py-3 rounded-tr-lg">数据来源</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {/* Row 1 - High */}
                  <tr className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3 font-mono text-slate-300">179.4.164.130</td>
                    <td className="px-4 py-3">
                      <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/20">高危</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-xs w-8">93%</span>
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-red-500 w-[93%]"></div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-xs text-slate-400">C2控制</span>
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-xs text-slate-400">扫描器</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-500">本地启发式</td>
                  </tr>
                  
                  {/* Row 2 - High */}
                  <tr className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3 font-mono text-slate-300">155.190.194.249</td>
                    <td className="px-4 py-3">
                      <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/20">高危</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-xs w-8">99%</span>
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-red-500 w-[99%]"></div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex gap-2">
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-xs text-slate-400">C2控制</span>
                        <span className="px-2 py-0.5 rounded bg-slate-800 text-xs text-slate-400">扫描器</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-500">本地启发式</td>
                  </tr>

                  {/* Row 3 - Medium */}
                  <tr className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3 font-mono text-slate-300">123.71.103.143</td>
                    <td className="px-4 py-3">
                      <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-orange-500/20 text-orange-400 border border-orange-500/20">中危</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-xs w-8">75%</span>
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-orange-400 w-[75%]"></div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-xs text-slate-400">可疑</span>
                    </td>
                    <td className="px-4 py-3 text-slate-500">本地启发式</td>
                  </tr>

                  {/* Row 4 - Low */}
                  <tr className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3 font-mono text-slate-300">1.87.105.112</td>
                    <td className="px-4 py-3">
                      <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-slate-700 text-slate-300 border border-slate-600">低危</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-xs w-8">57%</span>
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-slate-400 w-[57%]"></div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-xs text-slate-400">未知</span>
                    </td>
                    <td className="px-4 py-3 text-slate-500">本地启发式</td>
                  </tr>

                  {/* Row 5 - Low */}
                  <tr className="hover:bg-slate-800/30 transition-colors">
                    <td className="px-4 py-3 font-mono text-slate-300">214.239.184.97</td>
                    <td className="px-4 py-3">
                      <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-slate-700 text-slate-300 border border-slate-600">低危</span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-xs w-8">72%</span>
                        <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div className="h-full bg-slate-400 w-[72%]"></div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-xs text-slate-400">未知</span>
                    </td>
                    <td className="px-4 py-3 text-slate-500">本地启发式</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

        </div>

        {/* Action Center (Interactive) */}
        <section className="bg-slate-800/50 rounded-xl border border-slate-700 p-6 shadow-lg mt-8">
          <div className="flex items-start gap-4">
            <div className="bg-slate-800 p-3 rounded-full border border-slate-700 shadow-sm mt-1">
              <ShieldAlert size={24} className="text-blue-400" />
            </div>
            
            <div className="flex-1">
              <h2 className="text-lg font-semibold text-white mb-2">建议响应动作</h2>
              <p className="text-sm text-slate-300 mb-6">
                建议优先对 Top 外部访问实体执行封禁审批；并对封禁前后关联高危告警进行人工复核。
              </p>

              <div className="bg-slate-900 rounded-lg p-4 border border-slate-800 mb-6">
                <div className="flex justify-between items-center mb-3">
                  <h3 className="text-sm font-medium text-slate-300">批量封禁目标名单 ({blockIps.length} 个 IP)</h3>
                  <span className="text-xs text-slate-500">点击 ✕ 可移出本次封禁任务</span>
                </div>
                
                {/* Interactive IP Chips */}
                <div className="flex flex-wrap gap-2">
                  {blockIps.length > 0 ? (
                    blockIps.map((ip) => (
                      <div key={ip} className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 border border-slate-700 rounded-full text-sm font-mono text-slate-300 group hover:border-slate-500 transition-colors">
                        {ip}
                        <button 
                          onClick={() => removeIp(ip)}
                          className="text-slate-500 hover:text-red-400 focus:outline-none"
                          title="移出名单"
                        >
                          <X size={14} />
                        </button>
                      </div>
                    ))
                  ) : (
                    <div className="text-sm text-slate-500 py-2">已清空封禁名单，无动作执行。</div>
                  )}
                </div>
              </div>

              {/* Action Button */}
              <div className="flex items-center gap-4">
                <button 
                  disabled={blockIps.length === 0}
                  className={`flex items-center gap-2 px-6 py-3 rounded-lg font-medium transition-all shadow-md
                    ${blockIps.length > 0 
                      ? 'bg-red-600 hover:bg-red-500 text-white hover:shadow-red-900/50' 
                      : 'bg-slate-800 text-slate-500 cursor-not-allowed'}`}
                >
                  <Shield size={18} />
                  发起批量封禁审批 ({blockIps.length} 个目标)
                </button>
                <span className="text-xs text-slate-500 flex items-center gap-1">
                  <Info size={14} />
                  点击后将进入工单流程，不会立即阻断业务
                </span>
              </div>
            </div>
          </div>
        </section>

      </div>
    </div>
  );
};

export default ExecutiveDashboard;