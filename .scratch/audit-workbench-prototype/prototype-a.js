// THROWAWAY PROTOTYPE. A revision: targets → candidates → every model decision.
// All records below are illustrative, not copied from a real audit run.
const demoTargets = [
  {
    id: '6', name: 'D-Link DIR-890L', firmware: '路由器固件', generation: 'gen-0002',
    state: '运行中', stateClass: 'run', phase: 'Analysis 正在调查 cand-0001', updatedAt: '2026-09-27T11:42:00+08:00',
    count: 4, files: '2,184', calls: '62 / 120', errors: '1 条已恢复', sourcePath:'/home/dr/fw/cases/dir890l', outputPath:'result/D-Link DIR-890L',
    candidates: null,
  },
  {
    id: '7', name: 'Tenda AC18', firmware: '路由器固件', generation: 'gen-0001',
    state: '已封存', stateClass: 'confirm', phase: '事实报告与工件已封存', updatedAt: '2026-09-26T18:16:00+08:00',
    count: 3, files: '1,746', calls: '88 / 120', errors: '无当前阻塞', sourcePath:'/home/dr/fw/cases/tenda-ac18', outputPath:'result/Tenda AC18',
    candidates: [
      { id: 'cand-0001', title: '配置接口输入处理', file: 'extracted/usr/sbin/httpd', kind: '信号候选', status: '已确认', pill: 'confirm', evidence: 9, action: '复核已完成' },
      { id: 'cand-0002', title: 'Samba 认证配置', file: 'extracted/etc/smb.conf', kind: '信号候选', status: '证据不足', pill: 'warn', evidence: 4, action: '缺少运行时证据' },
      { id: 'cand-0003', title: '升级包校验入口', file: 'extracted/usr/bin/upgrade', kind: '覆盖候选', status: '已排除', pill: 'dim', evidence: 3, action: '发现决定性反证' },
    ],
  },
  {
    id: '8', name: 'OpenWrt', firmware: '系统固件', generation: 'gen-0001',
    state: '已中断', stateClass: 'warn', phase: 'LLMError，调查现场可恢复', updatedAt: '2026-09-27T10:26:00+08:00',
    count: 2, files: '3,012', calls: '62 / 120', errors: '1 个运行阻塞', sourcePath:'/home/dr/fw/cases/openwrt', outputPath:'result/OpenWrt',
    candidates: [
      { id: 'cand-0001', title: 'Web 管理入口检查', file: 'extracted/www/cgi-bin/luci', kind: '覆盖候选', status: '调查中', pill: 'run', evidence: 6, action: 'LLM 调用中断' },
      { id: 'cand-0002', title: '默认账号配置', file: 'extracted/etc/shadow', kind: '信号候选', status: '待调查', pill: 'dim', evidence: 1, action: '队列中' },
    ],
  },
];

let aScreen = 'targets';
let aTarget = '6';
let aCandidate = 'cand-0001';
let aNewProjectName = '';
let aNewSourcePath = '';
let aPreflight = null;

function aTargetRecord() { return demoTargets.find(t => t.id === aTarget) || demoTargets[0]; }
function aCandidates(t) { return t.id === '6' ? candidates : t.candidates; }
function aCandidateRecord() { return aCandidates(aTargetRecord()).find(c => c.id === aCandidate) || aCandidates(aTargetRecord())[0]; }
function aSafe(value) { return String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function aActivity(value) { return new Intl.DateTimeFormat('zh-CN', {timeZone:'Asia/Shanghai', month:'numeric', day:'numeric', hour:'2-digit', minute:'2-digit', hour12:false}).format(new Date(value)); }
function chooseTarget(id) { aTarget = id; aScreen = 'target'; aCandidate = aCandidates(aTargetRecord())[0]?.id || ''; render(); }
function resumeProject(id) { aTarget = id; aCandidate = aCandidates(aTargetRecord())[0]?.id || ''; resumeTarget(); }
function chooseCandidate(id) { aCandidate = id; aScreen = 'candidate'; render(); }
function showTargets() { aScreen = 'targets'; render(); }
function showTarget() { aScreen = 'target'; render(); }
function openNewProject() { aScreen = 'new'; aNewProjectName = ''; aNewSourcePath = ''; aPreflight = null; render(); }
function updateProjectName(value) {
  aNewProjectName = value;
  const preview = document.getElementById('outputPathPreview');
  if (preview) preview.textContent = `result/${value.trim() || '项目名'}`;
}

function normalizeSourcePath(raw) {
  const value = String(raw || '').trim();
  const prefix = '\\\\wsl.localhost\\kali-linux\\';
  if (value.toLowerCase().startsWith(prefix.toLowerCase())) {
    return '/' + value.slice(prefix.length).split('\\').join('/');
  }
  return value;
}

function inspectSourceFolder() {
  const pathInput = document.getElementById('newSourcePath');
  const nameInput = document.getElementById('newProjectName');
  aNewSourcePath = pathInput?.value || '';
  aNewProjectName = nameInput?.value || '';
  const normalized = normalizeSourcePath(aNewSourcePath);
  if (!normalized.startsWith('/')) {
    aPreflight = {count:0, error:'请输入 Kali 可访问的绝对目录，或粘贴 WSL UNC 路径。'};
  } else {
    const duplicate = demoTargets.find(t => t.sourcePath === normalized);
    if (duplicate) {
      aNewProjectName = duplicate.name;
      if (nameInput) nameInput.value = duplicate.name;
    }
    const nameConflict = demoTargets.find(t => t.name.toLowerCase() === aNewProjectName.trim().toLowerCase() && t.sourcePath !== normalized);
    const low = normalized.toLowerCase();
    const count = /(^|[\/_-])(multi|multiple)([\/_-]|$)/.test(low) ? 2 : /(^|[\/_-])(empty|no-firmware)([\/_-]|$)/.test(low) ? 0 : 1;
    const basename = normalized.split('/').filter(Boolean).pop() || 'firmware';
    aPreflight = {count, normalized, firmware:count===1?`${basename}.bin`:null, duplicate:duplicate?.id || null, nameConflict:nameConflict?.id || null};
  }
  render();
}

function startNewProject() {
  const name = aNewProjectName.trim();
  if (!aPreflight || aPreflight.count !== 1) return;
  if (!name || /[<>:"/\\|?*]/.test(name) || name === '.' || name === '..') {
    aPreflight = {...aPreflight, error:'请输入有效项目名；名称不能含路径分隔符或保留字符。'}; render(); return;
  }
  if (aPreflight.duplicate) { aTarget=aPreflight.duplicate; aScreen='target'; aCandidate=aCandidates(aTargetRecord())[0]?.id || ''; render(); return; }
  const sameName=demoTargets.find(t=>t.name.toLowerCase()===name.toLowerCase());
  if (sameName) { aPreflight={...aPreflight,error:`项目名已用于不同源目录（项目 ${sameName.name}），请换一个名称。`}; render(); return; }
  const active=demoTargets.find(t=>t.state==='运行中');
  if (active) { aPreflight={...aPreflight,error:`${active.name} 正在运行；结束或停止当前审计后再启动。`}; render(); return; }
  const next=(Math.max(0,...demoTargets.map(t=>Number(t.id)||0))+1).toString();
  demoTargets.push({id:next,name,firmware:'固件文件夹',generation:'gen-0001',state:'运行中',stateClass:'run',phase:'Step0 正在预处理',updatedAt:new Date().toISOString(),count:0,files:'待扫描',calls:'0 / 120',errors:'无错误',sourcePath:aPreflight.normalized,firmwareFile:aPreflight.firmware,outputPath:`result/${name}`,candidates:[]});
  aTarget=next; aCandidate=''; aScreen='target'; render();
}

function requestStop() {
  const t=aTargetRecord();
  document.getElementById('drawer').innerHTML=`<button class="icon-button close" aria-label="关闭详情" onclick="closeDrawer()">×</button><div class="eyebrow">停止审计 / ${aSafe(t.name)}</div><h2>保留当前进度并停止？</h2><p>系统会请求正在运行的审计进程中断并保存可恢复现场。之后可以从这个项目继续运行。</p><button class="ax-action-btn stop" onclick="confirmStop()">确认停止审计</button>`;
  document.getElementById('drawerBack').classList.add('open');
}

function confirmStop() {
  const t=aTargetRecord(); t.state='已中断'; t.stateClass='warn'; t.phase='已停止 · 现场可恢复'; t.updatedAt=new Date().toISOString(); closeDrawer(); aScreen='target'; render();
}

function resumeTarget() {
  const active=demoTargets.find(t=>t.state==='运行中');
  if (active) { document.getElementById('drawer').innerHTML=`<button class="icon-button close" onclick="closeDrawer()">×</button><h2>已有项目正在运行</h2><p>${aSafe(active.name)} 结束后才能继续这个项目。</p>`; document.getElementById('drawerBack').classList.add('open'); return; }
  const t=aTargetRecord(); t.state='运行中';t.stateClass='run';t.phase='Analysis 从保存现场恢复';t.updatedAt=new Date().toISOString();aScreen='target';render();
}

function aDecisions() {
  const c = aCandidateRecord();
  if (aTarget === '6' && c.id === 'cand-0001') return [
    { at:'11:35', role:'Analysis', summary:'先确认入口文件与参数解析位置', reason:'候选引用了管理接口；先读取目标内容确定可见入口。', kind:'工具', tool:'read_file', args:{path:c.file}, result:'成功 · 读取 318 行；发现 action 参数分支', raw:'int action = get_query_param("action");\nif (action != NULL) { dispatch_action(action); }', command:null, status:'ok', evidence:'ev-000018' },
    { at:'11:37', role:'Analysis', summary:'搜索命令执行相关字符串', reason:'沿当前假设寻找命令执行信号。', kind:'工具', tool:'strings_query', args:{file_ref:c.file.replace(/^extracted\//,'' )}, result:'协议拒绝 · 缺少必填 pattern；未执行工具', raw:'invalid_agent_proposal: $.next.arguments.pattern is required', command:null, status:'rejected', evidence:null },
    { at:'11:39', role:'Analysis', summary:'修正参数后重新检索', reason:'根据 Host 反馈补齐 pattern，并缩小检索范围。', kind:'工具', tool:'strings_query', args:{file_ref:c.file.replace(/^extracted\//,''),pattern:'re:(system|popen|exec)'}, result:'成功 · 命中 system 与 exec 字符串', raw:'0x00043a20 system\n0x00043aa8 exec', command:null, status:'ok', evidence:'ev-000019' },
    { at:'11:41', role:'Analysis', summary:'检查 system 的调用点', reason:'字符串只是信号；需要确认它是否与参数处理路径相连。', kind:'工具', tool:'r2_xref_query', args:{file_ref:c.file.replace(/^extracted\//,''),symbol:'system'}, result:'成功 · 找到 2 个引用，仍需追踪参数传播', raw:'0x0006b1a4 CALL sym.imp.system\n0x0006c290 CALL sym.imp.system', command:{host:['docker','run','--rm','--entrypoint','r2','--network','none','-v','<workspace>/extracted:/work/extracted:ro','firm_audit/sandbox:latest','-q','-A','-e','bin.relocs.apply=true','-c','axtj sym.imp.system','/work/extracted/www/cgi-bin/admin.cgi'], container:['r2','-q','-A','-e','bin.relocs.apply=true','-c','axtj sym.imp.system','/work/extracted/www/cgi-bin/admin.cgi']}, status:'ok', evidence:'ev-000020' },
    { at:'11:42', role:'Analysis', summary:'继续沿调用链核实可控性', reason:'目前只能证明调用点存在，尚不能确认外部输入到达 sink。', kind:'工具', tool:'r2_disassemble_function', args:{file_ref:c.file.replace(/^extracted\//,''),func_or_addr:'0x0006b150'}, result:'进行中 · 等待工具返回', raw:'尚无返回记录。', command:null, status:'pending', evidence:null },
  ];
  const first = { at:'10:21', role:'Analysis', summary:'核对候选锚点和目标文件', reason:'先从候选已有证据进入，避免依赖标题猜测。', kind:'工具', tool:'read_file', args:{path:c.file}, result:'成功 · 已取得目标内容', raw:'示例原始 Observation：目标文件已读取。', command:null, status:'ok', evidence:'ev-000001' };
  const second = { at:'10:23', role:'Analysis', summary:'依据首轮结果选择下一项取证', reason:'检查入口或配置是否在当前环境实际生效。', kind:'工具', tool:'search_code', args:{keyword:'auth',directory:'extracted'}, result:aTarget==='8'?'调用中断 · LLMError，已保留现场':'成功 · 返回相关路径', raw:aTarget==='8'?'LLMError: request timed out; checkpoint retained.':'示例结果：发现 3 个相关路径。', command:null, status:aTarget==='8'?'error':'ok', evidence:aTarget==='8'?null:'ev-000002' };
  const third = { at:'10:26', role:aTarget==='7'?'Verification':'Analysis', summary:aTarget==='7'?'独立复核并提交结论':'等待恢复后继续调查', reason:aTarget==='7'?'按 Claim 逐项核对证据。':'当前中断不是候选结论。', kind:'状态', tool:null, args:null, result:aTarget==='7'?c.status:'未形成最终结论', raw:'此步骤没有工具调用。', command:null, status:aTarget==='7'?'ok':'pending', evidence:null };
  return [first,second,third];
}

function openDecision(index) {
  const d = aDecisions()[index];
  const drawer = document.getElementById('drawer');
  const command = d.command ? `<div class="ax-command-label">宿主实际 argv · 模拟示例</div><pre class="ax-command">${aSafe(JSON.stringify(d.command.host,null,2))}</pre><div class="ax-command-label">容器内 argv</div><pre class="ax-command">${aSafe(JSON.stringify(d.command.container,null,2))}</pre>` : d.tool ? '<div class="ax-preflight idle">本例未展示底层 argv。正式记录需区分：Host 内部工具（无外部命令）、已记录的宿主/容器 argv，以及“未记录”。</div>' : '';
  const tool = d.tool ? `<div class="fact"><span>工具名称</span><strong class="mono">${aSafe(d.tool)}</strong></div><h3>Agent 调用参数</h3><pre>${aSafe(JSON.stringify(d.args,null,2))}</pre>${command}` : '<p>本轮没有工具调用，只有状态或结论提案。</p>';
  drawer.innerHTML = `<button class="icon-button close" aria-label="关闭详情" onclick="closeDrawer()">×</button><div class="eyebrow">${aSafe(aTargetRecord().id)} / ${aSafe(aCandidate)} / 决策 ${String(index+1).padStart(2,'0')}</div><h2>${aSafe(d.summary)}</h2>${pill(d.status==='rejected'?'协议拒绝':d.status==='error'?'运行中断':d.status==='pending'?'等待结果':'已完成',d.status==='rejected'||d.status==='error'?'warn':d.status==='pending'?'dim':'run')}<h3>LLM 决策</h3><p>${aSafe(d.reason)}</p><div class="fact"><span>角色 / 时间</span><strong>${aSafe(d.role)} · ${aSafe(d.at)}</strong></div><div class="fact"><span>Host 处理</span><strong>${aSafe(d.result)}</strong></div>${tool}<h3>返回结果 / 原始 Observation</h3><pre>${aSafe(d.raw)}</pre>${d.evidence?`<div class="fact"><span>Evidence Reference</span><strong>${aSafe(d.evidence)}</strong></div>`:''}<p>本原型使用模拟数据。正式界面会将 Transcript 决策与 Evidence 的参数、结果按记录身份关联；没有保存的底层命令明确标为未记录。</p>`;
  document.getElementById('drawerBack').classList.add('open');
}

function aSidebar() {
  return `<aside class="a-side"><div class="a-logo"><i>▣</i> 审计工作台</div><div class="micro">工作区</div><button class="ax-side-target ${aScreen==='targets'||aScreen==='target'||aScreen==='candidate'?'on':''}" onclick="showTargets()"><strong>审计项目</strong></button><button class="ax-side-target ${aScreen==='new'?'on':''}" onclick="openNewProject()"><strong>新建项目</strong></button><div class="side-foot">本机工作台<br>原型使用模拟数据</div></aside>`;
}

function aHeader(title,subtitle) {
  const crumb = aScreen==='targets' ? '<strong>全部项目</strong>' : aScreen==='new' ? '<button onclick="showTargets()">全部项目</button><span>/</span><strong>新建项目</strong>' : `<button onclick="showTargets()">全部项目</button><span>/</span>${aScreen==='target'?`<strong>${aSafe(aTargetRecord().name)}</strong>`:`<button onclick="showTarget()">${aSafe(aTargetRecord().name)}</button><span>/</span><strong>${aSafe(aCandidate)}</strong>`}`;
  return `<div class="ax-crumb">${crumb}</div><div class="ax-header"><div><h1>${title}</h1><p>${subtitle}</p></div></div>`;
}

function aStatusIcon(status) {
  return `<span class="ax-state-icon ${status}" aria-hidden="true"></span>`;
}

function aTargetsView() {
  const running=demoTargets.filter(t=>t.state==='运行中');
  const sealed=demoTargets.filter(t=>t.state==='已封存');
  const attention=demoTargets.filter(t=>t.state==='已中断');
  const projectRows=[...demoTargets].sort((a,b)=>new Date(b.updatedAt)-new Date(a.updatedAt)).map(t=>{
    const status=t.state==='运行中'?'running':t.state==='已封存'?'sealed':'attention';
    return `<div class="ax-project-row"><button class="ax-project-name ax-project-open" onclick="chooseTarget('${t.id}')"><span class="ax-project-name-copy"><strong>${aSafe(t.name)}</strong><small title="${aSafe(t.sourcePath)}">${aSafe(t.sourcePath)} · ${aSafe(t.generation)}</small></span></button><span class="ax-project-state ${status}">${aStatusIcon(status)}<span>${aSafe(t.state)}</span></span><span class="ax-project-phase"><strong>${aSafe(t.phase)}</strong>${status==='attention'?`<button class="ax-inline-action" onclick="resumeProject('${t.id}')">继续审计</button>`:`<small>${aSafe(t.firmware)}</small>`}</span><span class="ax-project-time">${aActivity(t.updatedAt)}</span><span class="ax-project-candidates">${t.count}</span></div>`;
  }).join('');
  return `${aHeader('审计项目','按最近活动排序。打开项目查看候选调查和运行记录。')}<div class="ax-project-toolbar"><div class="ax-overview"><div><span class="eyebrow">全部</span><strong>${demoTargets.length}</strong></div><div><span class="eyebrow">运行中</span><strong>${running.length}</strong></div><div class="attention"><span class="eyebrow">需处理</span><strong>${attention.length}</strong></div><div><span class="eyebrow">已封存</span><strong>${sealed.length}</strong></div></div><button class="ax-create-button" onclick="openNewProject()">新建审计项目</button></div><div class="ax-project-list"><div class="ax-project-list-head"><span>项目 / 来源目录</span><span>状态</span><span>当前阶段</span><span>最近活动</span><span style="text-align:right">候选</span></div>${projectRows||'<div class="ax-project-empty">尚无项目。新建项目后会在这里显示运行状态。</div>'}</div>`;
}

function aNewProjectView() {
  const p=aPreflight;
  let preview='填写目录后扫描固件。目录必须恰好包含一个可识别的固件文件。';
  let mode='idle';
  if(p?.error){preview=p.error;mode='bad';}
  else if(p?.count===0){preview='没有识别到固件。请检查目录，确认固件文件位于所选目录顶层。';mode='bad';}
  else if(p?.count>1){preview='识别到多个固件文件。请把每个固件放入独立目录，再选择其中一个目录。';mode='bad';}
  else if(p?.count===1){preview=`识别到 1 个固件：${p.firmware}`;mode=p.nameConflict?'bad':'good';if(p.duplicate)preview='这个源目录已经登记；继续将打开已有审计项目。';if(p.nameConflict)preview='项目名已被不同源目录使用，请换一个项目名。';}
  const normalized=p?.normalized||normalizeSourcePath(aNewSourcePath);
  const output=`result/${aNewProjectName.trim()||'项目名'}`;
  const active=demoTargets.find(t=>t.state==='运行中');
  const canStart=Boolean(p?.count===1&&aNewProjectName.trim()&&!p.error&&!p.nameConflict&&(p.duplicate||!active));
  const startLabel=p?.duplicate?'打开已有审计项目':'开始完整审计 · Step0 → Step1 → Step5';
  return `${aHeader('新建审计项目','项目名用于识别结果目录；源固件保持在原位置。')}<div class="ax-new-grid"><section class="card ax-form-card"><div class="eyebrow">新建 / 启动</div><h2>项目资料</h2><label class="ax-field"><span>项目名称</span><input id="newProjectName" value="${aSafe(aNewProjectName)}" placeholder="例如：家用路由器固件审计" oninput="updateProjectName(this.value)"></label><label class="ax-field"><span>固件目录</span><input id="newSourcePath" value="${aSafe(aNewSourcePath)}" placeholder="/home/dr/cases/router-firmware" oninput="aNewSourcePath=this.value"><p class="ax-help">支持 Kali 路径，例如 /home/dr/cases/router；也接受 &#92;&#92;wsl.localhost&#92;kali-linux&#92;...。目录内须恰好有一个固件。</p></label><button class="ax-action-btn" onclick="inspectSourceFolder()">模拟扫描目录</button><p class="ax-help">这是交互原型：扫描结果由示例路径模拟，不会读取真实目录。</p><div class="ax-preview"><div class="kv"><span>固件检查</span><strong>${p?.count===1?'1 个文件':p?.count>1?`${p.count} 个文件`:p?'未通过':'待检查'}</strong></div><div class="ax-preflight ${mode}">${preview}</div><div class="ax-path-normal">解析目录：${aSafe(normalized||'尚未填写')}</div></div><div class="ax-preview"><div class="kv"><span>结果目录</span><strong id="outputPathPreview">${aSafe(output)}</strong></div><p class="ax-help">解包材料、候选、运行世代和报告都保存在 fw/${aSafe(output)}/。</p></div>${active&&!p?.duplicate?`<div class="ax-preflight bad">${aSafe(active.name)} 正在运行；一次只允许一个项目活动。停止当前审计后才能开始新项目。</div>`:''}<button class="ax-start" onclick="startNewProject()" ${canStart?'':'disabled'}>${startLabel}</button></section><aside class="card ax-side-card"><div class="eyebrow">启动前说明</div><h2>源目录不变，审计另存</h2><p>正式控制台会从你提供的目录读取固件，把结果写入 <code>fw/result/&lt;项目名&gt;/</code>。</p><p>已登记的同一源目录会打开原项目并恢复未完成世代；项目已封存时，重新开始会创建新的运行世代。</p><p>工作台服务重启或浏览器关闭后，审计仍继续运行。页面可查看 LLM 决策、工具参数、返回结果，以及可取得的宿主与容器命令参数。</p></aside></div>`;
}

function aTargetView() {
  const t=aTargetRecord();
  const canRun=demoTargets.some(x=>x.state==='运行中');
  const action=t.state==='运行中'?`<button class="ax-action-btn stop" onclick="requestStop()">停止审计</button>`:t.state==='已中断'?`<button class="ax-action-btn resume" onclick="resumeTarget()">继续审计</button>`:'';
  const list=aCandidates(t)||[];
  const content=list.length?`<div class="ax-list"><div class="ax-list-head"><span>候选 / 目标</span><span>状态</span><span>证据</span><span>最近动作</span></div>${list.map(c=>`<button class="ax-list-row" onclick="chooseCandidate('${c.id}')"><span><strong>${aSafe(c.title)}</strong><small>${aSafe(c.id)} · ${aSafe(c.file)}</small></span><span>${pill(c.status,c.pill)}</span><span class="ax-count">${c.evidence} 条</span><span class="small muted">${aSafe(c.action)}</span></button>`).join('')}</div>`:`<div class="ax-empty">${t.state==='运行中'?'Recon 正在扫描固件，Candidate Store 生成候选后会显示在这里。':'当前没有候选记录。'}<br>页面会持续显示当前阶段和错误状态。</div>`;
  return `${aHeader(aSafe(t.name),`${t.firmware} · ${t.generation} · ${t.count} 个候选`)}<div class="ax-summary"><section class="card"><div class="eyebrow">当前工作流</div><h2>${aSafe(t.phase)}</h2><p>Step0 预处理 → Step1 引导解包 → Step5 逐候选调查</p><div class="ax-phases"><div class="${t.phase.startsWith('Step0')?'running':'done'}"></div><div class="${t.phase.startsWith('Step1')?'running':t.phase.startsWith('Step0')?'':'done'}"></div><div class="${t.phase.startsWith('Analysis')?'running':t.state==='已封存'?'done':''}"></div></div></section><section class="card"><div class="eyebrow">运行状态</div><h2>${pill(t.state,t.stateClass)} ${action}</h2><p>${aSafe(t.calls)} 模型调用 · ${aSafe(t.files)} 解包文件 · ${aSafe(t.errors)}</p><p class="ax-help">关闭浏览器或重启界面服务，审计继续运行；重新打开可查看现场。</p></section></div><div class="a-section"><h2 class="ax-section-title">候选列表</h2><span>${t.state==='运行中'?'点击候选查看每轮决策与工具记录':'查看候选的完整调查过程'}</span></div>${content}`;
}

function aCandidateView() {
  const c=aCandidateRecord(), chain=aDecisions();
  return `${aHeader(c.title,`${aTargetRecord().name} · ${aTargetRecord().generation} · ${c.id}`)}<div class="ax-case-head"><section class="card"><div class="eyebrow">调查状态</div><h2>${pill(c.status,c.pill)} <span style="font-size:12px;color:#82928a;margin-left:8px">${c.kind}</span></h2><p>目标：<span class="mono">${c.file}</span><br>被拒绝的提案也保留在记录中；只有实际执行的工具才会形成 Evidence。</p></section><section class="card"><div class="eyebrow">当前记录</div><div class="kv"><span>决策轮次</span><strong>${chain.length}</strong></div><div class="kv"><span>证据引用</span><strong>${c.evidence} 条</strong></div><div class="kv"><span>最近动作</span><strong>${c.action}</strong></div></section></div><div class="ax-decision-head"><div><h2>LLM 决策链</h2><p>按会话顺序排列。打开记录可查看工具、参数、返回结果和已记录的命令。</p></div><span class="eyebrow">${chain.length} 轮</span></div><div class="ax-chain">${chain.map((d,i)=>`<button class="ax-decision ${d.status==='rejected'||d.status==='error'?'error':''}" onclick="openDecision(${i})"><span class="ax-number">${String(i+1).padStart(2,'0')}</span><span class="when">${d.at}<br>${d.role}</span><span class="copy"><strong>${d.summary}</strong><p>${d.reason}${d.tool?` · <span class="mono">${d.tool}</span>`:''}</p></span><span class="result">${d.status==='rejected'?'协议拒绝':d.status==='error'?'运行中断':d.status==='pending'?'等待结果':d.evidence||'已记录'}<br>查看记录</span></button>`).join('')}<div class="ax-chain-note">本原型只展示少量模拟轮次。正式页面应展示该候选全部 Transcript 决策。记录了实际 CLI argv 时原样展示；未持久化的命令明确标为“未记录”，不能由工具名猜造。</div></div>`;
}

function variantANew() {
  const body=aScreen==='targets'?aTargetsView():aScreen==='new'?aNewProjectView():aScreen==='target'?aTargetView():aCandidateView();
  const place=aScreen==='targets'?'全部项目':aScreen==='new'?'新建项目':`${aTargetRecord().name} / ${aTargetRecord().generation}`;
  return `<div class="a">${aSidebar()}<div class="a-main"><div class="a-top"><span>审计工作台 / ${aSafe(place)}</span><span><span class="dot green"></span> 模拟预览 · 不执行任务</span></div>${body}</div></div>`;
}
