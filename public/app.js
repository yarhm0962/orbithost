const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = {
  user: null, csrf: '', config: { hostingMode: 'worker', workerReady: false, maxUploadMb: 1024, pythonVersions: ['3.10','3.11','3.12','3.13'] },
  dashboard: null, activePage: 'overview', activeProject: null, activeTab: 'overview', modal: null,
  sidebarCollapsed: false, mobileNavOpen: false, projectSearch: '', logStream: 'runtime', logSearch: '', modalReturnFocusSelector: '',
  logs: [], logCursor: null, logSeen: new Set(), logController: null, logStreamKey: '', logReconnectTimer: null, logStreamErrorShown: false, metrics: null, busy: false, authMode: 'login', registerStep: 1, registerData: {}
};
const iconPaths = {
  orbit:'<circle cx="12" cy="12" r="7.5"/><ellipse cx="12" cy="12" rx="11" ry="4.5" transform="rotate(-35 12 12)"/><circle cx="19.5" cy="4.5" r="1"/>',
  grid:'<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/>',
  boxes:'<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="m3 12 9 5 9-5M3 16l9 5 9-5"/>',
  activity:'<path d="M22 12h-4l-3 8L9 4l-3 8H2"/>',
  settings:'<circle cx="12" cy="12" r="3"/><path d="m19.4 15 .1.1 1.2 2.1-2.1 2.1-2.2-1.2a8 8 0 0 1-1.6.7l-.7 2.4h-3l-.7-2.4a8 8 0 0 1-1.6-.7l-2.2 1.2-2.1-2.1 1.2-2.2a8 8 0 0 1-.7-1.6L2.6 13v-3l2.4-.7a8 8 0 0 1 .7-1.6L4.5 5.5l2.1-2.1 2.2 1.2a8 8 0 0 1 1.6-.7l.7-2.4h3l.7 2.4a8 8 0 0 1 1.6.7l2.2-1.2 2.1 2.1-1.2 2.2a8 8 0 0 1 .7 1.6l2.4.7v3l-2.4.7a8 8 0 0 1-.8 1.5Z" transform="translate(0 1) scale(.92)"/>',
  plus:'<path d="M12 5v14M5 12h14"/>',
  chevronDown:'<path d="m7 10 5 5 5-5"/>',
  chevronRight:'<path d="m9 18 6-6-6-6"/>',
  chevronLeft:'<path d="m15 18-6-6 6-6"/>',
  menu:'<path d="M4 6h16M4 12h16M4 18h16"/>',
  collapse:'<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M9 3v18"/><path d="m15 9-3 3 3 3"/>',
  search:'<circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/>',
  bell:'<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9"/><path d="M10 21h4"/>',
  help:'<circle cx="12" cy="12" r="10"/><path d="M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>',
  external:'<path d="M14 3h7v7M10 14 21 3"/><path d="M19 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h6"/>',
  check:'<path d="m5 12 4 4L19 6"/>',
  checkCircle:'<circle cx="12" cy="12" r="10"/><path d="m8 12 2.5 2.5L16 9"/>',
  x:'<path d="m18 6-12 12M6 6l12 12"/>',
  close:'<path d="m18 6-12 12M6 6l12 12"/>',
  alert:'<path d="m10.3 3.9-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3.1l-8-14a2 2 0 0 0-3.4 0Z"/><path d="M12 9v4M12 17h.01"/>',
  clock:'<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  cpu:'<rect x="5" y="5" width="14" height="14" rx="2"/><path d="M9 9h6v6H9zM9 1v4m6-4v4M9 19v4m6-4v4M19 9h4m-4 6h4M1 9h4m-4 6h4"/>',
  memory:'<rect x="4" y="6" width="16" height="12" rx="2"/><path d="M8 10h8M8 14h5M8 3v3m8-3v3M8 18v3m8-3v3"/>',
  server:'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M11 6.5h6M11 17.5h6"/>',
  terminal:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
  rocket:'<path d="M4.5 16.5c-1.5 1.3-2 4-2 4s2.7-.5 4-2c.7-.8.7-2 0-2.7-.7-.7-1.9-.7-2.7 0Z"/><path d="m12 15-3-3a22 22 0 0 1 2-3c3.5-4 7-5 10-5 0 3-1 6.5-5 10a22 22 0 0 1-3 2Z"/><path d="M9 12H5s1-4 5-5M12 15v4s4-1 5-5"/><circle cx="15.5" cy="8.5" r="1.5"/>',
  play:'<path d="m7 4 13 8-13 8V4Z"/>',
  pause:'<rect x="6" y="4" width="4" height="16" rx="1"/><rect x="14" y="4" width="4" height="16" rx="1"/>',
  refresh:'<path d="M20 7v5h-5M4 17v-5h5"/><path d="M5.5 9A7 7 0 0 1 18 6l2 6M4 12l2 6a7 7 0 0 0 12.5-3"/>',
  rotate:'<path d="M3 12a9 9 0 0 1 15-6.7L21 8M21 3v5h-5M21 12a9 9 0 0 1-15 6.7L3 16m0 5v-5h5"/>',
  upload:'<path d="M12 16V4m-5 5 5-5 5 5"/><path d="M20 16.5v2A2.5 2.5 0 0 1 17.5 21h-11A2.5 2.5 0 0 1 4 18.5v-2"/>',
  github:'<path d="M9 19c-4.3 1.4-4.3-2.5-6-3m12 6v-3.9a3.4 3.4 0 0 0-.9-2.6c3-.3 6.2-1.5 6.2-6.7a5.2 5.2 0 0 0-1.4-3.6 4.8 4.8 0 0 0-.1-3.6s-1.2-.4-3.9 1.4a13.5 13.5 0 0 0-7 0C5.2 1.2 4 1.6 4 1.6a4.8 4.8 0 0 0-.1 3.6 5.2 5.2 0 0 0-1.4 3.6c0 5.2 3.2 6.4 6.2 6.7a3.4 3.4 0 0 0-.9 2.6V22" transform="translate(2 0) scale(.86)"/>',
  file:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6M8 13h8M8 17h8"/>',
  lock:'<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/>',
  key:'<circle cx="8" cy="15" r="4"/><path d="m11 12 8-8 2 2-2 2 2 2-3 3-2-2-2 2"/>',
  eye:'<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
  trash:'<path d="M3 6h18M8 6V4h8v2m3 0-1 14H6L5 6m4 4v6m6-6v6"/>',
  edit:'<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z"/>',
  arrowUpRight:'<path d="M7 17 17 7M7 7h10v10"/>',
  calendar:'<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 11h18"/>',
  book:'<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2Z"/>',
  globe:'<circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10Z"/>',
  shield:'<path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11Z"/><path d="m9 12 2 2 4-4"/>',
  logOut:'<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>',
  externalLink:'<path d="M15 3h6v6m-11 5L21 3"/><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>',
  database:'<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14a9 3 0 0 0 18 0V5M3 12a9 3 0 0 0 18 0"/>',
  more:'<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
  monitor:'<rect x="3" y="3" width="18" height="13" rx="2"/><path d="M8 21h8m-4-5v5"/>',
  wrench:'<path d="M14.7 6.3a5 5 0 0 0-6.4 6.4L3 18l3 3 5.3-5.3a5 5 0 0 0 6.4-6.4L14 12l-3-3Z"/>',
  sparkles:'<path d="m12 3 1.5 5.5L19 10l-5.5 1.5L12 17l-1.5-5.5L5 10l5.5-1.5L12 3ZM19 16l.8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8L19 16Z"/>',
  clock3:'<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
  sliders:'<path d="M4 21v-7m0-4V3m8 18v-9m0-4V3m8 18v-5m0-4V3M2 14h4m4-6h4m4 6h4"/>',
  package:'<path d="m12 3 9 5-9 5-9-5 9-5Z"/><path d="M3 8v8l9 5 9-5V8m-9 5v8"/>',
  circle:'<circle cx="12" cy="12" r="9"/>',
  info:'<circle cx="12" cy="12" r="10"/><path d="M12 11v5m0-9h.01"/>',
  filter:'<path d="M4 7h16M7 12h10m-7 5h4"/>',
  clipboard:'<rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 4.5h6V2H9zM8 10h8m-8 4h8m-8 4h5"/>',
  wand:'<path d="m15 4 5 5M5 20l14-14M3 7l2 2m9 10 2 2M4 13l-1 1m11-10 1-1"/>',
};
function icon(name, cls = '') { return `<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true">${iconPaths[name] || iconPaths.circle}</svg>`; }
function esc(v = '') { return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function initials(email = '') { return (email.split('@')[0].slice(0,2) || 'OH').toUpperCase(); }
function prettyTime(date) {
  if (!date) return '—'; const d = new Date(date); if (Number.isNaN(d.getTime())) return '—';
  const sec = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (sec < 60) return 'just now'; if (sec < 3600) return `${Math.floor(sec/60)}m ago`; if (sec < 86400) return `${Math.floor(sec/3600)}h ago`; if (sec < 86400*7) return `${Math.floor(sec/86400)}d ago`;
  return d.toLocaleDateString(undefined,{month:'short',day:'numeric'});
}
function duration(ms) { if (ms == null) return '—'; if (ms < 1000) return `${ms} ms`; return `${(ms/1000).toFixed(1)}s`; }
function statusPill(status) {
  const map={online:['Online','online'],stopped:['Stopped','stopped'],deploying:['Deploying','deploying'],building:['Building','building'],failed:['Failed','failed'],success:['Deployed','online']};
  const [label,cls]=map[status]||[status||'Unknown','stopped'];
  return `<span class="status-pill status-${cls}"><span class="status-dot"></span>${label}</span>`;
}
function modeLabel() { return 'Container worker'; }
async function api(url, options = {}) {
  const method=(options.method||'GET').toUpperCase();
  const headers={...(options.headers||{})};
  if (!['GET','HEAD','OPTIONS'].includes(method) && state.csrf) headers['x-csrf-token']=state.csrf;
  if (options.body && !(options.body instanceof FormData) && typeof options.body !== 'string') { headers['content-type']='application/json'; options={...options,body:JSON.stringify(options.body)}; }
  const response=await fetch(url,{credentials:'same-origin',...options,method,headers});
  const data=await response.json().catch(()=>({}));
  if (!response.ok) { const err=new Error(data.error||`Request failed (${response.status}).`); err.data=data; err.status=response.status; throw err; }
  if(data.csrfToken) state.csrf=data.csrfToken;
  return data;
}
async function bootstrap() {
  try {
    const [csrf,config,me]=await Promise.all([api('/api/auth/csrf'),api('/api/config'),api('/api/auth/me')]);
    state.csrf=csrf.csrfToken;state.config=config;state.user=me.user;
    if(state.user) await refreshDashboard();
  } catch (e) { console.error(e); }
  render();
}
async function refreshDashboard() { state.dashboard=await api('/api/dashboard'); }
async function openProject(id, tab = 'overview') {
  stopLiveLogs();
  state.activeProject=await api(`/api/projects/${encodeURIComponent(id)}`);
  state.activePage='project';state.activeTab=tab;state.mobileNavOpen=false;
  if(tab==='logs') await refreshLogs();
  if(tab==='overview') await refreshMetrics();
  render();
}
async function refreshProject() {
  if(!state.activeProject?.project?.id) return;
  state.activeProject=await api(`/api/projects/${encodeURIComponent(state.activeProject.project.id)}`);
}
function showToast(message, type='success', detail='') {
  const region=$('#toast-region'); if(!region)return;
  const node=document.createElement('div');node.className=`toast ${type}`;
  node.innerHTML=`${icon(type==='success'?'checkCircle':type==='error'?'alert':'info')}<div><p>${esc(message)}</p>${detail?`<small>${esc(detail)}</small>`:''}</div>`;
  region.append(node);setTimeout(()=>{node.style.opacity='0';node.style.transform='translateY(5px)';setTimeout(()=>node.remove(),220)},4200);
}
function setButtonBusy(button, label='Working…') { if(!button)return;button.disabled=true;button.dataset.original=button.innerHTML;button.innerHTML=`<span class="spinner"></span>${esc(label)}`; }
function resetButton(button) { if(button){button.disabled=false;if(button.dataset.original){button.innerHTML=button.dataset.original;delete button.dataset.original;}} }
// Keep keyboard focus predictable when the shell is re-rendered around a dialog.
function focusSelectorFor(element) {
  if (!element) return '';
  if (element.id) return `#${CSS.escape(element.id)}`;
  const selectors = [['data-action', element.dataset.action], ['data-nav', element.dataset.nav], ['data-project-tab', element.dataset.projectTab], ['data-edit-env', element.dataset.editEnv], ['data-delete-env', element.dataset.deleteEnv], ['data-open-project', element.dataset.openProject]];
  const match = selectors.find(([, value]) => value);
  return match ? `[${match[0]}=\"${CSS.escape(match[1])}\"]` : '';
}
function openModal(type, data = {}) {
  state.modalReturnFocusSelector = focusSelectorFor(document.activeElement);
  state.modal={type,...data};
  render();
  const dialog=$('.modal');
  if(dialog) dialog.setAttribute('tabindex','-1');
  const field=$('.modal input:not([type=radio]):not([type=checkbox]),.modal select,.modal textarea');
  const firstControl=$('.modal button:not([disabled]),.modal a[href]');
  (field || firstControl || dialog)?.focus({preventScroll:true});
}
function closeModal() {
  state.modal=null;
  render();
  const returnTarget = state.modalReturnFocusSelector ? $(state.modalReturnFocusSelector) : null;
  (returnTarget || $('.page-title') || $('#main-content'))?.focus({preventScroll:true});
  state.modalReturnFocusSelector='';
}
function shell(content) {
  const navItems=[['overview','grid','Overview'],['projects','boxes','Projects'],['activity','activity','Activity'],['settings','settings','Settings']];
  const active=state.activePage==='project'?'projects':state.activePage;
  return `<div class="app-shell ${state.sidebarCollapsed?'sidebar-collapsed':''} ${state.mobileNavOpen?'mobile-nav-open':''}">
    <!-- A real button backdrop is keyboard/screen-reader visible and closes the mobile drawer. -->
    ${state.mobileNavOpen?'<button type="button" class="mobile-nav-backdrop" data-action="close-mobile-menu" aria-label="Close navigation"></button>':''}
    <a class="skip-link" href="#main-content">Skip to main content</a>
    <aside class="sidebar" id="primary-navigation" aria-label="Main navigation">
      <div class="sidebar-top"><div class="brand-mark"><svg viewBox="0 0 40 40" aria-hidden="true"><circle cx="20" cy="20" r="13"/><ellipse cx="20" cy="20" rx="18" ry="7" transform="rotate(-35 20 20)"/><circle class="mark-dot" cx="31" cy="10" r="2.5"/></svg></div><div class="brand-copy"><div class="brand-name">OrbitHost</div><div class="brand-tagline">Bot infrastructure</div></div></div>
      <div class="nav-label">Workspace</div><nav class="nav-list">${navItems.map(([id,ic,label])=>`<button class="nav-link ${active===id?'active':''}" data-nav="${id}" title="${label}" ${active===id?'aria-current="page"':''}>${icon(ic)}<span class="nav-text">${label}</span>${id==='projects'?`<span class="nav-count">${state.dashboard?.stats?.total||0}</span>`:''}</button>`).join('')}</nav>
      <div class="nav-label">Resources</div><nav class="nav-list"><button class="nav-link" data-resource="docs">${icon('book')}<span class="nav-text">Setup guide</span>${icon('external')}</button><button class="nav-link" data-resource="worker">${icon('server')}<span class="nav-text">Worker status</span></button></nav>
      <div class="sidebar-bottom"><div class="worker-card"><div class="worker-card-top"><span class="worker-led" style="${state.config.workerReady?'background:var(--green)':'background:var(--red)'}"></span>${state.config.workerReady?'Worker connected':'Worker unavailable'}</div><p>${state.config.workerReady?'Container execution and live process logs are available.':'No live worker connection. Configure WORKER_URL and WORKER_TOKEN; deployments will fail clearly until the worker is reachable.'}</p><button class="text-link" data-nav="settings">Hosting configuration ${icon('chevronRight')}</button></div>
      <div class="user-mini"><div class="avatar">${esc(initials(state.user?.email))}</div><div class="user-mini-copy"><div class="user-email">${esc(state.user?.email||'Workspace user')}</div><div class="user-plan">Hosting workspace</div></div><button class="icon-button" title="Sign out" aria-label="Sign out" data-action="logout">${icon('logOut')}</button></div></div>
    </aside>
    <main class="shell-main" id="main-content" tabindex="-1"><header class="topbar"><div class="topbar-left"><button class="icon-button mobile-menu" data-action="mobile-menu" aria-label="${state.mobileNavOpen?'Close navigation':'Open navigation'}" aria-controls="primary-navigation" aria-expanded="${state.mobileNavOpen}">${icon('menu')}</button><button class="icon-button desktop-collapse" data-action="collapse-sidebar" aria-label="Collapse sidebar" title="Collapse sidebar">${icon('collapse')}</button><div class="topbar-divider"></div><div class="crumb">Workspace <span style="color:#596681;margin:0 6px">/</span> <span class="crumb-current">${esc(state.activePage==='project'?state.activeProject?.project?.name||'Project':state.activePage[0].toUpperCase()+state.activePage.slice(1))}</span></div></div>
      <div class="topbar-right"><label class="topbar-search">${icon('search')}<input id="global-search" type="search" placeholder="Find a project…" aria-label="Search projects" value="${esc(state.projectSearch)}"><span class="keycap">/</span></label><div class="topbar-divider"></div><button class="icon-button topbar-icon" data-resource="docs" title="Help and setup guide" aria-label="Help">${icon('help')}</button><button class="icon-button topbar-icon" data-nav="activity" title="Activity" aria-label="Activity">${icon('bell')}<span class="notification-dot"></span></button><div class="avatar">${esc(initials(state.user?.email))}</div></div></header>
      <div class="page-content">${content}</div></main>${state.modal?renderModal():''}</div>`;
}
function statCard(label,value,ic,foot,opts={}) {
  return `<div class="stat-card" style="--glow:${opts.glow||'rgba(147,135,255,.08)'}"><div class="stat-top"><span>${label}</span><span class="stat-icon" style="--icon-bg:${opts.bg||'rgba(147,135,255,.12)'};--icon-color:${opts.color||'#a79bff'}">${icon(ic)}</span></div><div class="stat-value">${value}</div><div class="stat-foot">${foot}</div></div>`;
}
function projectCard(p) {
  const iconName=p.sourceType==='git'?'github':'file';
  const runtime='Python '+p.pythonVersion;
  return `<article class="project-row" data-project-search="${esc((p.name+' '+p.status+' '+runtime).toLowerCase())}"><div class="project-avatar">${icon(iconName)}</div><div class="project-main"><div class="project-name"><span>${esc(p.name)}</span></div><div class="project-meta"><span>${esc(runtime)}</span><span class="meta-dot"></span><span>${p.deploymentCount||0} deployments</span><span class="meta-dot"></span><span>${p.lastDeployedAt?`Updated ${prettyTime(p.lastDeployedAt)}`:'Not deployed'}</span></div></div><div class="project-side">${statusPill(p.status)}<button class="icon-button" data-open-project="${esc(p.id)}" aria-label="Open ${esc(p.name)}" title="Open project">${icon('chevronRight')}</button></div></article>`;
}
function activityItem(a, compact=false) {
  const icons={deployment_succeeded:'checkCircle',deployment_started:'rocket',deployment_failed:'alert',project_created:'plus',project_stop:'pause',project_stopped:'pause',project_start:'play',project_restart:'refresh',settings_updated:'settings',secret_updated:'key',secret_deleted:'trash',project_deleted:'trash',workspace_created:'sparkles'};
  const ic=icons[a.action]||'activity';
  return `<div class="${compact?'activity-small':'activity-item'}">${compact?icon(ic):`<span class="activity-icon">${icon(ic)}</span>`}<div class="${compact?'activity-small-copy':'activity-copy'}"><div class="${compact?'':'activity-message'}">${esc(a.message)}</div>${a.projectName&&!compact?`<div class="activity-time">${esc(a.projectName)}</div>`:''}<span class="${compact?'activity-small-time':'activity-time'}">${prettyTime(a.createdAt)}</span></div></div>`;
}
function deploymentRow(d, withProject=false) {
  const successful=['success','succeeded'].includes(d.status);
  return `<div class="deploy-row"><span class="deploy-indicator" style="${successful?'':'background:var(--red-soft);color:var(--red)'}">${icon(successful?'checkCircle':'alert')}</span><div class="deploy-copy"><div class="deploy-name">${withProject?`${esc(d.projectName)} · `:''}Deploy #${d.sequence}</div><div class="deploy-sub">${esc(d.summary||d.trigger||'Deployment')} · ${duration(d.durationMs)}</div></div><div class="deploy-time">${prettyTime(d.createdAt)}</div>${statusPill(d.status)}</div>`;
}
function sectionPanel(title, subtitle, body, action='') {
  return `<section class="panel"><div class="panel-head"><div><h2 class="panel-title">${title}</h2>${subtitle?`<div class="panel-note">${subtitle}</div>`:''}</div>${action}</div><div class="panel-body">${body}</div></section>`;
}
function renderOverview() {
  const d=state.dashboard||{projects:[],activity:[],recentDeployments:[],stats:{}};
  const projects=d.projects||[];
  const projectContent=projects.length?`<div class="project-list">${projects.slice(0,5).map(projectCard).join('')}</div>${projects.length>5?`<div style="text-align:center;margin-top:13px"><button class="plain-link" data-nav="projects">See all ${projects.length} projects ${icon('chevronRight')}</button></div>`:''}`:`<div class="empty-state"><div class="empty-art">${icon('boxes')}</div><div class="empty-title">Your next bot starts here</div><div class="empty-copy">Create a project from a ZIP archive or connect a public Git repository to get your workspace ready.</div><button class="button button-primary" data-action="new-project">${icon('plus')} Create a project</button></div>`;
  const activityContent=d.activity?.length?`<div class="activity-list">${d.activity.slice(0,5).map(a=>activityItem(a)).join('')}</div>`:`<div class="empty-state" style="padding:25px 10px"><div class="empty-title">No activity yet</div><div class="empty-copy">Project changes and deployment events will appear here.</div></div>`;
  const deployContent=d.recentDeployments?.length?d.recentDeployments.slice(0,4).map(x=>deploymentRow(x,true)).join(''):`<div class="empty-state" style="padding:25px 10px"><div class="empty-title">Nothing deployed yet</div><div class="empty-copy">Your deployment history will show up here.</div></div>`;
  return `<div class="page-heading"><div><div class="eyebrow">Workspace overview</div><h1 class="page-title">Your bots, in orbit.</h1><p class="page-subtitle">A clear view of your Discord bot projects and deployment activity.</p></div><button class="button button-primary" data-action="new-project">${icon('plus')} <span class="button-copy">New project</span></button></div>
    <div class="stat-grid">${statCard('Total projects',d.stats.total||0,'boxes','Across this workspace',{color:'#a69bff'})}${statCard('Currently online',d.stats.online||0,'activity','Running containers',{bg:'rgba(83,214,160,.1)',color:'#53d6a0',glow:'rgba(83,214,160,.06)'})}${statCard('Deployments',d.recentDeployments?.length||0,'rocket','Recent deployment events',{bg:'rgba(125,184,255,.1)',color:'#7db8ff',glow:'rgba(125,184,255,.06)'})}${statCard('Workspace uptime',d.stats.uptime==null?'—':formatUptime(d.stats.uptime),'clock','Total across running bots',{bg:'rgba(246,198,110,.1)',color:'#f6c66e',glow:'rgba(246,198,110,.05)'})}</div>
    <div class="content-grid"><div style="display:grid;gap:15px">${sectionPanel('Your projects',`${projects.length} project${projects.length===1?'':'s'} in this workspace`,`<div id="home-project-list">${projectContent}</div>`,`<button class="plain-link" data-nav="projects">View all ${icon('chevronRight')}</button>`)}${sectionPanel('Recent deployments','Latest deployment activity',deployContent,`<button class="plain-link" data-nav="projects">Browse projects ${icon('chevronRight')}</button>`)}</div>
    <div style="display:grid;gap:15px">${sectionPanel('Recent activity','What has changed recently',activityContent,`<button class="plain-link" data-nav="activity">View activity ${icon('chevronRight')}</button>`)}${sectionPanel('Quick start','Bring your bot online',`<div style="display:grid;gap:15px">${[['upload','Add your source','Upload a ZIP with your main.py and requirements.txt.'],['key','Set environment variables','Keep tokens and API keys out of your source code.'],['rocket','Deploy your bot','Build, start, and inspect logs from one place.']].map(([ic,t,c],i)=>`<div style="display:flex;gap:10px;align-items:flex-start"><div class="activity-icon">${icon(ic)}</div><div><div style="font-size:11px;font-weight:650;color:#d9dff0">${t}</div><div style="font-size:10px;color:#8995af;line-height:1.6;margin-top:4px">${c}</div></div></div>`).join('')}</div>`,`<button class="plain-link" data-resource="docs">Read the setup guide ${icon('chevronRight')}</button>`)}</div></div>`;
}
function renderProjects() {
  const projects=state.dashboard?.projects||[];
  const rows=projects.filter(p=>(p.name+' '+p.status+' '+p.pythonVersion).toLowerCase().includes(state.projectSearch.toLowerCase()));
  const body=rows.length?`<div class="project-list">${rows.map(projectCard).join('')}</div>`:`<div class="empty-state"><div class="empty-art">${icon('search')}</div><div class="empty-title">${projects.length?'No matching projects':'No projects yet'}</div><div class="empty-copy">${projects.length?'Try another search term.':'Create a bot project to start managing source, secrets, and deployments.'}</div>${projects.length?'':`<button class="button button-primary" data-action="new-project">${icon('plus')} Create a project</button>`}</div>`;
  return `<div class="page-heading"><div><div class="eyebrow">Workspace</div><h1 class="page-title">Projects</h1><p class="page-subtitle">Manage source, runtime settings, environment variables, and deployments.</p></div><button class="button button-primary" data-action="new-project">${icon('plus')} <span class="button-copy">New project</span></button></div>
    <div class="stat-grid" style="grid-template-columns:repeat(3,minmax(0,1fr))">${statCard('All projects',projects.length,'boxes','Across this workspace')}${statCard('Online',projects.filter(p=>p.status==='online').length,'activity','Active status',{bg:'rgba(83,214,160,.1)',color:'#53d6a0'})}${statCard('Stopped',projects.filter(p=>p.status==='stopped').length,'pause','Not running',{bg:'rgba(143,154,180,.1)',color:'#a0acc1'})}</div>
    ${sectionPanel('All projects',`${rows.length} shown`,`<div id="projects-list">${body}</div>`,`<label class="search-field" style="max-width:230px">${icon('search')}<input id="project-page-search" type="search" placeholder="Filter projects" aria-label="Filter projects" value="${esc(state.projectSearch)}"></label>`)}`;
}
function renderActivity() {
  const activity=state.dashboard?.activity||[];
  const deploys=state.dashboard?.recentDeployments||[];
  return `<div class="page-heading"><div><div class="eyebrow">Workspace history</div><h1 class="page-title">Activity</h1><p class="page-subtitle">An audit-friendly view of recent changes, project actions, and deployments.</p></div><button class="button button-quiet" data-action="refresh">${icon('refresh')} Refresh</button></div>
    <div class="activity-page-grid"><div>${sectionPanel('Recent events',`${activity.length} latest events`,activity.length?`<div class="activity-list global-activity">${activity.map(a=>activityItem(a)).join('')}</div>`:`<div class="table-empty">Events will appear as you create and manage projects.</div>`)}</div><div>${sectionPanel('Deployment history','Recent workspace deployments',deploys.length?deploys.map(d=>deploymentRow(d,true)).join(''):`<div class="table-empty">No deployments yet.</div>`)}</div></div>`;
}
function renderSettings() {
  const connected=Boolean(state.config.workerReady);
  const healthLabel=connected?'Connected and reachable':'Not reachable';
  return `<div class="page-heading"><div><div class="eyebrow">Workspace preferences</div><h1 class="page-title">Settings</h1><p class="page-subtitle">Account details, worker connectivity, and security configuration.</p></div></div>
    <div class="settings-grid"><div style="display:grid;gap:15px">${sectionPanel('Account','Your signed-in workspace',`<div class="detail-kv"><span class="kv-label">Email address</span><span class="kv-value">${esc(state.user?.email)}</span></div><div class="detail-kv"><span class="kv-label">Account created</span><span class="kv-value">${state.user?.createdAt?new Date(state.user.createdAt).toLocaleDateString(undefined,{year:'numeric',month:'long',day:'numeric'}):'—'}</span></div><div class="detail-kv"><span class="kv-label">Session</span><span class="kv-value" style="color:var(--green)">${icon('lock')} Authenticated · HTTP-only cookie</span></div>`)}${sectionPanel('Hosting integration',healthLabel,`<div class="inline-notice">${icon(connected?'checkCircle':'alert')} ${connected?'The worker health endpoint responded successfully. Builds and bot lifecycle actions use the real Docker worker.':'No worker health response was received. Set WORKER_URL and WORKER_TOKEN on the control plane, and run the worker privately before deploying.'}</div><div class="detail-kv"><span class="kv-label">Runtime</span><span class="kv-value">Python in Docker containers</span></div><div class="detail-kv"><span class="kv-label">Supported Python</span><span class="kv-value">3.10, 3.11, 3.12, 3.13</span></div><div class="detail-kv"><span class="kv-label">Resource policy</span><span class="kv-value">Operator-configurable worker resource settings; no per-account runtime quota is applied.</span></div><div class="detail-kv"><span class="kv-label">Worker URL</span><span class="kv-value">Configured server-side; never sent to the browser.</span></div>`)}${sectionPanel('Security basics','Keep the control plane and worker isolated',`<div class="activity-small">${icon('shield')}<div class="activity-small-copy"><strong>Encrypted secrets</strong><span class="activity-small-time">Environment values are encrypted at rest and redacted from logs.</span></div></div><div class="activity-small">${icon('lock')}<div class="activity-small-copy"><strong>Session and request protection</strong><span class="activity-small-time">HTTP-only SameSite cookies, CSRF tokens, authentication throttling, and password hashing.</span></div></div><div class="activity-small">${icon('server')}<div class="activity-small-copy"><strong>Private worker network</strong><span class="activity-small-time">Only trusted control-plane traffic should reach the worker. Docker daemon access is host-privileged.</span></div></div>`)}</div>
    <div style="display:grid;gap:15px">${sectionPanel('Deployment checklist','Recommended before accepting workloads',`<div style="display:grid;gap:13px">${[['checkCircle','Set strong secrets','Generate unique session, encryption, and worker keys.'],['checkCircle','Use HTTPS','Terminate TLS and set TRUST_PROXY only behind a trusted reverse proxy.'],['checkCircle','Isolate the worker','Use a dedicated VM, restrictive network egress, and minimal credentials.'],['checkCircle','Monitor the host','Track disk, memory, CPU, Docker failures, backups, and worker reachability. Logs are not truncated by OrbitHost.']].map(([ic,t,c])=>`<div style="display:flex;gap:10px"><span style="color:var(--green)">${icon(ic)}</span><div><div style="font-size:11px;font-weight:650;color:#d9dff0">${t}</div><div style="font-size:10px;color:#8794ad;line-height:1.6;margin-top:3px">${c}</div></div></div>`).join('')}</div>`,`<button class="button button-primary" data-resource="docs">${icon('book')} Open setup guide</button>`)}${sectionPanel('Workspace session','Bot containers run independently of your browser session',`<div class="settings-note">Signing out ends this browser session. It does not stop deployed bot containers.</div>`,`<button class="button button-danger" data-action="logout">${icon('logOut')} Sign out</button>`)}</div></div>`;
}
function renderDetail() {
  const wrapper=state.activeProject; if(!wrapper?.project) return '<div class="empty-state">Loading project…</div>';
  const p=wrapper.project; const tab=state.activeTab; const detailHead=`<div class="page-heading" style="align-items:center"><div class="project-hero"><button class="back-link" data-nav="projects" title="Back to projects" aria-label="Back to projects">${icon('chevronLeft')}</button><div class="project-avatar">${icon(p.sourceType==='git'?'github':'file')}</div><div style="min-width:0"><div style="display:flex;align-items:center;gap:9px;flex-wrap:wrap"><h1 class="page-title">${esc(p.name)}</h1>${statusPill(p.status)}</div><p class="page-subtitle">Python ${p.pythonVersion} · Created ${prettyTime(p.createdAt)}</p></div></div><div class="hero-actions"><button class="button button-quiet button-sm" data-action="restart" ${(p.status==='deploying'||!p.lastDeployedAt||p.status==='failed')?'disabled':''}>${icon('rotate')} <span class="button-label">Restart</span></button>${p.status==='online'?`<button class="button button-quiet button-sm" data-action="stop">${icon('pause')} <span class="button-label">Stop</span></button>`:(p.status==='stopped'&&p.lastDeployedAt?`<button class="button button-quiet button-sm" data-action="start">${icon('play')} <span class="button-label">Start</span></button>`:'')}<button class="button button-primary button-sm" data-action="deploy" ${p.status==='deploying'?'disabled':''}>${icon('rocket')} <span class="button-label">Deploy</span></button></div></div>`;
  const tabs=[['overview','Overview','monitor'],['deployments','Deployments','rocket'],['logs','Logs','terminal'],['environment','Environment','key'],['settings','Settings','settings']];
  let body='';
  if(tab==='overview') body=renderDetailOverview(wrapper);
  else if(tab==='deployments') body=renderDeployments(wrapper.deployments||[]);
  else if(tab==='logs') body=renderLogs();
  else if(tab==='environment') body=renderEnvironment(wrapper.environment||[]);
  else if(tab==='settings') body=renderProjectSettings(p);
  return `${detailHead}<div class="project-tabs" role="tablist" aria-label="Project sections">${tabs.map(([id,label,ic])=>`<button role="tab" id="tab-${id}" aria-controls="project-tab-panel" tabindex="${tab===id?0:-1}" aria-selected="${tab===id}" class="project-tab ${tab===id?'active':''}" data-project-tab="${id}">${icon(ic)} ${label}</button>`).join('')}</div><div class="detail-tab-content" id="project-tab-panel" role="tabpanel" aria-labelledby="tab-${tab}" tabindex="0">${body}</div>`;
}
function renderDetailOverview(wrapper) {
  const p=wrapper.project, m=state.metrics||{status:p.status,cpuPercent:null,memoryMb:null,memoryLimitMb:null,uptime:null,mode:'unavailable'};
  const deployment=wrapper.latestDeployment;
  const hasMetrics=m.mode==='container'||m.mode==='process';
  const memPct=m.memoryLimitMb>0&&m.memoryMb!=null?Math.min(100,Math.round(m.memoryMb/m.memoryLimitMb*100)):null;
  const cpuPct=m.cpuPercent==null?null:Math.min(100,Math.max(0,Math.round(Number(m.cpuPercent)||0)));
  const online=m.status==='online';
  const memoryDisplay=m.memoryMb==null?'—':`${m.memoryMb}<span style="font-size:10px;color:#8692ad;font-weight:600"> MB</span>`;
  const memoryFoot=m.memoryLimitMb>0?`of ${m.memoryLimitMb} MB ${m.mode==='process'?'system memory':'container limit'}`:'No memory limit configured';
  const runtimeHtml=`<div class="inner-stat-grid"><div class="inner-stat"><div class="inner-stat-label">${icon('cpu')} CPU usage</div><div class="inner-stat-value" id="cpu-metric">${m.cpuPercent==null?'—':`${m.cpuPercent}%`}</div><div class="inner-stat-foot">${m.mode==='process'?'Measured from the bot process':'Measured from Docker'}</div></div><div class="inner-stat"><div class="inner-stat-label">${icon('memory')} Memory</div><div class="inner-stat-value" id="mem-metric">${memoryDisplay}</div><div class="inner-stat-foot" id="mem-foot">${memoryFoot}</div></div><div class="inner-stat"><div class="inner-stat-label">${icon('clock')} Uptime</div><div class="inner-stat-value" id="uptime-metric">${m.uptime==null?'—':formatUptime(m.uptime)}</div><div class="inner-stat-foot">${m.mode==='process'?'Since the process started':'Since actual container start'}</div></div></div><div class="usage-block"><div class="usage-heading"><span>Memory utilization</span><strong id="mem-percent">${memPct==null?'—':`${memPct}%`}</strong></div><div class="progress-track"><div class="progress-fill ${memPct!=null&&memPct<=85?'green':''}" id="mem-progress" style="width:${memPct||0}%"></div></div></div><div class="usage-block"><div class="usage-heading"><span>CPU utilization</span><strong id="cpu-percent">${cpuPct==null?'—':`${m.cpuPercent}% of worker CPU`}</strong></div><div class="progress-track"><div class="progress-fill" id="cpu-progress" style="width:${cpuPct||0}%"></div></div></div><div class="inline-notice" style="margin:17px 0 0">${icon(hasMetrics?'info':'alert')} ${m.mode==='process'?'Metrics are measured directly from the running bot process.':hasMetrics?'Metrics are read from the actual Docker container. Resource settings are configured on the worker.':'Worker metrics are unavailable. Reconnect the worker to view measured runtime data.'}</div>`;
  const configHtml=`<div class="detail-kv"><span class="kv-label">Source</span><span class="kv-value">${p.sourceType==='git'?'<span class="code-chip">Git repository</span>':'<span class="code-chip">ZIP upload</span>'}</span></div><div class="detail-kv"><span class="kv-label">Python</span><span class="kv-value">Python ${esc(p.pythonVersion)}</span></div><div class="detail-kv"><span class="kv-label">Build command</span><span class="kv-value"><code class="code-chip">${esc(p.buildCommand||'Automatic dependency install')}</code></span></div><div class="detail-kv"><span class="kv-label">Start command</span><span class="kv-value"><code class="code-chip">${esc(p.startCommand)}</code></span></div><div class="detail-kv"><span class="kv-label">Environment</span><span class="kv-value">${p.environmentCount} secret variable${p.environmentCount===1?'':'s'} configured</span></div><div class="detail-kv"><span class="kv-label">Last deploy</span><span class="kv-value">${p.lastDeployedAt?prettyTime(p.lastDeployedAt):'Never'}</span></div>`;
  return `<div class="project-overview-grid"><div style="display:grid;gap:15px">${sectionPanel('Resource usage',online?'Current live container performance':'No running container',runtimeHtml,`<button class="plain-link" data-action="refresh-metrics">${icon('refresh')} Refresh</button>`)}${sectionPanel('Latest deployment',deployment?`Deployment #${deployment.sequence} · ${prettyTime(deployment.createdAt)}`:'No deployment recorded',deployment?`<div class="detail-kv"><span class="kv-label">Status</span><span class="kv-value">${statusPill(deployment.status)}</span></div><div class="detail-kv"><span class="kv-label">Summary</span><span class="kv-value">${esc(deployment.summary)}</span></div><div class="detail-kv"><span class="kv-label">Duration</span><span class="kv-value">${duration(deployment.durationMs)}</span></div><div style="margin-top:14px"><button class="button button-quiet button-sm" data-project-tab="deployments">View deployment history ${icon('chevronRight')}</button></div>`:`<div class="empty-state" style="padding:23px">Deploy this project to create the first deployment record.</div>`)}</div><div style="display:grid;gap:15px">${sectionPanel('Configuration','Active runtime settings',configHtml,`<button class="plain-link" data-project-tab="settings">Edit settings ${icon('chevronRight')}</button>`)}${sectionPanel('Project activity','Recent project events',`<div class="activity-small">${icon('rocket')}<div class="activity-small-copy">${deployment?esc(deployment.summary):'Project created'}<span class="activity-small-time">${prettyTime(deployment?.createdAt||p.createdAt)}</span></div></div><div class="activity-small">${icon('key')}<div class="activity-small-copy">${p.environmentCount} environment variable${p.environmentCount===1?'':'s'} currently configured<span class="activity-small-time">Secret values are masked by design.</span></div></div><div class="activity-small">${icon('terminal')}<div class="activity-small-copy">Actual container stdout/stderr<span class="activity-small-time">The Logs tab streams the running process in real time.</span></div></div>`,`<button class="plain-link" data-project-tab="logs">Open logs ${icon('chevronRight')}</button>`)}</div></div>`;
}
function formatUptime(total) { total=Math.max(0,Number(total)||0);const d=Math.floor(total/86400),h=Math.floor((total%86400)/3600),m=Math.floor((total%3600)/60);if(d)return `${d}d ${h}h`;if(h)return `${h}h ${m}m`;return `${m}m`; }
function renderDeployments(deployments) {
  const rows=deployments.length?`<div class="table-wrap"><table class="data-table"><thead><tr><th>Deployment</th><th>Status</th><th>Trigger</th><th>Duration</th><th>Created</th></tr></thead><tbody>${deployments.map(d=>`<tr><td data-label="Deployment"><strong>#${d.sequence}</strong><div class="muted-cell deployment-summary">${esc(d.summary)}</div></td><td data-label="Status">${statusPill(d.status)}</td><td data-label="Trigger">${esc(d.trigger)}</td><td data-label="Duration">${duration(d.durationMs)}</td><td data-label="Created" class="muted-cell">${prettyTime(d.createdAt)}</td></tr>`).join('')}</tbody></table></div>`:`<div class="empty-state"><div class="empty-art">${icon('rocket')}</div><div class="empty-title">No deployments yet</div><div class="empty-copy">Your first build and deployment record will appear here.</div><button class="button button-primary" data-action="deploy">${icon('rocket')} Deploy project</button></div>`;
  return sectionPanel('Deployment history',`${deployments.length} recent deployments`,`<div class="inline-notice">${icon('info')} Build history records when a deploy was requested, its result, and its duration. Open Logs to inspect detailed output.</div>${rows}`,`<button class="button button-primary button-sm" data-action="deploy">${icon('rocket')} Deploy</button>`);
}
function renderLogLine(line) {
  return `<div class="log-line"><span class="log-time">${esc(line.createdAt?new Date(line.createdAt).toLocaleTimeString(undefined,{hour12:false}):'--:--:--')}</span><span><span class="log-level-${esc(line.level||'info')}">[${esc((line.level||'info').toUpperCase())}]</span> ${esc(line.message)}</span></div>`;
}
function filteredLogs() {
  const query=state.logSearch.trim().toLowerCase();
  return query?state.logs.filter(line=>String(line.message||'').toLowerCase().includes(query)||String(line.level||'').toLowerCase().includes(query)):state.logs;
}
function renderLogOutput() {
  const output=$('#log-output');if(!output)return;
  const entries=filteredLogs();
  output.innerHTML=entries.length?entries.map(renderLogLine).join(''):`<div class="log-empty">${state.logSearch?'No log lines match that search.':'No log output yet. Deploy your project or wait for process output.'}</div>`;
  const count=output.parentElement?.querySelector('.log-toolbar span');if(count)count.textContent=`${entries.length} visible lines · ${state.logs.length} received`;
  output.scrollTop=output.scrollHeight;
}
function appendLiveLog(line) {
  const output=$('#log-output');if(!output)return;
  const query=state.logSearch.trim().toLowerCase();
  const matches=!query||String(line.message||'').toLowerCase().includes(query)||String(line.level||'').toLowerCase().includes(query);
  if(matches){
    const atBottom=output.scrollHeight-output.scrollTop-output.clientHeight<28;
    output.querySelector('.log-empty')?.remove();
    output.insertAdjacentHTML('beforeend',renderLogLine(line));
    if(atBottom)output.scrollTop=output.scrollHeight;
  }
  const count=output.parentElement?.querySelector('.log-toolbar span');
  if(count)count.textContent=`${output.querySelectorAll('.log-line').length} visible lines · ${state.logs.length} received`;
}
function renderLogs() {
  const entries=filteredLogs();
  const content=entries.length?entries.map(renderLogLine).join(''):`<div class="log-empty">${state.logSearch?'No log lines match that search.':'No log output yet. Deploy your project or wait for process output.'}</div>`;
  return `<section class="panel"><div class="panel-head"><div><h2 class="panel-title">Build & runtime logs</h2><div class="panel-note">Live process output from the worker. Secret values are redacted; log history is not truncated by OrbitHost.</div></div><button class="button button-quiet button-sm" data-action="refresh-logs">${icon('refresh')} Reload history</button></div><div class="log-toolbar"><label class="visually-hidden" for="log-stream">Log stream</label><select class="select" id="log-stream"><option value="runtime" ${state.logStream==='runtime'?'selected':''}>Runtime logs</option><option value="build" ${state.logStream==='build'?'selected':''}>Build logs</option></select><label class="search-field">${icon('search')}<input id="log-search" type="search" value="${esc(state.logSearch)}" placeholder="Search received log output…" aria-label="Search log output"></label><span style="font-size:10px;color:#7e8ba6;white-space:nowrap">${entries.length} visible · ${state.logs.length} received</span></div><div class="log-output" id="log-output" role="region" aria-label="${state.logStream==='runtime'?'Runtime':'Build'} log output" aria-live="off">${content}</div><div class="log-footer"><span id="log-connection-state" role="status" aria-live="polite">Live stream starts when connected to the worker.</span><button class="plain-link" data-action="copy-logs">${icon('clipboard')} Copy visible logs</button></div></section>`;
}
function renderEnvironment(vars) {
  const rows=vars.length?`<div class="environment-list">${vars.map(v=>`<div class="env-row"><div class="env-key-icon">${icon('key')}</div><div class="env-copy"><div class="env-key">${esc(v.key)}</div><div class="env-hint">Updated ${prettyTime(v.updatedAt)} · encrypted at rest</div></div><div class="env-mask" aria-label="Secret value is hidden">••••••••</div><div class="env-actions"><button class="icon-button" data-edit-env="${esc(v.key)}" title="Rotate secret" aria-label="Rotate ${esc(v.key)}">${icon('edit')}</button><button class="icon-button" data-delete-env="${esc(v.key)}" title="Delete secret" aria-label="Delete ${esc(v.key)}">${icon('trash')}</button></div></div>`).join('')}</div>`:`<div class="empty-state"><div class="empty-art">${icon('key')}</div><div class="empty-title">No environment variables</div><div class="empty-copy">Store Discord bot tokens and API keys as encrypted secrets instead of committing them to your source code.</div><button class="button button-primary" data-action="add-env">${icon('plus')} Add variable</button></div>`;
  return `<div class="environment-grid"><div style="display:grid;gap:15px">${sectionPanel('Environment variables',`${vars.length} secret variable${vars.length===1?'':'s'}`,rows,`<button class="button button-primary button-sm" data-action="add-env">${icon('plus')} Add variable</button>`)}</div><div style="display:grid;gap:15px">${sectionPanel('Secret handling','Keep credentials out of your code',`<div class="activity-small">${icon('lock')}<div class="activity-small-copy"><strong>Encrypted at rest</strong><span class="activity-small-time">Values are encrypted using AES-256-GCM on the server before they are stored.</span></div></div><div class="activity-small">${icon('eye')}<div class="activity-small-copy"><strong>Never revealed in the UI</strong><span class="activity-small-time">The API returns variable names and masked state only, never stored values.</span></div></div><div class="activity-small">${icon('terminal')}<div class="activity-small-copy"><strong>Log redaction</strong><span class="activity-small-time">Known secret values are masked before logs are returned; avoid printing credentials.</span></div></div>`)}${sectionPanel('Discord bot setup','Common variable names',`<div class="detail-kv"><span class="kv-label"><code class="code-chip">DISCORD_TOKEN</code></span><span class="kv-value">Bot token from Discord Developer Portal</span></div><div class="detail-kv"><span class="kv-label"><code class="code-chip">PREFIX</code></span><span class="kv-value">Optional command prefix</span></div><div class="field-hint" style="margin-top:12px">Use the exact variable names expected by your bot code. Rotate leaked tokens in the provider portal; deleting one here does not revoke it.</div>`)}</div></div>`;
}
function renderProjectSettings(p) {
  const versionOptions=(state.config.pythonVersions||['3.10','3.11','3.12','3.13']).map(v=>`<option value="${v}" ${v===p.pythonVersion?'selected':''}>Python ${v}</option>`).join('');
  return `<div class="settings-grid"><div style="display:grid;gap:15px">${sectionPanel('Build & runtime','Change how this project is prepared and started',`<form data-form="project-settings" id="project-settings-form"><div class="field"><label class="field-label" for="setting-name">Project name</label><input class="field-input" id="setting-name" name="name" maxlength="60" value="${esc(p.name)}" required><div class="field-hint">Shown in your workspace and deployment history.</div></div><div class="field"><label class="field-label" for="setting-python">Python version</label><select class="select" style="width:100%" id="setting-python" name="pythonVersion">${versionOptions}</select><div class="field-hint">The worker builds against an official Python slim image.</div></div><div class="field"><label class="field-label" for="setting-build">Build command <span style="font-weight:400;color:#7e8ba7">(optional)</span></label><input class="field-input" id="setting-build" name="buildCommand" maxlength="500" value="${esc(p.buildCommand)}" placeholder="e.g. python -m compileall ."><div class="field-hint">The worker automatically installs requirements.txt first when present. Custom build commands run as an unprivileged user inside the image build.</div></div><div class="field"><label class="field-label" for="setting-start">Start command</label><input class="field-input" id="setting-start" name="startCommand" maxlength="500" value="${esc(p.startCommand)}" required><div class="field-hint">Examples: <code class="code-chip">python main.py</code> or <code class="code-chip">python bot.py</code>.</div></div><div class="form-actions"><button class="button button-primary" type="submit">Save settings</button></div></form>`)}${sectionPanel('Source connection','Current source type',`<div class="detail-kv"><span class="kv-label">Provider</span><span class="kv-value">${p.sourceType==='git'?'Git over HTTPS':'ZIP archive'}</span></div>${p.repositoryUrl?`<div class="detail-kv"><span class="kv-label">Repository</span><span class="kv-value">${esc(p.repositoryUrl)}</span></div>`:''}<div class="field-hint" style="margin-top:11px">This starter supports public HTTPS repositories. Private-repository credentials should be added through a dedicated deploy-key or Git-provider integration, not embedded in the URL.</div>`)}</div><div style="display:grid;gap:15px">${sectionPanel('Danger zone','Actions are permanent',`<div class="danger-zone"><h3>Delete this project</h3><p>Remove project metadata, deployment history, environment variables, and uploaded source archive. If live worker mode is enabled, the associated container and image are removed too.</p><button class="button button-danger" data-action="delete-project">${icon('trash')} Delete project</button></div>`)}${sectionPanel('Runtime mode','Current execution behavior',`<div class="inline-notice">${icon('info')} This project uses worker-backed container execution. Actions are sent to the real worker.</div><div class="settings-note"><strong>Plan and infrastructure affect uptime.</strong> This application does not provide a hosting SLA by itself. Configure monitoring, persistence, and recovery on the worker infrastructure.</div>`)}</div></div>`;
}
function renderRegisterWizard() {
  const step=state.registerStep||1;
  const rd=state.registerData||{};
  const back=step>1?'<button type="button" class="button button-quiet" data-action="register-back">Back</button>':'';
  let fields='';
  if(step===1){
    fields='<div class="field"><label class="field-label" for="auth-email">Gmail address</label><input class="field-input" id="auth-email" name="email" type="email" autocomplete="email" placeholder="you@gmail.com" maxlength="254" value="'+esc(rd.email||'')+'" required><div class="field-hint">Must be a Gmail address ending in @gmail.com.</div></div>';
  }else if(step===2){
    fields='<div class="field"><label class="field-label" for="auth-username">Username</label><input class="field-input" id="auth-username" name="username" autocomplete="username" placeholder="e.g. zen.dev" maxlength="20" value="'+esc(rd.username||'')+'" required><div class="field-hint">3 to 20 characters. Letters, numbers, and dots only: no spaces, and no dot at the start or end.</div></div>';
  }else{
    fields='<div class="field"><label class="field-label" for="auth-password">Password</label><input class="field-input" id="auth-password" name="password" type="password" autocomplete="new-password" placeholder="At least 10 characters" minlength="10" maxlength="128" required><div class="field-hint">At least 10 characters, including at least one letter and one number. A password manager is recommended.</div></div>';
  }
  const submitLabel=step===1?'Continue':step===2?'Continue':'Create account';
  return '<form class="auth-form" data-form="auth"><div class="field-hint" style="margin-bottom:10px">Step '+step+' of 3: '+(step===1?'Gmail address':step===2?'Username':'Password')+'</div>'+fields+'<div class="form-actions" style="display:flex;gap:10px;justify-content:flex-end;margin-top:6px">'+back+'<button class="button button-primary auth-submit" type="submit">'+submitLabel+' '+icon('chevronRight')+'</button></div></form>';
}
function renderAuth() {
  const registering=state.authMode==='register';
  return `<div class="auth-screen"><section class="auth-showcase"><div class="auth-brand"><div class="brand-mark"><svg viewBox="0 0 40 40" aria-hidden="true"><circle cx="20" cy="20" r="13"/><ellipse cx="20" cy="20" rx="18" ry="7" transform="rotate(-35 20 20)"/><circle class="mark-dot" cx="31" cy="10" r="2.5"/></svg></div><div><div class="brand-name">OrbitHost</div><div class="brand-tagline">Bot infrastructure</div></div></div><div class="auth-copy"><div class="eyebrow">A home for your Discord bots</div><h1>Less server babysitting.<br><span>More building.</span></h1><p>Keep your bot projects, secrets, deployment history, and runtime logs in one calm, focused workspace.</p><div class="auth-feature-list"><div class="auth-feature"><span class="feature-icon">${icon('rocket')}</span>Deploy from a ZIP or Git repository</div><div class="auth-feature"><span class="feature-icon">${icon('lock')}</span>Encrypted environment variables</div><div class="auth-feature"><span class="feature-icon">${icon('terminal')}</span>Searchable logs and deployment history</div></div></div><div class="auth-foot">OrbitHost · Built for developers who ship bots.</div></section><section class="auth-form-side"><div class="auth-form-wrap"><div class="auth-mobile-brand"><div class="brand-mark"><svg viewBox="0 0 40 40" aria-hidden="true"><circle cx="20" cy="20" r="13"/><ellipse cx="20" cy="20" rx="18" ry="7" transform="rotate(-35 20 20)"/><circle class="mark-dot" cx="31" cy="10" r="2.5"/></svg></div><div><div class="brand-name">OrbitHost</div><div class="brand-tagline">Bot infrastructure</div></div></div><div class="auth-form-heading"><div class="eyebrow">Your workspace awaits</div><h2>${registering?'Create your account':'Welcome back'}</h2><p>${registering?'Start organizing and deploying your Discord bot projects.':'Sign in to continue to your bot workspace.'}</p></div><div id="auth-alert" class="auth-alert" role="alert"></div>${registering?renderRegisterWizard():`<form class="auth-form" data-form="auth"><div class="field"><label class="field-label" for="auth-email">Email address</label><input class="field-input" id="auth-email" name="email" type="email" autocomplete="email" placeholder="you@example.com" maxlength="254" required></div><div class="field"><label class="field-label" for="auth-password">Password</label><input class="field-input" id="auth-password" name="password" type="password" autocomplete="current-password" placeholder="Enter your password" maxlength="128" required></div><button class="button button-primary auth-submit" type="submit">Sign in ${icon('chevronRight')}</button></form>`}<div class="auth-switch">${registering?'Already have an account?':'New to OrbitHost?'} <button type="button" data-auth-mode="${registering?'login':'register'}">${registering?'Sign in':'Create an account'}</button></div><div class="auth-footnote">By continuing, you agree to use this platform responsibly. Real bot uptime depends on your configured hosting infrastructure.</div></div></section>${state.verify?renderVerifyOverlay():''}</div>`;
}
function renderModal() {
  const m=state.modal;if(!m)return '';
  if(m.type==='new-project') {
    return `<div class="modal-backdrop" data-dismiss="modal"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><div class="modal-header"><div><div class="modal-title" id="modal-title">Create a project</div><div class="modal-subtitle">Bring your bot source into OrbitHost and configure its runtime.</div></div><button class="icon-button" data-action="close-modal" aria-label="Close dialog">${icon('x')}</button></div><form data-form="create-project" id="create-project-form"><div class="modal-body"><div class="field"><label class="field-label" for="new-project-name">Project name</label><input id="new-project-name" class="field-input" name="name" maxlength="60" placeholder="my-discord-bot" pattern="[A-Za-z0-9][A-Za-z0-9 ._-]{0,59}" required><div class="field-hint">Use letters, numbers, spaces, dots, underscores, and hyphens.</div></div><div class="field" style="margin-top:17px"><span class="field-label">Choose your source</span><div class="source-choice"><label class="source-option selected"><input type="radio" name="sourceType" value="zip" checked><span><strong>${icon('upload')} Upload a ZIP</strong><span>Upload your bot's source archive.</span></span></label><label class="source-option"><input type="radio" name="sourceType" value="git"><span><strong>${icon('github')} Git repository</strong><span>Connect a public HTTPS URL.</span></span></label></div></div><div id="upload-source"><div class="upload-zone">${icon('upload')}<p><strong>Choose your source archive</strong></p><p>ZIP only · max ${state.config.maxUploadMb} MB · no unsafe paths or symbolic links</p><input type="file" name="bundle" id="source-bundle" accept=".zip,application/zip"></div><div class="field-hint">Include main.py or your chosen entry file. requirements.txt is installed automatically by the worker.</div></div><div id="git-source" hidden><div class="field"><label class="field-label" for="repo-url">Repository HTTPS URL</label><input class="field-input" name="repositoryUrl" id="repo-url" type="url" placeholder="https://github.com/you/your-bot.git"><div class="field-hint">Public repositories only in this starter. Do not put access tokens in the URL.</div></div></div><div class="field" style="margin-top:18px"><label class="field-label" for="new-python">Python version</label><select class="select" style="width:100%" id="new-python" name="pythonVersion">${(state.config.pythonVersions||['3.10','3.11','3.12','3.13']).map(v=>`<option value="${v}" ${v==='3.12'?'selected':''}>Python ${v}</option>`).join('')}</select></div><div class="field"><label class="field-label" for="new-build">Build command <span style="color:#8190aa;font-weight:400">(optional)</span></label><input class="field-input" name="buildCommand" id="new-build" maxlength="500" placeholder="e.g. python -m compileall ."><div class="field-hint">The worker installs requirements.txt automatically before this command.</div></div><div class="field"><label class="field-label" for="new-start">Start command</label><input class="field-input" name="startCommand" id="new-start" value="python main.py" maxlength="500" required></div><label class="check-row"><input type="checkbox" name="source-confirm" required><span>I trust this project source and its dependencies. I understand that deployment executes code in an isolated worker container.</span></label><div class="modal-footer"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary" id="create-project-submit">${icon('plus')} Create project</button></div></div></form></section></div>`;
  }
  if(m.type==='env') {
    return `<div class="modal-backdrop" data-dismiss="modal"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><div class="modal-header"><div><div class="modal-title" id="modal-title">${m.key?'Rotate secret':'Add environment variable'}</div><div class="modal-subtitle">Variable values are encrypted on the server and will not be revealed again in the UI.</div></div><button class="icon-button" data-action="close-modal" aria-label="Close dialog">${icon('x')}</button></div><form data-form="save-env"><div class="modal-body"><div class="field"><label class="field-label" for="env-key">Variable name</label><input class="field-input" id="env-key" name="key" maxlength="128" pattern="[A-Za-z_][A-Za-z0-9_]*" placeholder="DISCORD_TOKEN" value="${esc(m.key||'')}" ${m.key?'readonly':''} required><div class="field-hint">Letters, numbers, and underscores; the first character cannot be a number.</div></div><div class="field"><label class="field-label" for="env-value">${m.key?'New value':'Value'}</label><input class="field-input" id="env-value" name="value" type="password" maxlength="8192" autocomplete="new-password" placeholder="${m.key?'Enter a new value to rotate this secret':'Paste the secret value'}" required><div class="field-hint">Line breaks are not supported. Existing secret values cannot be recovered from the dashboard.</div></div><div class="modal-footer"><button type="button" class="button button-quiet" data-action="close-modal">Cancel</button><button type="submit" class="button button-primary">${icon('lock')} Save encrypted secret</button></div></div></form></section></div>`;
  }
  if(m.type==='confirm-delete-project'||m.type==='confirm-delete-env') {
    const project=m.type==='confirm-delete-project';
    return `<div class="modal-backdrop" data-dismiss="modal"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><div class="modal-header"><div><div class="modal-title" id="modal-title">${project?'Delete this project?':'Remove this environment variable?'}</div><div class="modal-subtitle">This action cannot be undone.</div></div><button class="icon-button" data-action="close-modal" aria-label="Close dialog">${icon('x')}</button></div><div class="modal-body"><div class="confirm-copy">${project?`This permanently deletes <strong>${esc(state.activeProject?.project?.name)}</strong>, its source archive, deployment history, and environment variables. In worker mode, its container and image will also be removed.`:`The variable <code class="code-chip">${esc(m.key)}</code> will be removed from this project. This does not revoke the secret at its provider.`}</div><div class="modal-footer"><button class="button button-quiet" data-action="close-modal">Keep ${project?'project':'variable'}</button><button class="button button-danger" data-action="confirm-delete">${icon('trash')} Delete permanently</button></div></div></section></div>`;
  }
  if(m.type==='docs') {
    return `<div class="modal-backdrop" data-dismiss="modal"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><div class="modal-header"><div><div class="modal-title" id="modal-title">Quick setup guide</div><div class="modal-subtitle">Configure real containers and stream process output.</div></div><button class="icon-button" data-action="close-modal" aria-label="Close dialog">${icon('x')}</button></div><div class="modal-body"><div style="display:grid;gap:16px">${[['1','Create your project','Upload a ZIP or connect a public HTTPS Git URL. Include your bot entry file and requirements.txt.'],['2','Configure your runtime','Choose Python 3.10–3.13, set your start command, and add secrets such as DISCORD_TOKEN under Environment.'],['3','Deploy the source','Deploy runs the real build, installs requirements.txt, and starts your process in its container.'],['4','Inspect live logs','Runtime logs come directly from the container stdout/stderr stream, including bot.py output.'],['5','Monitor the workload','Inspect measured resources, deployment history, worker health, and host storage. Uptime depends on your plan and infrastructure.']].map(([n,t,c])=>`<div style="display:flex;gap:12px"><div class="activity-icon" style="width:30px;height:30px;font-size:11px;font-weight:750">${n}</div><div><div style="font-size:12px;font-weight:700">${t}</div><div style="font-size:10px;color:#8f9bb5;line-height:1.7;margin-top:5px">${c}</div></div></div>`).join('')}</div><div class="modal-footer"><button class="button button-primary" data-action="close-modal">Got it</button></div></div></section></div>`;
  }
  return '';
}
function renderVerifyOverlay(){
  const v=state.verify;if(!v)return '';
  return `<div class="verify-backdrop" data-dismiss="verify" role="presentation"><section class="verify-card" role="dialog" aria-modal="true" aria-labelledby="verify-title">
  <button class="icon-button verify-close" data-action="verify-close" aria-label="Close dialog">${icon('x')}</button>
  <div class="verify-kicker">Almost there</div>
  <div class="verify-title" id="verify-title">Check your email</div>
  <p class="verify-sub">We sent a 6-digit code to <strong>${esc(v.email)}</strong>. Enter it below to finish${v.from==='login'?' signing in':' creating your account'}.</p>
  <form id="verify-form" data-form="verify">
    <input id="verify-code" class="verify-input" name="code" data-verify-input inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="\u00b7\u00b7\u00b7\u00b7\u00b7\u00b7" value="${esc(v.code||'')}" ${v.busy?'disabled':''}>
    <div class="verify-actions">
      <button type="submit" class="button button-primary" ${v.busy?'disabled':''}>${v.busy?'Verifying\u2026':'Verify email'}</button>
      <button type="button" class="button button-quiet" data-action="verify-resend" ${Date.now()<(v.resendAt||0)?'disabled':''}>Resend code</button>
    </div>
  </form>
  ${v.error?`<div class="verify-error" role="alert">${esc(v.error)}</div>`:''}
  ${v.ok?`<div class="verify-ok">${esc(v.ok)}</div>`:''}
  <button type="button" class="verify-link" data-action="verify-back">Wrong address? Go back</button>
  <div class="verify-note">The code expires in 10 minutes. Can't find it? Check your spam folder.</div>
  </section></div>`;
}
let verifyTicker=null;
function startVerifyTicker(){
  if(verifyTicker)clearInterval(verifyTicker);
  verifyTicker=setInterval(()=>{
    const btn=document.querySelector('[data-action="verify-resend"]');
    if(!btn){clearInterval(verifyTicker);verifyTicker=null;return;}
    if(!state.verify)return;
    const left=Math.max(0,Math.ceil(((state.verify.resendAt||0)-Date.now())/1000));
    if(btn.disabled!==(left>0))btn.disabled=left>0;
    btn.textContent=left>0?`Resend code in ${left}s`:'Resend code';
  },1000);
}
function render() {
  const app=$('#app');if(!app)return;
  // Preserve focus for stable inputs after a data refresh; state-driven search itself stays DOM-local.
  const focusedId=document.activeElement?.id;
  const selectionStart=typeof document.activeElement?.selectionStart==='number'?document.activeElement.selectionStart:null;
  const selectionEnd=typeof document.activeElement?.selectionEnd==='number'?document.activeElement.selectionEnd:null;
  if(!state.user) { stopLiveLogs(); app.innerHTML=renderAuth(); }
  else {
    let content='';
    if(state.activePage==='overview')content=renderOverview();
    else if(state.activePage==='projects')content=renderProjects();
    else if(state.activePage==='activity')content=renderActivity();
    else if(state.activePage==='settings')content=renderSettings();
    else if(state.activePage==='project')content=renderDetail();
    else content=renderOverview();
    app.innerHTML=shell(content);
  }
  if(focusedId) {
    const replacement=document.getElementById(focusedId);
    if(replacement) {
      replacement.focus({preventScroll:true});
      if(selectionStart!==null && typeof replacement.setSelectionRange==='function') {
        try { replacement.setSelectionRange(selectionStart,selectionEnd); } catch {}
      }
    }
  }
  if(state.user&&state.activePage==='project'&&state.activeTab==='logs') void connectLiveLogs();
  else stopLiveLogs();
}
function logEntryKey(line) { return line.id || `${line.stream||state.logStream}\0${line.createdAt||''}\0${line.message||''}`; }
function stopLiveLogs() {
  if(state.logReconnectTimer){clearTimeout(state.logReconnectTimer);state.logReconnectTimer=null;}
  if(state.logController){state.logController.abort();state.logController=null;}
  state.logStreamKey='';
}
function reportLogStreamError(message) {
  const status=$('#log-connection-state');if(status)status.textContent='Live stream disconnected; attempting to reconnect.';
  if(!state.logStreamErrorShown){showToast(message||'Live log stream disconnected.','error');state.logStreamErrorShown=true;}
}
async function connectLiveLogs() {
  const projectId=state.activeProject?.project?.id;
  if(!state.user||state.activePage!=='project'||state.activeTab!=='logs'||!projectId)return;
  const key=`${projectId}:${state.logStream}`;
  if(state.logController&&state.logStreamKey===key)return;
  stopLiveLogs();
  const controller=new AbortController();state.logController=controller;state.logStreamKey=key;
  const qs=new URLSearchParams({stream:state.logStream});
  if(state.logStream==='build'&&state.logCursor!==null&&state.logCursor!==undefined)qs.set('offset',String(state.logCursor));
  if(state.logStream==='runtime'&&state.logCursor)qs.set('since',String(state.logCursor));
  try {
    const response=await fetch(`/api/projects/${encodeURIComponent(projectId)}/logs/stream?${qs}`,{credentials:'same-origin',headers:{accept:'text/event-stream'},signal:controller.signal});
    if(!response.ok){const data=await response.json().catch(()=>({}));throw new Error(data.error||`Log stream request failed (${response.status}).`);}
    const status=$('#log-connection-state');if(status)status.textContent='Connected · receiving real container output';
    state.logStreamErrorShown=false;
    if(!response.body)throw new Error('This browser does not support streaming log output.');
    const reader=response.body.getReader();const decoder=new TextDecoder();let buffer='';
    while(!controller.signal.aborted){
      const {value,done}=await reader.read();if(done)break;
      buffer+=decoder.decode(value,{stream:true}).replace(/\r/g,'');
      let boundary;
      while((boundary=buffer.indexOf('\n\n'))>=0){
        const block=buffer.slice(0,boundary);buffer=buffer.slice(boundary+2);
        let eventName='message';const dataLines=[];
        for(const line of block.split('\n')){if(line.startsWith('event:'))eventName=line.slice(6).trim();else if(line.startsWith('data:'))dataLines.push(line.slice(5).trimStart());}
        if(!dataLines.length)continue;
        let payload;try{payload=JSON.parse(dataLines.join('\n'))}catch{continue;}
        if(eventName==='log'){
          const entry=payload;const entryKey=logEntryKey(entry);
          if(!state.logSeen.has(entryKey)){state.logSeen.add(entryKey);state.logs.push(entry);appendLiveLog(entry);}if(entry.cursor!==undefined&&entry.stream==='build')state.logCursor=entry.cursor;if(entry.stream==='runtime'&&entry.createdAt)state.logCursor=entry.createdAt;
        }else if(eventName==='stream-error')reportLogStreamError(payload.error);
      }
    }
  } catch(error) {
    if(!controller.signal.aborted)reportLogStreamError(error.message);
  } finally {
    if(state.logController===controller)state.logController=null;
    if(state.logStreamKey===key)state.logStreamKey='';
    if(!controller.signal.aborted&&state.user&&state.activePage==='project'&&state.activeTab==='logs'&&state.activeProject?.project?.id===projectId){
      state.logReconnectTimer=setTimeout(()=>{state.logReconnectTimer=null;void connectLiveLogs();},4000);
    }
  }
}
async function refreshLogs() {
  if(!state.activeProject?.project?.id)return;
  try {
    const url=`/api/projects/${encodeURIComponent(state.activeProject.project.id)}/logs?stream=${encodeURIComponent(state.logStream)}`;
    const data=await api(url);
    state.logs=data.entries||[];state.logCursor=data.cursor??null;state.logSeen=new Set(state.logs.map(logEntryKey));
    renderLogOutput();
  }catch(e){showToast(e.message,'error')}
}
async function refreshMetrics() {
  if(!state.activeProject?.project?.id)return;
  try {
    const m=await api(`/api/projects/${encodeURIComponent(state.activeProject.project.id)}/metrics`);state.metrics=m;
    const p=state.activeProject.project;
    if(m.status&&p.status!=='deploying'&&p.status!==m.status){p.status=m.status;refreshDashboard().then(()=>render()).catch(()=>{});}
    const cpu=$('#cpu-metric'),mem=$('#mem-metric'),uptime=$('#uptime-metric'),memFoot=$('#mem-foot'),memPercent=$('#mem-percent'),memProgress=$('#mem-progress'),cpuPercent=$('#cpu-percent'),cpuProgress=$('#cpu-progress');
    if(cpu)cpu.textContent=m.cpuPercent==null?'—':`${m.cpuPercent}%`;
    if(mem)mem.innerHTML=m.memoryMb==null?'—':`${m.memoryMb}<span style="font-size:10px;color:#8692ad;font-weight:600"> MB</span>`;
    if(uptime)uptime.textContent=m.uptime==null?'—':formatUptime(m.uptime);
    if(memFoot)memFoot.textContent=m.memoryLimitMb>0?`of ${m.memoryLimitMb} MB container limit`:'No container memory limit configured';
    const mp=m.memoryLimitMb>0&&m.memoryMb!=null?Math.min(100,Math.round(m.memoryMb/m.memoryLimitMb*100)):null;
    const cp=m.cpuPercent==null?null:Math.min(100,Math.max(0,Math.round(Number(m.cpuPercent)||0)));
    if(memPercent)memPercent.textContent=mp==null?'—':`${mp}%`;
    if(memProgress){memProgress.style.width=`${mp||0}%`;memProgress.classList.toggle('green',mp!=null&&mp<=85)}
    if(cpuPercent)cpuPercent.textContent=cp==null?'—':`${m.cpuPercent}% of worker CPU`;
    if(cpuProgress)cpuProgress.style.width=`${cp||0}%`;
  }catch(e){
    state.metrics={status:'unknown',cpuPercent:null,memoryMb:null,memoryLimitMb:null,uptime:null,mode:'unavailable'};
    if(state.activeProject?.project)state.activeProject.project.status='unknown';
    const cpu=$('#cpu-metric'),mem=$('#mem-metric'),uptime=$('#uptime-metric');if(cpu)cpu.textContent='—';if(mem)mem.textContent='—';if(uptime)uptime.textContent='—';
    const status=$('.status-pill');if(status)status.textContent='Unknown';
    console.warn('Live worker metrics unavailable',e);
  }
}
function navigate(page) {
  state.activePage=page;state.mobileNavOpen=false;state.modal=null;
  if(page!=='project')state.activeProject=null;
  render();
}
async function switchProjectTab(tab, focusTab=false) {
  state.activeTab=tab;
  if(state.activeProject?.project?.id) {
    if(tab==='logs')await refreshLogs();
    if(tab==='overview')await refreshMetrics();
    await refreshProject().catch(()=>{});
  }
  render();
  const activeTab=$(`.project-tab[data-project-tab="${CSS.escape(tab)}"]`);
  activeTab?.scrollIntoView({inline:'center',block:'nearest',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'});
  if(focusTab)activeTab?.focus({preventScroll:true});
}
async function loadProjectAfterAction(message) {
  await refreshDashboard();await refreshProject();if(state.activeTab==='logs')await refreshLogs();if(state.activeTab==='overview')await refreshMetrics();render();if(message)showToast(message,'success');
}
async function handleClick(e) {
  const target=e.target.closest('button,[data-open-project],[data-edit-env],[data-delete-env],[data-project-tab],[data-dismiss],[data-resource],[data-auth-mode]');if(!target)return;
  if(target.matches('[data-dismiss="modal"]') && target===e.target){closeModal();return;}
  if(target.dataset.action==='verify-close'){if(state.verify){state.verify=null;render();}return;}
  if(target.dataset.action==='verify-back'){const backEmail=state.verify?state.verify.email:'';const fromLogin=state.verify?state.verify.from==='login':false;state.verify=null;if(fromLogin){state.authMode='login';}else{state.authMode='register';state.registerStep=1;state.registerData=backEmail?{email:backEmail}:{};}render();return;}
  if(target.dataset.action==='verify-resend'){
    if(!state.verify||state.verify.busy||Date.now()<(state.verify.resendAt||0))return;
    state.verify.busy=true;state.verify.error='';state.verify.ok='';render();
    try{await api('/api/auth/verify/resend',{method:'POST',body:{email:state.verify.email}});if(state.verify){state.verify.busy=false;state.verify.ok='New code sent. Check your inbox.';state.verify.code='';state.verify.resendAt=Date.now()+60000;render();startVerifyTicker();}}
    catch(err){if(state.verify){state.verify.busy=false;state.verify.error=err.message||'Could not resend the code.';render();}}
    return;
  }
  if(target.dataset.dismiss==='verify'&&!e.target.closest('.verify-card')){if(state.verify){state.verify=null;render();}return;}
  if(target.dataset.action==='register-back'){state.registerStep=Math.max(1,(state.registerStep||1)-1);render();return;}
  if(target.dataset.authMode){state.authMode=target.dataset.authMode;state.registerStep=1;state.registerData={};render();return;}
  if(target.dataset.nav){navigate(target.dataset.nav);return;}
  if(target.dataset.openProject){await openProject(target.dataset.openProject);return;}
  if(target.dataset.projectTab){await switchProjectTab(target.dataset.projectTab);return;}
  if(target.dataset.editEnv){openModal('env',{key:target.dataset.editEnv});return;}
  if(target.dataset.deleteEnv){openModal('confirm-delete-env',{key:target.dataset.deleteEnv});return;}
  if(target.dataset.resource==='worker'){navigate('settings');return;}
  if(target.dataset.resource==='docs'){openModal('docs');return;}
  const action=target.dataset.action;
  if(!action)return;
  if(action==='mobile-menu'){state.mobileNavOpen=!state.mobileNavOpen;render();if(state.mobileNavOpen)$('.nav-link.active')?.focus({preventScroll:true});else $('.mobile-menu')?.focus({preventScroll:true});return;}
  if(action==='close-mobile-menu'){state.mobileNavOpen=false;render();$('.mobile-menu')?.focus({preventScroll:true});return;}
  if(action==='collapse-sidebar'){if(innerWidth<=700){state.mobileNavOpen=!state.mobileNavOpen}else state.sidebarCollapsed=!state.sidebarCollapsed;render();return;}
  if(action==='new-project'){openModal('new-project');return;}
  if(action==='close-modal'){closeModal();return;}
  if(action==='add-env'){openModal('env');return;}
  if(action==='delete-project'){openModal('confirm-delete-project');return;}
  if(action==='confirm-delete'){await confirmDelete();return;}
  if(action==='refresh'){await refreshDashboard();render();showToast('Workspace refreshed.');return;}
  if(action==='refresh-metrics'){await refreshMetrics();await refreshProject();render();showToast('Resource metrics refreshed.');return;}
  if(action==='refresh-logs'){stopLiveLogs();await refreshLogs();render();showToast('Log history reloaded.');return;}
  if(action==='copy-logs'){const text=filteredLogs().map(x=>`[${x.level||'info'}] ${x.message}`).join('\n');try{await navigator.clipboard.writeText(text);showToast('Visible logs copied.')}catch{showToast('Clipboard access was blocked by the browser.','error')}return;}
  if(action==='logout'){await logout();return;}
  if(['deploy','start','stop','restart'].includes(action)){await projectAction(action,target);return;}
}
async function projectAction(action,button) {
  const id=state.activeProject?.project?.id;if(!id)return;
    setButtonBusy(button,action==='deploy'?'Deploying…':`${action[0].toUpperCase()+action.slice(1)}…`);
  try {
    let result;
    if(action==='deploy')result=await api(`/api/projects/${encodeURIComponent(id)}/deploy`,{method:'POST',body:{}});
    else result=await api(`/api/projects/${encodeURIComponent(id)}/action`,{method:'POST',body:{action}});
    await loadProjectAfterAction(result.message||`${action} completed.`);
  }catch(error){showToast(error.message,'error');await refreshProject().catch(()=>{});render();}finally{resetButton(button)}
}
async function confirmDelete() {
  const m=state.modal;if(!m)return;
  try {
    if(m.type==='confirm-delete-project') {
      const id=state.activeProject?.project?.id; if(!id)return;
      await api(`/api/projects/${encodeURIComponent(id)}`,{method:'DELETE'});
      state.modal=null;state.activeProject=null;state.activePage='projects';await refreshDashboard();render();showToast('Project deleted.','success');
    } else if(m.type==='confirm-delete-env') {
      const id=state.activeProject?.project?.id;if(!id)return;
      const key=m.key;await api(`/api/projects/${encodeURIComponent(id)}/env/${encodeURIComponent(key)}`,{method:'DELETE'});
      state.modal=null;await refreshProject();await refreshDashboard();render();showToast(`${key} removed.`);
    }
  }catch(error){showToast(error.message,'error')}
}
async function logout() {
  try{await api('/api/auth/logout',{method:'POST',body:{}})}catch{}
  stopLiveLogs();state.user=null;state.dashboard=null;state.activeProject=null;state.activePage='overview';state.csrf='';state.authMode='login';
  try{const t=await api('/api/auth/csrf');state.csrf=t.csrfToken}catch{}
  render();showToast('You have signed out.');
}
document.addEventListener('click',e=>{handleClick(e).catch(error=>showToast(error.message,'error'))});
document.addEventListener('change',e=>{
  if(e.target.matches('input[name="sourceType"]')){
    const git=e.target.value==='git';const upload=$('#upload-source'),repo=$('#git-source');if(upload)upload.hidden=git;if(repo)repo.hidden=!git;
    const zip=$('#source-bundle'),url=$('#repo-url');if(zip)zip.required=!git;if(url)url.required=git;
    $$('.source-option').forEach(option=>option.classList.toggle('selected',option.contains(e.target)));
  }
  if(e.target.id==='log-stream'){state.logStream=e.target.value;state.logSearch=$('#log-search')?.value||'';state.logs=[];state.logCursor=null;state.logSeen=new Set();stopLiveLogs();refreshLogs().then(()=>render());}
});
document.addEventListener('input',e=>{
  if(e.target.id==='global-search'){
    state.projectSearch=e.target.value;
    if(state.activePage==='projects'){$$('#projects-list .project-row').forEach(row=>row.hidden=!row.dataset.projectSearch.includes(state.projectSearch.toLowerCase()));const shown=$$('#projects-list .project-row').filter(x=>!x.hidden).length;const note=$('.panel-note');if(note)note.textContent=`${shown} shown`;}
    if(state.activePage==='overview'){$$('#home-project-list .project-row').forEach(row=>row.hidden=!row.dataset.projectSearch.includes(state.projectSearch.toLowerCase()));}
  }
  if(e.target.id==='project-page-search'){
    state.projectSearch=e.target.value;$$('#projects-list .project-row').forEach(row=>row.hidden=!row.dataset.projectSearch.includes(state.projectSearch.toLowerCase()));const note=$('.panel-note');if(note)note.textContent=`${$$('#projects-list .project-row').filter(x=>!x.hidden).length} shown`;
  }
  if(e.target.id==='log-search'){
    state.logSearch=e.target.value;renderLogOutput();
  }
});
document.addEventListener('submit',async e=>{
  const form=e.target.closest('form[data-form]');if(!form)return;e.preventDefault();
  const type=form.dataset.form;const submit=form.querySelector('button[type="submit"]');setButtonBusy(submit,type==='verify'?'Verifying…':type==='auth'?'Signing in…':type==='create-project'?'Creating project…':type==='save-env'?'Saving secret…':'Saving…');
  try {
    if(type==='verify') {
      if(!state.verify)return;
      const code=String(new FormData(form).get('code')||'').replace(/\D/g,'');
      if(code.length!==6){state.verify.busy=false;state.verify.error='Enter the 6-digit code from your email.';render();return;}
      state.verify.busy=true;state.verify.error='';state.verify.ok='';render();
      try{const result=await api('/api/auth/verify',{method:'POST',body:{email:state.verify.email,code}});state.user=result.user;state.csrf=result.csrfToken;state.verify=null;state.activePage='overview';state.activeProject=null;await refreshDashboard();render();showToast('Email verified. Welcome to OrbitHost.');}
      catch(err){if(state.verify){state.verify.busy=false;state.verify.error=err.message||'Verification failed.';render();}}
      return;
    }
    if(type==='auth') {
      const data=Object.fromEntries(new FormData(form).entries());
      if(state.authMode==='register') {
        state.registerData=state.registerData||{};
        if(state.registerStep===1) {
          state.registerData.email=String(data.email||'').trim();
          await api('/api/auth/register/check-email',{method:'POST',body:{email:state.registerData.email}});
          state.registerStep=2;render();return;
        }
        if(state.registerStep===2) {
          state.registerData.username=String(data.username||'').trim();
          await api('/api/auth/register/check-username',{method:'POST',body:{username:state.registerData.username}});
          state.registerStep=3;render();return;
        }
        const result=await api('/api/auth/register',{method:'POST',body:{email:state.registerData.email,username:state.registerData.username,password:data.password}});
        if(result.needsVerification){state.verify={email:result.email||state.registerData.email,from:'register',busy:false,error:'',ok:'',code:'',resendAt:Date.now()+60000};state.registerStep=1;state.registerData={};render();startVerifyTicker();return;}
        state.user=result.user;state.csrf=result.csrfToken;state.activePage='overview';state.activeProject=null;state.registerStep=1;state.registerData={};
        await refreshDashboard();render();showToast('Your workspace is ready.');return;
      }
      let result;
      try{result=await api('/api/auth/login',{method:'POST',body:data});}
      catch(err){if(err&&err.data&&err.data.needsVerification){state.verify={email:err.data.email||String(data.email||'').toLowerCase(),from:'login',busy:false,error:'',ok:'',code:'',resendAt:0};render();startVerifyTicker();return;}throw err;}
      state.user=result.user;state.csrf=result.csrfToken;state.activePage='overview';state.activeProject=null;
      await refreshDashboard();render();showToast('Welcome back.');
    } else if(type==='create-project') {
      const data=new FormData(form);const source=data.get('sourceType');
      if(source==='zip'&&!data.get('bundle')?.size)throw new Error('Choose a ZIP file to upload.');
      const res=await api('/api/projects',{method:'POST',body:data});state.modal=null;await refreshDashboard();state.activeProject=await api(`/api/projects/${encodeURIComponent(res.project.id)}`);state.activePage='project';state.activeTab='overview';await refreshMetrics();render();showToast('Project created. Add environment variables before deploying.');
    } else if(type==='save-env') {
      const data=Object.fromEntries(new FormData(form).entries());const id=state.activeProject.project.id;
      const res=await api(`/api/projects/${encodeURIComponent(id)}/env`,{method:'PUT',body:data});state.modal=null;await refreshProject();await refreshDashboard();render();showToast(res.message||'Secret saved securely.');
    } else if(type==='project-settings') {
      const data=Object.fromEntries(new FormData(form).entries());const id=state.activeProject.project.id;
      const res=await api(`/api/projects/${encodeURIComponent(id)}`,{method:'PATCH',body:data});state.activeProject.project=res.project;await refreshDashboard();await refreshProject();render();showToast('Project settings saved.');
    }
  } catch(error) {
    if(type==='auth') {const alert=$('#auth-alert');if(alert){alert.textContent=error.message;alert.classList.add('visible')}}else showToast(error.message,'error');
  } finally {if(document.body.contains(submit))resetButton(submit)}
});
document.addEventListener('keydown',async e=>{
  if(e.key==='Escape'&&state.modal){closeModal();return;}
  if(e.key==='Escape'&&state.mobileNavOpen){state.mobileNavOpen=false;render();$('.mobile-menu')?.focus({preventScroll:true});return;}
  // WCAG keyboard navigation for the project tablist.
  const currentTab=e.target.closest?.('[role="tab"][data-project-tab]');
  if(currentTab&&(e.key==='ArrowRight'||e.key==='ArrowLeft'||e.key==='Home'||e.key==='End')){
    const tabs=$$('.project-tab[data-project-tab]');
    const index=tabs.indexOf(currentTab);
    const nextIndex=e.key==='Home'?0:e.key==='End'?tabs.length-1:(index+(e.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;
    if(tabs[nextIndex]){e.preventDefault();await switchProjectTab(tabs[nextIndex].dataset.projectTab,true);}return;
  }
  // Keep keyboard focus inside an open modal until it is dismissed.
  if(state.modal&&e.key==='Tab'){
    const dialog=$('.modal');
    const focusable=$$('button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),a[href],[tabindex]:not([tabindex="-1"])',dialog).filter(el=>el.getClientRects().length);
    if(!focusable.length){e.preventDefault();dialog?.focus();return;}
    const first=focusable[0],last=focusable[focusable.length-1];
    if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}
    else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}
    return;
  }
  if(e.key==='/'&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)&&state.user){e.preventDefault();$('#global-search')?.focus();}
});
bootstrap();
document.addEventListener('input',e=>{
  const el=e.target.closest?e.target.closest('[data-verify-input]'):null;if(!el)return;
  const digits=el.value.replace(/\D/g,'').slice(0,6);
  if(el.value!==digits)el.value=digits;
  if(state.verify)state.verify.code=digits;
  if(digits.length===6&&state.verify&&!state.verify.busy){const f=document.getElementById('verify-form');if(f)f.requestSubmit();}
});
