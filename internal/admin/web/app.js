import {initThroughput} from './throughput.mjs';
import {initTypePicker} from './type-picker.mjs';
import {initPlayground} from './playground.mjs';
import {activeStates, reportMetrics, reportIsCurrent, progressPercent, runPresentation, verdictDescription} from './load-model.mjs';
const $ = (s, root=document) => root.querySelector(s);
const $$ = (s, root=document) => [...root.querySelectorAll(s)];
const state = {access:null, certs:[], test:null, report:null, bundle:null, testDirty:false, testBusy:false, epoch:0, pollBusy:false, testOffline:false, pendingSince:0};
const weightNames = ['mask_only','round_trip','stable_retry','expected_conflict'];
let formConfig, formRevision, systemRevision;
const playground=initPlayground(api);
const throughput=initThroughput(api);
const detectPicker=initTypePicker($('#detect-types-picker'),'Типы детекции');
const maskPicker=initTypePicker($('#mask-types-picker'),'Типы маскирования');
const esc = v => String(v ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));

async function api(path, options={}) {
  const headers = {'Accept':'application/json', ...options.headers};
  if (options.body && typeof options.body !== 'string') { headers['Content-Type']='application/json'; options.body=JSON.stringify(options.body); }
  if (options.method && options.method !== 'GET') headers['X-AlfaGen-CSRF']='1';
  const response = await fetch(path, {...options, headers, signal:options.signal?AbortSignal.any([options.signal,AbortSignal.timeout(15000)]):AbortSignal.timeout(15000)});
  const body = response.status === 204 ? null : await response.json().catch(()=>({error:{message:'Некорректный ответ сервера'}}));
  if (!response.ok) {
    if (response.status===401 && path!='/api/v1/session') showLogin();
    throw new Error(apiError(body?.error, response.status));
  }
  return body;
}

function apiError(error, status){
  const message=error?.message||`HTTP ${status}`;
  if(error?.code==='revision_conflict')return 'Настройки уже изменены. Обновите страницу кнопкой ↻ и повторите изменение.';
  if(error?.code==='test_active')return 'Прогон уже выполняется. Сначала остановите его.';
  if(message.includes('config: invalid policy'))return 'Проверьте профиль и типы: нельзя маскировать типы, для которых отключена детекция.';
  if(message.includes('request_timeout must be a positive duration'))return 'Тайм-аут должен быть больше нуля, например 2s.';
  if(message.includes('system is disabled'))return 'Выбранная система отключена. Включите её в разделе «Доступ».';
  if(message.includes('select a registered system'))return 'Выберите существующую систему из раздела «Доступ».';
  if(message.includes('rotate this system'))return 'Для этой системы нужно выпустить API-ключ в разделе «Доступ».';
  return message;
}

function toast(message, bad=false) { const el=$('#toast'); el.textContent=message; el.className='toast show'+(bad?' bad':''); clearTimeout(toast.timer); toast.timer=setTimeout(()=>el.className='toast',3200); }
function showLogin(){ throughput.stop(); playground.clear(); state.epoch++;  $('#app').classList.add('hidden'); $('#login').classList.remove('hidden'); }
function showApp(){ $('#login').classList.add('hidden'); $('#app').classList.remove('hidden'); }
function statusPill(text, kind=''){ return `<span class="pill ${kind}">${esc(text)}</span>`; }
function fmtDate(v){ return v && !String(v).startsWith('0001-') ? new Date(v).toLocaleString('ru-RU',{dateStyle:'short',timeStyle:'short'}) : '—'; }

async function refreshAll() {
  try {
    const dash = await api('/api/v1/dashboard');
    state.testOffline=false; state.access=dash.access; state.certs=dash.certificates||[]; state.test=dash.test;
    $('[data-page="certs"]').hidden=dash.certificates_enabled===false;
    $('#metric-certs').closest('article').hidden=dash.certificates_enabled===false;
    showApp(); renderAll(); throughput.start(); await Promise.all([loadReport(), loadAudit()]);
    $('#sync').textContent='Синхронизировано '+new Date().toLocaleTimeString('ru-RU',{hour:'2-digit',minute:'2-digit'});
  } catch(e) { if ($('#app').classList.contains('hidden')) $('#login-error').textContent=e.message; else toast(e.message,true); }
}

function renderAll(){ renderOverview(); renderSystems(); renderCerts(); renderTest(); playground.updateSystems(state.access?.systems); }
function renderOverview(){
  const systems=state.access?.systems||[], activeCerts=state.certs.filter(c=>!c.revoked&&new Date(c.not_after)>new Date()).length;
  $('#hero-systems').textContent=systems.length; $('#metric-systems').textContent=systems.filter(s=>s.enabled).length;
  $('#metric-certs').textContent=activeCerts; $('#metric-test').textContent=runPresentation(state.test?.status).label;
  $('#metric-version').textContent=state.access?.version||'—';
  $('#overview-systems').innerHTML=systems.slice(0,5).map(s=>`<div class="compact-row"><b>${esc(s.id)}</b><small>${esc(s.access_mode)}</small>${statusPill(s.enabled?'active':'off',s.enabled?'ok':'bad')}</div>`).join('')||'<div class="report-empty">Систем пока нет</div>';
}
function deleteSystemButton(system){
  if(system.default)return '';
  return `<button data-delete="${esc(system.id)}" title="Удалить">×</button>`;
}
function renderSystems(){
  const rows=(state.access?.systems||[]).map(s=>`<tr><td><b>${esc(s.id)}</b>${s.default?' '+statusPill('default'):''}</td><td>${statusPill(s.enabled?'активна':'отключена',s.enabled?'ok':'bad')}</td><td>${esc(s.access_mode)} ${s.has_api_key?'<small>· key</small>':''}</td><td><small>${esc(s.detection_profile||'default')} / ${esc(s.mask_mode)}</small></td><td><div class="row-actions"><button data-edit="${esc(s.id)}" title="Изменить">✎</button><button data-key="${esc(s.id)}" title="Ротировать API-ключ">↻ key</button>${deleteSystemButton(s)}</div></td></tr>`).join('');
  $('#systems-table').innerHTML=rows||'<tr><td colspan="5">Нет систем</td></tr>';
  $$('[data-edit]').forEach(b=>b.onclick=()=>openSystem(b.dataset.edit));
  $$('[data-key]').forEach(b=>b.onclick=()=>rotateKey(b.dataset.key));
  $$('[data-delete]').forEach(b=>b.onclick=()=>deleteSystem(b.dataset.delete));
  const select=$('#cert-form [name=system_id]'); select.innerHTML=(state.access?.systems||[]).filter(s=>s.enabled).map(s=>`<option>${esc(s.id)}</option>`).join('');
}
function certificateStatus(cert){
  if(cert.revoked)return 'отозван';
  return new Date(cert.not_after)<new Date()?'истёк':'активен';
}
function revokeCertificateButton(cert){
  if(cert.revoked)return '';
  return `<div class="dialog-actions"><button class="secondary" data-revoke="${esc(cert.system_id)}" data-serial="${esc(cert.serial)}">Отозвать</button></div>`;
}
function renderCerts(){
  $('#cert-grid').innerHTML=state.certs.map(c=>`<article class="cert-card ${c.revoked?'revoked':''}"><div class="cert-top"><h4>${esc(c.system_id)}</h4>${statusPill(certificateStatus(c),c.revoked?'bad':'ok')}</div><div class="cert-meta"><div><small>Серийный номер</small><span class="mono">${esc(c.serial)}</span></div><div><small>Действует до</small><span>${fmtDate(c.not_after)}</span></div></div><div class="fingerprint mono" title="${esc(c.fingerprint)}">SHA-256 ${esc(c.fingerprint)}</div>${revokeCertificateButton(c)}</article>`).join('')||'<div class="panel report-empty">Выпущенных сертификатов нет</div>';
  $$('[data-revoke]').forEach(b=>b.onclick=()=>revokeCert(b.dataset.revoke,b.dataset.serial));
}
function loadTestForm(c){
  formConfig=structuredClone(c); formRevision=state.test.revision;
  const f=$('#test-form');
  const systems=state.access?.systems||[];
  f.elements.system_id.innerHTML=systems.map(x=>`<option value="${esc(x.id)}" ${x.enabled?'':'disabled'}>${esc(x.id)}${x.enabled?'':' — отключена'}</option>`).join('');
  if(!systems.some(x=>x.id===c.system_id))f.elements.system_id.add(new Option(c.system_id+' — отсутствует',c.system_id));
  if(![...f.elements.payload_profile.options].some(x=>x.value===c.payload_profile))f.elements.payload_profile.add(new Option(c.payload_profile,c.payload_profile));
  ['scenario','mode','rate_per_second','duration','request_timeout','operation_limit','target_url','system_id','payload_profile'].forEach(k=>{if(f.elements[k])f.elements[k].value=c[k]??''});
  weightNames.forEach(k=>f.elements['weight_'+k].value=c.operation_weights?.[k]??1);
}
function renderTest(){
  const c=state.test?.config; if(!c)return;
  if(!state.testDirty)loadTestForm(c);
  renderTestDraft(); renderRun();
}
function renderTestDraft(){
  $('#mixed-weights').hidden=$('#test-form').elements.scenario.value!=='mixed';
  const conflict=state.testDirty && formRevision!==state.test?.revision;
  let draft=state.testDirty?'Есть несохранённые изменения':'Настройки сохранены';
  if(conflict)draft='Настройки изменены в другой сессии. Обновите перед сохранением.';
  $('#test-draft').textContent=draft;
}
const number = (v,digits=0) => Number.isFinite(v) ? v.toLocaleString('ru-RU',{maximumFractionDigits:digits,minimumFractionDigits:digits}) : '—';
function stat(label,value){return `<div><small>${esc(label)}</small><b>${esc(value)}</b></div>`}
function httpCodes(statuses={}){return Object.entries(statuses).map(([code,count])=>statusPill(`HTTP ${code}: ${count}`,Number(code)>=400&&code!=='409'?'bad':'')).join('')}
function runDescription(t, status, view, p){
  let description=view.description;
  if(status.state==='pending'){
    state.pendingSince ||= Date.now();
    if(Date.now()-state.pendingSince>15000)description='Генератор отвечает, но пока не подтвердил запуск. Проверьте общий файл конфигурации и журналы mock-client.';
  }else state.pendingSince=0;
  if(status.state==='running'&&p?.config_version&&p.config_version!==t.config.version)description='Изменения сохранены, но ещё не применены к текущему прогону.';
  if(status.state==='running'&&p?.reload_rejected)description='Генератор отклонил обновление. Прогон продолжает работать с прежними настройками; проверьте параметры и доступность API-ключа.';
  if(state.testOffline)description='Не удаётся обновить данные. На экране последний полученный снимок. Повторяем подключение автоматически.';
  return description;
}
function renderRun(){
  const t=state.test, status=t?.status||{}, view=runPresentation(status), p=status.progress;
  $('#run-title').textContent=view.label;
  $('#metric-test').textContent=view.label;
  $('#test-state').className='pill '+view.kind; $('#test-state').textContent=view.label;
  const description=runDescription(t, status, view, p);
  if(state.testOffline){
    $('#run-title').textContent='Нет связи с админкой';
    $('#test-state').textContent='Нет связи';
    $('#test-state').className='pill bad';
  }
  $('#run-description').textContent=description;
  $('#run-id').textContent=t?.config?.run_id?'Прогон: '+t.config.run_id:'Новый прогон ещё не запускался';
  $('#run-heartbeat').textContent=status.updated_at && !status.updated_at.startsWith('0001-')?'Сигнал генератора: '+new Date(status.updated_at).toLocaleTimeString('ru-RU'):'Нет сигнала генератора';
  const progress=$('#run-progress'), percent=progressPercent(p);
  progress.hidden=!p||(percent===null&&!activeStates.has(status.state));
  if(percent===null)progress.removeAttribute('value'); else progress.value=percent;
  $('#run-stats').innerHTML=p?stat('Прошло',number(p.elapsed_seconds,1)+' с')+stat('HTTP RPS (среднее)',number(p.http_rps,1))+stat('HTTP-запросы',number(p.counts.http_requests))+stat('В работе',number(p.in_flight))+stat('Успешные операции',number(p.counts.successful_operations))+stat('Ошибки операций',number(p.counts.failed_operations))+stat('Пропущено операций',number(p.counts.dropped_operations))+stat('P95',number(p.latency_ms.p95,1)+' мс'):'';
  $('#start-test').disabled=state.testBusy||state.testOffline||activeStates.has(status.state)||status.state==='unavailable';
  $('#stop-test').disabled=state.testBusy||state.testOffline||(!t?.config?.enabled&&!activeStates.has(status.state));
  $('#save-test').disabled=state.testBusy||state.testOffline;
  $$('#test-form input, #test-form select').forEach(el=>el.disabled=state.testBusy);
  $('#start-test').textContent=state.testBusy?'Подождите…':'▶ Запустить';
}
function renderReport(){
  const box=$('#report'), small=$('#overview-report');
  const current=reportIsCurrent(state.test,state.report);
  $('#report-title').textContent=current?'Отчёт текущего прогона':'Последний сохранённый отчёт';
  if(!state.report){ box.innerHTML='<div class="report-empty">Отчёт появится автоматически после завершения прогона.</div>'; small.innerHTML=box.innerHTML; return; }
  const r=state.report, m=reportMetrics(r), c=m.counts;
  const reportHint=activeStates.has(state.test?.status?.state)?' Новый отчёт появится после завершения текущего.':' Для текущего прогона новый отчёт не получен.';
  const previous=!current&&state.test?.config?.run_id?`<p class="report-note">Это предыдущий прогон.${reportHint}</p>`:'';
  const html=`${previous}<div class="report-verdict">${esc(r.verdict||'COMPLETE')}</div><p class="report-note">${esc(verdictDescription(r))}</p><small>${esc(r.scenario||'')} · ${fmtDate(r.finished_at)}</small><p class="report-id muted">Прогон: ${esc(r.run_id||'—')}</p><div class="report-stats">${stat('HTTP RPS',number(m.httpRPS,1))}${stat('Успешных операций/с',number(m.operationRPS,1))}${stat('Целевой HTTP RPS',number(r.parameters?.target_rps,1))}${stat('P95',number(m.latency.p95,1)+' мс')}${stat('Успешные операции',number(c.successful_operations))}${stat('Ошибки операций',number(c.failed_operations))}${stat('HTTP-запросы',number(c.http_requests))}${stat('Пропущено операций',number(c.dropped_operations))}${stat('Тайм-ауты',number(c.timeouts))}${stat('Полные циклы',number(c.completed_pairs))}</div><div class="http-codes">${httpCodes(r.http_statuses)}</div>`;
  box.innerHTML=html; small.innerHTML=`<div class="report-verdict">${esc(r.verdict||'COMPLETE')}</div><small>${fmtDate(r.finished_at)}</small><div class="report-stats">${stat('HTTP RPS',number(m.httpRPS,1))}${stat('Ошибки операций',number(c.failed_operations))}</div>`;
}
async function loadReport(){const data=await api('/api/v1/tests/report'); state.report=data.available?data.report:null; renderReport();}
async function loadAudit(){ try{const data=await api('/api/v1/audit?limit=100'); $('#audit-list').innerHTML=(data.entries||[]).slice().reverse().map(e=>`<div class="audit-row"><time>${fmtDate(e.time)}</time><b>${esc(e.action)}</b><span>${esc(e.resource)}</span>${statusPill(e.result,e.result==='success'?'ok':'bad')}</div>`).join('')||'<div class="report-empty">Операций пока нет</div>';}catch(e){toast(e.message,true)} }

function editableAccessMode(system){
  if(system?.access_mode==='disabled')return system.has_api_key?'api_key':'anonymous';
  return system?.access_mode||'api_key';
}
function openSystem(id){ $('#system-error').textContent=''; systemRevision=state.access?.revision; const f=$('#system-form'), s=(state.access?.systems||[]).find(x=>x.id===id); f.reset(); f.elements.original_id.value=id||''; f.elements.id.value=id||''; f.elements.id.disabled=!!id; f.elements.enabled.checked=s?.enabled??true; f.elements.access_mode.value=editableAccessMode(s); f.elements.mask_mode.value=s?.mask_mode||'format'; f.elements.allow_demask.checked=s?.allow_demask??true; f.elements.generate_api_key.checked=!s; f.elements.detection_profile.value=s?.detection_profile||''; detectPicker.reset(state.access?.available_types,s?.detect_types); maskPicker.reset(state.access?.available_types,s?.mask_types); f.elements.generate_api_key.disabled=f.elements.access_mode.value!=='api_key'; $('#system-dialog').showModal(); }
async function saveSystem(ev){ ev.preventDefault(); if($('#save-system').disabled){return;} $('#save-system').disabled=true; $('#system-error').textContent=''; const f=ev.currentTarget,id=f.elements.original_id.value||f.elements.id.value; try{const result=await api('/api/v1/systems/'+encodeURIComponent(id),{method:'PUT',body:{revision:systemRevision,enabled:f.elements.enabled.checked,access_mode:f.elements.access_mode.value,generate_api_key:f.elements.generate_api_key.checked,allow_demask:f.elements.allow_demask.checked,mask_mode:f.elements.mask_mode.value,detection_profile:f.elements.detection_profile.value,detect_types:detectPicker.value(),mask_types:maskPicker.value()}}); $('#system-dialog').close(); if(result.api_key){showSecret('Новый API-ключ','Скопируйте ключ сейчас — повторно он не отображается.',result.api_key);} toast(result.message||'Политика сохранена и ожидает применения backend',!!result.message); await refreshAll();}catch(e){$('#system-error').textContent=e.message;toast(e.message,true)}finally{$('#save-system').disabled=false} }
async function rotateKey(id){ if(!confirm(`Выпустить новый API-ключ для ${id}? Старый перестанет работать после hot reload.`)){return;} try{const r=await api(`/api/v1/systems/${encodeURIComponent(id)}/rotate-key`,{method:'POST',body:{revision:state.access.revision}}); showSecret('Новый API-ключ',r.message||'Скопируйте ключ сейчас — повторно он не отображается.',r.api_key); if(r.message){toast(r.message,true);} await refreshAll();}catch(e){toast(e.message,true)} }
async function deleteSystem(id){ if(!confirm(`Удалить систему ${id} из allowlist?`)){return;} try{await api(`/api/v1/systems/${encodeURIComponent(id)}?revision=${encodeURIComponent(state.access.revision)}`,{method:'DELETE'}); toast('Система удалена'); await refreshAll();}catch(e){toast(e.message,true)} }
async function issueCert(ev){ ev.preventDefault(); const id=ev.currentTarget.elements.system_id.value; try{const bundle=await api('/api/v1/certificates/'+encodeURIComponent(id),{method:'POST'}); $('#cert-dialog').close(); state.bundle=bundle; showSecret('mTLS bundle',bundle.notice,`# client.crt\n${bundle.certificate_pem}\n# client.key\n${bundle.private_key_pem}\n# ca.crt\n${bundle.ca_pem}`,true); await refreshAll();}catch(e){toast(e.message,true)} }
async function revokeCert(id,serial){ if(!confirm(`Отозвать сертификат ${id}? Изменение автоматически применится в Compose edge.`)){return;} try{await api(`/api/v1/certificates/${encodeURIComponent(id)}/${encodeURIComponent(serial)}`,{method:'DELETE'}); toast('Сертификат отозван; Compose edge обновляется автоматически'); await refreshAll();}catch(e){toast(e.message,true)} }
function showSecret(title,notice,value,bundle=false){ $('#secret-title').textContent=title; $('#secret-notice').textContent=notice; $('#secret-value').value=value; $('#download-secret').style.display=bundle?'block':'none'; $('#secret-dialog').showModal(); }
function testInput(){
  const f=$('#test-form'), c=structuredClone(formConfig);
  ['scenario','mode','duration','request_timeout','target_url','system_id','payload_profile'].forEach(k=>c[k]=f.elements[k].value.trim());
  ['rate_per_second','operation_limit'].forEach(k=>c[k]=Number(f.elements[k].value));
  delete c.concurrency; delete c.max_in_flight; // Admin server owns these fixed limits.
  if(c.scenario==='mixed')c.operation_weights=Object.fromEntries(weightNames.map(k=>[k,Number(f.elements['weight_'+k].value)]));
  else delete c.operation_weights;
  return c;
}
async function testAction(action){
  if(state.testBusy)return;
  if(action!=='stop'&&!$('#test-form').reportValidity())return;
  state.testBusy=true; state.epoch++; $('#test-error').textContent=''; renderRun();
  const body=action==='stop'?{revision:state.test.revision}:{revision:formRevision,config:testInput()};
  try{
    await api('/api/v1/tests/'+(action==='save'?'config':action),{method:action==='save'?'PUT':'POST',body});
    if(action!=='stop')state.testDirty=false;
    state.test=await api('/api/v1/tests/config'); renderTest(); await loadReport();
    toast({start:'Команда запуска сохранена. Ожидаем генератор.',stop:'Команда остановки отправлена.',save:'Конфигурация сохранена.'}[action]);
  }catch(e){$('#test-error').textContent=e.message; toast(e.message,true)}
  finally{state.testBusy=false; renderRun()}
}
async function saveTest(ev){ev.preventDefault();await testAction('save')}
async function toggleTest(enabled){await testAction(enabled?'start':'stop')}

$('#login-form').onsubmit=async ev=>{ev.preventDefault();$('#login-error').textContent='';try{await api('/api/v1/session',{method:'POST',body:{token:$('#token').value}});$('#token').value='';await refreshAll()}catch(e){$('#login-error').textContent=e.message}};
$('#logout').onclick=async()=>{try{await api('/api/v1/session',{method:'DELETE'})}catch{}showLogin()};
$$('nav button').forEach(b=>b.onclick=()=>switchPage(b.dataset.page));
$$('[data-jump]').forEach(b=>b.onclick=()=>switchPage(b.dataset.jump));
function switchPage(name){$$('nav button').forEach(x=>x.classList.toggle('active',x.dataset.page===name));$$('.page').forEach(x=>x.classList.toggle('active',x.id==='page-'+name));$('#page-title').textContent={overview:'Обзор',access:'Управление доступом',certs:'Сертификаты mTLS',tests:'Нагрузочный стенд',playground:'Ручная проверка',audit:'Аудит'}[name];if(name==='audit')loadAudit()}
$('#refresh').onclick=()=>{if(state.testDirty&&!confirm('Загрузить сохранённые настройки и отменить изменения формы?')){return;}state.testDirty=false;state.epoch++;refreshAll()}; $('#refresh-report').onclick=()=>loadReport().catch(e=>toast(e.message,true)); $('#add-system').onclick=()=>openSystem(); $('#system-form').onsubmit=saveSystem; $('#issue-cert').onclick=()=>$('#cert-dialog').showModal(); $('#cert-form').onsubmit=issueCert; $('#test-form').onsubmit=saveTest; $('#start-test').onclick=()=>toggleTest(true); $('#stop-test').onclick=()=>toggleTest(false);
$('#close-secret').onclick=()=>$('#secret-dialog').close(); $('#copy-secret').onclick=async()=>{await navigator.clipboard.writeText($('#secret-value').value);toast('Скопировано')};
$$('button[value=cancel]').forEach(button=>{button.type='button';button.onclick=()=>button.closest('dialog').close()});
$('#download-secret').onclick=()=>{const b=new Blob([$('#secret-value').value],{type:'text/plain'}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='alfagen-mtls-bundle.pem.txt';a.click();URL.revokeObjectURL(a.href)};
$('#test-form').addEventListener('input',()=>{state.testDirty=true;$('#test-error').textContent='';renderTestDraft()});
$('#system-form [name=access_mode]').addEventListener('change',ev=>{const key=$('#system-form [name=generate_api_key]');key.disabled=ev.target.value!=='api_key';if(key.disabled)key.checked=false});
$('#secret-dialog').addEventListener('close',()=>{$('#secret-value').value='';state.bundle=null});
await refreshAll();

async function pollTest(){
  if ($('#app').classList.contains('hidden') || state.testBusy || state.pollBusy) return;
  state.pollBusy=true; const epoch=state.epoch;
  try{
    const [current,data]=await Promise.all([api('/api/v1/tests/config'),api('/api/v1/tests/report')]);
    if(epoch!==state.epoch)return;
    state.testOffline=false; state.test=current; state.report=data.available?data.report:null;
    renderTest();renderReport();
    $('#sync').textContent='Обновлено '+new Date().toLocaleTimeString('ru-RU');
  }catch(e){if(epoch===state.epoch){state.testOffline=true;renderRun();$('#sync').textContent='Нет связи: '+e.message}}
  finally{state.pollBusy=false}
}
setInterval(pollTest,2000);
