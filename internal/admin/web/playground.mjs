// Drafts live only in this page; never store payloads in URLs or browser storage.
export function initPlayground(api) {
  const $ = id => document.getElementById(id);
  let systems=[], pair=null, busy=false, epoch=0, controller;
  const fields=$('manual-fields'), select=$('manual-system');
  function invalidate() {
    epoch++; controller?.abort(); busy=false; fields.disabled=false;
    $('manual-clear').disabled=false;
    pair=null;
    $('manual-masked').value=''; $('manual-restored').value='';
    $('manual-match').textContent=''; $('manual-error').textContent='';
    $('manual-status').textContent='Готово к отправке';
    renderPolicy();
  }
  function renderPolicy() {
    const system=systems.find(s=>s.id===select.value);
    let policy='Добавьте активную систему в разделе «Доступ».';
    if(system){
      const demask=system.allow_demask?'разрешено':'запрещено политикой';
      const disabled=system.enabled?'':' Система отключена.';
      policy=`Маска: ${system.mask_mode}. Восстановление ${demask}.${disabled}`;
    }
    $('manual-policy').textContent=policy;
    $('manual-mask').disabled=busy||!system?.enabled;
    $('manual-restore').disabled=busy||!pair||!system?.enabled;
  }
  function updateSystems(value) {
    systems=value||[];
    const previous=select.value;
    select.replaceChildren(...systems.map(s=>{
      const option=new Option(s.id+(s.enabled?'':' — отключена'),s.id);
      option.disabled=!s.enabled; return option;
    }));
    if(systems.some(s=>s.id===previous))select.value=previous;
    else select.value=systems.find(s=>s.enabled)?.id||'';
    if(previous!==select.value)invalidate();
    renderPolicy();
  }
  function newID() {
    $('manual-id').value=crypto.randomUUID?.()||'manual-'+Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,'0')).join('');
    invalidate();
  }
  function clear() {
    epoch++; controller?.abort(); busy=false; fields.disabled=false;
    $('manual-clear').disabled=false; $('manual-source').value=''; newID();
  }
  function applyResult(restore, result, original) {
    if(restore){
      $('manual-restored').value=result;
      $('manual-match').textContent=result===pair.original?'Точное совпадение с исходником, включая пробелы.':'Ответ отличается от исходника. Проверьте текст маски и срок хранения контекста.';
      return;
    }
    pair={original}; $('manual-masked').value=result;
    if(result===original)$('manual-match').textContent='Текст не изменился. Возможно, в нём нет данных, маскируемых выбранной политикой.';
  }
  async function send(restore) {
    if(busy||!$('manual-form').reportValidity()||(restore&&!pair))return;
    const systemID=select.value, payloadID=$('manual-id').value;
    const original=$('manual-source').value; // Preserve whitespace and Unicode exactly.
    const payload=restore?$('manual-masked').value:original;
    if(!restore)invalidate();
    else {$('manual-restored').value='';$('manual-match').textContent=''}
    $('manual-error').textContent='';
    busy=true; fields.disabled=true; $('manual-clear').disabled=true;
    $('manual-status').textContent=restore?'Восстанавливаем…':'Маскируем…';
    const version=++epoch; controller=new AbortController(); renderPolicy();
    try {
      const response=await api('/api/v1/playground/process',{method:'POST',signal:controller.signal,body:{system_id:systemID,payload_id:payloadID,payload}});
      if(version!==epoch)return;
      $('manual-status').textContent=`${restore?'Восстановление':'Маскирование'} · HTTP ${response.upstream_status} · ${Number(response.elapsed_ms).toLocaleString('ru-RU',{maximumFractionDigits:1})} мс`;
      if(response.error){$('manual-error').textContent=response.error.message;return}
      applyResult(restore, response.result, original);
    } catch(error) {
      if(version!==epoch)return;
      $('manual-status').textContent='Запрос не завершён';
      $('manual-error').textContent=error.message;
    } finally {
      if(version===epoch){busy=false;fields.disabled=false;$('manual-clear').disabled=false;renderPolicy()}
    }
  }
  $('manual-form').onsubmit=event=>{event.preventDefault();send(false)};
  $('manual-restore').onclick=()=>send(true);
  $('manual-new-id').onclick=newID; $('manual-clear').onclick=clear;
  select.onchange=invalidate; $('manual-id').oninput=invalidate; $('manual-source').oninput=invalidate;
  $('manual-masked').oninput=()=>{$('manual-restored').value='';$('manual-match').textContent='';$('manual-error').textContent=''};
  newID();
  return {updateSystems,clear};
}
