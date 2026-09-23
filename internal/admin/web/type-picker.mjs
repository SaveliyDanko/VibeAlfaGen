const labels = {
  full_name:'ФИО', date_of_birth:'Дата рождения', place_of_birth:'Место рождения',
  passport_number:'Номер паспорта', citizenship:'Гражданство', passport_issuer:'Кем выдан паспорт',
  passport_division_code:'Код подразделения', passport_issue_date:'Дата выдачи паспорта',
  driver_license:'Водительское удостоверение', address:'Адрес', email:'Электронная почта',
  phone:'Телефон', inn:'ИНН', card_number:'Номер банковской карты', cvv:'CVV / CVC',
  card_pin:'PIN-код карты', card_holder:'Владелец карты',
};

// null means all current and future types; [] means none. Keep that distinction
// even when a user explicitly selects every currently available checkbox.
export function initTypePicker(root, title) {
  root.classList.add('type-field');
  root.innerHTML=`<span class="type-label"></span><details class="type-picker">
    <summary><span class="type-summary"></span><span aria-hidden="true">⌄</span></summary>
    <div class="type-menu"><label class="type-search-label">Поиск типа<input type="search" autocomplete="off" placeholder="Название или код типа"></label>
      <div class="type-actions"><button type="button" data-select="all">Все типы</button><button type="button" data-select="none">Ни одного</button></div>
      <div class="type-options"></div><p class="type-empty muted" hidden>Ничего не найдено</p>
    </div></details>`;
  const label=root.querySelector('.type-label'), details=root.querySelector('details');
  const summary=root.querySelector('summary'), summaryText=root.querySelector('.type-summary');
  const search=root.querySelector('input[type=search]'), options=root.querySelector('.type-options');
  label.textContent=title;
  label.id=root.id+'-label'; summaryText.id=root.id+'-value';
  summary.setAttribute('aria-labelledby',label.id+' '+summaryText.id);
  let catalog=[], value=null;

  function selectionLabel() {
    if(value===null)return 'Все типы';
    if(value.length===0)return 'Ни одного';
    if(value.length<=2)return value.map(t=>labels[t]||t).join(', ');
    return `Выбрано типов: ${value.length}`;
  }
  function sync() {
    summaryText.textContent=selectionLabel();
    for(const checkbox of options.querySelectorAll('input')) checkbox.checked=value===null||value.includes(checkbox.value);
    root.querySelector('[data-select=all]').setAttribute('aria-pressed',String(value===null));
    root.querySelector('[data-select=none]').setAttribute('aria-pressed',String(value!==null&&value.length===0));
  }
  function filter() {
    const query=search.value.trim().toLowerCase(); let visible=0;
    for(const option of options.children){
      option.hidden=!option.textContent.toLowerCase().includes(query);
      if(!option.hidden)visible++;
    }
    root.querySelector('.type-empty').hidden=visible>0;
  }
  function populate() {
    options.replaceChildren();
    for(const type of catalog){
      const option=document.createElement('label'); option.className='type-option';
      const checkbox=document.createElement('input'); checkbox.type='checkbox'; checkbox.value=type;
      const caption=document.createElement('span'), name=document.createElement('span'), code=document.createElement('small');
      name.textContent=labels[type]||'Пользовательский тип'; code.textContent=type;
      caption.append(name,code); option.append(checkbox,caption); options.append(option);
      checkbox.addEventListener('change',()=>{
        const selected=new Set(value===null?catalog:value);
        if(checkbox.checked)selected.add(type);else selected.delete(type);
        value=[...selected];sync();
      });
    }
    sync();filter();
  }
  search.addEventListener('input',filter);
  details.addEventListener('keydown',event=>{
    if(event.key==='Escape'){event.preventDefault();event.stopPropagation();details.open=false;summary.focus();}
    if(event.key==='Enter'&&event.target===search)event.preventDefault();
  });
  details.addEventListener('toggle',()=>{
    if(details.open)for(const other of document.querySelectorAll('.type-picker[open]'))if(other!==details)other.open=false;
  });
  document.addEventListener('click',event=>{if(!root.contains(event.target))details.open=false;});
  root.querySelector('[data-select=all]').onclick=()=>{value=null;sync();};
  root.querySelector('[data-select=none]').onclick=()=>{value=[];sync();};
  return {
    reset(available,selected){
      value=selected==null?null:[...selected];
      // Never lose a previously saved selection if the catalog changes.
      catalog=[...new Set([...(available||[]),...(value||[])])].sort((a,b)=>(labels[a]||a).localeCompare(labels[b]||b,'ru'));
      search.value='';details.open=false;populate();
    },
    value(){return value===null?null:[...value];},
  };
}
