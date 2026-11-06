'use strict';
let csrf = '';
const $ = (id) => document.getElementById(id);
const statusNames = {new:'Новая', contacted:'Связались', confirmed:'Подтверждена', cancelled:'Отменена'};
const topicNames = {therapy:'Психотерапия', supervision:'Супервизия', education:'Образование', cooperation:'Сотрудничество'};
function message(text) { $('feedback').textContent = text; }
async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials:'same-origin',
    ...options,
    headers:{'Content-Type':'application/json', ...(options.method && options.method !== 'GET' ? {'X-Admin-CSRF':csrf} : {}), ...(options.headers || {})}
  });
  if (!response.ok) {
    if (response.status === 401) showLogin();
    throw new Error(response.status === 429 ? 'Слишком много попыток, попробуйте позднее.' : 'Ошибка запроса (HTTP '+response.status+').');
  }
  return response.json();
}
function showLogin() {
  csrf = '';
  $('login-panel').hidden = false;
  $('dashboard').hidden = true;
  $('logout').hidden = true;
  $('requests').replaceChildren();
}
function showDashboard() {
  $('login-panel').hidden = true;
  $('dashboard').hidden = false;
  $('logout').hidden = false;
}
function element(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = String(text);
  if (className) el.className = className;
  return el;
}
function showRequests(rows) {
  const container = $('requests');
  container.replaceChildren();
  if (!rows.length) { container.append(element('p', 'Заявок пока нет.')); return; }
  for (const r of rows) {
    const box = element('article', undefined, 'request');
    const date = new Date(r.created_at);
    box.append(element('small', '№'+r.id+' · '+(topicNames[r.topic]||r.topic)+' · '+(isNaN(date.valueOf()) ? '' : date.toLocaleString('ru-RU'))));
    box.append(element('h3',r.name));
    box.append(element('p','Контакт: '+r.contact));
    if (r.message) box.append(element('p','Обращение: '+r.message));
    box.append(element('p',r.notification_status === 'sent' ? 'Telegram: уведомление отправлено' : 'Telegram: уведомление ожидает отправки','muted'));
    const footer = element('footer');
    const select = document.createElement('select');
    select.setAttribute('aria-label','Статус заявки №'+r.id);
    for (const [key,label] of Object.entries(statusNames)) {
      const option = element('option',label);
      option.value=key;
      select.append(option);
    }
    select.value = r.status;
    select.addEventListener('change',async () => {
      select.disabled=true;
      try {
        await api('/api/admin/requests/'+r.id,{method:'PATCH',body:JSON.stringify({status:select.value})});
        message('Статус заявки №'+r.id+' обновлён.');
      } catch(e) { message(e.message); select.value=r.status; }
      finally {select.disabled=false;}
    });
    footer.append(select);
    const del = element('button','Удалить заявку','danger');
    del.type='button';
    del.addEventListener('click',async () => {
      if (!confirm('Безвозвратно удалить заявку №'+r.id+'?')) return;
      del.disabled=true;
      try {await api('/api/admin/requests/'+r.id,{method:'DELETE'});await load();message('Заявка удалена.');}
      catch(e){message(e.message);del.disabled=false;}
    });
    footer.append(del);
    box.append(footer);
    container.append(box);
  }
}
async function load() {
  const data=await api('/api/admin/requests?limit=100');
  showRequests(data.requests);
}
$('login-form').addEventListener('submit',async (e)=>{
  e.preventDefault();
  message('');
  const button=e.target.querySelector('button');
  button.disabled=true;
  try {
    const data=await api('/api/admin/login',{method:'POST',headers:{},body:JSON.stringify({password:$('password').value,code:$('otp').value})});
    csrf=data.csrf;
    $('password').value=''; $('otp').value='';
    showDashboard(); await load();
  }catch(err){message(err.message);}
  finally{button.disabled=false;}
});
$('refresh').addEventListener('click',async()=>{try{await load();message('Список обновлён.');}catch(e){message(e.message);}});
$('retry').addEventListener('click',async()=>{try{const result=await api('/api/admin/notifications/retry',{method:'POST'});message('Отправлено уведомлений: '+result.sent);await load();}catch(e){message(e.message);}});
$('logout').addEventListener('click',async()=>{try{await api('/api/admin/logout',{method:'POST'});}catch(e){message(e.message);}showLogin();});
(async()=>{try{const session=await api('/api/admin/session');csrf=session.csrf;showDashboard();await load();}catch(e){showLogin();}})();
