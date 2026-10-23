const enc = new TextEncoder();
const json = (data, status=200, headers={}) => new Response(JSON.stringify(data), {status, headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
const html = (body) => new Response(body,{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store'}});
const b64 = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const unb64 = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
async function hashPassword(password, salt=b64(crypto.getRandomValues(new Uint8Array(16)))) {
  const key=await crypto.subtle.importKey('raw',enc.encode(password),'PBKDF2',false,['deriveBits']);
  const bits=await crypto.subtle.deriveBits({name:'PBKDF2',salt:unb64(salt),iterations:210000,hash:'SHA-256'},key,256);
  return `${salt}.${b64(bits)}`;
}
async function verifyPassword(password, stored) {
  const [salt,expected]=String(stored||'').split('.');
  if(!salt||!expected)return false;
  const actual=(await hashPassword(password,salt)).split('.')[1];
  return actual===expected;
}
async function sign(value, secret) {
  const key=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);
  return b64(await crypto.subtle.sign('HMAC',key,enc.encode(value)));
}
async function token(payload, secret) {
  const raw=b64(enc.encode(JSON.stringify(payload)));
  return raw+'.'+await sign(raw,secret);
}
async function readSession(request, env) {
  const c=request.headers.get('Cookie')||'';
  const match=c.match(/(?:^|;\s*)elio_session=([^;]+)/);
  if(!match)return null;
  const [raw,sig]=match[1].split('.');
  if(!raw||!sig||await sign(raw,env.SESSION_SECRET)!==sig)return null;
  try { const p=JSON.parse(new TextDecoder().decode(unb64(raw))); if(p.exp<Date.now())return null; return p; } catch { return null; }
}
function cookie(value, maxAge=43200) {
  return `elio_session=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}
function ip(request){return request.headers.get('CF-Connecting-IP')||''}
async function audit(env, session, request, action, detail='') {
  await env.DB.prepare('INSERT INTO audit_log(actor_id,actor_username,action,detail,ip,user_agent) VALUES(?,?,?,?,?,?)')
    .bind(session?.id??null,session?.username??'system',action,String(detail).slice(0,1000),ip(request),(request.headers.get('User-Agent')||'').slice(0,300)).run();
}
async function requireAdmin(request,env,root=false) {
  const s=await readSession(request,env);
  if(!s || (root && s.role!=='root'))return null;
  const row=await env.DB.prepare('SELECT id,username,role,active FROM admins WHERE id=?').bind(s.id).first();
  if(!row||!row.active||row.username!==s.username||row.role!==s.role)return null;
  return s;
}
async function body(request){try{return await request.json()}catch{return null}}
function safeId(s){return /^[a-zA-Z0-9_-]{1,60}$/.test(String(s||''))}
let dbReady = false;
let dbInitPromise = null;
async function ensureDatabase(env) {
  if (!env.DB) throw new Error('D1 binding با نام DB متصل نشده است');
  if (dbReady) return;
  if (!dbInitPromise) dbInitPromise = (async () => {
    const statements = [
      `CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'admin' CHECK(role IN ('root','admin')), active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), created_by INTEGER)`,
      `CREATE TABLE IF NOT EXISTS categories (id TEXT PRIMARY KEY, title TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1)`,
      `CREATE TABLE IF NOT EXISTS menu_items (id TEXT PRIMARY KEY, category_id TEXT NOT NULL REFERENCES categories(id) ON DELETE CASCADE, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '', price INTEGER, options_json TEXT, sort_order INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1, stock_enabled INTEGER NOT NULL DEFAULT 0, stock_qty REAL NOT NULL DEFAULT 0, stock_unit TEXT NOT NULL DEFAULT 'عدد', updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), updated_by INTEGER)`,
      `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
      `CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, actor_id INTEGER, actor_username TEXT NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', user_agent TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))`
    ];
    for (const sql of statements) await env.DB.prepare(sql).run();
    const seed = [
      `INSERT OR IGNORE INTO settings(key,value) VALUES ('tagline',''),('currency','تومان'),('footer','کافه الیو | ELIO'),('discount_percent','0'),('markup_percent','0')`,
      `INSERT OR IGNORE INTO categories(id,title,sort_order) VALUES ('hot','نوشیدنی گرم',0),('cold','نوشیدنی سرد',1),('cake','کیک',2),('food','غذا',3)`,
      `INSERT OR IGNORE INTO menu_items(id,category_id,name,description,price,options_json,sort_order) VALUES
      ('espresso','hot','اسپرسو','',NULL,'[{"label":"۷۰-۳۰","price":[75000,95000]},{"label":"۹۰-۱۰","price":[90000,115000]}]',0),
      ('americano','hot','آمریکانو','',NULL,'[{"label":"۷۰-۳۰","price":[85000]},{"label":"۹۰-۱۰","price":[100000]}]',1),
      ('cappuccino','hot','کاپوچینو','',125000,NULL,2),
      ('latte','hot','لاته','',NULL,'[{"label":"۷۰-۳۰","price":[115000]},{"label":"۹۰-۱۰","price":[130000]},{"label":"سیروپ (شکلات-فندق-کارامل)","price":[10000]}]',3),
      ('hot-chocolate','hot','هات چاکلت','',120000,NULL,4),('masala','hot','چای ماسالا','',95000,NULL,5),('masala-2','hot','چای ماسالا 2','',95000,NULL,6),
      ('iced-latte','cold','آیس لاته','',125000,NULL,0),('iced-americano','cold','آیس آمریکانو','',95000,NULL,1),('lemonade','cold','لیموناد','',100000,NULL,2),('strawberry-shake','cold','شیک توت‌فرنگی','',135000,NULL,3),('nutella-shake','cold','شیک نوتلا','',140000,NULL,4),
      ('cheesecake','cake','چیزکیک','',150000,NULL,0),('tiramisu','cake','تیرامیسو','',155000,NULL,1),
      ('sandwich','food','ساندویچ','',210000,NULL,0),('cheese-croissant','food','کروسان پنیر','',140000,NULL,1),('veggie-omelet','food','املت سبزیجات','',180000,NULL,2),('caesar-salad','food','سالاد سزار','',195000,NULL,3)`
    ];
    for (const sql of seed) await env.DB.prepare(sql).run();
    dbReady = true;
  })().catch(err => { dbInitPromise = null; throw err; });
  await dbInitPromise;
}

const PUBLIC_HTML = `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>منوی کافه الیو | Elio</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;600;700&display=swap" rel="stylesheet"><style>
:root{--bg:#faf5e9;--card:#fffdf6;--ink:#2f3a2a;--muted:#7b8570;--green:#a8c686;--green-dark:#5f7f45;--line:#e6dfc8}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Vazirmatn,Tahoma,sans-serif;line-height:1.7}.wrap{max-width:720px;margin:auto;padding:0 18px 48px}header{text-align:center;padding:36px 0 18px}.leaf{width:56px;height:56px;color:var(--green-dark)}h1{margin:6px 0 0;font-size:2.4rem}h1 small{display:block;font-size:1rem;font-weight:300;color:var(--muted);letter-spacing:.3em}.tagline{color:var(--muted);font-size:.95rem}nav{position:sticky;top:0;z-index:5;background:var(--bg);padding:10px 0;display:flex;gap:8px;overflow-x:auto;scrollbar-width:none}nav button{flex:none;font:inherit;font-size:.95rem;border:1px solid var(--line);background:var(--card);color:var(--ink);padding:6px 18px;border-radius:999px;cursor:pointer}nav button.active{background:var(--green);border-color:var(--green);color:#243019;font-weight:600}.item{display:flex;align-items:baseline;gap:10px;padding:14px 4px;border-bottom:1px dashed var(--line)}.item:last-child{border:0}.name{font-weight:600}.desc{display:block;font-size:.85rem;color:var(--muted);font-weight:300}.dots{flex:1;border-bottom:2px dotted var(--line);transform:translateY(-4px);min-width:12px}.price{font-weight:600;color:var(--green-dark);white-space:nowrap}.price small{font-weight:300;color:var(--muted);font-size:.75rem;margin-right:3px}section{background:var(--card);border:1px solid var(--line);border-radius:20px;padding:10px 20px;margin-top:8px}.multi{display:block}.multi .name{margin-bottom:4px}.orow{display:flex;align-items:baseline;gap:10px;padding:3px 0}.olabel{font-size:.9rem}.pcell{min-width:76px;text-align:center;direction:rtl;unicode-bidi:plaintext}.head .pcell{font-size:.75rem;color:var(--muted);font-weight:300}footer{text-align:center;color:var(--muted);font-size:.8rem;margin-top:28px}.old{font-size:.75rem;color:#999;text-decoration:line-through;margin-left:5px}</style></head><body><div class="wrap"><header><svg class="leaf" viewBox="0 0 64 64" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M32 58V28"/><path d="M32 40C20 40 12 32 12 20c12 0 20 8 20 20z"/><path d="M32 32C32 20 40 12 52 12c0 12-8 20-20 20z"/></svg><h1>الیو<small>ELIO</small></h1><div class="tagline" id="tagline"></div></header><nav id="tabs"></nav><section id="list"></section><footer id="footer"></footer></div><script>
let data,active;const $=id=>document.getElementById(id),fmt=n=>Number(n).toLocaleString('fa-IR');function finalPrice(n){let x=Number(n||0)*(1+Number(data.settings.markup_percent||0)/100)*(1-Number(data.settings.discount_percent||0)/100);return Math.round(x)}
function price(n){let p=finalPrice(n),old=Number(data.settings.discount_percent)>0?Math.round(Number(n)*(1+Number(data.settings.markup_percent||0)/100)):0;return (old&&old!==p?'<span class="old">'+fmt(old)+'</span>':'')+'<span class="price">'+fmt(p)+'<small>'+esc(data.settings.currency||'تومان')+'</small></span>'}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function render(){let cats=data.categories; if(!cats.length){$('list').innerHTML='';return}if(!cats.some(c=>c.id===active))active=cats[0].id;$('tabs').innerHTML=cats.map(c=>'<button class="'+(c.id===active?'active':'')+'" data-id="'+esc(c.id)+'">'+esc(c.title)+'</button>').join('');let cat=cats.find(c=>c.id===active);$('list').innerHTML=cat.items.map(i=>{let name='<div class="name">'+esc(i.name)+(i.description?'<span class="desc">'+esc(i.description)+'</span>':'')+'</div>';if(i.options){let opts=typeof i.options==='string'?JSON.parse(i.options):i.options;return '<div class="item multi">'+name+opts.map(o=>'<div class="orow"><span class="olabel">'+esc(o.label)+'</span><span class="dots"></span>'+[].concat(o.price).map(n=>'<span class="pcell">'+price(n)+'</span>').join('')+'</div>').join('')+'</div>'}return '<div class="item">'+name+'<span class="dots"></span><div>'+price(i.price)+'</div></div>'}).join('');$('tagline').textContent=data.settings.tagline||'';$('footer').textContent=data.settings.footer||''}
$('tabs').onclick=e=>{let b=e.target.closest('button');if(b){active=b.dataset.id;render()}};fetch('/api/menu').then(r=>r.json()).then(d=>{data=d;active=d.categories[0]?.id;render()}).catch(()=>$('list').textContent='بارگذاری منو با مشکل مواجه شد.');
</script></body></html>`;
const ADMIN_HTML = `<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>مدیریت الیو</title><link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;600;700&display=swap" rel="stylesheet"><style>
:root{--bg:#faf5e9;--card:#fffdf6;--ink:#2f3a2a;--muted:#7b8570;--green:#a8c686;--line:#e6dfc8}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Vazirmatn,Tahoma,sans-serif}.wrap{max-width:1100px;margin:auto;padding:20px}.card{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:18px;margin:12px 0}h1,h2{margin-top:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}input,textarea,select,button{font:inherit;padding:10px;border:1px solid var(--line);border-radius:9px;background:white;color:var(--ink);max-width:100%}input,textarea,select{width:100%}button{cursor:pointer;background:var(--green);font-weight:600}.danger{background:#f4d4c9}.muted{color:var(--muted)}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.tabs{display:flex;gap:8px;flex-wrap:wrap}.tabs button{background:var(--card)}.tabs button.on{background:var(--green)}.hidden{display:none!important}.itemrow{display:grid;grid-template-columns:2fr 1fr auto auto;gap:8px;align-items:center;padding:10px 0;border-bottom:1px dashed var(--line)}table{width:100%;border-collapse:collapse}td,th{text-align:right;padding:8px;border-bottom:1px solid var(--line);font-size:.9rem;vertical-align:top}.notice{padding:10px;border-radius:8px;background:#eaf2df;margin:10px 0;white-space:pre-wrap}.login{max-width:430px;margin:9vh auto}@media(max-width:600px){.itemrow{grid-template-columns:1fr 1fr}.row{grid-template-columns:1fr}td,th{font-size:.78rem;padding:5px}}</style></head><body><div class="wrap"><div id="login" class="card login"><h1>ورود مدیریت الیو</h1><p class="muted">برای مدیریت منو، موجودی و گزارش‌ها وارد شوید.</p><form id="loginForm" method="post" action="/api/login"><label>نام کاربری<input name="username" autocomplete="username" required></label><br><br><label>گذرواژه<input name="password" type="password" autocomplete="current-password" required></label><br><br><button>ورود</button></form><div id="loginMsg"></div></div><div id="app" class="hidden"><h1>پنل مدیریت کافه الیو</h1><div class="muted" id="who"></div><div id="msg" class="notice hidden"></div><div class="tabs card" id="tabs"><button data-tab="menu" class="on">منو و قیمت‌ها</button><button data-tab="stock">موجودی</button><button data-tab="bulk">تخفیف و افزایش قیمت</button><button data-tab="settings">تنظیمات</button><button data-tab="profile">حساب کاربری</button><button data-tab="admins" id="adminsTab">مدیران</button><button data-tab="logs">تاریخچه</button><button id="logout" class="danger">خروج</button></div><div id="menu" class="panel card"><h2>دسته‌بندی‌ها</h2><div id="cats"></div><form id="catForm" class="row"><input name="title" placeholder="نام دسته‌بندی جدید" required><button>افزودن دسته‌بندی</button></form><hr><h2>آیتم‌ها</h2><div id="items"></div><h3 id="itemHeading">افزودن آیتم</h3><form id="itemForm"><input type="hidden" name="id"><div class="grid"><label>دسته‌بندی<select name="category_id" id="categorySelect"></select></label><label>نام آیتم<input name="name" required></label><label>قیمت (تومان، عدد صحیح)<input name="price" type="number" min="0"></label><label>توضیحات<input name="description"></label><label>گزینه‌های چندقیمتی (JSON اختیاری)<textarea name="options_json" rows="3" placeholder='[{"label":"تک","price":[70000]},{"label":"دوبل","price":[90000]}]'></textarea></label><label>ترتیب نمایش<input name="sort_order" type="number" value="0"></label><label><span><input name="stock_enabled" type="checkbox" style="width:auto"> کنترل موجودی فعال</span></label><label>مقدار موجودی<input name="stock_qty" type="number" step="0.01" value="0"></label><label>واحد موجودی<input name="stock_unit" value="عدد"></label></div><br><button>ذخیره آیتم</button> <button type="button" id="cancelEdit" class="danger">لغو و پاک‌کردن فرم</button></form></div><div id="stock" class="panel card hidden"><h2>مدیریت موجودی (فقط مدیران)</h2><p class="muted">موجودی در منوی عمومی نمایش داده نمی‌شود.</p><div id="stockRows"></div></div><div id="bulk" class="panel card hidden"><h2>تغییر سراسری قیمت‌ها</h2><p>این درصدها روی قیمت نمایش‌داده‌شده اعمال می‌شوند؛ قیمت پایه تغییر نمی‌کند. ابتدا افزایش قیمت، سپس تخفیف اعمال می‌شود.</p><form id="bulkForm" class="grid"><label>افزایش قیمت درصدی<input name="markup_percent" type="number" step=".01" min="0" max="500"></label><label>تخفیف درصدی<input name="discount_percent" type="number" step=".01" min="0" max="100"></label><button>ذخیره درصدها</button></form></div><div id="settings" class="panel card hidden"><h2>تنظیمات منو</h2><form id="settingsForm" class="grid"><label>شعار زیر نام کافه<input name="tagline"></label><label>واحد پول<input name="currency"></label><label>متن پایین صفحه<input name="footer"></label><button>ذخیره تنظیمات</button></form></div><div id="profile" class="panel card hidden"><h2>تغییر نام کاربری و گذرواژه</h2><p class="muted">برای حفظ امنیت، گذرواژه حداقل ۱۰ کاراکتر باشد. پس از تغییر نام کاربری یا گذرواژه، دوباره وارد شوید.</p><form id="profileForm" class="grid"><label>نام کاربری جدید<input name="username" required minlength="3" maxlength="40"></label><label>گذرواژه جدید (در صورت خالی‌بودن تغییر نمی‌کند)<input name="password" type="password" minlength="10"></label><button>ذخیره تغییرات حساب</button></form></div><div id="admins" class="panel card hidden"><h2>مدیریت مدیران</h2><p>این قسمت فقط برای root است. تغییرات مدیریتی نیز در تاریخچه امنیتی ثبت می‌شوند.</p><form id="adminForm" class="grid"><label>نام کاربری جدید<input name="username" required minlength="3" maxlength="40"></label><label>گذرواژه جدید<input name="password" type="password" required minlength="10"></label><button>ساخت مدیر</button></form><div id="adminRows"></div></div><div id="logs" class="panel card hidden"><h2>تاریخچه ورود و تغییرات</h2><button id="refreshLogs">به‌روزرسانی</button><div style="overflow:auto"><table><thead><tr><th>زمان</th><th>کاربر</th><th>عمل</th><th>جزئیات</th><th>IP</th></tr></thead><tbody id="logRows"></tbody></table></div></div></div></div><script>
const $=id=>document.getElementById(id);let me=null,all=null,selectedCat=null;
async function api(path,method='GET',data){let r=await fetch('/api'+path,{method,headers:data?{'content-type':'application/json'}:{},body:data?JSON.stringify(data):undefined});let d=await r.json().catch(()=>({error:'پاسخ نامعتبر'}));if(!r.ok)throw Error(d.error||'خطا');return d}
function msg(t){$('msg').textContent=t;$('msg').classList.remove('hidden');setTimeout(()=>$('msg').classList.add('hidden'),5000)}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function showTab(t){document.querySelectorAll('.panel').forEach(x=>x.classList.toggle('hidden',x.id!==t));document.querySelectorAll('#tabs button[data-tab]').forEach(x=>x.classList.toggle('on',x.dataset.tab===t));if(t==='logs')loadLogs();if(t==='stock')renderStock();if(t==='admins')loadAdmins()}
$('tabs').onclick=e=>{let b=e.target.closest('button');if(!b)return;if(b.id==='logout'){api('/logout','POST').finally(()=>location.reload());return}if(b.dataset.tab)showTab(b.dataset.tab)};
$('loginForm').onsubmit=async e=>{e.preventDefault();try{me=await api('/login','POST',Object.fromEntries(new FormData(e.target)));$('login').classList.add('hidden');$('app').classList.remove('hidden');$('who').textContent='واردشده به‌عنوان: '+me.username+' ('+me.role+')';$('adminsTab').classList.toggle('hidden',me.role!=='root');await loadAll()}catch(x){$('loginMsg').textContent=x.message}};
async function loadAll(){all=await api('/admin/data');$('profileForm').elements.username.value=me.username;renderCats();renderItems();renderStock();$('bulkForm').elements.markup_percent.value=all.settings.markup_percent||0;$('bulkForm').elements.discount_percent.value=all.settings.discount_percent||0;Object.keys(all.settings).forEach(k=>{if($('settingsForm').elements[k])$('settingsForm').elements[k].value=all.settings[k]});}
function renderCats(){ $('cats').innerHTML=all.categories.map(c=>'<span style="display:inline-flex;gap:5px;align-items:center;margin:4px"><button type="button" onclick="pickCat(\''+esc(c.id)+'\')">'+esc(c.title)+'</button><button type="button" class="danger" onclick="deleteCat(\''+esc(c.id)+'\')">حذف</button></span>').join('');$('categorySelect').innerHTML=all.categories.map(c=>'<option value="'+esc(c.id)+'">'+esc(c.title)+'</option>').join('');}
window.pickCat=id=>{selectedCat=id;renderItems()};
window.deleteCat=async id=>{if(!confirm('دسته‌بندی و تمام آیتم‌های آن حذف شود؟'))return;try{await api('/category/'+id,'DELETE');await loadAll();msg('دسته‌بندی حذف شد')}catch(e){msg(e.message)}};
function renderItems(){let rows=all.items.filter(i=>!selectedCat||i.category_id===selectedCat);$('items').innerHTML=rows.map(i=>'<div class="itemrow"><div><b>'+esc(i.name)+'</b><div class="muted">'+esc(all.categories.find(c=>c.id===i.category_id)?.title||'')+'</div></div><div>'+ (i.options_json?'چندقیمتی':Number(i.price||0).toLocaleString('fa-IR')+' تومان')+'</div><button type="button" onclick="editItem(\''+esc(i.id)+'\')">ویرایش</button><button type="button" class="danger" onclick="deleteItem(\''+esc(i.id)+'\')">حذف</button></div>').join('');}
window.editItem=id=>{let i=all.items.find(x=>x.id===id),f=$('itemForm');Object.keys(i).forEach(k=>{if(f.elements[k]){if(f.elements[k].type==='checkbox')f.elements[k].checked=!!i[k];else f.elements[k].value=i[k]??''}});$('itemHeading').textContent='ویرایش آیتم: '+i.name;window.scrollTo({top:$('itemForm').offsetTop,behavior:'smooth'})};
window.deleteItem=async id=>{if(!confirm('آیتم حذف شود؟'))return;try{await api('/item/'+id,'DELETE');await loadAll();msg('آیتم حذف شد')}catch(e){msg(e.message)}};
$('cancelEdit').onclick=()=>{$('itemForm').reset();$('itemForm').elements.id.value='';$('itemForm').elements.sort_order.value=0;$('itemForm').elements.stock_qty.value=0;$('itemHeading').textContent='افزودن آیتم'};
$('itemForm').onsubmit=async e=>{e.preventDefault();let f=e.target,o=Object.fromEntries(new FormData(f));o.stock_enabled=f.elements.stock_enabled.checked?1:0;o.price=o.price===''?null:Number(o.price);o.sort_order=Number(o.sort_order||0);o.stock_qty=Number(o.stock_qty||0);try{if(o.options_json){JSON.parse(o.options_json)}else o.options_json=null;await api('/item','POST',o);await loadAll();$('cancelEdit').click();msg('آیتم ذخیره شد')}catch(x){msg('خطا: '+x.message)}};
$('catForm').onsubmit=async e=>{e.preventDefault();try{await api('/category','POST',{title:e.target.title.value});e.target.reset();await loadAll();msg('دسته‌بندی اضافه شد')}catch(x){msg(x.message)}};
function renderStock(){$('stockRows').innerHTML=(all?.items||[]).map(i=>'<div class="itemrow"><div><b>'+esc(i.name)+'</b><div class="muted">'+(i.stock_enabled?'کنترل فعال':'کنترل غیرفعال')+'</div></div><div>'+esc(i.stock_qty)+' '+esc(i.stock_unit)+'</div><button onclick="stockEdit(\''+esc(i.id)+'\')">تغییر موجودی</button><span></span></div>').join('')}
window.stockEdit=async id=>{let i=all.items.find(x=>x.id===id),q=prompt('موجودی جدید '+i.name+' ('+i.stock_unit+')',i.stock_qty);if(q===null||q.trim()===''||!Number.isFinite(Number(q))||Number(q)<0)return;try{await api('/stock','POST',{id,stock_qty:Number(q)});await loadAll();msg('موجودی به‌روزرسانی شد')}catch(e){msg(e.message)}};
$('bulkForm').onsubmit=async e=>{e.preventDefault();try{await api('/settings','POST',{markup_percent:Number(e.target.markup_percent.value),discount_percent:Number(e.target.discount_percent.value)});await loadAll();msg('درصدها ذخیره شدند')}catch(x){msg(x.message)}};
$('settingsForm').onsubmit=async e=>{e.preventDefault();try{await api('/settings','POST',Object.fromEntries(new FormData(e.target)));await loadAll();msg('تنظیمات ذخیره شد')}catch(x){msg(x.message)}};
$('profileForm').onsubmit=async e=>{e.preventDefault();try{await api('/profile','POST',Object.fromEntries(new FormData(e.target)));alert('اطلاعات حساب تغییر کرد؛ لطفاً دوباره وارد شوید.');await api('/logout','POST').catch(()=>{});location.reload()}catch(x){msg(x.message)}};\nasync function loadAdmins(){if(me.role!=='root')return;let a=await api('/admins');$('adminRows').innerHTML='<table><tr><th>نام کاربری</th><th>نقش</th><th>وضعیت</th><th>عملیات</th></tr>'+a.map(x=>'<tr><td>'+esc(x.username)+'</td><td>'+esc(x.role)+'</td><td>'+ (x.active?'فعال':'غیرفعال')+'</td><td>'+(x.role!=='root'?'<button class="danger" onclick="removeAdmin('+x.id+')">حذف</button>':'حساب اصلی')+'</td></tr>').join('')+'</table>'}
window.removeAdmin=async id=>{if(!confirm('این مدیر حذف شود؟'))return;try{await api('/admin/'+id,'DELETE');await loadAdmins();msg('مدیر حذف شد')}catch(e){msg(e.message)}};
$('adminForm').onsubmit=async e=>{e.preventDefault();try{await api('/admins','POST',Object.fromEntries(new FormData(e.target)));e.target.reset();await loadAdmins();msg('مدیر جدید ساخته شد')}catch(x){msg(x.message)}};
async function loadLogs(){try{let logs=await api('/logs');$('logRows').innerHTML=logs.map(l=>'<tr><td>'+esc(new Date(l.created_at).toLocaleString('fa-IR'))+'</td><td>'+esc(l.actor_username)+'</td><td>'+esc(l.action)+'</td><td>'+esc(l.detail)+'</td><td>'+esc(l.ip)+'</td></tr>').join('')}catch(e){msg(e.message)}}
$('refreshLogs').onclick=loadLogs;
(async()=>{try{me=await api('/me');$('login').classList.add('hidden');$('app').classList.remove('hidden');$('who').textContent='واردشده به‌عنوان: '+me.username+' ('+me.role+')';$('adminsTab').classList.toggle('hidden',me.role!=='root');await loadAll()}catch{}})();
</script></body></html>`;
export default {
 async fetch(request,env) {
  const url=new URL(request.url), path=url.pathname;
  try { await ensureDatabase(env); } catch (e) { return new Response('خطا در آماده‌سازی دیتابیس D1: '+String(e.message||e), {status:500,headers:{'content-type':'text/plain; charset=utf-8'}}); }
  if(!env.SESSION_SECRET)return new Response('SESSION_SECRET secret is required',{status:500});
  if(path==='/setup') return html(`<!doctype html><html lang="fa" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>راه‌اندازی مدیر اصلی</title><style>body{font-family:Tahoma;background:#faf5e9;color:#2f3a2a;max-width:520px;margin:8vh auto;padding:20px}form{background:#fffdf6;padding:22px;border-radius:16px}input,button{box-sizing:border-box;width:100%;padding:12px;margin:8px 0;font:inherit}button{background:#a8c686;border:0;border-radius:8px}</style><h2>ساخت حساب مدیر اصلی الیو</h2><p>این صفحه فقط تا قبل از ساخت اولین مدیر قابل استفاده است. کلید راه‌اندازی را از تنظیمات Worker وارد کنید.</p><form id="f"><label>کلید راه‌اندازی<input name="key" required></label><label>نام کاربری (۳ تا ۴۰ حرف لاتین)<input name="username" value="root" required minlength="3"></label><label>گذرواژه (حداقل ۱۰ کاراکتر)<input name="password" type="password" required minlength="10"></label><button>ساخت مدیر اصلی</button><p id="m"></p></form><script>f.onsubmit=async e=>{e.preventDefault();m.textContent='در حال انجام...';let d=Object.fromEntries(new FormData(f));let r=await fetch('/api/setup-root',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(d)});let x=await r.json();m.textContent = r.ok
  ? 'مدیر اصلی ساخته شد. این صفحه را ببندید و وارد /admin-route شوید.'
  : ((x.error || 'خطا') + (x.detail ? '\nجزئیات: ' + x.detail : ''));}</script></html>`);
  if(path==='/api/setup-root'&&request.method==='POST'){
    if(!env.SETUP_KEY)return json({error:'ابتدا متغیر SETUP_KEY را در تنظیمات Worker تعریف کنید'},500);
    const count=await env.DB.prepare('SELECT COUNT(*) AS n FROM admins').first();
    if(Number(count?.n)>0)return json({error:'حساب مدیر از قبل ساخته شده است'},403);
    const b=await body(request);
    if(!b||b.key!==env.SETUP_KEY)return json({error:'کلید راه‌اندازی اشتباه است'},403);
    if(!/^[a-zA-Z0-9_.-]{3,40}$/.test(b.username||'')||typeof b.password!=='string'||b.password.length<10)return json({error:'نام کاربری نامعتبر یا گذرواژه کمتر از ۱۰ کاراکتر است'},400);
    try {
  const passwordHash = await hashPassword(b.password);

  await env.DB.prepare(
    "INSERT INTO admins(username,password_hash,role,active) VALUES(?,?, 'root',1)"
  ).bind(b.username, passwordHash).run();

  return json({ok:true});
} catch (err) {
  return json({
    error: 'خطای واقعی هنگام ساخت مدیر',
    detail: String(err?.message || err)
  }, 500);
}
  }
  if(path==='/')return html(PUBLIC_HTML);
  if(path===(env.ADMIN_PATH||'/admin-route'))return html(ADMIN_HTML);
  if(path.startsWith('/api/')) {
   if(request.method==='OPTIONS')return new Response(null,{headers:{'access-control-allow-origin':'null'}});
   try {
    if(path==='/api/menu'&&request.method==='GET'){
      const [cats,items,settings]=await Promise.all([env.DB.prepare('SELECT id,title,sort_order FROM categories WHERE active=1 ORDER BY sort_order,id').all(),env.DB.prepare('SELECT id,category_id,name,description,price,options_json,sort_order FROM menu_items WHERE active=1 ORDER BY sort_order,id').all(),env.DB.prepare('SELECT key,value FROM settings').all()]);
      const st=Object.fromEntries(settings.results.map(x=>[x.key,x.value]));
      return json({categories:cats.results.map(c=>({...c,items:items.results.filter(i=>i.category_id===c.id).map(i=>({...i,options:i.options_json?JSON.parse(i.options_json):null}))})),settings:st});
    }
    if(path==='/api/login'&&request.method==='POST'){
      const b=await body(request);if(!b||typeof b.username!=='string'||typeof b.password!=='string')return json({error:'اطلاعات ورود نامعتبر است'},400);
      const a=await env.DB.prepare('SELECT * FROM admins WHERE username=? AND active=1').bind(b.username).first();
      if(!a||!await verifyPassword(b.password,a.password_hash)){await audit(env,{id:a?.id,username:b.username},request,'login_failed','ورود ناموفق');return json({error:'نام کاربری یا گذرواژه نادرست است'},401)}
      const s=await token({id:a.id,username:a.username,role:a.role,exp:Date.now()+Number(env.SESSION_HOURS||12)*3600000},env.SESSION_SECRET);
      await audit(env,{id:a.id,username:a.username,role:a.role},request,'login_success','ورود موفق');
      return json({id:a.id,username:a.username,role:a.role},{headers:{'set-cookie':cookie(s,Number(env.SESSION_HOURS||12)*3600)}});
    }
    if(path==='/api/logout'&&request.method==='POST'){const s=await readSession(request,env);if(s)await audit(env,s,request,'logout','خروج');return json({ok:true},{headers:{'set-cookie':cookie('',0)}})}
    const session=await requireAdmin(request,env);
    if(path==='/api/me'&&request.method==='GET'){if(!session)return json({error:'ورود لازم است'},401);return json({id:session.id,username:session.username,role:session.role})}
    if(!session)return json({error:'ابتدا وارد شوید'},401);
    if(path==='/api/profile'&&request.method==='POST'){
      const b=await body(request);
      if(!b||!/^[a-zA-Z0-9_.-]{3,40}$/.test(b.username||''))return json({error:'نام کاربری باید ۳ تا ۴۰ حرف لاتین، عدد یا . _ - باشد'},400);
      if(b.password && (typeof b.password!=='string'||b.password.length<10))return json({error:'گذرواژه باید حداقل ۱۰ کاراکتر باشد'},400);
      try{
        if(b.password) await env.DB.prepare('UPDATE admins SET username=?,password_hash=? WHERE id=?').bind(b.username,await hashPassword(b.password),session.id).run();
        else await env.DB.prepare('UPDATE admins SET username=? WHERE id=?').bind(b.username,session.id).run();
      }catch{return json({error:'این نام کاربری قبلاً استفاده شده است'},409)}
      await audit(env,session,request,'profile_update','تغییر نام کاربری و/یا گذرواژه');
      return json({ok:true},{headers:{'set-cookie':cookie('',0)}});
    }
    if(path==='/api/admin/data'&&request.method==='GET'){
      const [cats,items,settings]=await Promise.all([env.DB.prepare('SELECT * FROM categories ORDER BY sort_order,id').all(),env.DB.prepare('SELECT * FROM menu_items ORDER BY category_id,sort_order,id').all(),env.DB.prepare('SELECT key,value FROM settings').all()]);
      return json({categories:cats.results,items:items.results,settings:Object.fromEntries(settings.results.map(x=>[x.key,x.value]))});
    }
    if(path==='/api/category'&&request.method==='POST'){
      const b=await body(request);if(!b?.title?.trim())return json({error:'نام دسته‌بندی لازم است'},400);
      const id='cat-'+crypto.randomUUID().slice(0,8);await env.DB.prepare('INSERT INTO categories(id,title,sort_order) VALUES(?,?,?)').bind(id,b.title.trim().slice(0,100),Date.now()).run();await audit(env,session,request,'category_create',b.title);return json({ok:true,id});
    }
    if(path.startsWith('/api/category/')&&request.method==='DELETE'){
      const id=path.split('/').pop();await env.DB.prepare('DELETE FROM categories WHERE id=?').bind(id).run();await audit(env,session,request,'category_delete',id);return json({ok:true});
    }
    if(path==='/api/item'&&request.method==='POST'){
      const b=await body(request);if(!b||!b.name?.trim()||!safeId(b.id||crypto.randomUUID().slice(0,8))||!b.category_id)return json({error:'شناسه، نام و دسته‌بندی معتبر لازم است'},400);
      let opts=null;try{if(b.options_json){opts=JSON.stringify(JSON.parse(b.options_json));if(!Array.isArray(JSON.parse(opts)))throw Error()}}catch{return json({error:'JSON گزینه‌ها معتبر نیست؛ باید آرایه باشد'},400)}
      if(!opts&&(!Number.isFinite(Number(b.price))||Number(b.price)<0))return json({error:'قیمت معتبر وارد کنید'},400);
      const id=b.id||crypto.randomUUID().slice(0,8),old=await env.DB.prepare('SELECT id FROM menu_items WHERE id=?').bind(id).first();
      const q='INSERT INTO menu_items(id,category_id,name,description,price,options_json,sort_order,stock_enabled,stock_qty,stock_unit,updated_at,updated_by) VALUES(?,?,?,?,?,?,?,?,?,?,strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'),?) ON CONFLICT(id) DO UPDATE SET category_id=excluded.category_id,name=excluded.name,description=excluded.description,price=excluded.price,options_json=excluded.options_json,sort_order=excluded.sort_order,stock_enabled=excluded.stock_enabled,stock_qty=excluded.stock_qty,stock_unit=excluded.stock_unit,updated_at=excluded.updated_at,updated_by=excluded.updated_by';
      await env.DB.prepare(q).bind(id,b.category_id,b.name.trim().slice(0,120),String(b.description||'').slice(0,300),opts?null:Number(b.price),opts,Number(b.sort_order||0),b.stock_enabled?1:0,Math.max(0,Number(b.stock_qty||0)),String(b.stock_unit||'عدد').slice(0,20),session.id).run();
      await audit(env,session,request,old?'item_update':'item_create',b.name);return json({ok:true,id});
    }
    if(path.startsWith('/api/item/')&&request.method==='DELETE'){const id=path.split('/').pop();await env.DB.prepare('DELETE FROM menu_items WHERE id=?').bind(id).run();await audit(env,session,request,'item_delete',id);return json({ok:true})}
    if(path==='/api/stock'&&request.method==='POST'){const b=await body(request);if(!b||!Number.isFinite(Number(b.stock_qty))||Number(b.stock_qty)<0)return json({error:'موجودی نامعتبر است'},400);await env.DB.prepare('UPDATE menu_items SET stock_qty=?,updated_at=strftime(\'%Y-%m-%dT%H:%M:%fZ\',\'now\'),updated_by=? WHERE id=?').bind(Number(b.stock_qty),session.id,b.id).run();await audit(env,session,request,'stock_update',`${b.id}: ${b.stock_qty}`);return json({ok:true})}
    if(path==='/api/settings'&&request.method==='POST'){
      const b=await body(request);for(const k of ['markup_percent','discount_percent'])if(k in b&&(!Number.isFinite(Number(b[k]))||Number(b[k])<0||Number(b[k])>(k==='discount_percent'?100:500)))return json({error:'درصد واردشده خارج از محدوده است'},400);
      for(const [k,v] of Object.entries(b)){if(!['tagline','currency','footer','markup_percent','discount_percent'].includes(k))continue;await env.DB.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').bind(k,String(v).slice(0,300)).run()}
      await audit(env,session,request,'settings_update',Object.keys(b).join(','));return json({ok:true});
    }
    if(path==='/api/logs'&&request.method==='GET'){const rows=await env.DB.prepare('SELECT created_at,actor_username,action,detail,ip FROM audit_log ORDER BY id DESC LIMIT 300').all();return json(rows.results)}
    if(path==='/api/admins'&&request.method==='GET'){if(session.role!=='root')return json({error:'فقط root اجازه دارد'},403);return json((await env.DB.prepare('SELECT id,username,role,active,created_at FROM admins ORDER BY id').all()).results)}
    if(path==='/api/admins'&&request.method==='POST'){
      if(session.role!=='root')return json({error:'فقط root اجازه دارد'},403);const b=await body(request);
      if(!/^[a-zA-Z0-9_.-]{3,40}$/.test(b?.username||'')||typeof b.password!=='string'||b.password.length<10)return json({error:'نام کاربری ۳ تا ۴۰ حرف لاتین و گذرواژه حداقل ۱۰ کاراکتر باشد'},400);
      try{await env.DB.prepare('INSERT INTO admins(username,password_hash,role,created_by) VALUES(?,? ,\'admin\',?)').bind(b.username,await hashPassword(b.password),session.id).run()}catch{return json({error:'این نام کاربری قبلاً ثبت شده است'},409)}
      await audit(env,session,request,'admin_create',b.username);return json({ok:true});
    }
    if(path.startsWith('/api/admin/')&&request.method==='DELETE'){
      if(session.role!=='root')return json({error:'فقط root اجازه دارد'},403);const id=Number(path.split('/').pop());const a=await env.DB.prepare('SELECT username,role FROM admins WHERE id=?').bind(id).first();if(!a||a.role==='root')return json({error:'این حساب قابل حذف نیست'},400);await env.DB.prepare('DELETE FROM admins WHERE id=?').bind(id).run();await audit(env,session,request,'admin_delete',a.username);return json({ok:true});
    }
    return json({error:'مسیر یا روش درخواست شناخته نشد'},404);
   } catch(e){return json({error:'خطای سرور',detail:env.ENVIRONMENT==='development'?String(e):undefined},500)}
  }
  return new Response('Not found',{status:404});
 }
};