import http from 'node:http';
import {loadAccounts,verifyPassword,passwordRecord} from './accounts.mjs';
import {readFileSync,writeFileSync,mkdirSync,existsSync,renameSync} from 'node:fs';
import {randomBytes,randomUUID} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {once} from 'node:events';
const root=path.dirname(fileURLToPath(import.meta.url));
const dataDir=process.env.SCHOOL_DATA_DIR||path.join(root,'data');
mkdirSync(dataDir,{recursive:true});
const store=path.join(dataDir,'school.json');
const accountsFile=path.join(dataDir,'accounts.json');
const now=()=>new Date().toISOString();
let accounts=loadAccounts();
function saveAccounts(){writeFileSync(accountsFile+'.tmp',JSON.stringify(accounts,null,2),{mode:0o600});renameSync(accountsFile+'.tmp',accountsFile);}
const publicOrigin=process.env.SCHOOL_PUBLIC_ORIGIN||process.env.RENDER_EXTERNAL_URL||'';
if(publicOrigin&&new URL(publicOrigin).protocol!=='https:')throw new Error('SCHOOL_PUBLIC_ORIGIN must use HTTPS');
const secureCookie=publicOrigin?'; Secure':'';
const seed={students:[{id:'s1',name:'محمد خالد العتيبي',grade:'g4',parent:'p1'},{id:'s2',name:'عبدالله خالد العتيبي',grade:'g2',parent:'p1'},{id:'s3',name:'عمر سعد القحطاني',grade:'g3',parent:'p2'}],teachers:[{id:'t1',name:'عبدالله السالم'},{id:'t2',name:'فهد الدوسري'}],grades:['الأول','الثاني','الثالث','الرابع','الخامس','السادس'].map((x,i)=>({id:'g'+(i+1),name:'الصف '+x})),subjects:[{id:'math',name:'الرياضيات'},{id:'arabic',name:'لغتي الجميلة'},{id:'science',name:'العلوم'},{id:'islamic',name:'الدراسات الإسلامية'}],announcements:[{id:'n1',title:'نعود بشغف… ونتعلم بثقة',body:'أهلًا بطلابنا في رحلتهم التعليمية. تابعوا أوراق العمل والمراجعات من خلال مكتبة التعلم.',category:'أخبار المدرسة',createdAt:now()},{id:'n2',title:'معًا نغرس حب القراءة',body:'إعلان تجريبي: يشارك الطلاب في ساعة القراءة الأسبوعية بإشراف معلمي الصفوف.',category:'نشاط طلابي',createdAt:now()},{id:'n3',title:'استئذان أبنائكم أصبح أسهل',body:'يمكن لولي الأمر إرسال طلب الاستئذان ومتابعة قرار الإدارة من بوابته. انتظار الموافقة ضروري قبل الاستلام.',category:'لأولياء الأمور',createdAt:now()}],files:[{id:'f1',title:'مراجعة القيمة المنزلية',grade:'g4',subject:'math',teacher:'t1',kind:'مراجعات',filename:'math-review.txt',sample:'مراجعة تجريبية — القيمة المنزلية\n١. اكتب العدد ٣٤٥٦ بالصيغة التحليلية.\n٢. ما القيمة المنزلية للرقم ٥ في العدد ٢٥٧٠؟',createdAt:now()},{id:'f2',title:'ورقة عمل: الكائنات الحية',grade:'g3',subject:'science',teacher:'t2',kind:'أوراق عمل',filename:'science-worksheet.txt',sample:'ورقة عمل تجريبية — الكائنات الحية\n١. اذكر ثلاث حاجات أساسية للنبات.\n٢. قارن بين النبات والحيوان.',createdAt:now()},{id:'f3',title:'واجب القراءة والتعبير',grade:'g2',subject:'arabic',teacher:'t1',kind:'واجبات',filename:'reading-homework.txt',sample:'واجب تجريبي\nاقرأ قصة قصيرة واكتب جملتين عنها بمساعدة ولي أمرك.',createdAt:now()},{id:'f4',title:'دليل التعلم في الرياضيات',grade:'g4',subject:'math',teacher:'t1',kind:'كتب',filename:'learning-guide.txt',sample:'دليل تعليمي تجريبي وليس كتابًا وزاريًا معتمدًا.\nالموضوعات: الأعداد، القيمة المنزلية، الجمع والطرح.',createdAt:now()}],requests:[]};
let db=existsSync(store)?JSON.parse(readFileSync(store,'utf8')):structuredClone(seed);
function save(){writeFileSync(store+'.tmp',JSON.stringify(db,null,2));renameSync(store+'.tmp',store);}
if(!existsSync(store))save();
const sessions=new Map(),attempts=new Map(),publicAttempts=new Map();
function fail(status,message){throw Object.assign(new Error(message),{status});}
function text(v,max=300){if(typeof v!=='string'||!v.trim()||v.length>max)fail(400,'يرجى تعبئة الحقول المطلوبة بقيم صحيحة.');return v.trim();}
function role(user,...roles){if(!user)fail(401,'يرجى تسجيل الدخول أولًا.');if(user.role==='superadmin')return;if(!roles.includes(user.role))fail(403,'لا تملك صلاحية تنفيذ هذا الإجراء.');}
function ref(collection,id){if(!db[collection].some(x=>x.id===id))fail(400,'الاختيار غير موجود.');return id;}
const kinds=['كتب','أوراق عمل','واجبات','مراجعات','ملفات أخرى'];
const safeUser=u=>u?{id:u.id,name:u.name,role:u.role,title:u.title||(u.role==='superadmin'?'المشرف العام على الموقع ومدير النظام':'')}:null;
export const server=http.createServer(async(req,res)=>{
 const url=new URL(req.url,'http://127.0.0.1'); const p=url.pathname;
 res.setHeader('X-Robots-Tag','noindex, nofollow, noarchive');
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','same-origin');res.setHeader('X-Frame-Options','SAMEORIGIN');res.setHeader('Cache-Control','no-store');
 res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'");
 const json=(value,status=200)=>{res.writeHead(status,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(value));};
 try{
  const sid=(req.headers.cookie||'').split('; ').find(x=>x.startsWith('school_session='))?.slice(15);let session=sessions.get(sid);
  if(session&&session.expires<Date.now()){sessions.delete(sid);session=null;}const user=accounts.find(x=>x.id===session?.user);
  if(p.startsWith('/api/')&&!['/api/login','/api/me'].includes(p)&&!user)fail(401,'هذه تجربة مغلقة. يرجى تسجيل الدخول بحسابك المخصص.');
  let b={};
  if(['POST','PATCH','DELETE'].includes(req.method)){
   if(req.headers.origin!==(publicOrigin||`http://${req.headers.host}`))fail(403,'مصدر الطلب غير مسموح.');
   if(req.headers['content-type']!=='application/json')fail(415,'نوع الطلب غير مدعوم.');
   let chunks=[],size=0;for await(const chunk of req){size+=chunk.length;if(size>7500000)fail(413,'حجم الملف يتجاوز الحد المسموح (٥ ميغابايت).');chunks.push(chunk);}
   try{b=JSON.parse(Buffer.concat(chunks).toString()||'{}');}catch{fail(400,'الطلب غير صالح.');}
   if(!['/api/login'].includes(p)&&(!session||req.headers['x-csrf-token']!==session.csrf))fail(403,'انتهت الجلسة. يرجى تسجيل الدخول مجددًا.');
  }
  if(p==='/api/login'&&req.method==='POST'){
   const key=req.socket.remoteAddress,attempt=attempts.get(key)||{count:0,until:Date.now()+60000};if(attempt.until<Date.now()){attempt.count=0;attempt.until=Date.now()+60000;}
   if(attempt.count>=15)fail(429,'محاولات كثيرة. انتظر دقيقة ثم أعد المحاولة.');
   const a=accounts.find(x=>x.username===b.username);const valid=verifyPassword(a,b.password);
   if(!valid){attempt.count++;attempts.set(key,attempt);fail(401,'اسم المستخدم أو كلمة المرور غير صحيحة.');}
   attempts.delete(key);if(sid)sessions.delete(sid);const id=randomBytes(32).toString('hex'),csrf=randomBytes(24).toString('hex');sessions.set(id,{user:a.id,csrf,expires:Date.now()+8*3600000});res.setHeader('Set-Cookie',`school_session=${id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800${secureCookie}`);return json({user:safeUser(a),csrf});
  }
  if(p==='/api/logout'&&req.method==='POST'){sessions.delete(sid);res.setHeader('Set-Cookie',`school_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secureCookie}`);return json({ok:true});}
  if(p==='/api/me')return json({user:safeUser(user),csrf:session?.csrf});
  if(p==='/api/books'&&req.method==='GET'){
   const catalogPath=path.join(root,'books.json');
   const catalog=existsSync(catalogPath)?JSON.parse(readFileSync(catalogPath,'utf8').replace(/^\uFEFF/,'')):{books:[]};
   return json({importedAt:catalog.importedAt,books:catalog.books.map(({url,source,...book})=>book)});
  }
  if(p.startsWith('/api/books/download/')&&req.method==='GET'){
   const catalog=JSON.parse(readFileSync(path.join(root,'books.json'),'utf8').replace(/^\uFEFF/,''));
   const book=catalog.books.find(b=>b.id===p.split('/').pop());if(!book)fail(404,'الكتاب غير موجود.');
   const source=new URL(book.url);
   if(source.protocol!=='https:'||source.hostname!=='iencontent.ien.edu.sa')fail(400,'مصدر الكتاب غير مدعوم.');
   let upstream;try{upstream=await fetch(source,{redirect:'error',signal:AbortSignal.timeout(180000)});}catch{fail(502,'تعذر الاتصال بمصدر الكتاب. حاول مجددًا بعد قليل.');}
   if(!upstream.ok||!upstream.body)fail(502,'الكتاب غير متاح من المصدر حاليًا.');
   const reader=upstream.body.getReader();let first=Buffer.alloc(0);
   while(first.length<5){const part=await reader.read();if(part.done)break;first=Buffer.concat([first,Buffer.from(part.value)]);}
   if(first.subarray(0,5).toString()!=='%PDF-'){await reader.cancel();fail(502,'لم يُرجع المصدر ملف PDF صالحًا.');}
   const filename=(book.title+' - '+book.grade).replace(/[\\/\r\n]/g,' ') + '.pdf';
   res.writeHead(200,{'Content-Type':'application/pdf','Content-Disposition':`attachment; filename="school-book.pdf"; filename*=UTF-8''${encodeURIComponent(filename)}`});
   try{res.write(first);while(true){const part=await reader.read();if(part.done)break;if(!res.write(part.value))await once(res,'drain');}res.end();}catch(e){res.destroy(e);}finally{reader.releaseLock();}return;
  }
  if(p==='/api/catalog'&&req.method==='GET')return json({grades:db.grades,subjects:db.subjects,teachers:db.teachers,announcements:db.announcements,files:db.files.map(({content,sample,...f})=>({...f,size:content?Buffer.from(content,'base64').length:Buffer.byteLength(sample||'')}))});
  if(p.startsWith('/api/download/')&&req.method==='GET'){
   const f=db.files.find(x=>x.id===p.split('/').pop());if(!f)fail(404,'الملف غير موجود.');const content=f.content?Buffer.from(f.content,'base64'):Buffer.from('\ufeff'+f.sample);
   res.writeHead(200,{'Content-Type':'application/octet-stream','Content-Disposition':`attachment; filename="school-resource${path.extname(f.filename)}"; filename*=UTF-8''${encodeURIComponent(f.filename)}`});return res.end(content);
  }
  if(p==='/api/students'&&req.method==='GET'){role(user,'admin','counselor','parent');return json(db.students.filter(x=>['admin','counselor'].includes(user.role)||x.parent===user.id));}
  if(p==='/api/leave-requests'&&req.method==='POST'){
   role(user,'parent','admin','counselor');
   const studentName=text(b.studentName,120).replace(/\s+/g,' ');if(studentName.split(' ').length<4)fail(400,'يرجى كتابة الاسم الرباعي.');
   const parentId=text(b.parentId,10);if(!/^\d{10}$/.test(parentId))fail(400,'رقم الهوية يجب أن يتكون من 10 أرقام.');
   const parentPhone=text(b.parentPhone,12);if(!/^9665\d{8}$/.test(parentPhone))fail(400,'رقم جوال ولي الأمر غير صالح.');
   const grade=ref('grades',b.grade),reason=text(b.reason,500),time=text(b.time,30),key=text(b.requestKey,100);
   if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(time))fail(400,'موعد غير صالح.');
   const when=new Date(time+'+03:00');if(!Number.isFinite(when.getTime())||when.getTime()<Date.now()-60000||when.getTime()>Date.now()+30*86400000)fail(400,'اختر موعدًا قادمًا خلال 30 يومًا.');
   const prior=db.requests.find(x=>x.source==='whatsapp'&&x.requestKey===key&&x.owner===user.id);
   if(prior){if(prior.studentName!==studentName||prior.parentId!==parentId||prior.parentPhone!==parentPhone||prior.grade!==grade||prior.reason!==reason||prior.time!==time)fail(409,'تغيرت بيانات الطلب. أعد فتح النموذج.');return json({id:prior.id});}
   const ip=req.socket.remoteAddress,limit=publicAttempts.get(ip)||{count:0,until:0};if(limit.until<Date.now()){limit.count=0;limit.until=Date.now()+600000;}if(limit.count>=10)fail(429,'طلبات كثيرة. انتظر قليلًا ثم حاول مجددًا.');limit.count++;publicAttempts.set(ip,limit);
   const r={id:randomUUID(),requestKey:key,owner:user.id,source:'whatsapp',studentName,grade,gradeName:db.grades.find(g=>g.id===grade).name,parentId,parentPhone,reason,time,status:'جديد',createdAt:now(),note:'',history:[{status:'جديد',at:now(),by:'نموذج ولي الأمر — بانتظار التحقق'}]};db.requests.unshift(r);save();return json({id:r.id},201);
  }
  if(p.startsWith('/api/requests/')&&req.method==='GET'){role(user,'admin','counselor');const r=db.requests.find(x=>x.id===p.split('/').pop());if(!r)fail(404,'الطلب غير موجود.');const {requestKey,...record}=r;return json(record);}
  if(p==='/api/requests'&&req.method==='GET'){role(user,'admin','counselor','parent');return json(db.requests.filter(x=>['admin','counselor'].includes(user.role)||x.parent===user.id).map(({requestKey,...x})=>({...x,studentName:x.studentName||db.students.find(s=>s.id===x.student)?.name||'طالب مؤرشف',gradeName:x.gradeName||db.grades.find(g=>g.id===db.students.find(s=>s.id===x.student)?.grade)?.name||''})));}
  if(p==='/api/requests'&&req.method==='POST'){
   role(user,'parent');const student=db.students.find(x=>x.id===b.student&&x.parent===user.id);if(!student)fail(403,'هذا الطالب غير مرتبط بحسابك.');
   const reason=text(b.reason,500);const time=text(b.time,30);if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(time))fail(400,'يرجى تحديد موعد صحيح.');const dt=new Date(time+'+03:00');if(!Number.isFinite(dt.getTime())||dt<Date.now()-60000||dt>Date.now()+30*86400000)fail(400,'اختر موعدًا قادمًا خلال ٣٠ يومًا.');
   if(db.requests.some(x=>x.student===student.id&&['جديد','تمت الموافقة'].includes(x.status)))fail(409,'يوجد طلب نشط لهذا الطالب. انتظر إغلاقه قبل تقديم طلب آخر.');
   const r={id:randomUUID(),student:student.id,parent:user.id,reason,time,status:'جديد',createdAt:now(),history:[{status:'جديد',at:now(),by:user.name}],note:''};db.requests.unshift(r);save();return json(r,201);
  }
  if(p.startsWith('/api/requests/')&&req.method==='PATCH'){
   role(user,'admin','counselor');const r=db.requests.find(x=>x.id===p.split('/').pop());if(!r)fail(404,'الطلب غير موجود.');const transitions={'جديد':['تمت الموافقة','مرفوض'],'تمت الموافقة':['تم خروج الطالب']};if(!transitions[r.status]?.includes(b.status))fail(409,'لا يمكن تغيير حالة هذا الطلب بهذا الإجراء.');
   if(b.status==='مرفوض')text(b.note,300);r.status=b.status;r.note=typeof b.note==='string'?b.note.slice(0,300):'';const author=user.name+(user.title?` (${user.title})`:'');r.history.push({status:r.status,at:now(),by:author,note:r.note});save();return json(r);
  }
  if(p==='/api/files'&&req.method==='POST'){
   role(user,'teacher','admin');const filename=text(b.filename,150);const ext=path.extname(filename).toLowerCase();if(!['.pdf','.docx','.pptx','.xlsx','.txt','.png','.jpg','.jpeg'].includes(ext))fail(400,'صيغة الملف غير مدعومة.');
   if(typeof b.content!=='string'||!/^[A-Za-z0-9+/]*={0,2}$/.test(b.content))fail(400,'محتوى الملف غير صالح.');const bytes=Buffer.from(b.content,'base64');if(!bytes.length||bytes.length>5*1024*1024)fail(400,'ارفع ملفًا غير فارغ لا يتجاوز ٥ ميغابايت.');
   if(!kinds.includes(b.kind))fail(400,'اختر نوع المحتوى.');const f={id:randomUUID(),title:text(b.title,120),grade:ref('grades',b.grade),subject:ref('subjects',b.subject),teacher:user.role==='teacher'?user.id:ref('teachers',b.teacher),kind:b.kind,filename,content:b.content,createdAt:now()};db.files.unshift(f);save();return json({id:f.id},201);
  }
  if(p.startsWith('/api/files/')&&req.method==='DELETE'){role(user,'teacher','admin');const f=db.files.find(x=>x.id===p.split('/').pop());if(!f)fail(404,'الملف غير موجود.');if(user.role!=='admin'&&f.teacher!==user.id)fail(403,'يمكنك إدارة ملفاتك فقط.');db.files=db.files.filter(x=>x.id!==f.id);save();return json({ok:true});}
  if(p==='/api/announcements'&&req.method==='POST'){role(user,'teacher','admin');const n={id:randomUUID(),title:text(b.title,120),body:text(b.body,1500),category:user.role==='teacher'?'تنبيه من المعلم':'إعلان مدرسي',createdAt:now()};db.announcements.unshift(n);save();return json(n,201);}
  if(p.startsWith('/api/manage/')){
   role(user,'admin');const [, , ,collection,id]=p.split('/');if(!['students','teachers','grades','subjects','announcements'].includes(collection))fail(404,'القسم غير موجود.');
   if(req.method==='GET')return json({items:db[collection],parents:accounts.filter(a=>a.role==='parent').map(safeUser)});
   if(req.method==='POST'||req.method==='PATCH'){
    const item=collection==='announcements'?{title:text(b.title,120),body:text(b.body,1500),category:'إعلان مدرسي'}:{name:text(b.name,100)};
    if(collection==='students'){item.grade=ref('grades',b.grade);if(!accounts.some(a=>a.id===b.parent&&a.role==='parent'))fail(400,'اختر ولي أمر صحيحًا.');item.parent=b.parent;}
    if(req.method==='PATCH'){const current=db[collection].find(x=>x.id===id);if(!current)fail(404,'السجل غير موجود.');if(collection==='students'&&item.parent!==current.parent&&db.requests.some(r=>r.student===id))fail(409,'لا يمكن تغيير ارتباط ولي الأمر لطالب له طلبات مسجلة.');Object.assign(current,item);}else db[collection].push({id:randomUUID(),...item,...(collection==='announcements'?{createdAt:now()}:{})});save();return json({ok:true});
   }
   if(req.method==='DELETE'){
    if(!db[collection].some(x=>x.id===id))fail(404,'السجل غير موجود.');
    const linked=collection==='students'?db.requests.some(x=>x.student===id):collection==='grades'?db.students.some(x=>x.grade===id)||db.files.some(x=>x.grade===id):collection==='subjects'?db.files.some(x=>x.subject===id):collection==='teachers'?db.files.some(x=>x.teacher===id)||accounts.some(x=>x.id===id):false;
    if(linked)fail(409,'هذا السجل مرتبط ببيانات أخرى ولا يمكن حذفه.');db[collection]=db[collection].filter(x=>x.id!==id);save();return json({ok:true});
   }
  }
  if(p.startsWith('/api/superadmin/')){
   if(!user||user.role!=='superadmin')fail(403,'هذا القسم مخصص حصريًا للأستاذ جلال السلطاني (المشرف العام على الموقع).');
   if(p==='/api/superadmin/overview'&&req.method==='GET'){
    return json({
     supervisor:'الأستاذ جلال السلطاني',
     role:'المشرف العام ومدير النظام',
     accountsCount:accounts.length,
     requestsCount:db.requests.length,
     filesCount:db.files.length,
     studentsCount:db.students.length,
     teachersCount:db.teachers.length,
     activeSessions:sessions.size
    });
   }
   if(p==='/api/superadmin/accounts'&&req.method==='GET'){
    return json(accounts.map(a=>({id:a.id,username:a.username,name:a.name,role:a.role,title:a.title||'',disabled:!!a.disabled})));
   }
   if(p==='/api/superadmin/accounts'&&req.method==='POST'){
    const username=text(b.username,50).toLowerCase();
    if(accounts.some(a=>a.username===username))fail(409,'اسم المستخدم مسجل مسبقًا.');
    const validRoles=['admin','teacher','parent'];
    if(!validRoles.includes(b.role))fail(400,'الدور غير صالح.');
    const name=text(b.name,100);
    const rawPass=b.password?text(b.password,100):randomBytes(12).toString('base64url');
    const rec={id:b.role[0]+randomUUID().slice(0,6),username,name,role:b.role,...passwordRecord(rawPass)};
    accounts.push(rec);saveAccounts();
    return json({ok:true,account:{id:rec.id,username:rec.username,name:rec.name,role:rec.role,password:rawPass}},201);
   }
   if(p.startsWith('/api/superadmin/accounts/')&&req.method==='PATCH'){
    const targetUsername=p.split('/').pop();
    const target=accounts.find(a=>a.username===targetUsername);
    if(!target)fail(404,'الحساب غير موجود.');
    if(b.action==='toggle'){
     if(target.role==='superadmin')fail(403,'لا يمكن تعطيل حساب المشرف العام.');
     target.disabled=!target.disabled;
     saveAccounts();
     return json({ok:true,disabled:target.disabled});
    }
    if(b.action==='reset'){
     const newPass=b.password?text(b.password,100):randomBytes(12).toString('base64url');
     Object.assign(target,passwordRecord(newPass));
     saveAccounts();
     return json({ok:true,password:newPass});
    }
    fail(400,'الإجراء غير مدعوم.');
   }
  }
  if(p.startsWith('/api/'))fail(404,'المسار غير موجود.');
  const assets={'/school-banner.png':['school-banner.png','image/png'],'/amiri-bold.ttf':['amiri-bold.ttf','font/ttf'],'/':['index.html','text/html; charset=utf-8'],'/app.js':['app.js','text/javascript; charset=utf-8'],'/style.css':['style.css','text/css; charset=utf-8'],'/favicon.svg':['favicon.svg','image/svg+xml']};const asset=assets[p];if(!asset)fail(404,'الصفحة غير موجودة.');res.writeHead(200,{'Content-Type':asset[1]});res.end(readFileSync(path.join(root,'public',asset[0])));
 }catch(e){if(!res.headersSent)json({error:e.status?e.message:'تعذر إكمال العملية. حاول مرة أخرى.'},e.status||500);else res.end();}
});
if(process.env.SCHOOL_TEST!=='1')server.listen(Number(process.env.PORT)||4173,process.env.SCHOOL_BIND||'127.0.0.1',()=>console.log('School preview: http://127.0.0.1:'+server.address().port));
