import {existsSync,readFileSync,writeFileSync,renameSync,mkdirSync} from 'node:fs';
import {randomBytes,scryptSync,timingSafeEqual} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.dirname(fileURLToPath(import.meta.url));
const directory=process.env.SCHOOL_DATA_DIR||path.join(root,'data');
mkdirSync(directory,{recursive:true});
const file=path.join(directory,'accounts.json');
export function passwordRecord(password){const salt=randomBytes(24).toString('hex');return {salt,password:scryptSync(password,salt,64).toString('hex')};}
export function verifyPassword(account,password){const candidate=scryptSync(typeof password==='string'?password.slice(0,200):'',account?.salt||'invalid-account',64);return !!account&&!account.disabled&&timingSafeEqual(Buffer.from(account.password,'hex'),candidate);}
function persist(accounts){writeFileSync(file+'.tmp',JSON.stringify(accounts,null,2),{mode:0o600});renameSync(file+'.tmp',file);}
if(!existsSync(file)){
 const initial=[{id:'sa1',username:'jalal',name:'الأستاذ جلال السلطاني',role:'superadmin',title:'المشرف العام على الموقع ومدير النظام'},{id:'a1',username:'admin',name:'الأستاذ سالم شريدة العنزي',role:'admin',title:'مدير المدرسة'},{id:'a2',username:'salem',name:'الأستاذ سالم شريدة العنزي',role:'admin',title:'مدير المدرسة'},{id:'c1',username:'saud',name:'الأستاذ سعود ضحوي العنزي',role:'counselor',title:'الموجه الطلابي'},{id:'p1',username:'parent',name:'خالد العتيبي',role:'parent',title:'ولي أمر'},{id:'p2',username:'parent2',name:'سعد القحطاني',role:'parent',title:'ولي أمر'},{id:'t1',username:'teacher',name:'عبدالله السالم',role:'teacher',title:'معلم'}];
 const credentials=initial.map(a=>({...a,password:randomBytes(18).toString('base64url')}));
 persist(credentials.map(a=>({...a,...passwordRecord(a.password)})));
 writeFileSync(path.join(directory,'pilot-access.json'),JSON.stringify({notice:'بيانات دخول سرية للتجربة المغلقة. سلّم لكل مشارك حسابه فقط. الأسماء والطلاب تجريبيون.',accounts:credentials},null,2),{mode:0o600});
}
export function loadAccounts(){return JSON.parse(readFileSync(file,'utf8'));}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const [command,username]=process.argv.slice(2),accounts=loadAccounts(),account=accounts.find(a=>a.username===username);
 if(!account||!['reset','disable','enable'].includes(command))throw new Error('Usage: node accounts.mjs reset|disable|enable USERNAME');
 if(command==='disable'&&account.role==='superadmin')throw new Error('لا يمكن تعطيل حساب المشرف العام (الأستاذ جلال السلطاني)');
 if(command==='disable'&&account.role==='admin'&&accounts.filter(a=>['admin','superadmin'].includes(a.role)&&!a.disabled).length===1)throw new Error('Cannot disable the last administrator');
 if(command==='reset'){const password=randomBytes(18).toString('base64url');Object.assign(account,passwordRecord(password));writeFileSync(path.join(directory,'reset-access.json'),JSON.stringify({username,password},null,2),{mode:0o600});}
 else account.disabled=command==='disable';
 persist(accounts);console.log('Account updated. Restart the server to revoke existing sessions. Reset credentials, if requested, are in data/reset-access.json.');
}
