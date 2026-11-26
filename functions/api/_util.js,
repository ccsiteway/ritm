export const json=(o,status=200)=>new Response(JSON.stringify(o),{status,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});
const enc=new TextEncoder();
export const hex=u=>[...new Uint8Array(u)].map(b=>b.toString(16).padStart(2,'0')).join('');
export const unhex=s=>Uint8Array.from(s.match(/../g)||[],h=>parseInt(h,16));
export async function pbkdf2(pw,salt){
  const k=await crypto.subtle.importKey('raw',enc.encode(pw),'PBKDF2',false,['deriveBits']);
  return hex(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt,iterations:100000},k,256))}
export const sha=async s=>hex(await crypto.subtle.digest('SHA-256',enc.encode(s)));
export async function userFrom(request,env){
  const m=/^Bearer (\S+)$/.exec(request.headers.get('Authorization')||'');
  if(!m)return null;
  const r=await env.DB.prepare('SELECT user_id FROM sessions WHERE token_hash=?').bind(await sha(m[1])).first();
  return r?r.user_id:null}
