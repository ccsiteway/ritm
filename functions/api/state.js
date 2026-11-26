import {json,userFrom} from './_util.js';
export async function onRequestGet({request,env}){
  const uid=await userFrom(request,env);if(!uid)return json({error:'auth'},401);
  const r=await env.DB.prepare('SELECT data,ts FROM state WHERE user_id=?').bind(uid).first();
  if(!r)return json({ts:0,data:null});
  return new Response('{"ts":'+r.ts+',"data":'+r.data+'}',{headers:{'Content-Type':'application/json','Cache-Control':'no-store'}})}
export async function onRequestPut({request,env}){
  const uid=await userFrom(request,env);if(!uid)return json({error:'auth'},401);
  const txt=await request.text();
  if(txt.length>1900000)return json({error:'Данных слишком много для облака (лимит около 2 МБ)'},413);
  let b;try{b=JSON.parse(txt)}catch(e){return json({error:'bad json'},400)}
  if(!b||typeof b.data!=='object'||!b.data||!Number.isFinite(b.ts))return json({error:'bad body'},400);
  await env.DB.prepare('INSERT INTO state(user_id,data,ts) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET data=excluded.data,ts=excluded.ts').bind(uid,JSON.stringify(b.data),b.ts).run();
  return json({ok:true})}
