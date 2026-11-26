import {json,hex,unhex,pbkdf2,sha,userFrom} from './_util.js';
export async function onRequestPost({request,env}){
  let b;try{b=await request.json()}catch(e){return json({error:'Некорректный запрос'},400)}
  if(b.action==='logout'){
    const m=/^Bearer (\S+)$/.exec(request.headers.get('Authorization')||'');
    if(m)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha(m[1])).run();
    return json({ok:true})}
  const email=String(b.email||'').trim().toLowerCase(),pw=String(b.password||'');
  if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)||email.length>200)return json({error:'Проверь почту'},400);
  if(pw.length<6||pw.length>200)return json({error:'Пароль нужен от 6 символов'},400);
  let uid;
  if(b.action==='register'){
    if(await env.DB.prepare('SELECT 1 FROM users WHERE email=?').bind(email).first())return json({error:'Такая почта уже есть, нажми «Войти»'},409);
    uid=crypto.randomUUID();const salt=crypto.getRandomValues(new Uint8Array(16));
    await env.DB.prepare('INSERT INTO users(id,email,salt,hash,created) VALUES(?,?,?,?,?)').bind(uid,email,hex(salt),await pbkdf2(pw,salt),Date.now()).run()
  }else if(b.action==='login'){
    const u=await env.DB.prepare('SELECT id,salt,hash FROM users WHERE email=?').bind(email).first();
    const salt=u?unhex(u.salt):crypto.getRandomValues(new Uint8Array(16));
    const h=await pbkdf2(pw,salt);
    if(!u||h!==u.hash)return json({error:'Неверная почта или пароль'},401);
    uid=u.id
  }else return json({error:'Неизвестное действие'},400);
  const token=hex(crypto.getRandomValues(new Uint8Array(32)));
  await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,created) VALUES(?,?,?)').bind(await sha(token),uid,Date.now()).run();
  return json({token,email})}
