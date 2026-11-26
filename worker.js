import * as auth from './functions/api/auth.js';
import * as state from './functions/api/state.js';

const nf=()=>new Response('{"error":"not found"}',{status:404,headers:{'Content-Type':'application/json'}});

export default {
  async fetch(request, env) {
    const p = new URL(request.url).pathname;
    const m = request.method;
    try {
      if (p === '/api/auth' && m === 'POST') return await auth.onRequestPost({ request, env });
      if (p === '/api/state' && m === 'GET') return await state.onRequestGet({ request, env });
      if (p === '/api/state' && m === 'PUT') return await state.onRequestPut({ request, env });
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Ошибка сервера' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
    if (p.startsWith('/api/')) return nf();
    return env.ASSETS.fetch(request);
  }
};
