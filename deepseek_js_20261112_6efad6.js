/**
 * Trae + WorkBuddy + Qoder 每日签到 —— Cloudflare Worker（单文件）
 * 安全审计修复版：P0 - P3 全部修复
 */

/* ================================================================== */
/* 模块一：Trae —— 设备身份 / 扫码授权 / 签到 */
/* ================================================================== */

const Trae = (() => {
const API = 'https://api.trae.cn';

const EP = {
  claim: '/trae/api/v2/ug/checkin_credits/claim',
  status: '/trae/api/v2/ug/checkin_credits/status',
  entitle: '/trae/api/v2/pay/user_current_entitlement_list',
  exchange: '/trae/api/v3/oauth/ExchangeToken',
  exchangeLegacy: 'https://api.trae.com.cn/cloudide/api/v3/trae/oauth/ExchangeToken',
};

const CLIENT_ID_IDE = 'ono9krqynydwx5';
const CLIENT_ID_OLD = 'en1oxy7wnw8j9n';
const IDE_VERSION = '1.107.1';
const UA = 'Trae/' + IDE_VERSION;

const AUTHORIZE_BASE = 'https://www.trae.cn';
const OAUTH_APP_ID = '6eefa01c-1036-4c7e-9ca5-d891f63bfcd8';
const OAUTH_APP_VERSION = '3.3.100';
const OAUTH_PLUGIN_VERSION = '2.3.83560';
const CALLBACK_LOCAL = 'http://127.0.0.1:17388/authorize';
const TRAE_LINE = { authFrom: 'trae', clientId: 'ono9krqynydwx5', platform: 'IDE_PC', label: 'Trae' };
const LOGIN_TTL = 900;

const REQ_BODY = '{"req_source": 1}';
const CODE_OK = 0;
const CODE_ALREADY = 9095;
const CODE_RATE = 9074;
const AUTH_FAIL_CODES = [1001, 1002, 401, 403];
const COOLDOWN_MIN = 55;
const PEAK_COOLDOWN_MIN = 12;

const enc = new TextEncoder();
const dec = new TextDecoder();

function b64encode(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function b64decode(str) {
  const bin = atob(String(str).replace(/\s+/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlEncode(buf) {
  return b64encode(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  return b64decode(s + '='.repeat((4 - (s.length % 4)) % 4));
}

function randomId(bytes = 12) {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

function randomHex(bytes = 16) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}

/** FIX P1-2：哈希后定长比较 */
async function timingSafeEqual(a, b) {
  const h = async (s) => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(String(s ?? ''))));
  const [x, y] = await Promise.all([h(a), h(b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function deriveKey(env, salt) {
  const raw = env.TRAE_MASTER_KEY;
  if (!raw) throw new Error('缺少 MASTER_KEY');
  let master;
  try { master = b64decode(raw.trim()); } catch { throw new Error('MASTER_KEY 不是合法 base64'); }
  if (master.length !== 32) throw new Error('MASTER_KEY 必须是 32 字节');

  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('trae-signin/v1/account') },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function sealRecord(env, obj) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(env, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  return JSON.stringify({ v: 1, s: b64encode(salt), i: b64encode(iv), d: b64encode(ct) });
}

async function openRecord(env, text) {
  const box = JSON.parse(text);
  if (box.v !== 1) throw new Error('不认识的记录版本');
  const key = await deriveKey(env, b64decode(box.s));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64decode(box.i) }, key, b64decode(box.d));
  return JSON.parse(dec.decode(pt));
}

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

function pemToDer(pem) {
  return b64decode(String(pem).replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''));
}

function bytesToBig(bytes) {
  let h = '';
  for (const b of bytes) h += b.toString(16).padStart(2, '0');
  return h ? BigInt('0x' + h) : 0n;
}

function bigToBytes(x) {
  let h = x.toString(16);
  if (h.length % 2) h = '0' + h;
  const out = [];
  for (let i = 0; i < h.length; i += 2) out.push(parseInt(h.slice(i, i + 2), 16));
  return Uint8Array.from(out);
}

function derInt(bytes) {
  const arr = Array.from(bytes);
  let i = 0;
  while (i < arr.length - 1 && arr[i] === 0) i++;
  let v = arr.slice(i);
  if (v.length === 0 || (v[0] & 0x80)) v = [0, ...v];
  return [0x02, v.length, ...v];
}

function derSig(rBytes, sBytes) {
  const body = derInt(rBytes).concat(derInt(sBytes));
  return Uint8Array.from([0x30, body.length, ...body]);
}

function derNext(buf, i) {
  const tag = buf[i++];
  let len = buf[i++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let k = 0; k < n; k++) len = len * 256 + buf[i++];
  }
  return { tag, val: buf.subarray(i, i + len), next: i + len };
}

function sec1Scalar(pem) {
  const der = pemToDer(pem);
  const outer = derNext(der, 0);
  if (outer.tag !== 0x30) throw new Error('SEC1 私钥结构异常');
  let i = 0, d = null;
  while (i < outer.val.length) {
    const node = derNext(outer.val, i);
    if (node.tag === 0x04 && !d) d = node.val;
    i = node.next;
  }
  if (!d) throw new Error('SEC1 私钥里没找到私钥标量');
  return d;
}

function spkiPoint(pem) {
  const der = pemToDer(pem);
  const outer = derNext(der, 0);
  if (outer.tag !== 0x30) throw new Error('公钥结构异常');
  const alg = derNext(outer.val, 0);
  const bits = derNext(outer.val, alg.next);
  if (bits.tag !== 0x03 || bits.val[0] !== 0 || bits.val[1] !== 0x04) throw new Error('公钥不是未压缩的 P-256 点');
  return { x: bits.val.subarray(2, 34), y: bits.val.subarray(34, 66) };
}

const ecdsaAlg = { name: 'ECDSA', namedCurve: 'P-256' };

async function importPrivateKey(pem, pubPem) {
  if (!pem) throw new Error('缺少设备私钥');
  try {
    return await crypto.subtle.importKey('pkcs8', pemToDer(pem), ecdsaAlg, false, ['sign']);
  } catch (e) {
    if (!pubPem) throw new Error('私钥不是 PKCS#8，且没有公钥可用于 SEC1 转换');
    const d = sec1Scalar(pem);
    const { x, y } = spkiPoint(pubPem);
    return crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', d: b64urlEncode(d), x: b64urlEncode(x), y: b64urlEncode(y), ext: true }, ecdsaAlg, false, ['sign']);
  }
}

async function ecSign(pem, data, pubPem) {
  const key = await importPrivateKey(pem, pubPem);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, data));
  let r = bytesToBig(raw.subarray(0, 32));
  let s = bytesToBig(raw.subarray(32));
  if (s > P256_N >> 1n) s = P256_N - s;
  return b64encode(derSig(bigToBytes(r), bigToBytes(s)));
}

async function traeFetch(path, { method = 'POST', headers = {}, body = '{}', timeout = 20000 } = {}) {
  const url = path.startsWith('http') ? path : API + path;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(url, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: method === 'GET' ? undefined : body, signal: ctrl.signal });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, json, text };
  } finally { clearTimeout(timer); }
}

function ugHeaders(token, acct) {
  const h = { Authorization: 'Cloud-IDE-JWT ' + token, 'X-User-Region': 'CN', 'User-Agent': UA, 'Content-Type': 'application/json' };
  const did = String(acct?.deviceId ?? '').trim();
  if (did) h['x-device-id'] = did;
  h['x-device-type'] = String(acct?.deviceType || 'Windows');
  h['x-os-version'] = String(acct?.osVersion || '10.0.19045');
  h['x-app-version'] = IDE_VERSION;
  const brand = String(acct?.deviceBrand ?? '').trim();
  if (brand) h['x-device-brand'] = brand;
  return h;
}

function jwtExp(token) {
  try {
    const json = JSON.parse(dec.decode(b64urlDecode(String(token).split('.')[1])));
    let v = Number(json.exp || json.TokenExpireAt || 0) || 0;
    if (v > 1e12) v = Math.floor(v / 1000);
    return v;
  } catch { return 0; }
}

async function buildProof(acct, path, clientId, platformCode, refreshToken) {
  const ts = Math.floor(Date.now() / 1000);
  const nonce = randomHex(16);
  const canonical = ['POST', path, clientId, refreshToken, String(ts), nonce].join('\n');
  const signature = await ecSign(acct.privateKeyPem, enc.encode(canonical), acct.publicKeyPem);
  return {
    proof: { Timestamp: ts, Nonce: nonce, Signature: signature },
    info: {
      DeviceID: String(acct.deviceId || ''), MachineID: String(acct.machineId || ''), PlatformCode: platformCode,
      DeviceType: 'PC', DeviceName: String(acct.deviceName || 'PC'), DeviceModel: String(acct.deviceModel || ''),
      ClientVersion: IDE_VERSION, DevicePublicKey: String(acct.publicKeyPem || ''), DeviceBrand: String(acct.deviceBrand || ''),
      DeviceCPU: '', OSInfo: String(acct.osInfo || 'Windows'), OSVersion: String(acct.osVersion || '10.0.19045'),
    },
  };
}

function explainRefreshErr(json, text) {
  const err = (json?.ResponseMetadata?.Error) || {};
  const code = err.Code;
  const msg = (err.Data && err.Data['__Message.error']) || err.Message || String(text).slice(0, 200);
  const hint = { 20101: 'refreshToken 已失效或被别处轮换', 10101: 'refreshToken 与当前产品线不匹配', 20405: '服务端要求设备证明', 20403: '设备密钥与令牌不匹配' }[code] || '';
  return `code=${code ?? '?'} ${msg}${hint ? '（' + hint + '）' : ''}`;
}

async function refreshTokens(acct) {
  const rt = String(acct.refreshToken || '').trim();
  if (!rt) throw new Error('账号没有 refreshToken');
  const hasKeys = !!(acct.privateKeyPem && acct.publicKeyPem);
  if (!hasKeys) {
    const body = JSON.stringify({ ClientID: CLIENT_ID_OLD, RefreshToken: rt, ClientSecret: '-', UserID: '' });
    const r = await traeFetch(EP.exchangeLegacy, { headers: { Accept: 'application/json', 'User-Agent': UA }, body });
    const token = r.json?.Result?.Token;
    if (r.status >= 400 || !token) throw new Error('刷新令牌失败: ' + explainRefreshErr(r.json, r.text));
    return { accessToken: token, refreshToken: r.json.Result.RefreshToken || rt };
  }
  const combos = [[acct.clientId || CLIENT_ID_IDE, acct.platformCode || 'IDE_PC'], [CLIENT_ID_OLD, 'IDE_PC'], [CLIENT_ID_OLD, 'SOLO_PC']]
    .filter((v, i, arr) => arr.findIndex((x) => x[0] === v[0] && x[1] === v[1]) === i);
  let lastErr = null;
  for (const [clientId, platformCode] of combos) {
    let built;
    try { built = await buildProof(acct, EP.exchange, clientId, platformCode, rt); } catch (e) { throw new Error('设备签名失败: ' + e.message); }
    const body = JSON.stringify({ ClientID: clientId, ClientSecret: '', RefreshToken: rt, DeviceInfo: built.info, DeviceProof: built.proof, IDEVersion: IDE_VERSION });
    const r = await traeFetch(EP.exchange, { headers: { 'x-cloudide-token': '' }, body });
    const token = r.json?.Result?.Token;
    if (r.status < 400 && token) return { accessToken: token, refreshToken: r.json.Result.RefreshToken || rt };
    lastErr = explainRefreshErr(r.json, r.text);
    if (!String(r.text || '').includes('10101') && !String(r.text || '').includes('20403')) break;
  }
  throw new Error('刷新令牌失败: ' + (lastErr || '未知错误'));
}

async function claim(token, acct) {
  const r = await traeFetch(EP.claim, { headers: ugHeaders(token, acct), body: REQ_BODY });
  if (!r.json) return { status: r.status, code: '?', msg: String(r.text).slice(0, 160), points: null };
  const data = r.json.data;
  return { status: r.status, code: r.json.code ?? -1, msg: r.json.message || String(r.text).slice(0, 160), points: data && typeof data === 'object' ? data.points ?? null : null };
}

async function statusOf(token, acct) {
  const r = await traeFetch(EP.status, { headers: ugHeaders(token, acct), body: REQ_BODY });
  if (!r.json) return { ok: false, code: '?', raw: String(r.text).slice(0, 160) };
  if (r.status >= 400) return { ok: false, code: r.json.code ?? -1, raw: String(r.text).slice(0, 160) };
  return { ok: true, checked: r.json.checked_in === true, credits: typeof r.json.credits === 'number' ? r.json.credits : null, enable: r.json.enable ?? null, code: r.json.code ?? -1 };
}

async function creditsOf(token, acct) {
  const r = await traeFetch(EP.entitle, { headers: ugHeaders(token, acct), body: '{"require_usage": true}' });
  const d = r.json;
  if (!d) return null;
  const root = d.data || d;
  const us = root.usage_summary || {};
  const total = Number(us.total_amount || 0), used = Number(us.consumed_amount || 0);
  if (total > 0) return total - used;
  const packs = root.user_entitlement_pack_list || [];
  let sum = 0, found = false;
  for (const p of packs) {
    const limit = Number(p?.entitlement_base_info?.quota?.credits_limit || 0);
    const consumed = Number(p?.usage?.credits_amount || 0);
    if (limit > 0) { found = true; sum += Math.max(limit - consumed, 0); }
  }
  return found ? sum : null;
}

const acctKey = (id) => `acct:${id}`;
const INDEX_KEY = 'index:accounts';
const loginKey = (trace) => `login:${trace}`;

async function listAccounts(env) { const raw = await env.TRAE_KV.get(INDEX_KEY); return raw ? JSON.parse(raw) : []; }
async function saveIndex(env, list) { await env.TRAE_KV.put(INDEX_KEY, JSON.stringify(list)); }
async function getAccount(env, id) { const raw = await env.TRAE_KV.get(acctKey(id)); return raw ? openRecord(env, raw) : null; }
async function putAccount(env, acct) { await env.TRAE_KV.put(acctKey(acct.id), await sealRecord(env, acct)); }

const bjDay = (ms = Date.now()) => new Date(ms + 8 * 3600e3).toISOString().slice(0, 10);
const bjHour = (ms = Date.now()) => new Date(ms + 8 * 3600e3).getUTCHours();
const cooldownMinutes = () => bjHour() === 0 ? PEAK_COOLDOWN_MIN : COOLDOWN_MIN;

async function signinOne(env, acct, { force = false } = {}) {
  const now = Date.now(); const today = bjDay(now); const base = { id: acct.id, label: acct.label };
  if (!force && Number(acct.cooldownUntil || 0) > now) return { ...base, state: 'cooldown', msg: `限流冷却中，约 ${Math.ceil((acct.cooldownUntil - now) / 60000)} 分钟` };
  if (!force && acct.lastOkDate === today) return { ...base, state: 'skipped', msg: '今日已完成' };

  let token = String(acct.accessToken || '');
  const exp = jwtExp(token);
  if (!(token && (!exp || exp * 1000 - now > 120000))) {
    try {
      const t = await refreshTokens(acct);
      token = t.accessToken; acct.refreshToken = t.refreshToken; acct.accessToken = token;
      acct.accessExp = jwtExp(token); acct.tokenRefreshedAt = now;
      await putAccount(env, acct);
    } catch (e) {
      acct.lastState = 'token_dead'; acct.lastMsg = e.message; acct.lastRun = now;
      await putAccount(env, acct); return { ...base, state: 'token_dead', msg: e.message };
    }
  }

  let res = await claim(token, acct);
  if (AUTH_FAIL_CODES.includes(res.code)) {
    try {
      const t = await refreshTokens(acct);
      token = t.accessToken; acct.refreshToken = t.refreshToken; acct.accessToken = token;
      acct.accessExp = jwtExp(token); await putAccount(env, acct); res = await claim(token, acct);
    } catch (e) {
      acct.lastState = 'token_dead'; acct.lastMsg = e.message; acct.lastRun = now;
      await putAccount(env, acct); return { ...base, state: 'token_dead', msg: e.message };
    }
  }

  acct.lastRun = now;
  if (res.code === CODE_RATE || res.status === 429 || res.status >= 500) {
    const mins = cooldownMinutes(); acct.cooldownUntil = now + mins * 60000;
    acct.lastState = 'rate'; acct.lastMsg = `限流 9074，冷却 ${mins} 分钟`;
    await putAccount(env, acct); return { ...base, state: 'rate', msg: acct.lastMsg };
  }

  if (res.code === CODE_ALREADY) {
    acct.lastState = 'already'; acct.lastMsg = '今日已签'; acct.lastOkDate = today; acct.cooldownUntil = 0;
    const st = await statusOf(token, acct).catch(() => null);
    if (st?.ok) { acct.credits = st.credits ?? acct.credits ?? null; acct.checkedIn = true; }
    await putAccount(env, acct); return { ...base, state: 'already', msg: '今日已签', credits: acct.credits ?? null };
  }

  if (res.code !== CODE_OK) {
    acct.lastState = 'error'; acct.lastMsg = `签到失败 code=${res.code} ${res.msg ?? ''}`.trim();
    await putAccount(env, acct); return { ...base, state: 'error', msg: acct.lastMsg };
  }

  let confirmed = false, credits = null;
  try {
    const st = await statusOf(token, acct);
    if (st.ok) { confirmed = st.checked === true; credits = st.credits; }
  } catch {}

  if (!confirmed) {
    const bal = await creditsOf(token, acct).catch(() => null);
    acct.lastState = 'pending'; acct.lastMsg = '已提交，但回查未确认，等下轮再试';
    acct.credits = bal ?? credits ?? acct.credits ?? null; acct.cooldownUntil = now + 12 * 60000;
    await putAccount(env, acct); return { ...base, state: 'pending', msg: acct.lastMsg, credits: acct.credits ?? null };
  }

  const bal = await creditsOf(token, acct).catch(() => null);
  acct.lastState = 'checked'; acct.lastMsg = res.points ? `+${res.points} 积分` : '签到成功';
  acct.lastOkDate = today; acct.lastCredit = res.points ?? null;
  acct.totalCredit = (acct.totalCredit ?? 0) + (Number(res.points) || 0);
  acct.totalSigned = (acct.totalSigned ?? 0) + 1;
  acct.credits = bal ?? credits ?? acct.credits ?? null; acct.checkedIn = true; acct.cooldownUntil = 0;
  await putAccount(env, acct);
  return { ...base, state: 'checked', msg: acct.lastMsg, credits: acct.credits ?? null, points: res.points ?? null };
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } });
}

async function requireAdmin(request, env) {
  const url = new URL(request.url);
  const given = request.headers.get('X-Admin-Token') || (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token');
  if (!env.ADMIN_TOKEN) return { ok: false, res: json({ error: '未配置 ADMIN_TOKEN' }, 500) };
  if (!(await timingSafeEqual(given, env.ADMIN_TOKEN))) return { ok: false, res: json({ error: '登录密码不正确' }, 401) };
  return { ok: true };
}

async function requireCron(request, env) {
  const secret = env.CRON_SECRET || env.ADMIN_TOKEN;
  const given = request.headers.get('X-Cron-Secret');
  if (!secret) return { ok: false, res: json({ error: '未配置 CRON_SECRET / ADMIN_TOKEN' }, 500) };
  if (!(await timingSafeEqual(given, secret))) return { ok: false, res: json({ error: '口令不对' }, 401) };
  return { ok: true };
}

async function readBody(request) { try { return await request.json(); } catch { return {}; } }

async function handleRemove(request, env) {
  const body = await readBody(request); const id = String(body.id ?? '').trim();
  if (!id) return json({ error: '缺少 id' }, 400);
  await env.TRAE_KV.delete(acctKey(id));
  const list = (await listAccounts(env)).filter((x) => x.id !== id); await saveIndex(env, list);
  return json({ ok: true, removed: id });
}

async function handleRename(request, env) {
  const body = await readBody(request); const id = String(body.id ?? '').trim(); const label = String(body.label ?? '').trim().slice(0, 40);
  if (!id) return json({ error: '缺少 id' }, 400);
  if (!label) return json({ error: '备注不能为空' }, 400);
  const acct = await getAccount(env, id); if (!acct) return json({ error: '账号不存在' }, 404);
  acct.label = label; await putAccount(env, acct);
  const list = await listAccounts(env); await saveIndex(env, list.map((x) => (x.id === id ? { ...x, label } : x)));
  return json({ ok: true, id, label });
}

async function handleList(request, env) {
  const list = await listAccounts(env); const out = []; const now = Date.now(); const today = bjDay(now);
  for (const meta of list) {
    const a = await getAccount(env, meta.id); if (!a) continue;
    out.push({
      id: a.id, label: a.label, lastState: a.lastState, lastMsg: a.lastMsg,
      lastRun: a.lastRun ? new Date(a.lastRun + 8 * 3600e3).toISOString().replace('Z', ' +08:00') : null,
      lastOkDate: a.lastOkDate ?? null, lastCredit: a.lastCredit ?? null,
      credits: typeof a.credits === 'number' ? Math.round(a.credits * 100) / 100 : null,
      totalCredit: a.totalCredit ?? 0, totalSigned: a.totalSigned ?? 0,
      cooldownUntil: Number(a.cooldownUntil || 0) > now ? a.cooldownUntil : 0,
      hasKeys: !!(a.privateKeyPem && a.publicKeyPem), hasDevice: !!String(a.deviceId || '').trim(),
      today, signedToday: a.lastOkDate === today, ranToday: a.lastRun ? bjDay(a.lastRun) === today : false,
    });
  }
  return json({ count: out.length, today, accounts: out });
}

async function handleRun(request, env, force) {
  const list = await listAccounts(env); const results = [];
  for (const meta of list) {
    const a = await getAccount(env, meta.id); if (!a) continue;
    try { results.push(await signinOne(env, a, { force })); }
    catch (e) { results.push({ id: a.id, label: a.label, state: 'error', msg: e.message }); }
  }
  return json({
    at: new Date(Date.now() + 8 * 3600e3).toISOString().replace('Z', ' +08:00'), accounts: results.length,
    checked: results.filter((r) => r.state === 'checked').length,
    already: results.filter((r) => ['already', 'skipped'].includes(r.state)).length,
    failed: results.filter((r) => ['error', 'token_dead'].includes(r.state)).length,
    cooling: results.filter((r) => ['rate', 'cooldown', 'pending'].includes(r.state)).length, results,
  });
}

const b64std = (buf) => b64encode(buf);

function toPem(der, label) {
  const b = b64std(der); const lines = b.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

async function genDeviceIdentity() {
  const kp = await crypto.subtle.generateKey(ecdsaAlg, true, ['sign', 'verify']);
  return { privateKeyPem: toPem(await crypto.subtle.exportKey('pkcs8', kp.privateKey), 'PRIVATE KEY'), publicKeyPem: toPem(await crypto.subtle.exportKey('spki', kp.publicKey), 'PUBLIC KEY') };
}

function genDeviceId() {
  const a = crypto.getRandomValues(new Uint8Array(15)); let s = String(1 + (a[0] % 9));
  for (let i = 1; i < 15; i++) s += String(a[i] % 10); return s;
}

async function pkcePair() {
  const verifier = randomHex(32);
  return { verifier, challenge: b64urlEncode(await crypto.subtle.digest('SHA-256', enc.encode(verifier))) };
}

function qsQuote(v) { return encodeURIComponent(String(v)).replace(/%2F/g, '/'); }

function buildAuthorizeUrl(o) {
  const params = [
    ['login_version', '1'], ['auth_from', o.authFrom], ['login_channel', 'native_ide'], ['plugin_version', OAUTH_PLUGIN_VERSION], ['auth_type', 'local'],
    ['client_id', o.clientId], ['redirect', '0'], ['login_trace_id', o.trace], ['auth_callback_url', o.callback], ['machine_id', o.machineId],
    ['device_id', o.deviceId], ['x_device_id', o.deviceId], ['x_machine_id', o.machineId], ['x_device_brand', 'PC'], ['x_device_type', 'Windows'],
    ['x_os_version', '10.0.19045'], ['x_env', ''], ['x_app_version', OAUTH_APP_VERSION], ['x_app_type', 'stable'], ['code_challenge', o.challenge],
    ['code_challenge_method', 'S256'], ['channel_name', 'common'],
  ];
  return AUTHORIZE_BASE + '/authorization?' + params.map(([k, v]) => k + '=' + qsQuote(v)).join('&');
}

const ALLOWED_HOSTS = new Set(['api.trae.cn', 'api.trae.com.cn']);
function hostBase(h) {
  const s = String(h || '').trim(); if (!s) return 'https://api.trae.cn';
  let raw = s; if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;
  let u; try { u = new URL(raw); } catch { return 'https://api.trae.cn'; }
  if (!ALLOWED_HOSTS.has(u.hostname.toLowerCase())) return 'https://api.trae.cn';
  return u.origin;
}

function deepFind(obj, keys, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 6) return '';
  for (const k of keys) { const v = obj[k]; if (typeof v === 'string' && v.trim()) return v.trim(); }
  for (const v of Object.values(obj)) { const r = deepFind(v, keys, depth + 1); if (r) return r; }
  return '';
}

const ACCESS_KEYS = ['AccessToken', 'access_token', 'Jwt', 'JWT', 'token'];
const REFRESH_KEYS = ['RefreshToken', 'refresh_token'];
const NICK_KEYS = ['Nickname', 'nickname', 'NickName', 'nick_name', 'UserName', 'userName', 'user_name', 'username', 'ScreenName', 'screen_name', 'DisplayName', 'displayName', 'display_name', 'Name', 'name'];

function pickNickname(obj, depth = 0) {
  if (!obj || typeof obj !== 'object' || depth > 5) return '';
  for (const k of NICK_KEYS) {
    const v = obj[k];
    if (typeof v === 'string') {
      const s = v.trim();
      if (s && s.length <= 32 && !/^(pc|windows|web|ide|trae|unknown)$/i.test(s)) return s;
    }
  }
  for (const v of Object.values(obj)) { if (v && typeof v === 'object') { const r = pickNickname(v, depth + 1); if (r) return r; } }
  return '';
}

function nicknameFromJwt(tok) {
  const parts = String(tok || '').split('.'); if (parts.length < 3) return '';
  try { return pickNickname(JSON.parse(dec.decode(b64urlDecode(parts[1])))); } catch { return ''; }
}

function describeExchangeErr(json, text, status) {
  const err = json?.ResponseMetadata?.Error || json?.error || {}; const code = err.Code ?? json?.code;
  const msg = (err.Data && err.Data['__Message.error']) || err.Message || json?.message || json?.msg || String(text || '').slice(0, 160);
  return `code=${code ?? '?'} ${msg} (HTTP ${status})`;
}

async function exchangeAuthCode({ authCode, verifier, device, clientId, platform, host }) {
  const dev = {
    DeviceID: String(device.deviceId || ''), MachineID: String(device.machineId || ''), PlatformCode: platform, DeviceType: 'PC', DeviceName: 'PC', DeviceModel: '',
    ClientVersion: OAUTH_APP_VERSION, DevicePublicKey: String(device.publicKeyPem || ''), DeviceBrand: '', DeviceCPU: '', OSInfo: 'Windows', OSVersion: '10.0.19045',
  };
  const baseHeaders = { Accept: '*/*', 'User-Agent': 'Trae/' + OAUTH_APP_VERSION, 'x-device-id': dev.DeviceID, 'x-app-id': OAUTH_APP_ID, 'x-platform-code': platform };
  const safeHost = hostBase(host);
  const variants = [
    { tag: 'DeviceInfo', url: safeHost + EP.exchange, headers: { ...baseHeaders, 'x-cloudide-token': '' }, body: { ClientID: clientId, AuthCode: authCode, CodeVerifier: verifier, DeviceInfo: dev, IDEVersion: OAUTH_APP_VERSION } },
    { tag: 'AuthCode', url: EP.exchangeLegacy, headers: baseHeaders, body: { ClientID: clientId, AuthCode: authCode, CodeVerifier: verifier, DeviceID: dev.DeviceID, PlatformCode: platform } },
    { tag: 'Code', url: EP.exchangeLegacy, headers: baseHeaders, body: { ClientID: clientId, Code: authCode, CodeVerifier: verifier, DeviceID: dev.DeviceID, PlatformCode: platform } },
  ];
  const errors = [];
  for (const v of variants) {
    const { status, json, text } = await traeFetch(v.url, { method: 'POST', headers: v.headers, body: JSON.stringify(v.body) });
    const refreshToken = deepFind(json, REFRESH_KEYS), accessToken = deepFind(json, ACCESS_KEYS);
    if (refreshToken) return { tokens: { refreshToken, accessToken }, tag: v.tag, name: pickNickname(json) || nicknameFromJwt(accessToken) };
    errors.push(`${v.tag}: ${describeExchangeErr(json, text, status)}`);
  }
  throw new Error('登录失败 → ' + errors.join(' | '));
}

async function putLoginSession(env, sess) { await env.TRAE_KV.put(loginKey(sess.trace), await sealRecord(env, sess), { expirationTtl: LOGIN_TTL }); }
async function getLoginSession(env, trace) {
  const raw = await env.TRAE_KV.get(loginKey(trace)); if (!raw) return null;
  try { return await openRecord(env, raw); } catch { return null; }
}

async function saveScannedAccount(env, { label, refreshToken, device, clientId, platform }) {
  const rt = String(refreshToken || '').trim(); if (!rt) throw new Error('登录响应里没有 refreshToken');
  const id = randomId(9);
  const acct = {
    id, label: String(label || '').trim().slice(0, 40) || `Trae-${String(device.deviceId || '').slice(-4)}`, refreshToken: rt,
    deviceId: String(device.deviceId || ''), machineId: String(device.machineId || ''), privateKeyPem: String(device.privateKeyPem || ''),
    publicKeyPem: String(device.publicKeyPem || ''), deviceName: 'PC', deviceModel: '', deviceBrand: '', deviceType: 'Windows', osInfo: 'Windows',
    osVersion: '10.0.19045', clientId: String(clientId || ''), platformCode: String(platform || ''), source: 'scan', createdAt: Date.now(),
    lastState: 'new', lastMsg: '扫码登录，尚未运行', cooldownUntil: 0,
  };
  await putAccount(env, acct);
  const list = await listAccounts(env); list.push({ id, label: acct.label, createdAt: acct.createdAt }); await saveIndex(env, list);
  return acct;
}

function parseCallbackParams(url) {
  const q = url.searchParams; let authCode = ''; const raw = q.get('authCodeInfo');
  if (raw) { try { authCode = String(JSON.parse(raw).AuthCode || '').trim(); } catch {} }
  if (!authCode) authCode = String(q.get('code') || q.get('AuthCode') || '').trim();
  let refreshToken = '';
  for (const k of ['refreshToken', 'refresh_token', 'RefreshToken']) { const v = String(q.get(k) || '').trim().replace(/^"+|"+$/g, ''); if (v) { refreshToken = v; break; } }
  return {
    authCode, refreshToken, trace: String(q.get('loginTraceID') || q.get('login_trace_id') || q.get('state') || '').trim().slice(0, 64),
    host: String(q.get('host') || '').trim().slice(0, 200), name: String(q.get('name') || q.get('nickname') || q.get('userName') || '').trim().slice(0, 40),
    uid: String(q.get('uid') || '').trim().slice(0, 64), error: String(q.get('error') || '').trim().slice(0, 200),
  };
}

async function completeLogin(env, sess, p) {
  if (sess.status === 'ok') return { ok: true, label: sess.label, id: sess.accountId, repeat: true };
  let refreshToken = p.refreshToken, via = 'callback', nick = p.name || nicknameFromJwt(p.refreshToken);
  if (!refreshToken) {
    if (!p.authCode) throw new Error('回调里既没有 AuthCode 也没有 refreshToken');
    const r = await exchangeAuthCode({ authCode: p.authCode, verifier: sess.verifier, device: sess, clientId: sess.clientId, platform: sess.platform, host: p.host });
    refreshToken = r.tokens.refreshToken; via = r.tag; nick = nick || r.name;
  }
  const label = String(nick || p.uid || '').trim() || `Trae-${String(sess.deviceId || '').slice(-4)}`;
  const acct = await saveScannedAccount(env, { label, refreshToken, device: sess, clientId: sess.clientId, platform: sess.platform });
  sess.status = 'ok'; sess.label = acct.label; sess.accountId = acct.id; sess.via = via; sess.error = '';
  await putLoginSession(env, sess);
  return { ok: true, label: acct.label, id: acct.id, via };
}

async function handleLoginStart(request, env) {
  const device = await genDeviceIdentity(), deviceId = genDeviceId(), machineId = randomHex(16);
  const { verifier, challenge } = await pkcePair(), trace = randomHex(8);
  const authUrl = buildAuthorizeUrl({ authFrom: TRAE_LINE.authFrom, clientId: TRAE_LINE.clientId, trace, callback: CALLBACK_LOCAL, deviceId, machineId, challenge });
  const sess = {
    trace, line: 'trae', verifier, callback: CALLBACK_LOCAL, deviceId, machineId,
    privateKeyPem: device.privateKeyPem, publicKeyPem: device.publicKeyPem,
    clientId: TRAE_LINE.clientId, platform: TRAE_LINE.platform, status: 'pending', createdAt: Date.now(),
  };
  await putLoginSession(env, sess);
  return json({ ok: true, trace, authUrl, callback: CALLBACK_LOCAL, deviceId, line: 'trae', label: TRAE_LINE.label });
}

async function handleLoginPoll(request, env) {
  const url = new URL(request.url); const trace = String(url.searchParams.get('trace') || '').trim();
  if (!trace) return json({ error: '缺少 trace' }, 400);
  if (!/^[0-9a-f]{8,64}$/i.test(trace)) return json({ error: 'trace 格式不正确' }, 400);
  const sess = await getLoginSession(env, trace);
  if (!sess) return json({ status: 'expired' });
  return json({ status: sess.status || 'pending', label: sess.label || '', error: sess.error || '', accountId: sess.accountId || '', via: sess.via || '' });
}

async function handleLoginClaim(request, env) {
  const body = await readBody(request); const text = String(body.url || body.text || '').trim();
  if (!text) return json({ error: '请粘贴回调地址' }, 400);
  let u; try { u = new URL(text); } catch {
    try { const tail = text.startsWith('?') ? text : text.replace(/^[?/]+/, ''); u = new URL('https://placeholder.local/' + tail); }
    catch { return json({ error: '这不像是回调地址' }, 400); }
  }
  const p = parseCallbackParams(u);
  if (!p.authCode && !p.refreshToken) return json({ error: '地址里没找到 authCodeInfo / code' }, 400);
  const trace = p.trace;
  if (!trace) return json({ error: '回调地址缺少 loginTraceID（trace），请确认复制了完整链接' }, 400);
  if (!/^[0-9a-f]{8,64}$/i.test(trace)) return json({ error: 'trace 格式不正确' }, 400);
  const sess = await getLoginSession(env, trace); if (!sess) return json({ error: '登录会话已过期，请重新发起' }, 400);
  try { const r = await completeLogin(env, sess, p); return json({ ok: true, label: r.label, id: r.id, via: r.via }); }
  catch (e) { sess.status = 'error'; sess.error = e.message; await putLoginSession(env, sess); return json({ error: e.message }, 502); }
}

const PAGE = '<!DOCTYPE html><meta charset="utf-8"><title>控制台</title><p>控制台在根路径 <a href="/">/</a>。</p>';

const __mod = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url); const path = url.pathname.replace(/\/+$/, '') || '/'; const method = request.method.toUpperCase();
    try {
      if (path === '/' || path === '/index.html') return new Response(PAGE, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
      if (path === '/cron') { const c = await requireCron(request, env); if (!c.ok) return c.res; return handleRun(request, env, false); }
      if (!path.startsWith('/api/')) return json({ error: 'not found' }, 404);
      const a = await requireAdmin(request, env); if (!a.ok) return a.res;
      if (path === '/api/login/start' && method === 'POST') return handleLoginStart(request, env);
      if (path === '/api/login/poll' && method === 'GET') return handleLoginPoll(request, env);
      if (path === '/api/login/claim' && method === 'POST') return handleLoginClaim(request, env);
      if (path === '/api/list' && method === 'GET') return handleList(request, env);
      if (path === '/api/accounts/remove' && method === 'POST') return handleRemove(request, env);
      if (path === '/api/rename' && method === 'POST') return handleRename(request, env);
      if (path === '/api/run' && method === 'POST') return handleRun(request, env, url.searchParams.get('force') === '1');
      return json({ error: 'not found' }, 404);
    } catch (e) { return json({ error: e.message || String(e) }, 500); }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      const list = await listAccounts(env);
      for (const meta of list) { const acct = await getAccount(env, meta.id); if (!acct) continue; try { await signinOne(env, acct, { force: false }); } catch {} }
    })());
  },
};
const __internal = { ecSign, importPrivateKey, derSig, jwtExp, buildProof, PEM_TEST: true };
return { fetch: __mod.fetch, scheduled: __mod.scheduled, __internal };
})();


/* ================================================================== */
/* 模块二：WorkBuddy —— 扫码授权 / 令牌续期 / 签到 */
/* ================================================================== */

const WorkBuddy = (() => {
const API = 'https://copilot.tencent.com';
const enc = new TextEncoder();
const dec = new TextDecoder();

function b64encode(buf) { const b = new Uint8Array(buf); let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
function b64decode(str) { const bin = atob(str); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
function b64urlEncode(buf) { return b64encode(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlDecode(str) { const s = str.replace(/-/g, '+').replace(/_/g, '/'); return b64decode(s + '='.repeat((4 - (s.length % 4)) % 4)); }
function randomId(bytes = 12) { return b64urlEncode(crypto.getRandomValues(new Uint8Array(bytes))); }

async function timingSafeEqual(a, b) {
  const h = async (s) => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(String(s ?? ''))));
  const [x, y] = await Promise.all([h(a), h(b)]);
  let diff = 0; for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function deriveKey(env, salt) {
  const raw = env.WB_MASTER_KEY; if (!raw) throw new Error('缺少 MASTER_KEY');
  let master; try { master = b64decode(raw.trim()); } catch { throw new Error('MASTER_KEY 不是合法 base64'); }
  if (master.length !== 32) throw new Error('MASTER_KEY 必须是 32 字节');
  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('wb-signin/v1/account') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function sealRecord(env, obj) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12)), key = await deriveKey(env, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  return JSON.stringify({ v: 1, s: b64encode(salt), i: b64encode(iv), d: b64encode(ct) });
}

async function openRecord(env, text) {
  const box = JSON.parse(text); if (box.v !== 1) throw new Error('不认识的记录版本');
  const key = await deriveKey(env, b64decode(box.s));
  return JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64decode(box.i) }, key, b64decode(box.d))));
}

const acctKey = (id) => `acct:${id}`, INDEX_KEY = 'index:accounts';
async function listAccounts(env) { const raw = await env.WB_KV.get(INDEX_KEY); return raw ? JSON.parse(raw) : []; }
async function saveIndex(env, list) { await env.WB_KV.put(INDEX_KEY, JSON.stringify(list)); }
async function getAccount(env, id) { const raw = await env.WB_KV.get(acctKey(id)); return raw ? openRecord(env, raw) : null; }
async function putAccount(env, acct) { await env.WB_KV.put(acctKey(acct.id), await sealRecord(env, acct)); }

async function wbFetch(path, { method = 'POST', headers = {}, body = '{}', timeout = 20000 } = {}) {
  const ctrl = new AbortController(), timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(API + path, { method, headers: { 'Content-Type': 'application/json', 'User-Agent': 'workbuddy-signin-worker/1.0', ...headers }, body: method === 'GET' ? undefined : body, signal: ctrl.signal });
    const text = await res.text(); let json;
    try { json = JSON.parse(text); } catch { throw new Error(`响应不是 JSON (HTTP ${res.status}): ${text.slice(0, 120)}`); }
    return { status: res.status, json };
  } finally { clearTimeout(timer); }
}

async function refreshTokens(refreshToken) {
  const { status, json } = await wbFetch('/v2/plugin/auth/token/refresh', { headers: { 'X-Refresh-Token': refreshToken, 'X-Auth-Refresh-Source': 'plugin', 'X-Domain': 'copilot.tencent.com' } });
  if (json?.code !== 0 || !json?.data) { const err = new Error(`刷新令牌失败 code=${json?.code} ${json?.msg ?? ''}`); err.code = json?.code; err.fatal = true; throw err; }
  const d = json.data;
  return { accessToken: d.accessToken, refreshToken: d.refreshToken || refreshToken, expiresIn: Number(d.expiresIn) || 0, refreshExpiresIn: Number(d.refreshExpiresIn) || 0 };
}

async function requestLoginState() {
  const { status, json } = await wbFetch('/v2/plugin/auth/state?platform=workbuddy', { headers: { 'X-No-Authorization': 'true', 'X-No-User-Id': 'true', 'X-No-Enterprise-Id': 'true', 'X-No-Department-Info': 'true', 'X-Domain': 'copilot.tencent.com' } });
  if (json?.code !== 0 || !json?.data?.state) throw new Error(`申请登录态失败 code=${json?.code} ${json?.msg ?? ''}`);
  return { state: json.data.state, authUrl: json.data.authUrl };
}

async function pollLoginToken(state) {
  const { status, json } = await wbFetch(`/v2/plugin/auth/token?state=${encodeURIComponent(state)}`, { method: 'GET', headers: { 'X-No-Authorization': 'true', 'X-No-User-Id': 'true', 'X-No-Enterprise-Id': 'true', 'X-No-Department-Info': 'true', 'X-Domain': 'copilot.tencent.com' } });
  if (json?.code === 11217) return { pending: true };
  if (json?.code === 0 && json?.data?.accessToken) return { tokens: json.data };
  throw new Error(`轮询登录结果失败 code=${json?.code} ${json?.msg ?? ''}`);
}

async function fetchNickname(at) {
  try {
    const { json } = await wbFetch('/v2/accounts', { method: 'GET', headers: { ...authHeader(at), 'X-Domain': 'copilot.tencent.com' } });
    const list = json?.data?.accounts ?? json?.data, first = Array.isArray(list) ? list[0] : null;
    return String(first?.nickname ?? first?.nickName ?? '').trim();
  } catch { return ''; }
}

async function persistAccount(env, { refreshToken, label, accessToken }) {
  const id = randomId(9); let name = String(label ?? '').trim().slice(0, 40);
  if (!name && accessToken) name = await fetchNickname(accessToken);
  if (!name) name = `账号-${id.slice(0, 4)}`;
  const acct = { id, label: name, refreshToken, createdAt: Date.now(), lastState: 'new', lastMsg: '尚未运行', verified: true, tokenRefreshedAt: Date.now() };
  await putAccount(env, acct);
  const list = await listAccounts(env); list.push({ id, label: acct.label, createdAt: acct.createdAt }); await saveIndex(env, list);
  return acct;
}

const authHeader = (at) => ({ Authorization: `Bearer ${at}` });

async function checkinStatus(at) {
  const { json } = await wbFetch('/v2/billing/meter/checkin-activity-status', { headers: authHeader(at) });
  return (json?.code !== 0 || !json?.data) ? { ok: false, code: json?.code, msg: json?.msg } : { ok: true, data: json.data };
}

async function doCheckin(at) {
  const { json } = await wbFetch('/v2/billing/meter/daily-checkin', { headers: authHeader(at) });
  if (json?.code === 0) return { state: 'checked', credit: json.data?.credit ?? 100, raw: json.data };
  if (json?.code === 10001) return { state: 'already', credit: 0 };
  return { state: 'error', code: json?.code, msg: json?.msg };
}

async function signinOne(env, acct, { force = false } = {}) {
  const now = Date.now(), today = new Date(now + 8 * 3600 * 1000).toISOString().slice(0, 10);
  if (!force && acct.lastOkDate === today) return { id: acct.id, label: acct.label, state: 'skipped', msg: '今日已完成' };
  let tokens;
  try { tokens = await refreshTokens(acct.refreshToken); }
  catch (e) { acct.lastState = e.fatal ? 'token_dead' : 'error'; acct.lastMsg = e.message; acct.lastRun = now; await putAccount(env, acct); return { id: acct.id, label: acct.label, state: acct.lastState, msg: e.message }; }
  acct.refreshToken = tokens.refreshToken; acct.tokenRefreshedAt = now;

  let result;
  try { result = await doCheckin(tokens.accessToken); }
  catch (e) { acct.lastState = 'error'; acct.lastMsg = `签到请求异常: ${e.message}`; acct.lastRun = now; await putAccount(env, acct); return { id: acct.id, label: acct.label, state: 'error', msg: acct.lastMsg }; }

  let streak = null, total = null;
  try {
    const st = await checkinStatus(tokens.accessToken);
    if (st.ok) {
      streak = st.data.streak_days ?? null; total = st.data.total_credits ?? null;
      if (st.data.checked_in_today === true && result.state === 'error') result = { state: 'already', credit: 0 };
    }
  } catch {}

  acct.lastRun = now; acct.streak = streak; acct.total = total;
  if (result.state === 'error') { acct.lastState = 'error'; acct.lastMsg = `签到失败 code=${result.code} ${result.msg ?? ''}`; }
  else {
    acct.lastState = result.state; acct.lastMsg = result.state === 'checked' ? `+${result.credit} 积分` : '今日已签'; acct.lastOkDate = today;
    if (result.state === 'checked') { acct.lastCredit = result.credit; acct.totalSigned = (acct.totalSigned ?? 0) + 1; }
  }
  await putAccount(env, acct);
  return { id: acct.id, label: acct.label, state: acct.lastState, msg: acct.lastMsg, streak, total };
}

function json(data, status = 200) { return new Response(JSON.stringify(data, null, 2), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } }); }
async function requireAdmin(request, env) { const url = new URL(request.url), given = request.headers.get('X-Admin-Token') || (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token'); if (!env.ADMIN_TOKEN) return { ok: false, res: json({ error: '未配置 ADMIN_TOKEN' }, 500) }; if (!(await timingSafeEqual(given, env.ADMIN_TOKEN))) return { ok: false, res: json({ error: '登录密码不正确' }, 401) }; return { ok: true }; }
async function requireCron(request, env) { const secret = env.CRON_SECRET || env.ADMIN_TOKEN, given = request.headers.get('X-Cron-Secret'); if (!secret) return { ok: false, res: json({ error: '未配置 CRON_SECRET / ADMIN_TOKEN' }, 500) }; if (!(await timingSafeEqual(given, secret))) return { ok: false, res: json({ error: '口令不对' }, 401) }; return { ok: true }; }
async function readBody(request) { try { return await request.json(); } catch { return {}; } }

async function handleLoginStart(request, env) {
  const { state, authUrl } = await requestLoginState();
  await env.WB_KV.put(`login:${state}`, String(Date.now()), { expirationTtl: 900 });
  return json({ ok: true, state, authUrl });
}

async function handleLoginPoll(request, env) {
  const url = new URL(request.url), state = String(url.searchParams.get('state') ?? '').trim();
  if (!state) return json({ error: '缺少 state' }, 400);
  if (!/^[A-Za-z0-9_-]{8,128}$/.test(state)) return json({ error: 'state 格式不正确' }, 400);
  const known = await env.WB_KV.get(`login:${state}`); if (!known) return json({ error: '登录会话已过期，请重新获取二维码' }, 400);
  const r = await pollLoginToken(state); if (r.pending) return json({ status: 'pending' });
  const rt = String(r.tokens.refreshToken ?? '').trim(); if (!rt) return json({ error: '登录成功但服务端没返回 refreshToken' }, 502);
  const acct = await persistAccount(env, { refreshToken: rt, accessToken: r.tokens.accessToken });
  await env.WB_KV.delete(`login:${state}`);
  return json({ status: 'ok', id: acct.id, label: acct.label });
}

async function handleList(request, env) {
  const list = await listAccounts(env), out = [];
  for (const meta of list) {
    const a = await getAccount(env, meta.id); if (!a) continue;
    out.push({ id: a.id, label: a.label, lastState: a.lastState, lastMsg: a.lastMsg, lastRun: a.lastRun ? new Date(a.lastRun + 8 * 3600e3).toISOString().replace('Z', ' +08:00') : null, lastOkDate: a.lastOkDate ?? null, streak: a.streak ?? null, total: a.total ?? null, totalSigned: a.totalSigned ?? 0 });
  }
  return json({ count: out.length, accounts: out });
}

async function handleRemove(request, env) { const body = await readBody(request), id = String(body.id ?? '').trim(); if (!id) return json({ error: '缺少 id' }, 400); await env.WB_KV.delete(acctKey(id)); await saveIndex(env, (await listAccounts(env)).filter((x) => x.id !== id)); return json({ ok: true, removed: id }); }
async function handleRename(request, env) { const body = await readBody(request), id = String(body.id ?? '').trim(), label = String(body.label ?? '').trim().slice(0, 40); if (!id || !label) return json({ error: '参数错误' }, 400); const acct = await getAccount(env, id); if (!acct) return json({ error: '账号不存在' }, 404); acct.label = label; await putAccount(env, acct); const list = await listAccounts(env); await saveIndex(env, list.map((x) => (x.id === id ? { ...x, label } : x))); return json({ ok: true, id, label }); }

async function handleRun(request, env, force) {
  const list = await listAccounts(env), results = [];
  for (const meta of list) { const a = await getAccount(env, meta.id); if (!a) continue; try { results.push(await signinOne(env, a, { force })); } catch (e) { results.push({ id: a.id, label: a.label, state: 'error', msg: e.message }); } }
  return json({ at: new Date(Date.now() + 8 * 3600e3).toISOString().replace('Z', ' +08:00'), accounts: results.length, checked: results.filter((r) => r.state === 'checked').length, already: results.filter((r) => r.state === 'already' || r.state === 'skipped').length, failed: results.filter((r) => r.state === 'error' || r.state === 'token_dead').length, results });
}

const PAGE = '<!DOCTYPE html><meta charset="utf-8"><title>控制台</title><p>控制台在根路径 <a href="/">/</a>。</p>';

const __mod = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url), path = url.pathname.replace(/\/+$/, '') || '/', method = request.method.toUpperCase();
    try {
      if (path === '/' || path === '/index.html') return new Response(PAGE, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' } });
      if (path === '/cron') { const c = await requireCron(request, env); if (!c.ok) return c.res; return handleRun(request, env, false); }
      if (!path.startsWith('/api/')) return json({ error: 'not found' }, 404);
      const a = await requireAdmin(request, env); if (!a.ok) return a.res;
      if (path === '/api/list' && method === 'GET') return handleList(request, env);
      if (path === '/api/login/start' && method === 'POST') return handleLoginStart(request, env);
      if (path === '/api/login/poll' && method === 'GET') return handleLoginPoll(request, env);
      if (path === '/api/remove' && method === 'POST') return handleRemove(request, env);
      if (path === '/api/rename' && method === 'POST') return handleRename(request, env);
      if (path === '/api/run' && method === 'POST') return handleRun(request, env, url.searchParams.get('force') === '1');
      return json({ error: 'not found' }, 404);
    } catch (e) { return json({ error: e.message || String(e) }, 500); }
  },
  async scheduled(event, env, ctx) { ctx.waitUntil((async () => { const list = await listAccounts(env); for (const meta of list) { const acct = await getAccount(env, meta.id); if (!acct) continue; try { await signinOne(env, acct, { force: false }); } catch {} } })()); },
};
return { fetch: __mod.fetch, scheduled: __mod.scheduled };
})();


/* ================================================================== */
/* 模块三：Qoder —— 设备授权登录 / 活动领取式签到 */
/* ================================================================== */

const Qoder = (() => {
const REGION = { key: 'cn', name: '国内版', web: 'https://qoder.com.cn', api: 'https://openapi.qoder.com.cn', clientId: '', redirectUri: '', lang: 'zh-CN' };
const regionOf = () => REGION;
const EP = { devicePage: '/device/selectAccounts', poll: '/api/v1/deviceToken/poll', refresh: '/api/v1/deviceToken/refresh', campaigns: '/sash/api/v1/me/campaigns' };
const CLIENT_TYPE = '10', UA = 'Qoder', LOGIN_TTL = 900, COOLDOWN_MIN = 30;
const enc = new TextEncoder(), dec = new TextDecoder();

function b64encode(buf) { const b = new Uint8Array(buf); let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); }
function b64decode(str) { const bin = atob(String(str)), out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }
function b64urlEncode(buf) { return b64encode(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64urlDecode(str) { const s = String(str).replace(/-/g, '+').replace(/_/g, '/'); return b64decode(s + '='.repeat((4 - (s.length % 4)) % 4)); }
function randomId(bytes = 12) { return b64urlEncode(crypto.getRandomValues(new Uint8Array(bytes))); }
function randomHex(bytes = 16) { const b = crypto.getRandomValues(new Uint8Array(bytes)); let s = ''; for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0'); return s; }

async function timingSafeEqual(a, b) { const h = async (s) => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(String(s ?? '')))); const [x, y] = await Promise.all([h(a), h(b)]); let diff = 0; for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i]; return diff === 0; }
function jwtClaims(tok) { const parts = String(tok || '').split('.'); if (parts.length < 3) return {}; try { return JSON.parse(dec.decode(b64urlDecode(parts[1]))) || {}; } catch { return {}; } }

async function deriveKey(env, salt) {
  const raw = env.QODER_MASTER_KEY; if (!raw) throw new Error('缺少 MASTER_KEY');
  let master; try { master = b64decode(raw.trim()); } catch { throw new Error('MASTER_KEY 不是合法 base64'); }
  if (master.length !== 32) throw new Error('MASTER_KEY 必须是 32 字节');
  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode('qoder-signin/v1/account') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function sealRecord(env, obj) { const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12)), key = await deriveKey(env, salt); const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj))); return JSON.stringify({ v: 1, s: b64encode(salt), i: b64encode(iv), d: b64encode(ct) }); }
async function openRecord(env, text) { const box = JSON.parse(text); if (box.v !== 1) throw new Error('不认识的记录版本'); const key = await deriveKey(env, b64decode(box.s)); return JSON.parse(dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64decode(box.i) }, key, b64decode(box.d)))); }

const acctKey = (id) => `acct:${id}`, INDEX_KEY = 'index:accounts', loginKey = (nonce) => `login:${nonce}`;
async function listAccounts(env) { const raw = await env.QODER_KV.get(INDEX_KEY); return raw ? JSON.parse(raw) : []; }
async function saveIndex(env, list) { await env.QODER_KV.put(INDEX_KEY, JSON.stringify(list)); }
async function getAccount(env, id) { const raw = await env.QODER_KV.get(acctKey(id)); return raw ? openRecord(env, raw) : null; }
async function putAccount(env, acct) { await env.QODER_KV.put(acctKey(acct.id), await sealRecord(env, acct)); }
const bjDay = (ms = Date.now()) => new Date(ms + 8 * 3600e3).toISOString().slice(0, 10);

async function qoderFetch(region, path, { method = 'GET', headers = {}, body, timeout = 20000 } = {}) {
  const ctrl = new AbortController(), timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const res = await fetch(region.api + path, { method, headers: { accept: 'application/json', 'accept-language': region.lang, 'user-agent': UA, ...headers }, body: body === undefined ? undefined : JSON.stringify(body), signal: ctrl.signal });
    const text = await res.text(); let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch { json = {}; }
    return { status: res.status, json, text };
  } finally { clearTimeout(timer); }
}

function authHeaders(at, region, extra) { const h = { authorization: 'Bearer ' + at, 'cosy-clienttype': CLIENT_TYPE, 'user-agent': UA, accept: 'application/json', 'accept-language': region.lang }; return extra ? Object.assign(h, extra) : h; }

const CLIENT_VERSION = '0.4.8', MACHINE_OS = 'x86_64_win32', MACHINE_HOSTNAME = 'DESKTOP';

async function riskHeaders(acct, env, overrides) {
  const h = { 'cosy-version': (overrides && overrides.version) || CLIENT_VERSION, 'cosy-machineos': MACHINE_OS, 'cosy-machinehostname': MACHINE_HOSTNAME };
  const mid = String(acct?.machineId || '').trim(); if (mid) h['cosy-machineid'] = mid;
  return h;
}

async function sha256b64url(str) { return b64urlEncode(new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(str)))); }

async function handleLoginStart(request, env) {
  const body = await readBody(request), region = REGION;
  const verifier = randomId(32), challenge = await sha256b64url(verifier), nonce = randomHex(16), machineId = crypto.randomUUID();
  const pairs = [['challenge', challenge], ['challenge_method', 'S256']];
  if (region.clientId) pairs.push(['client_id', region.clientId]);
  pairs.push(['machine_id', machineId], ['nonce', nonce]);
  if (region.redirectUri) pairs.push(['redirect_uri', region.redirectUri]);
  const authUrl = region.web + EP.devicePage + '?' + pairs.map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&');
  await env.QODER_KV.put(loginKey(nonce), await sealRecord(env, { verifier, machineId, region: region.key, at: Date.now() }), { expirationTtl: LOGIN_TTL });
  return json({ ok: true, nonce, region: region.key, regionName: region.name, authUrl });
}

async function handleLoginPoll(request, env) {
  const url = new URL(request.url), nonce = String(url.searchParams.get('nonce') ?? '').trim();
  if (!nonce) return json({ error: '缺少 nonce' }, 400);
  if (!/^[0-9a-f]{16,64}$/i.test(nonce)) return json({ error: 'nonce 格式不正确' }, 400);
  const raw = await env.QODER_KV.get(loginKey(nonce)); if (!raw) return json({ error: '授权会话已过期，请重新点「添加账号」' }, 400);
  let sess; try { sess = await openRecord(env, raw); } catch { return json({ error: '授权会话损坏，请重新点「添加账号」' }, 400); }
  const region = regionOf(sess.region);
  const q = '?nonce=' + encodeURIComponent(nonce) + '&verifier=' + encodeURIComponent(sess.verifier) + '&challenge_method=S256';
  const r = await qoderFetch(region, EP.poll + q, { headers: { 'Cosy-Version': '1.0.1', 'Cosy-ClientType': '5', 'user-agent': 'qoder-local-proxy' } });
  if (r.status === 202 || r.status === 404) return json({ status: 'pending' });
  if (r.status >= 400) { const msg = r.json.errorMessage || r.json.message || r.json.msg || ''; return json({ error: '授权轮询失败（HTTP ' + r.status + '）' + msg }, 502); }
  const data = r.json && typeof r.json.data === 'object' && r.json.data ? r.json.data : r.json;
  const token = String(data.token || data.access_token || data.device_token || '').trim();
  if (!token) { const code = r.json?.code; if (code != null && code !== 0 && code !== '0') { const msg = r.json.errorMessage || r.json.msg || r.json.message || ''; return json({ error: '授权失败（code=' + code + '）' + msg }, 502); } return json({ status: 'pending' }); }
  const acct = await persistAccount(env, { accessToken: token, refreshToken: String(data.refresh_token || data.refreshToken || '').trim(), userId: String(data.user_id || data.userId || '').trim(), email: String(data.email || data.user_email || '').trim(), machineId: sess.machineId, region: region.key });
  await env.QODER_KV.delete(loginKey(nonce));
  return json({ status: 'ok', id: acct.id, label: acct.label, region: region.key });
}

async function persistAccount(env, { accessToken, refreshToken, userId, email, machineId, via }) {
  const id = randomId(9), reg = REGION, claims = jwtClaims(accessToken);
  const fallback = (reg.key === 'global' ? 'Qoder-Intl-' : 'Qoder-') + (userId ? userId.slice(-4) : id.slice(0, 4));
  const name = String(claims.nickname || claims.name || claims.email || email || '').trim().slice(0, 40) || fallback;
  const acct = { id, label: name, region: reg.key, accessToken: String(accessToken || ''), refreshToken: String(refreshToken || ''), userId: String(userId || ''), machineId: String(machineId || ''), createdAt: Date.now(), lastState: 'new', lastMsg: '授权完成，尚未运行', totalCredit: 0, totalSigned: 0, cooldownUntil: 0, via: String(via || '') };
  await putAccount(env, acct);
  const list = await listAccounts(env); list.push({ id, label: acct.label, createdAt: acct.createdAt }); await saveIndex(env, list);
  return acct;
}

async function refreshAccount(acct) {
  const rt = String(acct.refreshToken || '').trim(); if (!rt) { const e = new Error('账号缺少 refreshToken，无法续期'); e.fatal = true; throw e; }
  const region = regionOf(acct.region), r = await qoderFetch(region, EP.refresh, { method: 'POST', headers: { 'user-agent': 'qoder-local-proxy', 'content-type': 'application/json' }, body: { refresh_token: rt } });
  if (r.status === 401 || r.status === 403) { const e = new Error('refreshToken 已失效'); e.fatal = true; throw e; }
  if (r.status >= 400) throw new Error('令牌续期失败（HTTP ' + r.status + '）');
  const d = r.json && typeof r.json.data === 'object' && r.json.data ? r.json.data : r.json;
  const token = String(d.device_token || d.deviceToken || d.token || d.access_token || '').trim();
  if (!token) throw new Error('续期响应里没有新的 access token');
  acct.accessToken = token; const nr = String(d.refresh_token || d.refreshToken || '').trim(); if (nr) acct.refreshToken = nr; acct.tokenRefreshedAt = Date.now();
  return token;
}

async function fetchCampaigns(at, acct, env, { risk = true, force = true, version } = {}) {
  const region = regionOf(acct.region), url = EP.campaigns + (force ? '?forceRefresh=true' : '');
  const extra = risk ? await riskHeaders(acct, env, { version }) : null;
  return qoderFetch(region, url, { headers: authHeaders(at, region, extra) });
}

async function claimCampaign(at, campaignId, acct, env) {
  const region = regionOf(acct.region);
  const headers = Object.assign({ 'content-type': 'application/json', origin: region.api }, await riskHeaders(acct, env));
  return qoderFetch(region, EP.campaigns + '/' + encodeURIComponent(campaignId) + '/claim', { method: 'POST', headers: authHeaders(at, region, headers), body: {} });
}

function campaignRows(payload) { const rows = payload?.campaigns ?? payload?.data?.campaigns; return Array.isArray(rows) ? rows : []; }
const isClaimable = (s) => /^(CLAIMABLE|UNCLAIMED|UN_CLAIMED|AVAILABLE|PENDING_CLAIM)$/i.test(String(s || ''));
const isClaimedStatus = (s) => /^(CLAIMED|ALREADY_CLAIMED|RECEIVED|GRANTED|DONE)$/i.test(String(s || ''));
const ACTION_PRIORITY = ['CLAIM_BENEFIT', 'VIEW_DETAILS', 'DAILY_CHECKIN', 'SIGN_IN'];
const actionRank = (t) => { const i = ACTION_PRIORITY.indexOf(String(t || '')); return i < 0 ? ACTION_PRIORITY.length : i; };

function describeRow(row) {
  const type = String(row?.actionType ?? '空'), st = String(row?.claimStatus ?? '空');
  const title = String(row?.title || row?.name || row?.campaignName || row?.displayName || '').trim();
  const amt = Number(row?.benefit?.amount ?? row?.reward?.amount ?? row?.credits ?? row?.creditAmount ?? 0) || 0;
  return type + ' / ' + st + (title ? '「' + title.slice(0, 12) + '」' : '') + (amt ? ' +' + amt : '');
}

function digestCampaigns(payload) {
  const rows = campaignRows(payload);
  if (!rows.length) { const keys = payload && typeof payload === 'object' ? Object.keys(payload).slice(0, 6).join('/') : '非对象'; const dataKeys = payload?.data && typeof payload.data === 'object' ? Object.keys(payload.data).slice(0, 6).join('/') : ''; return '返回 0 条活动，顶层字段 ' + (keys || '空') + (dataKeys ? '，data 字段 ' + dataKeys : ''); }
  const parts = []; for (const row of rows) { const k = describeRow(row); if (!parts.includes(k)) parts.push(k); }
  const text = '返回 ' + rows.length + ' 条：' + parts.slice(0, 4).join('，'); return text.length > 150 ? text.slice(0, 148) + '…' : text;
}

const bjHour = (ms = Date.now()) => new Date(ms + 8 * 3600e3).getUTCHours();

async function signinOne(env, acct, { force = false } = {}) {
  const now = Date.now(), today = bjDay(now);
  if (!force && acct.lastOkDate === today && acct.lastState === 'checked') return { id: acct.id, label: acct.label, state: 'skipped', msg: '今日已完成' };
  if (!force && Number(acct.cooldownUntil || 0) > now) return { id: acct.id, label: acct.label, state: 'skipped', msg: '限流冷却中' };

  let at = String(acct.accessToken || ''), list;
  try {
    if (!at) at = await refreshAccount(acct);
    list = await fetchCampaigns(at, acct, env);
    if ((list.status === 401 || list.status === 403) && acct.refreshToken) { at = await refreshAccount(acct); list = await fetchCampaigns(at, acct, env); }
  } catch (e) { acct.lastState = e.fatal ? 'token_dead' : 'error'; acct.lastMsg = e.message; acct.lastRun = now; await putAccount(env, acct); return { id: acct.id, label: acct.label, state: acct.lastState, msg: e.message }; }

  let failed = '';
  if (list.status === 429) { acct.cooldownUntil = now + COOLDOWN_MIN * 60000; failed = 'error'; acct.lastMsg = '请求过于频繁（HTTP 429），' + COOLDOWN_MIN + ' 分钟后重试'; }
  else if (list.status === 401 || list.status === 403) { failed = 'token_dead'; acct.lastMsg = '凭证已失效，请删掉这个账号重新添加'; }
  else if (list.status !== 200) { failed = 'error'; acct.lastMsg = '活动列表返回 HTTP ' + list.status; }

  if (failed) { acct.lastState = failed; acct.lastRun = now; await putAccount(env, acct); return { id: acct.id, label: acct.label, state: failed, msg: acct.lastMsg }; }

  const rows = campaignRows(list.json);
  const claimed = rows.some((row) => row && isClaimedStatus(row.claimStatus));
  const target = rows.filter((row) => row && isClaimable(row.claimStatus)).sort((a, b) => actionRank(a.actionType) - actionRank(b.actionType))[0] || null;
  acct.lastRun = now;

  if (!target) {
    const digest = digestCampaigns(list.json), hasBenefitRow = rows.some((row) => /CLAIM_BENEFIT/i.test(String(row?.actionType || '')));
    if (claimed) {
      if (hasBenefitRow) { acct.lastState = 'already'; acct.lastOkDate = today; acct.lastMsg = '今日已领取（活动状态已是 CLAIMED）'; }
      else { acct.lastState = 'wait'; acct.lastMsg = '今日没有签到活动，只有营销活动 · ' + digest; }
    } else { acct.lastState = 'wait'; acct.lastMsg = '没有可领取的活动 · ' + digest; }
    await putAccount(env, acct); return { id: acct.id, label: acct.label, state: acct.lastState, msg: acct.lastMsg };
  }

  const campaignId = String(target.campaignId || target.campaignKey || target.key || target.id || '').trim();
  if (!campaignId) { acct.lastState = 'error'; acct.lastMsg = '活动数据里没有 campaignId，无法领取'; await putAccount(env, acct); return { id: acct.id, label: acct.label, state: acct.lastState, msg: acct.lastMsg }; }

  let claim;
  try { claim = await claimCampaign(at, campaignId, acct, env); }
  catch (e) { acct.lastState = 'error'; acct.lastMsg = '领取请求异常：' + e.message; await putAccount(env, acct); return { id: acct.id, label: acct.label, state: acct.lastState, msg: acct.lastMsg }; }

  const body = claim.json || {}, already = claim.status === 409 || body.result === 'ALREADY_CLAIMED' || body.replayed === true;
  if (already) { acct.lastState = 'already'; acct.lastOkDate = today; acct.lastMsg = '今日已领取'; }
  else if (claim.status === 200 || claim.status === 201) {
    const pick = (o) => (o && typeof o === 'object' ? o : {}), b1 = pick(body.benefit).amount ?? pick(body.reward).amount ?? body.credits ?? body.creditAmount, b2 = pick(target.benefit).amount ?? pick(target.reward).amount ?? target.credits ?? target.creditAmount, amount = Number(b1 ?? b2 ?? 0) || 0;
    const typeTag = String(target.actionType || '') !== 'CLAIM_BENEFIT' ? '（' + String(target.actionType || '未知类型') + '）' : '';
    if (body.status && body.status !== 'CLAIMED') { acct.lastState = 'pending'; acct.lastMsg = '提交成功但上游未确认（状态 ' + body.status + '）'; }
    else { acct.lastState = 'checked'; acct.lastOkDate = today; acct.lastCredit = amount; acct.totalCredit = Number(acct.totalCredit || 0) + amount; acct.totalSigned = Number(acct.totalSigned || 0) + 1; acct.lastMsg = '领取成功 +' + amount + ' credits' + typeTag; }
  }
  else if (claim.status === 429) { acct.lastState = 'error'; acct.cooldownUntil = now + COOLDOWN_MIN * 60000; acct.lastMsg = '领取被限流（HTTP 429），稍后重试'; }
  else if (claim.status === 401 || claim.status === 403) { acct.lastState = 'token_dead'; acct.lastMsg = '领取失败，凭证已失效，请重新添加账号'; }
  else { acct.lastState = 'error'; const why = [body.message, body.errorMessage, body.msg, body.result, body.code].find((x) => typeof x === 'string' && x.trim()) || ''; acct.lastMsg = '领取失败（HTTP ' + claim.status + '）' + why; }
  await putAccount(env, acct); return { id: acct.id, label: acct.label, state: acct.lastState, msg: acct.lastMsg };
}

async function handleList(request, env) {
  const list = await listAccounts(env), out = [], now = Date.now(), today = bjDay(now);
  for (const meta of list) {
    const a = await getAccount(env, meta.id); if (!a) continue;
    out.push({ id: a.id, label: a.label, region: regionOf(a.region).key, regionName: regionOf(a.region).name, lastState: a.lastState, lastMsg: a.lastMsg, lastRun: a.lastRun ? new Date(a.lastRun + 8 * 3600e3).toISOString().replace('Z', ' +08:00') : null, lastOkDate: a.lastOkDate ?? null, lastCredit: a.lastCredit ?? null, totalCredit: a.totalCredit ?? 0, totalSigned: a.totalSigned ?? 0, cooldownUntil: Number(a.cooldownUntil || 0) > now ? a.cooldownUntil : 0, today, signedToday: a.lastOkDate === today, ranToday: a.lastRun ? bjDay(a.lastRun) === today : false, via: a.via || '' });
  }
  return json({ count: out.length, today, accounts: out });
}

async function handleRun(request, env, force) {
  const list = await listAccounts(env), results = [];
  for (const meta of list) { const a = await getAccount(env, meta.id); if (!a) continue; try { results.push(await signinOne(env, a, { force })); } catch (e) { results.push({ id: a.id, label: a.label, state: 'error', msg: e.message }); } }
  return json({ at: new Date(Date.now() + 8 * 3600e3).toISOString().replace('Z', ' +08:00'), count: results.length, results });
}

async function handleRemove(request, env) { const body = await readBody(request), id = String(body.id ?? '').trim(); if (!id) return json({ error: '缺少 id' }, 400); await env.QODER_KV.delete(acctKey(id)); await saveIndex(env, (await listAccounts(env)).filter((x) => x.id !== id)); return json({ ok: true, removed: id }); }
async function handleRename(request, env) { const body = await readBody(request), id = String(body.id ?? '').trim(), label = String(body.label ?? '').trim().slice(0, 40); if (!id || !label) return json({ error: '参数错误' }, 400); const acct = await getAccount(env, id); if (!acct) return json({ error: '账号不存在' }, 404); acct.label = label; await putAccount(env, acct); const list = await listAccounts(env); await saveIndex(env, list.map((x) => (x.id === id ? { ...x, label } : x))); return json({ ok: true, id, label }); }

async function handleInspect(request, env) {
  const url = new URL(request.url), id = String(url.searchParams.get('id') ?? '').trim();
  let acct = id ? await getAccount(env, id) : null;
  if (!acct && !id) { const first = (await listAccounts(env))[0]; acct = first ? await getAccount(env, first.id) : null; }
  if (!acct) return json({ error: '没有可诊断的账号' }, 404);
  const region = regionOf(acct.region); let at = String(acct.accessToken || ''), r;
  try {
    if (!at) { at = await refreshAccount(acct); await putAccount(env, acct); } // FIX P3-2
    r = await fetchCampaigns(at, acct, env);
    if ((r.status === 401 || r.status === 403) && acct.refreshToken) { at = await refreshAccount(acct); await putAccount(env, acct); r = await fetchCampaigns(at, acct, env); }
  } catch (e) { return json({ label: acct.label, region: region.key, error: e.message }, 502); }
  const rows = campaignRows(r.json); let versionProbe = null;
  const tryVer = String(url.searchParams.get('version') || '').trim();
  if (tryVer) { const x = await fetchCampaigns(at, acct, env, { risk: true, force: true, version: tryVer }).catch((e) => ({ status: 0, json: {}, text: String(e.message || e) })); versionProbe = { version: tryVer, httpStatus: x.status, count: campaignRows(x.json).length, digest: digestCampaigns(x.json) }; }
  let variants = null;
  if (url.searchParams.get('probe') === '1') {
    const one = async (risk, force) => { const x = await fetchCampaigns(at, acct, env, { risk, force }).catch((e) => ({ status: 0, json: {}, text: String(e.message || e) })); return { risk, forceRefresh: force, httpStatus: x.status, count: campaignRows(x.json).length, digest: digestCampaigns(x.json) }; };
    variants = [{ risk: true, forceRefresh: true, httpStatus: r.status, count: rows.length, digest: digestCampaigns(r.json) }, await one(false, true), await one(true, false)];
  }
  const rh = await riskHeaders(acct, env), sent = Object.keys(authHeaders(at, region, rh)).filter((k) => k !== 'authorization');
  return json({
    label: acct.label, region: region.key, api: region.api, httpStatus: r.status, count: rows.length, claimable: rows.filter((x) => x && isClaimable(x.claimStatus)).length,
    digest: digestCampaigns(r.json), sentHeaders: sent, clientVersion: CLIENT_VERSION, versionProbe, variants,
    willClaim: (() => { const t = rows.filter((x) => x && isClaimable(x.claimStatus)).sort((a, b) => actionRank(a.actionType) - actionRank(b.actionType))[0]; if (!t) return null; return { actionType: t.actionType ?? null, id: String(t.campaignId || t.campaignKey || t.key || t.id || '') || null, row: t }; })(),
    campaigns: rows, raw: r.json,
  });
}

function json(data, status = 200) { return new Response(JSON.stringify(data, null, 2), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } }); }
async function requireAdmin(request, env) { const url = new URL(request.url), given = request.headers.get('X-Admin-Token') || (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token'); if (!env.ADMIN_TOKEN) return { ok: false, res: json({ error: '未配置 ADMIN_TOKEN' }, 500) }; if (!(await timingSafeEqual(given, env.ADMIN_TOKEN))) return { ok: false, res: json({ error: '登录密码不正确' }, 401) }; return { ok: true }; }
async function requireCron(request, env) { const secret = env.CRON_SECRET || env.ADMIN_TOKEN, given = request.headers.get('X-Cron-Secret'); if (!secret) return { ok: false, res: json({ error: '未配置 CRON_SECRET / ADMIN_TOKEN' }, 500) }; if (!(await timingSafeEqual(given, secret))) return { ok: false, res: json({ error: '口令不对' }, 401) }; return { ok: true }; }
async function readBody(request) { try { return await request.json(); } catch { return {}; } }

const __mod = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url), path = url.pathname.replace(/\/+$/, '') || '/', method = request.method.toUpperCase();
    try {
      if (path === '/cron') { const c = await requireCron(request, env); if (!c.ok) return c.res; return handleRun(request, env, false); }
      if (!path.startsWith('/api/')) return json({ error: 'not found' }, 404);
      const a = await requireAdmin(request, env); if (!a.ok) return a.res;
      if (path === '/api/list' && method === 'GET') return handleList(request, env);
      if (path === '/api/login/start' && method === 'POST') return handleLoginStart(request, env);
      if (path === '/api/login/poll' && method === 'GET') return handleLoginPoll(request, env);
      if (path === '/api/remove' && method === 'POST') return handleRemove(request, env);
      if (path === '/api/rename' && method === 'POST') return handleRename(request, env);
      if (path === '/api/inspect' && method === 'GET') return handleInspect(request, env);
      if (path === '/api/run' && method === 'POST') return handleRun(request, env, url.searchParams.get('force') === '1');
      return json({ error: 'not found' }, 404);
    } catch (e) { return json({ error: e.message || String(e) }, 500); }
  },
  async scheduled(event, env, ctx) { ctx.waitUntil((async () => { const list = await listAccounts(env); for (const meta of list) { const acct = await getAccount(env, meta.id); if (!acct) continue; try { await signinOne(env, acct, { force: false }); } catch {} } })()); },
};
return { fetch: __mod.fetch, scheduled: __mod.scheduled };
})();


/* ================================================================== */
/* 模块四：外壳 —— 绑定适配 / 路由分发 / 控制台 */
/* ================================================================== */

function kvScope(kv, prefix) {
  const strip = (keys) => (keys || []).map((x) => ({ ...x, name: String(x.name).slice(prefix.length) }));
  return {
    async get(k, o) { return kv.get(prefix + k, o); },
    async put(k, v, o) { return kv.put(prefix + k, v, o); },
    async delete(k) { return kv.delete(prefix + k); },
    async list(o = {}) { const r = await kv.list({ ...o, prefix: prefix + (o.prefix || '') }); return { ...r, keys: strip(r.keys) }; },
  };
}

function missingKV(hint) { const boom = () => { throw new Error(hint); }; return { get: boom, put: boom, delete: boom, list: boom }; }
function kvFor(env, prefix) { if (env.KV) return kvScope(env.KV, prefix); return missingKV('未绑定 KV：请给 Worker 添加一个 KV 命名空间，变量名填 KV'); }

function traeEnv(env) { return { TRAE_KV: kvFor(env, 'trae:'), TRAE_MASTER_KEY: env.MASTER_KEY, ADMIN_TOKEN: env.ADMIN_TOKEN, CRON_SECRET: env.CRON_SECRET }; }
function wbEnv(env) { return { WB_KV: kvFor(env, 'wb:'), WB_MASTER_KEY: env.MASTER_KEY, ADMIN_TOKEN: env.ADMIN_TOKEN, CRON_SECRET: env.CRON_SECRET }; }
function qoderEnv(env) { return { QODER_KV: kvFor(env, 'qoder:'), QODER_MASTER_KEY: env.MASTER_KEY, ADMIN_TOKEN: env.ADMIN_TOKEN, CRON_SECRET: env.CRON_SECRET }; }

function json(data, status = 200) { return new Response(JSON.stringify(data, null, 2), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' } }); }

function htmlResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      /* FIX P2-7：增加安全响应头 */
      'Referrer-Policy': 'no-referrer',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY'
    },
  });
}

/* FIX P1-2：统一改为异步定长比较 */
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const h = async (s) => new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(String(s ?? ''))));
  const [x, y] = await Promise.all([h(a), h(b)]);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function requireAdmin(request, env) {
  const url = new URL(request.url);
  const given = request.headers.get('X-Admin-Token') || (request.headers.get('Authorization') || '').replace(/^Bearer\s+/i, '') || url.searchParams.get('token');
  if (!env.ADMIN_TOKEN) return { ok: false, res: json({ error: '未配置 ADMIN_TOKEN' }, 500) };
  if (!(await safeEqual(given, env.ADMIN_TOKEN))) return { ok: false, res: json({ error: '登录密码不正确' }, 401) };
  return { ok: true };
}

/* FIX P2-6：移除 url.searchParams.get('key')，强制走 Header */
async function requireCron(request, env) {
  const secret = env.CRON_SECRET || env.ADMIN_TOKEN;
  const given = request.headers.get('X-Cron-Secret');
  if (!secret) return { ok: false, res: json({ error: '未配置 CRON_SECRET / ADMIN_TOKEN' }, 500) };
  if (!(await safeEqual(given, secret))) return { ok: false, res: json({ error: '口令不对' }, 401) };
  return { ok: true };
}

function repath(request, path) {
  const u = new URL(request.url);
  u.pathname = path || '/';
  return new Request(u.toString(), request);
}

async function runPlatform(mod, env, origin, force) {
  const target = new URL('/api/run' + (force ? '?force=1' : ''), origin);
  const req = new Request(target.toString(), { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Admin-Token': String(env.ADMIN_TOKEN || '') }, body: '{}' });
  const res = await mod.fetch(req, env, { waitUntil() {} });
  const data = await res.json().catch(() => ({ error: 'HTTP ' + res.status }));
  return data;
}

async function runAll(env, origin, force) {
  const out = {};
  for (const [key, mod, e] of [['trae', Trae, traeEnv(env)], ['wb', WorkBuddy, wbEnv(env)], ['qoder', Qoder, qoderEnv(env)]]) {
    try { out[key] = await runPlatform(mod, e, origin, force); }
    catch (err) { out[key] = { error: err.message || String(err) }; }
  }
  const result = { at: new Date(Date.now() + 8 * 3600e3).toISOString().replace('Z', ' +08:00'), ...out };
  try { const n = await notifyRun(env, result); if (n && n.errors) result.notifyError = n.errors; }
  catch (err) { result.notifyError = [String(err.message || err)]; }
  return result;
}

const NOTIFY_TIMEOUT = 12000;

/* FIX P2-4：QQ_OPENID_HELPER 改为读环境变量，避免 ps aux 泄露 AppSecret */
const QQ_OPENID_HELPER = `#!/usr/bin/env node
const appId = process.env.QQ_APP_ID || process.argv[2];
const secret = process.env.QQ_APP_SECRET || process.argv[3];

if (!appId || !secret) {
  console.error('用法: QQ_APP_ID=xxx QQ_APP_SECRET=yyy node openid-helper.mjs');
  console.error(' (或: node openid-helper.mjs <AppID> <AppSecret>)');
  process.exit(1);
}

const TOKEN_URL = 'https://bots.qq.com/app/getAppAccessToken';
const API = 'https://api.sgroup.qq.com';
const INTENTS_GROUP_AND_C2C = 1 << 25;

async function main() {
  console.log('1/3 换取 access_token…');
  const tr = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ appId, clientSecret: secret }),
  });
  const tj = await tr.json().catch(() => ({}));
  if (!tj.access_token) {
    console.error('✗ 换取 token 失败：' + JSON.stringify(tj));
    process.exit(1);
  }

  console.log('2/3 获取 WebSocket 网关…');
  const gr = await fetch(API + '/gateway', { headers: { authorization: 'QQBot ' + tj.access_token } });
  const gj = await gr.json().catch(() => ({}));
  if (!gj.url) {
    console.error('✗ 获取网关失败：' + JSON.stringify(gj));
    process.exit(1);
  }

  console.log('3/3 已连接，请现在用手机 QQ 给机器人发一条私聊消息…');
  console.log('    （60 秒内有效，收到后脚本会自己退出）');

  const ws = new WebSocket(gj.url);
  let seq = null, heartbeat = null;
  const timer = setTimeout(() => { console.error('✗ 超时：60 秒内没收到消息。'); cleanup(1); }, 60000);

  function cleanup(code) { clearTimeout(timer); if (heartbeat) clearInterval(heartbeat); try { ws.close(); } catch (e) {} setTimeout(() => process.exit(code), 80); }

  ws.onopen = () => console.log('   连接已建立，等待鉴权…');
  ws.onmessage = (ev) => {
    let p2;
    try { p2 = JSON.parse(ev.data); } catch (e) { return; }
    if (p2.s) seq = p2.s;
    if (p2.op === 10) {
      ws.send(JSON.stringify({ op: 2, d: { token: 'QQBot ' + tj.access_token, intents: INTENTS_GROUP_AND_C2C, shard: [0, 1], properties: { $os: 'linux', $browser: 'node', $device: 'node' } } }));
      heartbeat = setInterval(() => { try { ws.send(JSON.stringify({ op: 1, d: seq })); } catch (e) {} }, 40000);
      return;
    }
    if (p2.op === 9) { console.error('✗ 鉴权失败：intents 没权限。去 q.qq.com 确认机器人开通了「私聊消息」事件。'); cleanup(1); return; }
    if (p2.op !== 0 || !p2.t) return;
    if (p2.t === 'READY') { console.log('   鉴权通过，正在等你发消息…'); return; }
    const d = p2.d || {}, author = d.author || {}, oid = author.user_openid || author.member_openid || d.user_openid || '';
    if (oid) {
      console.log('\\n==============================================');
      console.log('✅ 拿到了 OpenID：\\n\\n   ' + oid + '\\n');
      console.log('事件类型: ' + p2.t);
      console.log('==============================================\\n');
      cleanup(0); return;
    }
    console.log('   收到事件 ' + p2.t + '，不是消息事件，继续等…');
  };
  ws.onerror = () => console.error('   连接异常，继续等待…');
}
main().catch((e) => { console.error('✗ ' + (e && e.message ? e.message : e)); process.exit(1); });
`;

const NOTIFY_KEY = 'config';

function envNotifyDefaults(env) {
  const s = (k) => String(env?.[k] || '').trim(), cfg = {};
  if (s('TG_BOT_TOKEN') || s('TG_CHAT_ID')) cfg.telegram = { enabled: true, token: s('TG_BOT_TOKEN'), chatId: s('TG_CHAT_ID') };
  if (s('QQ_APP_ID') || s('QQ_OPENID')) cfg.qq = { enabled: true, appId: s('QQ_APP_ID'), secret: s('QQ_APP_SECRET'), openid: s('QQ_OPENID'), sandbox: /^(1|true|yes)$/i.test(s('QQ_SANDBOX')) };
  return cfg;
}

function nvB64(buf) { const b = new Uint8Array(buf); let out = ''; for (let i = 0; i < b.length; i++) out += String.fromCharCode(b[i]); return btoa(out); }
function nvUnb64(str) { const bin = atob(str), out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; }

async function nvKey(env, salt) {
  const raw = String(env.MASTER_KEY || '').trim(); if (!raw) throw new Error('缺少 MASTER_KEY');
  const master = nvUnb64(raw); if (master.length !== 32) throw new Error('MASTER_KEY 必须是 32 字节');
  const base = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info: new TextEncoder().encode('notify/v1/config') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function nvSeal(env, obj) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12)), key = await nvKey(env, salt);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return JSON.stringify({ v: 1, s: nvB64(salt), i: nvB64(iv), d: nvB64(ct) });
}

async function nvOpen(env, text) {
  const box = JSON.parse(text), key = await nvKey(env, nvUnb64(box.s));
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nvUnb64(box.i) }, key, nvUnb64(box.d));
  return JSON.parse(new TextDecoder().decode(pt));
}

async function loadNotifyConfig(env) { try { const raw = await kvFor(env, 'notify:').get(NOTIFY_KEY); if (raw) return await nvOpen(env, raw); } catch {} return envNotifyDefaults(env); }
async function saveNotifyConfig(env, cfg) { await kvFor(env, 'notify:').put(NOTIFY_KEY, await nvSeal(env, cfg)); }

async function notifyChannels(env) {
  const cfg = await loadNotifyConfig(env), ch = {}, str = (v) => String(v || '').trim();
  const t = cfg.telegram || {};
  if (t.enabled !== false && str(t.token) && str(t.chatId)) ch.telegram = { token: str(t.token), chatId: str(t.chatId) };
  const q = cfg.qq || {};
  if (q.enabled !== false && str(q.appId) && str(q.secret) && str(q.openid)) ch.qq = { appId: str(q.appId), secret: str(q.secret), openid: str(q.openid), sandbox: !!q.sandbox };
  return ch;
}

/** FIX P1-1：密码类字段不回传明文，只回传掩码与状态 */
async function notifyConfigForUi(env) {
  const cfg = await loadNotifyConfig(env);
  const t = cfg.telegram || {}, q = cfg.qq || {};
  return {
    telegram: {
      enabled: t.enabled !== false,
      chatId: t.chatId || '',
      tokenSet: !!t.token,
      tokenMasked: t.token ? '***' + String(t.token).slice(-4) : '',
    },
    qq: {
      enabled: q.enabled !== false,
      appId: q.appId || '',
      openid: q.openid || '',
      sandbox: !!q.sandbox,
      secretSet: !!q.secret,
      secretMasked: q.secret ? '***' + String(q.secret).slice(-4) : '',
    },
    fromEnv: !(await kvFor(env, 'notify:').get(NOTIFY_KEY)),
  };
}

async function notifyFetch(url, { method = 'POST', headers = {}, body, timeout = NOTIFY_TIMEOUT } = {}) {
  const ctrl = new AbortController(), timer = setTimeout(() => ctrl.abort(), timeout);
  try {
    const r = await fetch(url, { method, headers: { accept: 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body), signal: ctrl.signal });
    const text = await r.text(); let json = {};
    try { json = text ? JSON.parse(text) : {}; } catch { json = {}; }
    return { status: r.status, json, text };
  } finally { clearTimeout(timer); }
}

async function sendTelegram(cfg, text) {
  const r = await notifyFetch('https://api.telegram.org/bot' + cfg.token + '/sendMessage', { headers: { 'content-type': 'application/json' }, body: { chat_id: cfg.chatId, text, disable_web_page_preview: true } });
  if (r.status >= 400 || r.json.ok === false) throw new Error('Telegram HTTP ' + r.status + '：' + (r.json.description || r.text.slice(0, 120)));
}

let qqToken = null;
async function qqAccessToken(cfg) {
  if (qqToken && qqToken.appId === cfg.appId && qqToken.exp > Date.now()) return qqToken.token;
  const r = await notifyFetch('https://bots.qq.com/app/getAppAccessToken', { headers: { 'content-type': 'application/json' }, body: { appId: cfg.appId, clientSecret: cfg.secret } });
  const token = r.json.access_token || r.json.accessToken;
  if (r.status >= 400 || !token) throw new Error('QQ 换 access_token 失败 HTTP ' + r.status + '：' + r.text.slice(0, 140));
  const ttl = Number(r.json.expires_in || r.json.expiresIn || 7200);
  qqToken = { appId: cfg.appId, token, exp: Date.now() + Math.max(60, ttl - 120) * 1000 };
  return token;
}

async function sendQQ(cfg, text) {
  const token = await qqAccessToken(cfg), base = cfg.sandbox ? 'https://sandbox.api.sgroup.qq.com' : 'https://api.sgroup.qq.com';
  const r = await notifyFetch(base + '/v2/users/' + encodeURIComponent(cfg.openid) + '/messages', { headers: { 'content-type': 'application/json', authorization: 'QQBot ' + token }, body: { content: text, msg_type: 0 } });
  if (r.status >= 400) throw new Error('QQ 发送失败 HTTP ' + r.status + '：' + (r.json.message || r.text.slice(0, 140)));
}

const PLATFORM_LABEL = { trae: 'Trae', wb: 'WorkBuddy', qoder: 'Qoder' };
function tally(d) { const rs = Array.isArray(d?.results) ? d.results : []; let ok = 0, skip = 0, bad = 0; for (const r of rs) { if (r.state === 'checked') ok++; else if (r.state === 'skipped' || r.state === 'already') skip++; else bad++; } return { ok, skip, bad, total: rs.length }; }

function formatReport(result) {
  const lines = [], at = String(result.at || '').replace(' +08:00', '');
  lines.push('📋 签到完成 · ' + (at ? at.slice(5, 16) : ''));
  let anyBad = false;
  for (const key of ['trae', 'wb', 'qoder']) {
    const d = result[key], name = PLATFORM_LABEL[key]; if (!d) continue;
    if (d.error) { lines.push(`${name}  ❌ ${String(d.error).slice(0, 90)}`); anyBad = true; continue; }
    const t = tally(d); if (!t.total) { lines.push(`${name}  — 没有账号`); continue; }
    const mark = t.bad ? '⚠️' : '✅'; if (t.bad) anyBad = true;
    const done = t.ok + t.skip, extra = [];
    if (t.ok) extra.push(`新签 ${t.ok}`); if (t.skip) extra.push(`已签 ${t.skip}`); if (t.bad) extra.push(`失败 ${t.bad}`);
    const suffix = extra.length > 1 || t.skip || t.bad ? ' · ' + extra.join(' · ') : '';
    lines.push(`${name}  ${mark} ${done}/${t.total}${suffix}`);
    for (const r of (d.results || []).slice(0, 6)) { if (r.state === 'checked' && r.msg) lines.push('   · ' + r.label + ' ' + String(r.msg).slice(0, 60)); else if (r.state !== 'checked' && r.state !== 'skipped' && r.msg) lines.push('   · ' + r.label + ' ' + String(r.msg).slice(0, 60)); }
    if ((d.results || []).length > 6) lines.push('   · …还有 ' + (d.results.length - 6) + ' 个');
  }
  if (anyBad) lines.push('', '需要处理的部分可以打开控制台看一眼。');
  return lines.join('\n');
}

async function notifyRun(env, result) {
  const ch = await notifyChannels(env); if (!ch.telegram && !ch.qq) return { skipped: true };
  const text = formatReport(result), jobs = [];
  if (ch.telegram) jobs.push(sendTelegram(ch.telegram, text).then(() => null, (e) => 'Telegram：' + (e.message || e)));
  if (ch.qq) jobs.push(sendQQ(ch.qq, text).then(() => null, (e) => 'QQ：' + (e.message || e)));
  const errors = (await Promise.all(jobs)).filter(Boolean);
  return errors.length ? { errors } : { ok: true, channels: Object.keys(ch) };
}

/* BUILD 版本号 */
const BUILD = '2026-11-12';

/* ------------------------------------------------------------------ */
/* 前端页面 (PAGE 常量) */
/* ------------------------------------------------------------------ */
const PAGE = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>签到控制台 · Trae + WorkBuddy + Qoder</title>
<style>
  :root{
    --bg:#eef1f5;--glow-a:rgba(16,160,110,.11);--glow-b:rgba(56,110,220,.09);--grid:rgba(15,23,42,.035);
    --surface:#fff;--surface-2:#f6f8fa;--line:rgba(15,23,42,.09);--line-2:rgba(15,23,42,.16);
    --txt:#0c141d;--dim:#5e6a78;--pri:#0d8a61;--pri-ink:#fff;--ring:rgba(13,138,97,.16);
    --ok:#0d8a61;--ok-bg:rgba(13,138,97,.10);--warn:#9a6407;--warn-bg:rgba(190,124,15,.13);
    --bad:#bf3529;--bad-bg:rgba(191,53,41,.10);--idle:#5e6a78;--idle-bg:rgba(15,23,42,.055);
    --bar:rgba(238,241,245,.78);--sh-1:0 1px 2px rgba(15,23,42,.04),0 10px 26px -16px rgba(15,23,42,.22);
    --sh-2:0 18px 44px -22px rgba(15,23,42,.35);--r:16px;
    --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
  }
  @media (prefers-color-scheme:dark){
    :root{
      --bg:#070a0e;--glow-a:rgba(45,208,126,.16);--glow-b:rgba(70,110,255,.13);--grid:rgba(255,255,255,.035);
      --surface:#101822;--surface-2:#0c131b;--line:rgba(255,255,255,.075);--line-2:rgba(255,255,255,.14);
      --txt:#e8eef5;--dim:#8b98a7;--pri:#2fd07e;--pri-ink:#04150d;--ring:rgba(47,208,126,.20);
      --ok:#3ddc97;--ok-bg:rgba(61,220,151,.13);--warn:#e6ae4a;--warn-bg:rgba(230,174,74,.13);
      --bad:#ff7d6e;--bad-bg:rgba(255,125,110,.13);--idle:#8b98a7;--idle-bg:rgba(255,255,255,.06);
      --bar:rgba(7,10,14,.72);--sh-1:0 1px 0 rgba(255,255,255,.03),0 14px 34px -22px rgba(0,0,0,.95);
      --sh-2:0 26px 60px -30px rgba(0,0,0,1);
    }
  }
  *{box-sizing:border-box}
  [hidden]{display:none!important}
  body{margin:0;background:var(--bg);color:var(--txt);-webkit-font-smoothing:antialiased;
       font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif}
  body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
    background:radial-gradient(58% 46% at 8% -6%,var(--glow-a),transparent 62%),
               radial-gradient(46% 42% at 96% 2%,var(--glow-b),transparent 62%)}
  body::after{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;background-image:
      linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);
    background-size:46px 46px;
    -webkit-mask-image:radial-gradient(72% 58% at 50% 0%,#000,transparent 78%);
            mask-image:radial-gradient(72% 58% at 50% 0%,#000,transparent 78%)}
  .wrap{position:relative;z-index:1;max-width:1920px;margin:0 auto;
        padding:clamp(16px,2.6vw,36px) clamp(16px,3vw,44px) 68px}

  .brand{display:flex;align-items:center;gap:13px}
  .mark{width:44px;height:44px;flex:0 0 auto;border-radius:14px;display:grid;place-items:center;
        background:linear-gradient(155deg,var(--pri),#0a6a4a);
        box-shadow:var(--sh-2),inset 0 1px 0 rgba(255,255,255,.3)}
  .mark svg{width:21px;height:21px;fill:none;stroke:#fff;stroke-width:2.6;stroke-linecap:round;stroke-linejoin:round}
  .eyebrow{font-family:var(--mono);font-size:10px;letter-spacing:.18em;text-transform:uppercase;color:var(--dim)}
  .eyebrow .ver{display:inline-block;margin-left:6px;padding:1px 5px;border-radius:4px;
    background:var(--idle-bg);color:var(--dim);letter-spacing:0;font-size:9.5px;text-transform:none}
  h1{font-size:clamp(19px,2.6vw,23px);margin:1px 0 0;font-weight:700;letter-spacing:-.02em;line-height:1.25}

  #loginView{min-height:min(74dvh,640px);display:grid;place-content:center;gap:26px}
  .login-card{width:min(470px,92vw);padding:26px;background:var(--surface);border:1px solid var(--line);
              border-radius:var(--r);box-shadow:var(--sh-1)}
  .lbl{display:block;font-family:var(--mono);font-size:10.5px;letter-spacing:.14em;
       text-transform:uppercase;color:var(--dim);margin-bottom:9px}
  .field{display:flex;gap:10px}
  .field input{flex:1;min-width:0}

  input{font:inherit;padding:12px 14px;border:1px solid var(--line-2);border-radius:12px;
        background:var(--surface);color:var(--txt);outline:none;transition:border-color .18s,box-shadow .18s;width:100%}
  input::placeholder{color:var(--dim)}
  input:focus{border-color:var(--pri);box-shadow:0 0 0 4px var(--ring)}
  button{font:inherit;font-weight:600;display:inline-flex;align-items:center;justify-content:center;gap:8px;
         padding:11px 18px;border-radius:12px;border:1px solid var(--line-2);background:var(--surface);color:var(--txt);
         cursor:pointer;transition:transform .12s ease,box-shadow .18s ease,border-color .18s ease,filter .18s ease}
  button:hover{border-color:var(--txt);transform:translateY(-1px);box-shadow:var(--sh-1)}
  button:active{transform:none}
  button:focus-visible{outline:2px solid var(--pri);outline-offset:2px}
  button.pri{background:var(--pri);border-color:transparent;color:var(--pri-ink);
             box-shadow:inset 0 1px 0 rgba(255,255,255,.22),0 12px 26px -14px var(--pri)}
  button.pri:hover{border-color:transparent;filter:brightness(1.06)}
  button:disabled{opacity:.55;cursor:not-allowed;transform:none;box-shadow:none}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}

  .topbar{position:sticky;top:0;z-index:4;display:flex;align-items:center;justify-content:space-between;
          gap:14px;flex-wrap:wrap;padding:12px 0 14px;margin-bottom:14px;background:var(--bar);
          backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--line)}
  .chip{display:inline-flex;align-items:center;gap:8px;padding:7px 13px;border-radius:999px;border:1px solid var(--line);
        background:var(--surface);font-size:12.5px;color:var(--dim);white-space:nowrap;box-shadow:var(--sh-1)}
  .chip b{color:var(--txt);font-family:var(--mono);font-variant-numeric:tabular-nums;font-size:12px}
  .chip .dot{width:7px;height:7px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px var(--ok-bg)}

  /* GitHub 仓库入口 */
  .gh{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:11px 15px;border-radius:12px;
      border:1px solid var(--line-2);background:var(--surface);color:var(--txt);font-size:13px;font-weight:600;
      text-decoration:none;white-space:nowrap;
      transition:transform .12s ease,box-shadow .18s ease,border-color .18s ease,color .18s ease}
  .gh svg{width:16px;height:16px;flex:0 0 auto;fill:currentColor}
  .gh:hover{border-color:var(--txt);transform:translateY(-1px);box-shadow:var(--sh-1)}
  .gh:active{transform:none}
  .gh:focus-visible{outline:2px solid var(--pri);outline-offset:2px}

  .tabs{display:flex;gap:4px;margin-bottom:18px;padding:4px;border:1px solid var(--line);border-radius:14px;
        background:var(--surface-2);width:fit-content;max-width:100%;overflow:auto}
  .tab{display:inline-flex;align-items:center;gap:9px;padding:10px 20px;border:0;border-radius:10px;background:transparent;
       color:var(--dim);font-size:14px;font-weight:600;white-space:nowrap;box-shadow:none}
  .tab:hover{color:var(--txt);background:var(--ok-bg);transform:none;box-shadow:none}
  .tab.on{background:var(--pri);color:var(--pri-ink);font-weight:700;box-shadow:0 6px 16px var(--ring)}
  .tab.on:hover{background:var(--pri);color:var(--pri-ink)}
  .tab b{font-family:var(--mono);font-size:11px;font-weight:600;padding:1px 7px;border-radius:999px;
         background:var(--idle-bg);color:var(--dim);font-variant-numeric:tabular-nums;transition:background .18s,color .18s}
  .tab.on b{background:rgba(0,0,0,.16);color:var(--pri-ink)}

  .grid{display:grid;gap:18px;grid-template-columns:minmax(0,1fr) clamp(400px,32vw,560px);align-items:start}
  .col{display:grid;gap:18px;min-width:0}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r);padding:20px;box-shadow:var(--sh-1)}
  .card-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px;flex-wrap:wrap}
  .card-head h2{margin:0;font-family:var(--mono);font-size:10.5px;letter-spacing:.16em;
                text-transform:uppercase;color:var(--dim);font-weight:600}
  .card-head .meta{font-family:var(--mono);font-size:11.5px;color:var(--dim);font-variant-numeric:tabular-nums}
  .actions{display:flex;flex-wrap:wrap;align-items:center;gap:10px}
  .actions .err{flex:1 1 100%;margin-top:2px}

  .list table{width:100%;border-collapse:separate;border-spacing:0;font-size:13.5px}
  .list td.time{white-space:nowrap;font-variant-numeric:tabular-nums;font-size:12.5px;color:var(--dim)}
  .list th{text-align:left;padding:0 10px 9px;border-bottom:1px solid var(--line);color:var(--dim);
           font-family:var(--mono);font-size:10px;letter-spacing:.12em;text-transform:uppercase;
           font-weight:600;white-space:nowrap}
  .list td{padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:middle}
  .list tbody tr{transition:background .16s ease}
  .list tbody tr:hover{background:var(--surface-2)}
  .list tbody tr:last-child td{border-bottom:0}
  .list td:first-child{font-weight:600}
  .list .lab-wrap{display:inline-flex;align-items:center;gap:6px;min-width:0;max-width:100%}
  .list td.labcell{white-space:nowrap}
  .list .lab{cursor:pointer;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
             border-bottom:1px dashed transparent;transition:border-color .15s}
  .list .lab:hover{border-bottom-color:var(--dim)}
  .list .pen{width:26px;height:26px;padding:0;flex:0 0 auto;display:inline-grid;place-items:center;
             border:1px solid var(--line-2);border-radius:9px;background:var(--surface-2);
             color:var(--dim);cursor:pointer;box-shadow:none;
             transition:color .15s,border-color .15s,background .15s}
  .list .pen svg{width:13px;height:13px;fill:none;stroke:currentColor;stroke-width:2;
                 stroke-linecap:round;stroke-linejoin:round}
  .list .pen:hover,.list .pen:focus-visible{color:var(--pri);border-color:var(--pri);background:var(--surface)}
  .list .lab-edit{font:inherit;font-weight:600;font-size:13.5px;padding:5px 9px;width:auto;min-width:130px;
                  max-width:210px;border:1px solid var(--pri);border-radius:9px;background:var(--surface);
                  color:var(--txt);box-shadow:0 0 0 3px var(--ring);outline:none}
  .list .thint{color:var(--dim);font-size:11.5px;margin:9px 2px 0;opacity:.85}
  .list .num{font-family:var(--mono);font-variant-numeric:tabular-nums;font-size:13px}
  .list .time{font-family:var(--mono);font-size:11.5px;color:var(--dim);white-space:nowrap}
  .list table button{padding:6px 12px;border-radius:10px;font-size:12.5px;box-shadow:none;white-space:nowrap}
  .list td.ops{white-space:nowrap}
  .list td.ops button{padding:5px 9px}
  .list td.ops button + button{margin-left:5px}
  .list table button:hover{color:var(--bad);border-color:var(--bad);background:var(--bad-bg)}

  .list .rgn{display:inline-block;margin-left:7px;padding:1px 7px;border-radius:7px;
       font-size:10.5px;font-weight:600;letter-spacing:.02em;vertical-align:2px;
       background:var(--idle-bg);color:var(--dim)}

  .tag{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;
       font-size:12px;font-weight:600;white-space:nowrap}
  .tag::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor;flex:0 0 auto}
  .t-ok{background:var(--ok-bg);color:var(--ok)}
  .t-warn{background:var(--warn-bg);color:var(--warn)}
  .t-bad{background:var(--bad-bg);color:var(--bad)}
  .t-idle{background:var(--idle-bg);color:var(--idle)}
  .hint{color:var(--dim);font-size:12.5px;margin-top:9px}
  code{font-family:var(--mono);font-size:11.5px;background:var(--idle-bg);color:var(--txt);padding:2px 6px;border-radius:6px}
  .empty{color:var(--dim);text-align:center;padding:26px 16px;font-size:13px}
  .err{color:var(--bad);font-size:13px;margin-top:10px;white-space:pre-wrap}

  .pass-input{width:100%;box-sizing:border-box;margin-top:4px;padding:9px 11px;border:1px solid var(--line-2);
    border-radius:9px;background:var(--surface-2);color:var(--txt);font-family:var(--mono);font-size:11.5px;
    line-height:1.55;resize:vertical;outline:none;transition:border-color .15s,box-shadow .15s}
  .pass-input:focus{border-color:var(--pri);box-shadow:0 0 0 3px var(--ring)}
  .pass-ok{display:flex;align-items:center;gap:8px;margin-top:4px;padding:9px 11px;border-radius:9px;
    background:var(--ok-bg);color:var(--ok);font-size:12.5px;font-family:var(--mono);word-break:break-all}
  .pass-bad{background:var(--warn-bg);color:var(--warn)}
  .pass-help{margin-top:10px;padding:11px 12px;border-radius:9px;background:var(--surface-2);border:1px solid var(--line)}
  .pass-help pre{margin:6px 0 0;font-family:var(--mono);font-size:11px;line-height:1.6;color:var(--txt);
    white-space:pre-wrap;word-break:break-all}
  .pass-steps{margin:10px 0 0;padding-left:18px;font-size:12.5px;color:var(--dim);line-height:1.7}
  .pass-steps li{margin:2px 0}

  @keyframes rise{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}
  .card,.login-card,.topbar,.tabs{animation:rise .55s cubic-bezier(.22,.9,.28,1) both}
  .col>.card:nth-child(2){animation-delay:.06s}
  .col:nth-child(2)>.card{animation-delay:.12s}
  @media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}

  @media (max-width:1080px){
    .grid{grid-template-columns:minmax(0,1fr)}
    .topbar{position:static}
  }
  @media (max-width:640px){
    #loginView{min-height:auto;padding:36px 0}
    .topbar .gh{padding:11px 12px}
    .topbar .gh .gh-t{display:none}
    .list table,.list tbody,.list tr,.list td{display:block}
    .list thead{display:none}
    .list tbody{display:grid;gap:10px}
    .list tr{padding:12px 14px;border:1px solid var(--line);border-radius:14px;background:var(--surface-2)}
    .list td{display:flex;align-items:center;justify-content:space-between;gap:14px;
             padding:5px 0;border:0;text-align:right}
    .list td::before{content:attr(data-label);flex:0 0 auto;text-align:left;font-family:var(--mono);
             font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--dim)}
    .list td:first-child{font-size:15px;padding-bottom:9px;margin-bottom:5px;border-bottom:1px solid var(--line)}
    .list td:first-child::before{display:none}
    .list td.st{flex-wrap:wrap;justify-content:flex-end}
    .list td.st>div{flex:1 1 100%;text-align:right;margin-top:4px}
    .list td:last-child{padding-top:9px}
    .tab{padding:8px 13px;font-size:13px}
  }
  .nv-mask{position:fixed;inset:0;z-index:60;background:rgba(8,15,24,.42);
    display:flex;align-items:center;justify-content:center;padding:24px;backdrop-filter:blur(3px)}
  .nv-card{width:min(560px,100%);max-height:min(88vh,820px);display:flex;flex-direction:column;
    background:var(--surface);border:1px solid var(--line);border-radius:16px;box-shadow:var(--sh-2);overflow:hidden}
  .nv-head{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--line)}
  .nv-head h3{margin:0;font-size:15px}
  .nv-x{border:0;background:none;font-size:20px;line-height:1;color:var(--dim);padding:4px 8px;box-shadow:none}
  .nv-x:hover{color:var(--txt);transform:none}
  .nv-body{padding:6px 18px 14px;overflow:auto}
  .nv-sec{padding:12px 0;border-bottom:1px dashed var(--line)}
  .nv-sec:last-child{border-bottom:0}
  .nv-h{display:flex;align-items:center;gap:8px;font-size:13.5px;font-weight:700;margin-bottom:10px;cursor:pointer}
  .nv-h input{width:15px;height:15px;accent-color:var(--pri);cursor:pointer}
  .nv-row{display:flex;align-items:center;gap:10px;margin-bottom:7px}
  .nv-row>span{width:56px;flex:none;font-size:12.5px;color:var(--dim)}
  .nv-row input,.nv-row select{flex:1;min-width:0;font-size:13px;padding:8px 10px;border-radius:9px;
    border:1px solid var(--line-2);background:var(--surface-2);color:var(--txt);font-family:inherit}
  .nv-row input:focus,.nv-row select:focus{outline:2px solid var(--ring);border-color:var(--pri)}
  .nv-tip{margin:8px 0 0;font-size:11.5px;line-height:1.7;color:var(--dim)}
  .nv-tip code{font-family:var(--mono);font-size:11px;padding:1px 5px;border-radius:5px;background:var(--surface-2)}
  .nv-warn{color:var(--warn)}
  .nv-tip a{color:var(--pri);text-decoration:none}
  .nv-tip a:hover{text-decoration:underline}
  .nv-copy{flex:none;padding:6px 11px;font-size:12px;border-radius:8px;box-shadow:none;white-space:nowrap}
  .nv-cmd{display:flex;align-items:center;gap:8px;margin-top:8px;padding:7px 10px;border-radius:9px;
    background:var(--surface-2);border:1px solid var(--line)}
  .nv-cmd code{flex:1;min-width:0;font-family:var(--mono);font-size:11.5px;color:var(--txt);overflow-x:auto;white-space:nowrap}
  .nv-os{display:inline-flex;gap:2px;margin-top:8px;padding:2px;background:var(--surface-2);
    border:1px solid var(--line);border-radius:8px}
  .nv-os button{padding:4px 12px;border:0;background:none;border-radius:6px;font-size:11.5px;
    color:var(--dim);box-shadow:none}
  .nv-os button:hover{color:var(--pri);transform:none}
  .nv-os button.on{background:var(--surface);color:var(--txt);box-shadow:0 1px 2px rgba(15,23,42,.08)}
  .nv-foot{display:flex;align-items:center;gap:10px;padding:12px 18px;border-top:1px solid var(--line);background:var(--surface-2)}
  .nv-foot button{padding:8px 16px;font-size:13px}
  .nv-msg{flex:1;font-size:12px;color:var(--dim);min-height:16px}

</style>
</head>
<body>
<div class="wrap">

  <div id="loginView">
    <div class="brand">
      <span class="mark"><svg viewBox="0 0 24 24"><path d="M4.5 12.6l4.6 4.6L19.5 6.8"/></svg></span>
      <div>
        <div class="eyebrow">Daily Check-in</div>
        <h1>签到控制台</h1>
      </div>
    </div>

    <div class="login-card">
      <label class="lbl" for="pwd">登录密码</label>
      <div class="field">
        <input id="pwd" type="password" placeholder="输入登录密码" autocomplete="current-password">
        <button id="loginbtn" class="pri">登录</button>
      </div>
      <div class="hint">密码即后台的 <code>ADMIN_TOKEN</code>。登录状态存在本机浏览器，公共电脑用完请点「退出登录」。</div>
      <div class="err" id="loginErr"></div>
    </div>
  </div>

  <div id="mainView" hidden>
    <header class="topbar">
      <div class="brand">
        <span class="mark"><svg viewBox="0 0 24 24"><path d="M4.5 12.6l4.6 4.6L19.5 6.8"/></svg></span>
        <div>
          <div class="eyebrow">Daily Check-in <span class="ver">${BUILD}</span></div>
          <h1>签到控制台</h1>
        </div>
      </div>
      <div class="row">
        <span class="chip"><i class="dot"></i>今日已签 <b id="statAll">—</b></span>
        <a class="gh" href="https://github.com/ggzhzc/workbuddy-trae-checkin" target="_blank" rel="noopener noreferrer" title="GitHub 仓库" aria-label="GitHub 仓库">
          <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 .5C5.73.5.9 5.34.9 11.6c0 4.91 3.17 9.07 7.57 10.53.55.1.75-.24.75-.53 0-.26-.01-1.13-.02-2.05-3.08.67-3.73-1.31-3.73-1.31-.5-1.28-1.23-1.62-1.23-1.62-1-.69.08-.67.08-.67 1.11.08 1.7 1.14 1.7 1.14.98 1.69 2.58 1.2 3.21.92.1-.72.39-1.21.7-1.48-2.46-.28-5.05-1.23-5.05-5.48 0-1.21.43-2.2 1.14-2.98-.12-.28-.5-1.41.11-2.94 0 0 .93-.3 3.05 1.14a10.5 10.5 0 0 1 5.56 0c2.11-1.44 3.04-1.14 3.04-1.14.61 1.53.23 2.66.11 2.94.71.78 1.14 1.77 1.14 2.98 0 4.26-2.6 5.19-5.07 5.47.4.34.75 1.01.75 2.04 0 1.48-.01 2.68-.01 3.04 0 .29.19.64.76.53 4.4-1.46 7.56-5.62 7.56-10.53C23.1 5.34 18.27.5 12 .5z"/></svg>
          <span class="gh-t">GitHub</span>
        </a>
        <button id="runAll" class="pri">全部签到</button>
        <button id="notifyOpen" title="配置签到结果通知">通知</button>
        <button id="logout">退出登录</button>
      </div>
    </header>

    <nav class="tabs">
      <button class="tab on" data-tab="trae">Trae <b id="cntTrae">0</b></button>
      <button class="tab" data-tab="wb">WorkBuddy <b id="cntWb">0</b></button>
      <button class="tab" data-tab="qoder">Qoder <b id="cntQoder">0</b></button>
    </nav>

    <section class="panel" id="panel-trae">
      <div class="grid">
        <div class="col">
          <div class="card actions">
            <button class="pri" data-run="trae">立即签到</button>
            <button data-refresh="trae">刷新</button>
            <div class="err" id="err-trae"></div>
          </div>
          <div class="card">
            <div class="card-head"><h2>Trae 账号</h2><span class="meta" id="lastRun-trae">—</span></div>
            <div class="list" id="list-trae"><div class="empty">加载中…</div></div>
          </div>
        </div>
        <div class="col">
          <div class="card">
            <div class="card-head"><h2>扫码登录 · Trae</h2></div>
            <div class="row">
              <button class="pri" id="traeQr">添加账号</button>
            </div>
            <div class="hint" id="traeQrStatus">点按钮打开官方登录页，用抖音扫码。登录完成后浏览器会停在一个打不开的本地页面，把地址栏里的整段链接复制过来即可。</div>
            <div id="traeQrFallback" style="margin-top:10px">
              <input id="traeQrUrl" placeholder="粘贴登录后地址栏的整段链接（127.0.0.1:17388/…）">
              <div class="row" style="margin-top:8px">
                <button id="traeQrClaim">绑定账号</button>
              </div>
              <div class="err" id="traeQrErr"></div>
            </div>
            <div class="hint">扫码走官网抖音授权，设备密钥由本服务现场生成并加密保存。全程无需在本机安装或运行任何东西。</div>
          </div>
        </div>
      </div>
    </section>

    <section class="panel" id="panel-wb" hidden>
      <div class="grid">
        <div class="col">
          <div class="card actions">
            <button class="pri" data-run="wb">立即签到</button>
            <button data-refresh="wb">刷新</button>
            <div class="err" id="err-wb"></div>
          </div>
          <div class="card">
            <div class="card-head"><h2>WorkBuddy 账号</h2><span class="meta" id="lastRun-wb">—</span></div>
            <div class="list" id="list-wb"><div class="empty">加载中…</div></div>
          </div>
        </div>
        <div class="col">
          <div class="card">
            <div class="card-head"><h2>扫码登录 · WorkBuddy</h2></div>
            <div class="row">
              <button class="pri" id="wbQr">添加账号</button>
            </div>
            <div class="hint" id="wbQrStatus">点按钮在新窗口打开官方登录页，用微信扫码并确认，账号会自动保存。</div>
            <div class="hint">二维码由官方登录页渲染，本服务不接触你的微信信息。</div>
          </div>
        </div>
      </div>
    </section>

    <section class="panel" id="panel-qoder" hidden>
      <div class="grid">
        <div class="col">
          <div class="card actions">
            <button class="pri" data-run="qoder">立即签到</button>
            <button data-refresh="qoder">刷新</button>
            <div class="err" id="err-qoder"></div>
          </div>
          <div class="card">
            <div class="card-head"><h2>Qoder 账号</h2><span class="meta" id="lastRun-qoder">—</span></div>
            <div class="list" id="list-qoder"><div class="empty">加载中…</div></div>
          </div>
        </div>
        <div class="col">
          <div class="card">
            <div class="card-head"><h2>添加账号 · Qoder</h2></div>
            <div class="row">
              <button class="pri" id="qoderAddCn">添加账号（国内版）</button>
            </div>
            <div class="hint" id="qoderQrStatus">点按钮在新窗口打开官方授权页，用要签到的账号确认一次，账号会自动保存。</div>
          </div>
        </div>
      </div>
    </section>
  </div>

</div>
<script>
var $ = function(s){ return document.querySelector(s); };
var PWD_KEY = 'signin-admin-pwd';
var state = { tok:'', tab:'trae', data:{ trae:null, wb:null, qoder:null } };

function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g, function(c){
  return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];
}); }
function fmt(n){ return n==null||n==='' ? '—' : String(n); }

function bjToday(){ return new Date(Date.now() + 8*3600e3).toISOString().slice(0,10); }
function bjHour(){ return new Date(Date.now() + 8*3600e3).getUTCHours(); }

function tagTrae(a, now){
  if(a.signedToday) return '<span class="tag t-ok">已签</span>';
  if(a.cooldownUntil && a.cooldownUntil > now) return '<span class="tag t-warn">限流 ' + Math.ceil((a.cooldownUntil-now)/60000) + ' 分钟</span>';
  if(a.lastState==='token_dead') return '<span class="tag t-bad">令牌失效</span>';
  if(a.lastState==='pending' && a.ranToday) return '<span class="tag t-warn">待确认</span>';
  if(a.lastState==='error' && a.ranToday) return '<span class="tag t-bad">签到失败</span>';
  if(!a.hasKeys) return '<span class="tag t-warn">缺设备密钥</span>';
  return '<span class="tag t-idle">今日未签</span>';
}
function msgTrae(a){
  if(a.signedToday) return a.lastState==='checked' ? (a.lastMsg||'') : '';
  if(a.lastState==='token_dead') return a.lastMsg || '';
  if(a.lastState==='pending' && a.ranToday) return a.lastMsg || '';
  if(a.lastState==='error' && a.ranToday) return a.lastMsg || '';
  return '';
}
function tagWb(a){
  if(a.signedToday) return '<span class="tag t-ok">已签</span>';
  if(a.lastState==='token_dead') return '<span class="tag t-bad">令牌失效</span>';
  if(a.lastState==='error' && a.ranToday) return '<span class="tag t-bad">签到失败</span>';
  return '<span class="tag t-idle">今日未签</span>';
}
function msgWb(a){
  if(a.signedToday) return a.lastState==='checked' ? (a.lastMsg||'') : '';
  if(a.lastState==='token_dead') return a.lastMsg || '';
  if(a.lastState==='error' && a.ranToday) return a.lastMsg || '';
  return '';
}
function tagQoder(a, now){
  if(a.signedToday) return '<span class="tag t-ok">已签</span>';
  if(a.cooldownUntil && a.cooldownUntil > now) return '<span class="tag t-warn">限流 ' + Math.ceil((a.cooldownUntil-now)/60000) + ' 分钟</span>';
  if(a.lastState==='token_dead') return '<span class="tag t-bad">令牌失效</span>';
  if(a.lastState==='pending' && a.ranToday) return '<span class="tag t-warn">待确认</span>';
  if(a.lastState==='error' && a.ranToday) return '<span class="tag t-bad">签到失败</span>';
  if(a.lastState==='wait' && a.ranToday) return '<span class="tag t-idle">无可领</span>';
  return '<span class="tag t-idle">今日未签</span>';
}
function msgQoder(a){
  if(a.signedToday) return a.lastMsg || '';
  if(a.lastState==='token_dead' || a.lastState==='error' || a.lastState==='pending' || a.lastState==='wait') return a.lastMsg || '';
  return '';
}

function api(path, opts){
  opts = opts || {};
  return fetch(path, {
    method: opts.method || 'GET',
    body: opts.body,
    headers: { 'Content-Type':'application/json', 'X-Admin-Token': state.tok }
  }).then(function(res){
    return res.json().catch(function(){ return { error:'响应无法解析' }; }).then(function(data){
      if(res.status === 401){
        var msg = data.error || '登录已失效，请重新登录';
        logout(msg);
        throw new Error(msg);
      }
      if(!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
      return data;
    });
  });
}

function setLoginErr(m){ $('#loginErr').textContent = m ? String(m) : ''; }
function showErr(p, e){ $('#err-' + p).textContent = e ? String(e.message || e) : ''; }

function login(password){
  var v = String(password==null?'':password).trim();
  if(!v){ setLoginErr('请输入登录密码'); return; }
  var btn = $('#loginbtn');
  btn.disabled = true; btn.textContent = '登录中…';
  return fetch('/api/ping', { headers: { 'X-Admin-Token': v } })
    .then(function(res){
      return res.json().catch(function(){ return { error:'响应无法解析' }; }).then(function(d){
        if(!res.ok) throw new Error(d.error || ('HTTP ' + res.status));
        state.tok = v;
        /* FIX P2-5：改用 sessionStorage */
        sessionStorage.setItem(PWD_KEY, v);
        setLoginErr('');
        $('#loginView').hidden = true;
        $('#mainView').hidden = false;
        loadAll();
      });
    })
    .catch(function(e){ setLoginErr(e.message || e); })
    .then(function(){ btn.disabled = false; btn.textContent = '登录'; });
}

function logout(msg){
  stopWbQr(); stopQoderQr();
  state.tok = '';
  state.data = { trae:null, wb:null, qoder:null };
  sessionStorage.removeItem(PWD_KEY);
  $('#pwd').value = '';
  $('#list-trae').innerHTML = '<div class="empty">加载中…</div>';
  $('#list-wb').innerHTML = '<div class="empty">加载中…</div>';
  $('#list-qoder').innerHTML = '<div class="empty">加载中…</div>';
  $('#statAll').textContent = '—';
  showErr('trae',''); showErr('wb',''); showErr('qoder','');
  setLoginErr(msg || '');
  $('#mainView').hidden = true;
  $('#loginView').hidden = false;
}

function lastRunOf(list){
  var times = list.map(function(a){ return a.lastRun; }).filter(Boolean).sort();
  return times.length ? times[times.length-1].replace('T',' ').slice(0,16) : (list.length ? '暂无记录' : '暂无账号');
}

function renderTrae(d){
  var box = $('#list-trae'), now = Date.now();
  state.data.trae = d;
  $('#lastRun-trae').textContent = lastRunOf(d.accounts);
  $('#cntTrae').textContent = d.accounts.filter(function(a){ return a.signedToday; }).length + '/' + d.accounts.length;
  if(!d.accounts.length){ box.innerHTML = '<div class="empty">还没有账号，右侧扫码添加</div>'; return; }
  box.innerHTML = '<table><thead><tr><th>备注</th><th>状态</th><th>本次</th><th>余额</th><th>上次运行</th><th></th></tr></thead><tbody>'
    + d.accounts.map(function(a){
        var m = msgTrae(a);
        var gain = (a.lastState==='checked' && a.lastCredit!=null) ? '+' + a.lastCredit : '—';
        return '<tr>'
          + '<td class="labcell" data-label="备注">' + labCellHtml('trae', a.id, a.label) + '</td>'
          + '<td class="st" data-label="状态">' + tagTrae(a, now)
            + (m ? '<div class="hint" style="margin:2px 0 0">' + esc(m) + '</div>' : '') + '</td>'
          + '<td class="num" data-label="本次">' + gain + '</td>'
          + '<td class="num" data-label="余额">' + fmt(a.credits) + '</td>'
          + '<td class="time" data-label="上次运行">' + (a.lastRun ? esc(a.lastRun.replace('T',' ').slice(5,16)) : '—') + '</td>'
          + '<td data-label="操作"><button data-del="trae|' + esc(a.id) + '">删除</button></td>'
          + '</tr>';
      }).join('') + '</tbody></table>'
    + '<div class="thint">点账号名或右边的铅笔，可以改备注</div>';
  bindDel();
}

function renderWb(d){
  var box = $('#list-wb'), today = bjToday();
  d.accounts.forEach(function(a){
    a.signedToday = a.lastOkDate === today;
    a.ranToday = !!a.lastRun && a.lastRun.slice(0,10) === today;
  });
  state.data.wb = d;
  $('#lastRun-wb').textContent = lastRunOf(d.accounts);
  $('#cntWb').textContent = d.accounts.filter(function(a){ return a.signedToday; }).length + '/' + d.accounts.length;
  if(!d.accounts.length){ box.innerHTML = '<div class="empty">还没有账号，右侧扫码添加</div>'; return; }
  box.innerHTML = '<table><thead><tr><th>备注</th><th>状态</th><th>连签</th><th>本期</th><th>上次运行</th><th></th></tr></thead><tbody>'
    + d.accounts.map(function(a){
        var m = msgWb(a);
        return '<tr>'
          + '<td class="labcell" data-label="备注">' + labCellHtml('wb', a.id, a.label) + '</td>'
          + '<td class="st" data-label="状态">' + tagWb(a)
            + (m ? '<div class="hint" style="margin:2px 0 0">' + esc(m) + '</div>' : '') + '</td>'
          + '<td class="num" data-label="连签">' + (a.streak==null ? '—' : a.streak + ' 天') + '</td>'
          + '<td class="num" data-label="本期">' + fmt(a.total) + '</td>'
          + '<td class="time" data-label="上次运行">' + (a.lastRun ? esc(a.lastRun.replace('T',' ').slice(5,16)) : '—') + '</td>'
          + '<td data-label="操作"><button data-del="wb|' + esc(a.id) + '">删除</button></td>'
          + '</tr>';
      }).join('') + '</tbody></table>'
    + '<div class="thint">点账号名或右边的铅笔，可以改备注</div>';
  bindDel();
}

function renderQoder(d){
  var box = $('#list-qoder'), now = Date.now();
  state.data.qoder = d;
  $('#lastRun-qoder').textContent = lastRunOf(d.accounts);
  $('#cntQoder').textContent = d.accounts.filter(function(a){ return a.signedToday; }).length + '/' + d.accounts.length;
  if(!d.accounts.length){ box.innerHTML = '<div class="empty">还没有账号，点右侧「添加账号（国内版）」</div>'; return; }
  box.innerHTML = '<table><thead><tr><th>备注</th><th>状态</th><th>本次</th><th>累计</th><th>上次运行</th><th></th></tr></thead><tbody>'
    + d.accounts.map(function(a){
        var m = msgQoder(a);
        var gain = (a.lastState==='checked' && a.lastCredit!=null) ? '+' + a.lastCredit : '—';
        var rgn = '<span class="rgn" title="国内版 qoder.com.cn">国内版</span>';
        return '<tr>'
          + '<td class="labcell" data-label="备注">' + labCellHtml('qoder', a.id, a.label, rgn) + '</td>'
          + '<td class="st" data-label="状态">' + tagQoder(a, now)
            + (m ? '<div class="hint" style="margin:2px 0 0">' + esc(m) + '</div>' : '') + '</td>'
          + '<td class="num" data-label="本次">' + gain + '</td>'
          + '<td class="num" data-label="累计">' + fmt(a.totalCredit) + '</td>'
          + '<td class="time" data-label="上次运行">' + (a.lastRun ? esc(a.lastRun.replace('T',' ').slice(5,16)) : '—') + '</td>'
          + '<td data-label="操作" class="ops"><button data-del="qoder|' + esc(a.id) + '">删除</button></td>'
          + '</tr>';
      }).join('') + '</tbody></table>'
    + '<div class="thint">点账号名或右边的铅笔，可以改备注</div>';
  bindDel();
}

function labCellHtml(p, id, label, extra){
  var k = 'data-rename="' + p + '|' + esc(id) + '" data-name="' + esc(label) + '"';
  return '<span class="lab-wrap">'
    + '<span class="lab" ' + k + ' title="点击修改备注">' + esc(label) + '</span>'
    + (extra || '')
    + '<button class="pen" type="button" ' + k + ' title="修改备注" aria-label="修改备注">'
    + '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 20h3.6L19 8.6a2.2 2.2 0 0 0-3.1-3.1L4.5 16.9V20z"/></svg>'
    + '</button></span>';
}

function startRename(el){
  var td = el.closest('td');
  if(!td || td.querySelector('.lab-edit')) return;
  var parts = el.dataset.rename.split('|');
  var p = parts[0], id = parts[1], old = el.dataset.name || '';
  var chip = td.querySelector('.rgn'), extra = chip ? chip.outerHTML : '';
  td.innerHTML = '<input class="lab-edit" maxlength="40" aria-label="备注" title="回车保存，Esc 取消" value="' + esc(old) + '">';
  var input = td.querySelector('.lab-edit');
  input.focus(); input.select();
  var done = false;
  function restore(){ td.innerHTML = labCellHtml(p, id, old, extra); bindDel(); }
  function finish(save){
    if(done) return;
    done = true;
    var v = input.value.trim();
    if(!save || !v || v === old){ restore(); return; }
    input.disabled = true;
    api(API_URL.rename[p], { method:'POST', body: JSON.stringify({ id:id, label:v }) })
      .then(function(){ return load(p); })
      .catch(function(e){ showErr(p, e); restore(); });
  }
  input.addEventListener('keydown', function(ev){
    if(ev.key === 'Enter'){ ev.preventDefault(); finish(true); }
    else if(ev.key === 'Escape'){ ev.preventDefault(); finish(false); }
  });
  input.addEventListener('blur', function(){ finish(true); });
}

function bindDel(){
  document.querySelectorAll('[data-del]').forEach(function(b){
    b.onclick = function(){
      var parts = b.dataset.del.split('|');
      var p = parts[0], id = parts[1];
      if(!confirm('删除这个账号？')) return;
      api(API_URL.remove[p], { method:'POST', body: JSON.stringify({ id:id }) })
        .then(function(){ return load(p); })
        .catch(function(e){ showErr(p, e); });
    };
  });
  document.querySelectorAll('[data-rename]').forEach(function(el){
    el.onclick = function(ev){ ev.stopPropagation(); startRename(el); };
  });
}

function renderStat(){
  var loaded = ['trae','wb','qoder'].filter(function(k){ return state.data[k]; });
  if(!loaded.length){ $('#statAll').textContent = '—'; return; }
  var all = [];
  loaded.forEach(function(k){ all = all.concat(state.data[k].accounts || []); });
  var signed = all.filter(function(a){ return a.signedToday; }).length;
  $('#statAll').textContent = signed + ' / ' + all.length;
}

var API_URL = {
  list:  { trae:'/trae/api/list', wb:'/wb/api/list', qoder:'/qoder/api/list' },
  run:   { trae:'/trae/api/run?force=1', wb:'/wb/api/run?force=1', qoder:'/qoder/api/run?force=1' },
  rename:{ trae:'/trae/api/rename', wb:'/wb/api/rename', qoder:'/qoder/api/rename' },
  remove:{ trae:'/trae/api/accounts/remove', wb:'/wb/api/remove', qoder:'/qoder/api/remove' },
  name:  { trae:'Trae', wb:'WorkBuddy', qoder:'Qoder' }
};

function load(p){
  return api(API_URL.list[p])
    .then(function(d){
      if(p === 'trae') renderTrae(d);
      else if(p === 'wb') renderWb(d);
      else renderQoder(d);
      renderStat();
    })
    .catch(function(e){ showErr(p, e); renderStat(); });
}

function loadAll(){
  return Promise.all([load('trae'), load('wb'), load('qoder')]);
}

function runOne(p){
  var btns = document.querySelectorAll('[data-run="' + p + '"]');
  btns.forEach(function(b){ b.disabled = true; b.textContent = '签到中…'; });
  showErr(p, '');
  return api(API_URL.run[p], { method:'POST', body:'{}' })
    .then(function(d){
      var bad = (d.results || []).filter(function(r){ return r.state==='error' || r.state==='token_dead'; });
      if(bad.length) showErr(p, bad.map(function(r){ return r.label + ': ' + r.msg; }).join('\\n'));
      return load(p);
    })
    .catch(function(e){ showErr(p, e); })
    .then(function(){ btns.forEach(function(b){ b.disabled = false; b.textContent = '立即签到'; }); });
}

function runAll(){
  var btn = $('#runAll');
  btn.disabled = true; btn.textContent = '签到中…';
  showErr('trae',''); showErr('wb','');
  api('/api/run-all?force=1', { method:'POST', body:'{}' })
    .then(function(d){
      var lines = [];
      ['trae','wb','qoder'].forEach(function(k){
        var r = d[k] || {};
        if(r.error){ lines.push(API_URL.name[k] + ': ' + r.error); return; }
        (r.results || []).forEach(function(x){ if(x.state==='error' || x.state==='token_dead') lines.push(x.label + ': ' + x.msg); });
      });
      if(lines.length) showErr('trae', lines.join('\\n'));
      return loadAll();
    })
    .catch(function(e){ showErr('trae', e); })
    .then(function(){ btn.disabled = false; btn.textContent = '全部签到'; });
}

document.querySelectorAll('.tab').forEach(function(t){
  t.onclick = function(){
    var p = t.dataset.tab;
    state.tab = p;
    document.querySelectorAll('.tab').forEach(function(x){ x.classList.toggle('on', x === t); });
    ['trae','wb','qoder'].forEach(function(k){ $('#panel-' + k).hidden = p !== k; });
  };
});

function startTraeQr(){
  var btn = $('#traeQr');
  var old = btn.textContent;
  btn.disabled = true; btn.textContent = '准备中…';
  $('#traeQrErr').textContent = '';
  return api('/trae/api/login/start', { method:'POST', body: '{}' })
    .then(function(d){
      var w = window.open(d.authUrl, 'trae-login', 'width=520,height=820');
      if(!w){
        $('#traeQrStatus').innerHTML = '新窗口被拦截了：<a href="' + esc(d.authUrl) + '" target="_blank" rel="noopener">点这里打开登录页</a>';
      }else{
        $('#traeQrStatus').textContent = '已打开登录页：扫码登录，页面跳到一个打不开的 127.0.0.1 地址后，复制地址栏的整段链接粘到下面。';
        var watch = setInterval(function(){ if(!w || w.closed){ clearInterval(watch); $('#traeQrUrl').focus(); } }, 1200);
      }
    })
    .catch(function(e){ $('#traeQrStatus').textContent = String(e.message || e); })
    .then(function(){ btn.disabled = false; btn.textContent = old; });
}

function claimTrae(){
  var btn = $('#traeQrClaim');
  var url = $('#traeQrUrl').value.trim();
  if(!url || btn.disabled) return;
  $('#traeQrErr').textContent = '';
  btn.disabled = true; btn.textContent = '绑定中…';
  api('/trae/api/login/claim', { method:'POST', body: JSON.stringify({ url: url }) })
    .then(function(d){
      $('#traeQrStatus').textContent = '登录成功，已保存为「' + d.label + '」';
      $('#traeQrUrl').value = '';
      return load('trae');
    })
    .catch(function(e){ $('#traeQrErr').textContent = String(e.message || e); })
    .then(function(){ btn.disabled = false; btn.textContent = '绑定账号'; });
}

$('#traeQr').onclick = startTraeQr;
$('#traeQrClaim').onclick = claimTrae;
$('#traeQrUrl').addEventListener('paste', function(){
  setTimeout(function(){ if($('#traeQrUrl').value.trim()) claimTrae(); }, 0);
});

var wbState = '', wbTimer = null;
function stopWbQr(){ if(wbTimer){ clearInterval(wbTimer); wbTimer = null; } }

$('#wbQr').onclick = function(){
  stopWbQr();
  var btn = $('#wbQr');
  btn.disabled = true; btn.textContent = '获取中…';
  showErr('wb', '');
  var win = window.open('about:blank', 'wb-login', 'width=640,height=880');
  api('/wb/api/login/start', { method:'POST', body:'{}' })
    .then(function(d){
      wbState = d.state;
      var opened = false;
      if(win && !win.closed){ try { win.location.href = d.authUrl; opened = true; } catch(e) {} }
      if(opened) $('#wbQrStatus').textContent = '已在新窗口打开登录页，用微信扫码并确认，本页会自动保存账号。';
      else $('#wbQrStatus').innerHTML = '新窗口被拦截了：<a href="' + esc(d.authUrl) + '" target="_blank" rel="noopener">点这里打开登录页</a>';
      btn.textContent = '添加账号'; btn.disabled = false;
      var n = 0;
      wbTimer = setInterval(function(){
        if(n++ > 150){ stopWbQr(); $('#wbQrStatus').textContent = '二维码已过期，请点「添加账号」重试'; return; }
        api('/wb/api/login/poll?state=' + encodeURIComponent(wbState)).then(function(r){
          if(r.status === 'ok'){
            stopWbQr();
            if(win && !win.closed){ try { win.close(); } catch(e){} }
            $('#wbQrStatus').textContent = '登录成功，已保存为「' + r.label + '」';
            load('wb');
          }
        }).catch(function(e){ stopWbQr(); $('#wbQrStatus').textContent = String(e.message || e); });
      }, 2500);
    })
    .catch(function(e){
      if(win && !win.closed){ try { win.close(); } catch(err){} }
      showErr('wb', e); btn.textContent = '添加账号'; btn.disabled = false;
    });
};

var qoderNonce = '', qoderTimer = null;
function stopQoderQr(){ if(qoderTimer){ clearInterval(qoderTimer); qoderTimer = null; } }

function bindQoderAdd(sel, region, regionName){
  var btn = $(sel);
  btn.onclick = function(){
    stopQoderQr();
    btn.disabled = true;
    var old = btn.textContent;
    btn.textContent = '获取中…';
    showErr('qoder', '');
    $('#qoderQrStatus').textContent = '正在向' + regionName + '申请设备授权…';
    var win = window.open('about:blank', 'qoder-login', 'width=640,height=880');
    api('/qoder/api/login/start', { method:'POST', body: JSON.stringify({ region: region }) })
      .then(function(d){
        qoderNonce = d.nonce;
        var opened = false;
        if(win && !win.closed){ try { win.location.href = d.authUrl; opened = true; } catch(e) {} }
        if(opened) $('#qoderQrStatus').textContent = '已在新窗口打开' + regionName + '授权页，登录并确认后本页会自动保存账号。';
        else $('#qoderQrStatus').innerHTML = '新窗口被拦截了：<a href="' + esc(d.authUrl) + '" target="_blank" rel="noopener">点这里打开' + regionName + '授权页</a>';
        btn.textContent = old; btn.disabled = false;
        var n = 0;
        qoderTimer = setInterval(function(){
          if(n++ > 150){ stopQoderQr(); $('#qoderQrStatus').textContent = '授权超时，请重新点「添加账号（' + regionName + '）」'; return; }
          api('/qoder/api/login/poll?nonce=' + encodeURIComponent(qoderNonce)).then(function(r){
            if(r.status === 'ok'){
              stopQoderQr();
              if(win && !win.closed){ try { win.close(); } catch(e){} }
              $('#qoderQrStatus').textContent = regionName + '登录成功，已保存为「' + r.label + '」';
              load('qoder');
            }
          }).catch(function(e){ stopQoderQr(); $('#qoderQrStatus').textContent = String(e.message || e); });
        }, 2500);
      })
      .catch(function(e){
        if(win && !win.closed){ try { win.close(); } catch(err){} }
        showErr('qoder', e); btn.textContent = old; btn.disabled = false;
      });
  };
}

bindQoderAdd('#qoderAddCn', 'cn', '国内版');

$('#loginbtn').onclick = function(){ login($('#pwd').value); };
$('#pwd').onkeydown = function(e){ if(e.key === 'Enter') login($('#pwd').value); };
$('#logout').onclick = function(){ if(confirm('退出登录？')) logout(''); };
$('#runAll').onclick = runAll;

document.querySelectorAll('[data-run]').forEach(function(b){ b.onclick = function(){ runOne(b.dataset.run); }; });
document.querySelectorAll('[data-refresh]').forEach(function(b){ b.onclick = function(){ load(b.dataset.refresh); }; });

var dayMark = bjToday();
setInterval(function(){
  var d = bjToday();
  if(d !== dayMark){ dayMark = d; if(state.tok) loadAll(); }
}, 60000);

/* FIX P2-5：sessionStorage */
var saved = sessionStorage.getItem(PWD_KEY);
if(saved) login(saved);

/* ---------------- 通知设置 ---------------- */
function nvOpen(){
  $('#nvModal').hidden = false;
  $('#nvMsg').textContent = '';
  api('/api/notify').then(function(c){
    var tg = c.telegram || {}, qq = c.qq || {};
    $('#tgOn').checked = tg.enabled !== false;
    $('#tgChat').value = tg.chatId || '';
    /* FIX P1-1：密码不回明文，填充掩码 */
    $('#tgToken').value = '';
    $('#tgToken').placeholder = tg.tokenSet ? '已配置 (' + tg.tokenMasked + ')' : '123456:ABC-DEF...';

    $('#qqOn').checked = qq.enabled !== false;
    $('#qqAppId').value = qq.appId || '';
    $('#qqOpenid').value = qq.openid || '';
    if(window.renderHelperCmds) window.renderHelperCmds();
    $('#qqSecret').value = '';
    $('#qqSecret').placeholder = qq.secretSet ? '已配置 (' + qq.secretMasked + ')' : 'AppSecret';

    if(c.fromEnv){ $('#nvMsg').textContent = '当前读的是环境变量，保存后会改存到 KV。'; }
  }).catch(function(e){ $('#nvMsg').textContent = String(e.message || e); });
}

function nvPayload(){
  return {
    telegram: { enabled: $('#tgOn').checked, token: $('#tgToken').value.trim(), chatId: $('#tgChat').value.trim() },
    qq: { enabled: $('#qqOn').checked, appId: $('#qqAppId').value.trim(), secret: $('#qqSecret').value.trim(), openid: $('#qqOpenid').value.trim() },
  };
}

function nvSave(){
  return api('/api/notify', { method:'POST', body: JSON.stringify(nvPayload()) });
}
</script>

  <div class="nv-mask" id="nvModal" hidden>
    <div class="nv-card">
      <div class="nv-head">
        <h3>签到结果通知</h3>
        <button type="button" class="nv-x" id="nvClose">×</button>
      </div>
      <div class="nv-body">
        <section class="nv-sec">
          <label class="nv-h"><input type="checkbox" id="tgOn"> Telegram</label>
          <div class="nv-row"><span>Bot Token</span><input id="tgToken" type="password" autocomplete="off"></div>
          <div class="nv-row"><span>Chat ID</span><input id="tgChat" placeholder="123456789" autocomplete="off"></div>
          <p class="nv-tip">找 <b>@BotFather</b> 发 <code>/newbot</code> 拿 Token；先给 bot 发条消息，再访问 <code>api.telegram.org/bot&lt;token&gt;/getUpdates</code> 取 chat id。</p>
        </section>

        <section class="nv-sec">
          <label class="nv-h"><input type="checkbox" id="qqOn"> QQ 机器人</label>
          <div class="nv-row"><span>AppID</span><input id="qqAppId" placeholder="q.qq.com 创建机器人后获得" autocomplete="off"></div>
          <div class="nv-row"><span>AppSecret</span><input id="qqSecret" type="password" autocomplete="off"></div>
          <div class="nv-row"><span>OpenID</span><input id="qqOpenid" placeholder="user_openid，不是 QQ 号" autocomplete="off"></div>
          <p class="nv-tip"><b>怎么拿</b>：本机终端跑下面这条，然后给机器人发条私聊消息，它会直接打印 OpenID。</p>
          <div class="nv-os" id="qqHelperOs">
            <button type="button" data-os="win" class="on">Windows</button>
            <button type="button" data-os="mac">macOS / Linux</button>
          </div>
          <div class="nv-cmd">
            <code id="qqHelperCmd">curl.exe -O {origin}/qq/openid-helper.mjs</code>
            <button type="button" class="nv-copy" data-copy="qqHelperCmd">复制</button>
          </div>
          <div class="nv-cmd">
            <code id="qqHelperRun">node openid-helper.mjs AppID AppSecret</code>
            <button type="button" class="nv-copy" data-copy="qqHelperRun">复制</button>
          </div>
          <p class="nv-tip" id="qqHelperNote">两条<b>分开执行</b>（PowerShell 5 不认 &amp;&amp;）。第二条里的 AppID / AppSecret 换成上面填的值；跑起来后 60 秒内给机器人发条私聊，终端会打印 <code>user_openid</code>。</p>

          <p class="nv-tip nv-warn">官方对「主动消息」有频次限制，超了会返回错误码。QQ 用户需要在 QQ 客户端机器人设置里打开「允许主动发送消息」。</p>
        </section>
      </div>
      <div class="nv-foot">
        <span class="nv-msg" id="nvMsg"></span>
        <button type="button" id="nvTest">发测试</button>
        <button type="button" class="pri" id="nvSave">保存</button>
      </div>
    </div>
  </div>
<script>
/* 通知弹窗的绑定放这里：它必须等上面的弹窗 DOM 解析完 */
(function(){
  var helperOs = (function(){
    var p = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '';
    return /mac|linux/i.test(p) ? 'mac' : 'win';
  })();

  window.renderHelperCmds = function(){
    var el = document.getElementById('qqHelperCmd');
    var run = document.getElementById('qqHelperRun');
    /* FIX P2-4：更新提示文字为环境变量方式 */
    if(el) el.textContent = (helperOs === 'mac' ? 'curl' : 'curl.exe') + ' -O ' + location.origin + '/qq/openid-helper.mjs';
    if(run) run.textContent = helperOs === 'mac' ? 'QQ_APP_ID=xxx QQ_APP_SECRET=yyy node openid-helper.mjs' : 'set QQ_APP_ID=xxx && set QQ_APP_SECRET=yyy && node openid-helper.mjs';
    
    var box = document.getElementById('qqHelperOs');
    if(box) box.querySelectorAll('button').forEach(function(b){
      b.classList.toggle('on', b.dataset.os === helperOs);
    });
    var note = document.getElementById('qqHelperNote');
    if(note){
      note.innerHTML = helperOs === 'mac'
        ? '两条<b>依次执行</b>。第二条里的 xxx 换成上面填的值；跑起来后 60 秒内给机器人发条私聊。'
        : '两条<b>分开执行</b>（PowerShell 5 不认 <code>&amp;&amp;</code>）。第二条里的 xxx 换成上面填的值；跑起来后 60 秒内给机器人发条私聊。';
    }
  };

  var osBox = document.getElementById('qqHelperOs');
  if(osBox) osBox.querySelectorAll('button').forEach(function(b){
    b.onclick = function(){ helperOs = b.dataset.os; window.renderHelperCmds(); };
  });

  var open = document.getElementById('notifyOpen');
  if(open) open.onclick = nvOpen;

  var close = document.getElementById('nvClose');
  if(close) close.onclick = function(){ document.getElementById('nvModal').hidden = true; };

  var mask = document.getElementById('nvModal');
  if(mask) mask.addEventListener('click', function(ev){ if(ev.target === this) this.hidden = true; });

  document.querySelectorAll('.nv-copy[data-copy]').forEach(function(b){
    b.onclick = function(){
      var el = document.getElementById(b.dataset.copy);
      if(!el) return;
      var txt = el.value || el.textContent || '';
      var done = function(){ b.textContent = '已复制'; setTimeout(function(){ b.textContent = '复制'; }, 1400); };
      if(navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(txt).then(done, function(){ b.textContent = '复制失败'; });
      } else {
        if(el.select) el.select();
        try { document.execCommand('copy'); done(); } catch(e){ b.textContent = '复制失败'; }
      }
    };
  });

  var saveBtn = document.getElementById('nvSave');
  if(saveBtn) saveBtn.onclick = function(){
    saveBtn.disabled = true;
    document.getElementById('nvMsg').textContent = '保存中…';
    nvSave().then(function(d){
      document.getElementById('nvMsg').textContent = d.channels && d.channels.length
        ? '已保存，启用：' + d.channels.join(' / ')
        : '已保存，但还没有填完整启用的渠道';
    }).catch(function(e){
      document.getElementById('nvMsg').textContent = '保存失败：' + String(e.message || e);
    }).then(function(){ saveBtn.disabled = false; });
  };

  var testBtn = document.getElementById('nvTest');
  if(testBtn) testBtn.onclick = function(){
    testBtn.disabled = true;
    document.getElementById('nvMsg').textContent = '发送中…';
    nvSave()
      .then(function(){ return api('/api/notify/test', { method:'POST', body:'{}' }); })
      .then(function(d){
        document.getElementById('nvMsg').textContent = d.errors && d.errors.length
          ? '部分失败：' + d.errors.join('；')
          : '已发送到 ' + (d.channels || []).join(' / ');
      })
      .catch(function(e){
        document.getElementById('nvMsg').textContent = '发送失败：' + String(e.message || e);
      })
      .then(function(){ testBtn.disabled = false; });
  };
})();
</script>

</body>
</html>`;

/* ------------------------------------------------------------------ */
/* 入口                                                                */
/* ------------------------------------------------------------------ */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = request.method.toUpperCase();

    try {
      if (path === '/' || path === '/index.html') return htmlResponse(PAGE);

      if (path === '/cron') {
        const c = await requireCron(request, env);
        if (!c.ok) return c.res;
        return json(await runAll(env, url.origin, false));
      }

      if (path === '/api/ping' && method === 'GET') {
        const a = await requireAdmin(request, env);
        return a.ok ? json({ ok: true }) : a.res;
      }

      if (path === '/api/run-all' && method === 'POST') {
        const a = await requireAdmin(request, env);
        if (!a.ok) return a.res;
        return json(await runAll(env, url.origin, url.searchParams.get('force') === '1'));
      }

      if (path === '/qq/openid-helper.mjs' && method === 'GET') {
        return new Response(QQ_OPENID_HELPER, { headers: { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store' } });
      }

      if (path === '/api/notify' && method === 'GET') {
        const a = await requireAdmin(request, env); if (!a.ok) return a.res;
        return json(await notifyConfigForUi(env));
      }

      if (path === '/api/notify' && method === 'POST') {
        const a = await requireAdmin(request, env); if (!a.ok) return a.res;
        const body = await request.json().catch(() => ({}));
        const prev = await loadNotifyConfig(env);
        const pick = (next, key, fallback) => {
          const v = String(next?.[key] ?? '').trim();
          return v || String(fallback?.[key] ?? '');
        };

        const tIn = body.telegram || {};
        const qIn = body.qq || {};

        const cfg = {
          telegram: { enabled: tIn.enabled !== false, token: pick(tIn, 'token', prev.telegram), chatId: String(tIn.chatId ?? '').trim() },
          qq: { enabled: qIn.enabled !== false, appId: String(qIn.appId ?? '').trim(), secret: pick(qIn, 'secret', prev.qq), openid: String(qIn.openid ?? '').trim(), sandbox: !!qIn.sandbox },
        };
        await saveNotifyConfig(env, cfg);
        const ch = await notifyChannels(env);
        return json({ ok: true, channels: Object.keys(ch) });
      }

      if (path === '/api/notify/test' && method === 'POST') {
        const a = await requireAdmin(request, env); if (!a.ok) return a.res;
        const ch = await notifyChannels(env);
        if (!Object.keys(ch).length) return json({ error: '还没有配置通知渠道' }, 400);
        const demo = {
          at: new Date(Date.now() + 8 * 3600e3).toISOString().replace('Z', ' +08:00'),
          trae: { results: [{ label: '示例账号', state: 'checked', msg: '+50 积分' }] },
          wb: { results: [{ label: '示例主号', state: 'skipped', msg: '今日已完成' }] },
          qoder: { results: [{ label: '示例号', state: 'checked', msg: '领取成功 +100 credits' }] },
        };
        const r = await notifyRun(env, demo);
        return json({ ...r, channels: Object.keys(ch) });
      }

      if (path === '/trae' || path === '/wb' || path === '/qoder') return Response.redirect(url.origin + '/', 302);
      if (path.startsWith('/trae/')) return await Trae.fetch(repath(request, path.slice(5) || '/'), traeEnv(env), ctx);
      if (path.startsWith('/wb/')) return await WorkBuddy.fetch(repath(request, path.slice(3) || '/'), wbEnv(env), ctx);
      if (path.startsWith('/qoder/')) return await Qoder.fetch(repath(request, path.slice(6) || '/'), qoderEnv(env), ctx);

      return json({ error: 'not found' }, 404);
    } catch (e) {
      return json({ error: e.message || String(e) }, 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      (async () => {
        const pending = [];
        const sink = { waitUntil: (p) => pending.push(p) };
        for (const [mod, e] of [[Trae, traeEnv(env)], [WorkBuddy, wbEnv(env)], [Qoder, qoderEnv(env)]]) {
          try { await mod.scheduled({}, e, sink); } catch {}
        }
        await Promise.allSettled(pending);
      })()
    );
  },
};