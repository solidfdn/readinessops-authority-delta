import type {Config} from './types';
const PKCE = 'authority-delta-pkce';
const SESSION = 'authority-delta-session';
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const nonce = () => b64(crypto.getRandomValues(new Uint8Array(32)));
export function checkedConfig(value: Config): Config {
  if (!/^https:\/\/authority-delta-[a-z0-9-]+\.auth\.ap-northeast-1\.amazoncognito\.com$/.test(value.auth_origin)
    || !/^https:\/\/[a-z0-9]+\.execute-api\.ap-northeast-1\.amazonaws\.com$/.test(value.api_origin)
    || !/^[a-z0-9]+$/.test(value.client_id) || value.redirect_uri !== location.origin + '/') throw new Error('Workspace configuration is unavailable.');
  return value;
}
export async function startSignIn(c: Config) {
  const verifier = nonce(), state = nonce();
  const challenge = b64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
  sessionStorage.setItem(PKCE, JSON.stringify({verifier, state, expires: Date.now() + 600_000}));
  const url = new URL(c.auth_origin + '/oauth2/authorize');
  url.search = new URLSearchParams({client_id:c.client_id, response_type:'code', redirect_uri:c.redirect_uri,
    scope:'openid authority-delta/read authority-delta/write authority-delta/approve authority-delta/publish', state, code_challenge:challenge, code_challenge_method:'S256'}).toString();
  location.assign(url.href);
}
export async function accessToken(c: Config): Promise<string | null> {
  const query = new URLSearchParams(location.search);
  if (query.has('error')) {
    history.replaceState({}, '', '/'); sessionStorage.removeItem(PKCE);
    throw new Error('Sign-in was not completed. Please try again.');
  }
  if (query.has('code')) {
    const saved = sessionStorage.getItem(PKCE); sessionStorage.removeItem(PKCE);
    history.replaceState({}, '', '/');
    const p = saved ? JSON.parse(saved) : null;
    if (!p || p.state !== query.get('state') || p.expires < Date.now() || typeof p.verifier !== 'string') throw new Error('Sign-in expired or could not be verified. Please sign in again.');
    const r = await fetch(c.auth_origin + '/oauth2/token', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:new URLSearchParams({grant_type:'authorization_code',client_id:c.client_id,code:query.get('code')!,redirect_uri:c.redirect_uri,code_verifier:p.verifier}), signal:AbortSignal.timeout(15_000)});
    if (!r.ok) throw new Error('Sign-in could not be completed. Please try again.');
    const t = await r.json();
    if (t.token_type !== 'Bearer' || typeof t.access_token !== 'string' || !Number.isFinite(t.expires_in) || t.expires_in <= 0) throw new Error('Invalid sign-in response.');
    sessionStorage.setItem(SESSION, JSON.stringify({token:t.access_token,expires:Date.now() + Math.min(t.expires_in, 900) * 1000}));
  }
  const saved = sessionStorage.getItem(SESSION); const s = saved ? JSON.parse(saved) : null;
  if (!s || s.expires <= Date.now() + 5000) { sessionStorage.removeItem(SESSION); return null; }
  return s.token;
}
export function signOut(c: Config) {
  sessionStorage.removeItem(SESSION); sessionStorage.removeItem(PKCE);
  location.assign(c.auth_origin + '/logout?' + new URLSearchParams({client_id:c.client_id,logout_uri:c.redirect_uri}));
}
export function clearSession() { sessionStorage.removeItem(SESSION); }
