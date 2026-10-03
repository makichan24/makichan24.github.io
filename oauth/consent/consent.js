// =============================================
// MAKKI Gate 同意画面の入口（ブラウザ用）。supabase-js は vendor/supabase.js（版を固定して同梱）を使う
// - publishable key だけを使う（service_role / secret key は使わない）
// - セッションはメモリの中だけ（persistSession / autoRefreshToken / detectSessionInUrl はすべて false）
// - 埋め込まれた画面では何も表示しない
// - console には何も出さない
// =============================================
import { createConsentFlow, isTopLevel } from './consent-core.js';
import { render } from './consent-view.js';

const SUPABASE_URL = 'https://igastlbpzmxywvkizmcs.supabase.co';
// publishable key（公開してよい鍵）。サインアップは OFF・anon にはテーブルの権限が無い
const SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_NfD82GNS_hh_7IgiqKxAyw_ze0sQqSN';

function main() {
  // 埋め込まれている（最上位の画面でない）ときは、body を表示しないまま終わる
  if (!isTopLevel(window)) return;
  const supabaseGlobal = window.supabase;
  const byId = (id) => document.getElementById(id);
  const view = { show: (screen, data) => render(byId, screen, data) };
  document.body.hidden = false;

  if (!supabaseGlobal || typeof supabaseGlobal.createClient !== 'function') {
    view.show('error', { message: 'unexpected' });
    return;
  }
  const client = supabaseGlobal.createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
  const flow = createConsentFlow({
    client,
    view,
    navigate: (url) => window.location.replace(url),
    search: window.location.search,
  });

  byId('signin-form').addEventListener('submit', (e) => {
    e.preventDefault();
    flow.signIn(byId('email').value, byId('password').value);
  });
  byId('mfa-form').addEventListener('submit', (e) => {
    e.preventDefault();
    flow.verifyTotp(byId('totp').value.trim());
  });
  byId('approve').addEventListener('click', () => flow.approve());
  byId('deny').addEventListener('click', () => flow.deny());

  flow.start();
}

main();
