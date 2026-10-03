// 描画と、ファイル全体の静的な検査（テスト方針の 10・11）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { MESSAGES, messageFor, render, SCREENS } from '../oauth/consent/consent-view.js';
import { AUTH_ID, FAKE_PASSWORD, FAKE_TOKEN, FAKE_TOTP, RAW_ERROR, setup, toConsent, details } from './helpers.js';

const here = dirname(fileURLToPath(import.meta.url));
const consentDir = join(here, '../oauth/consent');
const read = (f) => readFileSync(join(consentDir, f), 'utf8');

// innerHTML などを使うと即座に失敗する、偽の要素
function fakeDom() {
  const els = new Map();
  const forbid = (name) => () => { throw new Error(`${name} は使わない`); };
  const make = (id) => {
    const el = { id, hidden: false, disabled: false, value: '', textContent: '' };
    for (const p of ['innerHTML', 'outerHTML']) Object.defineProperty(el, p, { set: forbid(p), get: forbid(p) });
    for (const m of ['insertAdjacentHTML', 'setHTMLUnsafe']) el[m] = forbid(m);
    return el;
  };
  const ids = [...SCREENS.map((s) => `screen-${s}`), 'error-message', 'signin-message', 'mfa-message', 'client-name', 'redirect-uri', 'scope', 'approve', 'approve-unavailable', 'done-message', 'password', 'totp', 'email'];
  for (const id of ids) els.set(id, make(id));
  return { byId: (id) => els.get(id) ?? null, els, text: () => [...els.values()].map((e) => `${e.textContent}|${e.value}`).join('\n') };
}

test('10 描画は textContent だけ（innerHTML を使うと失敗する偽の要素で確認）・画面は1つだけ表示', () => {
  const dom = fakeDom();
  for (const s of SCREENS) {
    render(dom.byId, s, { message: 'unexpected', clientName: '<img src=x onerror=alert(1)>', canApprove: true });
    const shown = SCREENS.filter((x) => !dom.els.get(`screen-${x}`).hidden);
    assert.deepEqual(shown, [s]);
  }
  render(dom.byId, 'consent', { clientName: '<script>alert(1)</script>', redirectUri: 'x', scope: '', canApprove: false });
  assert.equal(dom.els.get('client-name').textContent, '<script>alert(1)</script>', '文字列のまま表示される（HTML として解釈しない）');
});

test('10 許可のボタンは canApprove が true のときだけ見えて押せる', () => {
  const dom = fakeDom();
  render(dom.byId, 'consent', { clientName: 'a', canApprove: false });
  assert.deepEqual([dom.els.get('approve').hidden, dom.els.get('approve').disabled, dom.els.get('approve-unavailable').hidden], [true, true, false]);
  render(dom.byId, 'consent', { clientName: 'a', canApprove: 'true' });
  assert.equal(dom.els.get('approve').hidden, true, '文字列の "true" は許可にならない');
  render(dom.byId, 'consent', { clientName: 'a', canApprove: true });
  assert.deepEqual([dom.els.get('approve').hidden, dom.els.get('approve').disabled, dom.els.get('approve-unavailable').hidden], [false, false, true]);
});

test('10 画面が変わるたびにパスワードと確認コードの入力欄を空にする', () => {
  const dom = fakeDom();
  dom.els.get('password').value = FAKE_PASSWORD;
  dom.els.get('totp').value = FAKE_TOTP;
  render(dom.byId, 'mfa', {});
  assert.equal(dom.els.get('password').value, '');
  assert.equal(dom.els.get('totp').value, '');
});

test('10 知らないメッセージの鍵・知らない画面名は、決まった文言とエラー画面になる', () => {
  assert.equal(messageFor(RAW_ERROR), MESSAGES.unexpected);
  assert.equal(messageFor('__proto__'), MESSAGES.unexpected);
  const dom = fakeDom();
  render(dom.byId, '<b>x</b>', { message: RAW_ERROR });
  assert.equal(dom.els.get('screen-error').hidden, false);
  assert.equal(dom.els.get('error-message').textContent, MESSAGES.unexpected);
});

test('10 どの流れでも、秘密（パスワード・TOTP・トークン・authorization_id）と生のエラーは DOM にも console にも出ない', async () => {
  const logged = [];
  const orig = {};
  for (const m of ['log', 'info', 'warn', 'error', 'debug', 'trace']) {
    orig[m] = console[m];
    console[m] = (...a) => logged.push(a.map(String).join(' '));
  }
  try {
    const dom = fakeDom();
    const runs = [
      await toConsent({ signInError: true }),
      await toConsent({ verifyError: true }),
      await toConsent({ detailsError: true }),
      await toConsent({ approveError: true }),
      await toConsent({ details: details({ client: { name: 'x' }, redirect_uri: 'http://127.0.0.1:1/x' }) }),
      await toConsent({ signOutThrows: true }),
    ];
    await runs[3].flow.approve();
    await runs[5].flow.approve();
    const t = setup();
    t.client.auth.signInWithPassword = async () => { throw new Error(RAW_ERROR); };
    t.flow.start();
    await t.flow.signIn('g@e.invalid', FAKE_PASSWORD);
    runs.push(t);
    for (const r of runs) for (const s of r.screens) render(dom.byId, s.screen, s.data);
    const everything = JSON.stringify(runs.map((r) => r.screens)) + dom.text() + logged.join('\n');
    for (const secret of [FAKE_PASSWORD, FAKE_TOKEN, FAKE_TOTP, AUTH_ID, RAW_ERROR, 'xyz-leak-77']) {
      assert.ok(!everything.includes(secret), `漏れ: ${secret.slice(0, 12)}`);
    }
    assert.deepEqual(logged, [], 'console には何も出ない');
  } finally {
    for (const m of Object.keys(orig)) console[m] = orig[m];
  }
});

test('10 同意画面の JavaScript は console・innerHTML・eval・document.write を使わない', () => {
  for (const f of ['consent.js', 'consent-core.js', 'consent-view.js']) {
    const src = read(f).replace(/^\s*\/\/.*$/gm, ''); // コメントは除く
    for (const bad of ['console.', 'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'eval(', 'new Function', 'document.write', 'localStorage', 'sessionStorage']) {
      assert.ok(!src.includes(bad), `${f} に ${bad}`);
    }
  }
});

test('11 index.html: CSP・no-referrer・最初は body を隠す・インラインの script なし・外部の読み込みなし', () => {
  const html = read('index.html');
  const csp = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)?.[1];
  assert.ok(csp, 'CSP がある');
  for (const d of ["default-src 'none'", "script-src 'self'", "style-src 'self'", 'connect-src https://igastlbpzmxywvkizmcs.supabase.co', "form-action 'none'", "base-uri 'none'", "object-src 'none'"]) {
    assert.ok(csp.includes(d), d);
  }
  assert.ok(!/unsafe-inline|unsafe-eval|\*/.test(csp));
  assert.ok(html.includes('<meta name="referrer" content="no-referrer">'));
  assert.ok(/<body hidden>/.test(html), '埋め込みの判定の前は何も見せない');
  const scripts = [...html.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)];
  assert.deepEqual(scripts.map((m) => /src="([^"]+)"/.exec(m[1])?.[1]), ['vendor/supabase.js', 'consent.js']);
  assert.ok(scripts.every((m) => m[2].trim() === ''), 'インラインの script なし');
  assert.ok(!/(src|href)="(https?:)?\/\//.test(html), '外部（CDN など）から読み込まない');
  assert.ok(!/ on[a-z]+=/i.test(html), 'インラインのイベントハンドラなし');
  assert.ok(/id="approve"[^>]*hidden[^>]*disabled/.test(html), '許可のボタンは最初は隠れて押せない');
});

test('11 consent.js: 最上位の画面でなければ、何も表示せずに終わる', () => {
  const src = read('consent.js');
  const iTop = src.indexOf('if (!isTopLevel(window)) return;');
  const iShow = src.indexOf('document.body.hidden = false');
  assert.ok(iTop > 0 && iShow > iTop, '埋め込みの判定のあとでだけ body を表示する');
});

test('supabase-js: 同梱ファイルの SHA-256 が記録と一致・セッションを保存しない設定・publishable key だけ', () => {
  const vendor = readFileSync(join(consentDir, 'vendor/supabase.js'));
  const recorded = read('vendor/supabase.js.sha256').split(/\s+/)[0];
  assert.equal(createHash('sha256').update(vendor).digest('hex'), recorded);
  assert.equal(recorded, '59d39487c3589843b410322d8a3d562ce022aba1e5ccb16898ef3fb2a0da2ecd');
  const v = vendor.toString('utf8');
  for (const fn of ['getAuthorizationDetails', 'approveAuthorization', 'denyAuthorization', 'skipBrowserRedirect']) assert.ok(v.includes(fn), fn);
  assert.ok(!v.includes('sourceMappingURL'), '外部の source map を読まない');
  const src = read('consent.js').replace(/^\s*\/\/.*$/gm, ''); // コメントは除く
  assert.ok(src.includes('persistSession: false, autoRefreshToken: false, detectSessionInUrl: false'));
  const keys = [...src.matchAll(/'(sb_[a-z]+_[A-Za-z0-9_-]+)'/g)].map((m) => m[1]);
  assert.equal(keys.length, 1);
  assert.ok(keys[0].startsWith('sb_publishable_'), 'publishable key だけ');
  for (const bad of ['sb_secret_', 'service_role', 'eyJ']) assert.ok(!src.includes(bad), bad);
});
