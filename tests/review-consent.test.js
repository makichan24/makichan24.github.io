// Codex 独立レビュー（同意画面）への対応のテスト
//   MEDIUM: client.id と redirect_uri の組で許可を判定する
//   LOW: 再試行できない終了では、ローカルのセッションを破棄し、フローの状態を初期化する
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ALLOWED_CLIENTS, matchAllowedClient } from '../oauth/consent/consent-core.js';
import { render, SCREENS } from '../oauth/consent/consent-view.js';
import {
  AUTH_ID, CODEX_CLIENT_ID, CODEX_REDIRECT, details, FAKE_PASSWORD, FAKE_TOKEN, FAKE_TOTP, OTHER_CLIENT_ID, RAW_ERROR,
  setup, toConsent,
} from './helpers.js';

test('許可リストは Codex の組1件だけ（戻り先はテスト側の独立した値と一致・client.id は UUID の形）', () => {
  assert.equal(ALLOWED_CLIENTS.length, 1);
  assert.equal(ALLOWED_CLIENTS[0].redirectUri, CODEX_REDIRECT);
  assert.match(ALLOWED_CLIENTS[0].clientId, /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  assert.ok(Object.isFrozen(ALLOWED_CLIENTS) && Object.isFrozen(ALLOWED_CLIENTS[0]));
});

test('MEDIUM 組の照合: 両方一致のときだけ戻り先を返す', () => {
  assert.equal(matchAllowedClient(details()), CODEX_REDIRECT);
  for (const d of [
    details({ client: { id: OTHER_CLIENT_ID, name: 'x' } }),
    details({ client: { name: 'MAKKI Gate - Codex' } }),
    details({ client: { id: '' } }),
    details({ client: { id: 123 } }),
    details({ client: null }),
    details({ client: 'x' }),
    details({ redirect_uri: 'http://127.0.0.1:43128/callback/H2ERSOpTdH_S' }),
    details({ redirect_uri: undefined }),
    details({ client: { id: CODEX_CLIENT_ID.toUpperCase() } }),
    details({ client: { id: ` ${CODEX_CLIENT_ID}` } }),
    null,
    'x',
  ]) {
    assert.equal(matchAllowedClient(d), null, JSON.stringify(d));
  }
});

const approvable = async (d) => {
  const t = await toConsent({ details: d });
  const shown = t.last();
  await t.flow.approve();
  return { t, shown, approved: t.names().includes('approveAuthorization') };
};

test('1 正しい client.id + 正しい redirect_uri -> 許可できる', async () => {
  const { t, shown, approved } = await approvable(details());
  assert.equal(shown.screen, 'consent');
  assert.equal(shown.data.canApprove, true);
  assert.equal(approved, true);
  assert.deepEqual(t.navigations, [`${CODEX_REDIRECT}?code=abc&state=xyz`]);
});

test('2 知らない client.id + 正しい redirect_uri -> 許可できない', async () => {
  const { t, shown, approved } = await approvable(details({ client: { id: OTHER_CLIENT_ID, name: 'MAKKI Gate - Codex' } }));
  assert.equal(shown.data.canApprove, false);
  assert.equal(approved, false);
  assert.deepEqual(t.navigations, []);
});

test('3 client.id が無い + 正しい redirect_uri -> 許可できない', async () => {
  for (const client of [{ name: 'MAKKI Gate - Codex' }, undefined, null, { id: '' }]) {
    const { shown, approved } = await approvable(details({ client }));
    assert.equal(shown.data.canApprove, false, JSON.stringify(client));
    assert.equal(approved, false);
  }
});

test('4 正しい client.id + 別の redirect_uri -> 許可できない', async () => {
  const { t, shown, approved } = await approvable(details({ redirect_uri: 'http://127.0.0.1:43127/callback/other' }));
  assert.equal(shown.data.canApprove, false);
  assert.equal(approved, false);
  assert.deepEqual(t.navigations, []);
});

test('5 知らない client.id でも拒否はできる（戻り先が許可リストの組でなければ移動しない）', async () => {
  const t = await toConsent({ details: details({ client: { id: OTHER_CLIENT_ID, name: 'x' } }) });
  await t.flow.deny();
  assert.ok(t.names().includes('denyAuthorization'));
  assert.deepEqual(t.navigations, [], '組が一致しないアプリの戻り先へは移動しない');
  assert.deepEqual(t.last(), { screen: 'done', data: { message: 'denied' } });
});

test('6 TOTP のあとの getAuthorizationDetails の失敗 -> signOut(local) を呼ぶ', async () => {
  const t = await toConsent({ detailsError: true });
  assert.deepEqual(t.last(), { screen: 'error', data: { message: 'details_failed' } });
  const so = t.client.calls.filter((c) => c.name === 'signOut');
  assert.equal(so.length, 1);
  assert.deepEqual(so[0].args, { scope: 'local' });
});

test('6 approve / deny の致命的な失敗・想定外の例外・mfa_required でも signOut(local) を呼ぶ', async () => {
  const cases = [
    async () => { const t = await toConsent({ approveError: true }); await t.flow.approve(); return t; },
    async () => { const t = await toConsent({ approveUrl: 'http://evil.example/?code=a' }); await t.flow.approve(); return t; },
    async () => { const t = await toConsent({ denyError: true }); await t.flow.deny(); return t; },
    async () => toConsent({ details: { redirect_url: 'http://evil.example/' } }),
    async () => toConsent({ aalAfterVerify: { currentLevel: 'aal1', nextLevel: 'aal2' } }),
    async () => toConsent({ details: details({ authorization_id: 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' }) }),
    async () => {
      const t = setup();
      t.client.auth.oauth.getAuthorizationDetails = async () => { throw new Error(RAW_ERROR); };
      t.flow.start();
      await t.flow.signIn('g@e.invalid', FAKE_PASSWORD);
      await t.flow.verifyTotp(FAKE_TOTP);
      return t;
    },
  ];
  for (const [i, make] of cases.entries()) {
    const t = await make();
    assert.equal(t.last().screen, 'error', `case ${i}`);
    assert.ok(t.client.calls.some((c) => c.name === 'signOut' && c.args?.scope === 'local'), `case ${i}: signOut`);
    assert.deepEqual(t.navigations, [], `case ${i}: 移動しない`);
  }
});

test('6 再試行できる誤り（パスワード違い・確認コード違い）では signOut しない', async () => {
  const s = setup({ signInError: true });
  s.flow.start();
  await s.flow.signIn('g@e.invalid', FAKE_PASSWORD);
  const v = setup({ verifyError: true });
  v.flow.start();
  await v.flow.signIn('g@e.invalid', FAKE_PASSWORD);
  await v.flow.verifyTotp(FAKE_TOTP);
  assert.ok(!s.names().includes('signOut'));
  assert.ok(!v.names().includes('signOut'));
  assert.equal(v.last().screen, 'mfa', 'もう一度入力できる');
});

test('7 再試行できない終了のあとは、許可できる状態が残らず、どの操作も受け付けない', async () => {
  const t = await toConsent({ approveError: true });
  assert.equal(t.last().data.canApprove, true, '前提: 失敗の前は許可できる状態');
  await t.flow.approve();
  const before = t.client.calls.length;
  await t.flow.approve();
  await t.flow.deny();
  await t.flow.returnToClient();
  await t.flow.signIn('g@e.invalid', FAKE_PASSWORD);
  await t.flow.verifyTotp(FAKE_TOTP);
  assert.equal(t.client.calls.length, before, 'Supabase はもう呼ばれない');
  assert.equal(t.names().filter((n) => n === 'approveAuthorization').length, 1);
  assert.deepEqual(t.last(), { screen: 'error', data: { message: 'approve_failed' } });
  // 描画しても、許可のボタンは見えない（エラー画面だけ）
  const els = new Map();
  const byId = (id) => {
    if (!els.has(id)) els.set(id, { hidden: false, disabled: false, value: '', textContent: '' });
    return els.get(id);
  };
  for (const s of t.screens) render(byId, s.screen, s.data);
  assert.deepEqual(SCREENS.filter((s) => !byId(`screen-${s}`).hidden), ['error']);
});

test('8 signOut が失敗（エラーの値・例外）しても、秘密や生のエラーは DOM にも console にも出ない', async () => {
  const logged = [];
  const orig = {};
  for (const m of ['log', 'info', 'warn', 'error', 'debug', 'trace']) {
    orig[m] = console[m];
    console[m] = (...a) => logged.push(a.map(String).join(' '));
  }
  try {
    const runs = [];
    for (const opt of [{ signOutError: true }, { signOutThrows: true }]) {
      runs.push(await toConsent({ ...opt, detailsError: true }));
      const a = await toConsent({ ...opt, approveError: true });
      await a.flow.approve();
      runs.push(a);
    }
    const els = new Map();
    const byId = (id) => {
      if (!els.has(id)) els.set(id, { hidden: false, disabled: false, value: '', textContent: '' });
      return els.get(id);
    };
    for (const r of runs) for (const s of r.screens) render(byId, s.screen, s.data);
    const everything = JSON.stringify(runs.map((r) => r.screens)) + [...els.values()].map((e) => `${e.textContent}|${e.value}`).join('\n') + logged.join('\n');
    for (const secret of [FAKE_PASSWORD, FAKE_TOTP, FAKE_TOKEN, AUTH_ID, RAW_ERROR, 'xyz-leak-77', CODEX_CLIENT_ID]) {
      assert.ok(!everything.includes(secret), `漏れ: ${secret.slice(0, 10)}`);
    }
    assert.deepEqual(logged, []);
    for (const r of runs) assert.ok(r.names().includes('signOut'));
  } finally {
    for (const m of Object.keys(orig)) console[m] = orig[m];
  }
});

test('画面に出す値に client.id は含めない（名前・戻り先・scope だけ）', async () => {
  const t = await toConsent();
  assert.deepEqual(Object.keys(t.last().data).sort(), ['canApprove', 'clientName', 'redirectUri', 'scope']);
  assert.ok(!JSON.stringify(t.screens).includes(CODEX_CLIENT_ID));
});
