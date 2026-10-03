// Codex 第2レビューの MEDIUM への対応のテスト:
// 「同意済み」で redirect_url だけが返る応答は、client.id を確かめられないので Phase 1 では fail closed
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { render, SCREENS, MESSAGES } from '../oauth/consent/consent-view.js';
import {
  AUTH_ID, CODEX_CLIENT_ID, CODEX_REDIRECT, details, FAKE_PASSWORD, FAKE_TOKEN, FAKE_TOTP, OTHER_CLIENT_ID, RAW_ERROR,
  toConsent,
} from './helpers.js';

const ONLY_REDIRECT = [
  { redirect_url: `${CODEX_REDIRECT}?code=prev-code-secret-41&state=s` }, // 正しい Codex の戻り先
  { redirect_url: CODEX_REDIRECT },
  // query に client_id を入れても補って信用しない
  { redirect_url: `${CODEX_REDIRECT}?code=c&client_id=${CODEX_CLIENT_ID}` },
  { redirect_url: 'http://evil.example/?code=x' },
  { redirect_url: 'javascript:alert(1)' },
  { redirect_url: 42 },
  {},
];

test('1・2 redirect_url だけの応答は、正しい Codex の戻り先でも移動しない（7通り）', async () => {
  for (const d of ONLY_REDIRECT) {
    const t = await toConsent({ details: d });
    assert.deepEqual(t.navigations, [], JSON.stringify(d));
    assert.deepEqual(t.last(), { screen: 'error', data: { message: 'previous_consent_unverifiable' } }, JSON.stringify(d));
  }
});

test('1 終了画面の文言は決まったもの', () => {
  assert.equal(MESSAGES.previous_consent_unverifiable, '以前の認可情報を確認できないため、この認可は続けられません。');
});

test('3 client 情報なしで「戻る」操作も、許可・拒否も実行できない（Supabase も呼ばない）', async () => {
  const t = await toConsent({ details: ONLY_REDIRECT[0] });
  const before = t.client.calls.length;
  await t.flow.returnToClient();
  await t.flow.approve();
  await t.flow.deny();
  await t.flow.signIn('g@e.invalid', FAKE_PASSWORD);
  assert.equal(t.client.calls.length, before);
  assert.deepEqual(t.navigations, []);
  assert.ok(!t.names().includes('approveAuthorization') && !t.names().includes('denyAuthorization'));
});

test('3 「Codex に戻る」の画面・ボタンは HTML にも画面の一覧にも無い', async () => {
  const { readFileSync } = await import('node:fs');
  const html = readFileSync(new URL('../oauth/consent/index.html', import.meta.url), 'utf8');
  assert.ok(!html.includes('screen-already') && !html.includes('id="return"'));
  assert.ok(!SCREENS.includes('already'));
});

test('4 フローの状態が初期化される（許可できる状態が残らない・描画しても許可のボタンが出ない）', async () => {
  const t = await toConsent({ details: ONLY_REDIRECT[0] });
  assert.ok(!t.screens.some((s) => s.screen === 'consent'), '許可の画面を一度も出していない');
  // 許可のボタンは HTML の初期状態（隠れていて押せない）から始める
  const els = new Map([['approve', { hidden: true, disabled: true, value: '', textContent: '' }]]);
  const byId = (id) => {
    if (!els.has(id)) els.set(id, { hidden: false, disabled: false, value: '', textContent: '' });
    return els.get(id);
  };
  for (const s of t.screens) render(byId, s.screen, s.data);
  assert.deepEqual(SCREENS.filter((s) => !byId(`screen-${s}`).hidden), ['error']);
  assert.deepEqual([byId('approve').hidden, byId('approve').disabled], [true, true], '許可のボタンは隠れたまま押せない');
  // 終了のあと、許可を呼んでも何も起きない（状態が残っていない）
  const before = t.client.calls.length;
  await t.flow.approve();
  assert.equal(t.client.calls.length, before);
});

test('5 signOut(local) を呼ぶ', async () => {
  const t = await toConsent({ details: ONLY_REDIRECT[0] });
  const so = t.client.calls.filter((c) => c.name === 'signOut');
  assert.equal(so.length, 1);
  assert.deepEqual(so[0].args, { scope: 'local' });
});

test('6 signOut が失敗しても、秘密・生のエラー・authorization_id・redirect_url・client_id は DOM にも console にも出ない', async () => {
  const logged = [];
  const orig = {};
  for (const m of ['log', 'info', 'warn', 'error', 'debug', 'trace']) {
    orig[m] = console[m];
    console[m] = (...a) => logged.push(a.map(String).join(' '));
  }
  try {
    const runs = [];
    for (const opt of [{ signOutError: true }, { signOutThrows: true }]) {
      for (const d of ONLY_REDIRECT.slice(0, 3)) runs.push(await toConsent({ ...opt, details: d }));
    }
    const els = new Map();
    const byId = (id) => {
      if (!els.has(id)) els.set(id, { hidden: false, disabled: false, value: '', textContent: '' });
      return els.get(id);
    };
    for (const r of runs) for (const s of r.screens) render(byId, s.screen, s.data);
    const everything = JSON.stringify(runs.map((r) => r.screens)) + [...els.values()].map((e) => `${e.textContent}|${e.value}`).join('\n') + logged.join('\n');
    for (const secret of [FAKE_PASSWORD, FAKE_TOTP, FAKE_TOKEN, AUTH_ID, RAW_ERROR, CODEX_CLIENT_ID, CODEX_REDIRECT, 'prev-code-secret-41']) {
      assert.ok(!everything.includes(secret), `漏れ: ${secret.slice(0, 12)}`);
    }
    assert.deepEqual(logged, []);
    for (const r of runs) assert.deepEqual(r.navigations, []);
  } finally {
    for (const m of Object.keys(orig)) console[m] = orig[m];
  }
});

test('7 通常の初回の認可（正しい client.id + 正しい redirect_uri）は、引き続き許可できる', async () => {
  const t = await toConsent({ details: details() });
  assert.equal(t.last().data.canApprove, true);
  await t.flow.approve();
  assert.deepEqual(t.navigations, [`${CODEX_REDIRECT}?code=abc&state=xyz`]);
});

test('8 知らない client.id は、引き続き許可できない', async () => {
  const t = await toConsent({ details: details({ client: { id: OTHER_CLIENT_ID, name: 'MAKKI Gate - Codex' } }) });
  assert.equal(t.last().data.canApprove, false);
  await t.flow.approve();
  assert.ok(!t.names().includes('approveAuthorization'));
  assert.deepEqual(t.navigations, []);
});
