// 同意画面の本体のテスト（テスト方針の 1 から 9・12）
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ALLOWED_REDIRECT_URIS, displayText, isSafeReturnUrl, isTopLevel, matchAllowedRedirectUri, readAuthorizationId,
} from '../oauth/consent/consent-core.js';
import { AUTH_ID, CODEX_REDIRECT, details, FAKE_PASSWORD, FAKE_TOTP, setup, toConsent } from './helpers.js';

// ---------- 2. authorization_id の検証 ----------

test('2 authorization_id: 小文字の base32 で32文字だけを受け付ける', () => {
  assert.equal(readAuthorizationId(`?authorization_id=${AUTH_ID}`), AUTH_ID);
  assert.equal(readAuthorizationId(`authorization_id=${AUTH_ID}&x=1`), AUTH_ID);
  for (const bad of [
    '', '?', '?authorization_id=', '?authorization_id=test',
    `?authorization_id=${AUTH_ID.toUpperCase()}`, // 大文字
    `?authorization_id=${AUTH_ID}a`, // 33文字
    `?authorization_id=${AUTH_ID.slice(1)}`, // 31文字
    `?authorization_id=${AUTH_ID.slice(0, 31)}1`, // base32 に無い 1
    `?authorization_id=${AUTH_ID.slice(0, 31)}8`, // base32 に無い 8
    `?authorization_id=${AUTH_ID.slice(0, 30)}%2F.`, // パス区切り
    `?authorization_id=../../${AUTH_ID.slice(6)}`,
    `?authorization_id=${AUTH_ID}&authorization_id=${AUTH_ID}`, // 2つ
    `?authorization_id=%00${AUTH_ID.slice(1)}`,
  ]) {
    assert.equal(readAuthorizationId(bad), null, bad);
  }
  assert.equal(readAuthorizationId(undefined), null);
  assert.equal(readAuthorizationId(42), null);
});

test('2 authorization_id が不正なら、ログインの画面も出さず Supabase も呼ばない', async () => {
  const t = setup({}, '?authorization_id=../etc');
  t.flow.start();
  await t.flow.signIn('a@b.c', FAKE_PASSWORD);
  assert.deepEqual(t.screens.map((s) => s.screen), ['error']);
  assert.deepEqual(t.last().data, { message: 'invalid_request' });
});

// ---------- 3・4. redirect_url の完全一致と、似た URL の拒否 ----------

test('3 Supabase が返した戻り先そのもの、または「戻り先 + ?...」だけを通す', () => {
  for (const ok of [CODEX_REDIRECT, `${CODEX_REDIRECT}?code=abc&state=xyz`, `${CODEX_REDIRECT}?error=access_denied&state=1`]) {
    assert.equal(isSafeReturnUrl(ok, CODEX_REDIRECT), true, ok);
  }
});

test('4 javascript: / data: / 別の port / 別の path / 似た host などは拒否', () => {
  const bad = [
    'javascript:alert(1)',
    `javascript:${CODEX_REDIRECT}`,
    'data:text/html,<script>alert(1)</script>',
    'http://127.0.0.1:43128/callback/H2ERSOpTdH_S?code=a', // 別の port
    'http://127.0.0.1/callback/H2ERSOpTdH_S?code=a', // port なし
    'http://127.0.0.1:43127/callback/H2ERSOpTdH_X?code=a', // 別の path
    'http://127.0.0.1:43127/callback/H2ERSOpTdH_S/x?code=a',
    'http://127.0.0.1:43127/callback?code=a',
    'http://127.0.0.1:43127/callback/H2ERSOpTdH_Sx?code=a',
    'http://127.0.0.1:43127/callback/h2ersoptdh_s?code=a', // 大文字小文字の違い
    'http://127.0.0.2:43127/callback/H2ERSOpTdH_S?code=a', // 別の host
    'http://localhost:43127/callback/H2ERSOpTdH_S?code=a',
    'http://127.0.0.1.evil.example:43127/callback/H2ERSOpTdH_S',
    'http://127.0.0.1:43127@evil.example/callback/H2ERSOpTdH_S',
    'http://user:pw@127.0.0.1:43127/callback/H2ERSOpTdH_S?code=a', // 認証情報付き
    'https://127.0.0.1:43127/callback/H2ERSOpTdH_S?code=a', // 別の scheme
    `${CODEX_REDIRECT}#code=a`, // fragment
    `${CODEX_REDIRECT}/../../evil?code=a`,
    `${CODEX_REDIRECT}%2F..%2Fevil?code=a`,
    `${CODEX_REDIRECT}\\@evil.example`,
    ` ${CODEX_REDIRECT}?code=a`, // 前の空白
    `${CODEX_REDIRECT}?code=a b`, // 空白
    `${CODEX_REDIRECT}?code=a\n`,
    '//evil.example/callback/H2ERSOpTdH_S',
    '/callback/H2ERSOpTdH_S',
    '',
    `${CODEX_REDIRECT}?${'a'.repeat(5000)}`, // 長すぎる
  ];
  for (const u of bad) assert.equal(isSafeReturnUrl(u, CODEX_REDIRECT), false, JSON.stringify(u));
  for (const u of [null, undefined, 1, {}, ['x']]) assert.equal(isSafeReturnUrl(u, CODEX_REDIRECT), false);
});

test('4 許可リストの照合は文字列の完全一致（Phase 1 は Codex の戻り先1件だけ）', () => {
  assert.deepEqual([...ALLOWED_REDIRECT_URIS], [CODEX_REDIRECT]);
  assert.equal(matchAllowedRedirectUri(CODEX_REDIRECT), CODEX_REDIRECT);
  for (const u of [`${CODEX_REDIRECT}/`, `${CODEX_REDIRECT}?x=1`, CODEX_REDIRECT.toUpperCase(), 'http://127.0.0.1:43127/callback', null]) {
    assert.equal(matchAllowedRedirectUri(u), null, String(u));
  }
});

// ---------- 5. 知らないアプリ・戻り先では許可できない ----------

test('5 戻り先が許可リストにないアプリは、許可のボタンを出さない（拒否だけ）', async () => {
  const t = await toConsent({ details: details({ redirect_uri: 'http://127.0.0.1:9999/callback/other', client: { name: 'Unknown App' } }) });
  assert.equal(t.last().screen, 'consent');
  assert.equal(t.last().data.canApprove, false);
  await t.flow.approve();
  assert.ok(!t.names().includes('approveAuthorization'), '許可は呼ばれない');
  assert.deepEqual(t.navigations, []);
});

test('5 知らない戻り先のアプリを拒否しても、その戻り先へは移動しない', async () => {
  const t = await toConsent({
    details: details({ redirect_uri: 'http://127.0.0.1:9999/cb' }),
    denyUrl: 'http://127.0.0.1:9999/cb?error=access_denied',
  });
  await t.flow.deny();
  assert.ok(t.names().includes('denyAuthorization'));
  assert.deepEqual(t.navigations, []);
  assert.deepEqual(t.last(), { screen: 'done', data: { message: 'denied' } });
  assert.ok(t.names().includes('signOut'));
});

test('5 承認の結果の redirect_url が想定と違えば、移動しない', async () => {
  for (const approveUrl of ['http://evil.example/?code=a', 'javascript:alert(1)', `${CODEX_REDIRECT.replace('43127', '43128')}?code=a`]) {
    const t = await toConsent({ approveUrl });
    await t.flow.approve();
    assert.deepEqual(t.navigations, [], approveUrl);
    assert.deepEqual(t.last(), { screen: 'error', data: { message: 'approve_failed' } });
  }
});

test('5 details の authorization_id が要求と違えば止める', async () => {
  const t = await toConsent({ details: details({ authorization_id: 'zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz' }) });
  assert.deepEqual(t.last(), { screen: 'error', data: { message: 'details_failed' } });
});

// ---------- 6・7. AAL2 を確かめるまで許可へ進まない ----------

test('6 ログイン直後（aal1）は確認コードの画面へ。内容の取得も許可もしない', async () => {
  const t = setup();
  t.flow.start();
  await t.flow.signIn('gate@example.invalid', FAKE_PASSWORD);
  assert.equal(t.last().screen, 'mfa');
  await t.flow.approve();
  assert.ok(!t.names().includes('getAuthorizationDetails'));
  assert.ok(!t.names().includes('approveAuthorization'));
});

test('6 TOTP の確認のあとも aal1 のままなら、内容を取らず止める', async () => {
  const t = await toConsent({ aalAfterVerify: { currentLevel: 'aal1', nextLevel: 'aal2' } });
  assert.deepEqual(t.last(), { screen: 'error', data: { message: 'mfa_required' } });
  assert.ok(!t.names().includes('getAuthorizationDetails'));
});

test('6 TOTP を持たない利用者（nextLevel が aal1）は先へ進めず、ログアウトする', async () => {
  const t = setup({ aalAfterSignIn: { currentLevel: 'aal1', nextLevel: 'aal1' } });
  t.flow.start();
  await t.flow.signIn('gate@example.invalid', FAKE_PASSWORD);
  assert.deepEqual(t.last(), { screen: 'error', data: { message: 'mfa_required' } });
  assert.ok(t.names().includes('signOut'));
});

test('6 確認コードの形の誤り・確認の失敗・TOTP が未登録', async () => {
  const t = setup();
  t.flow.start();
  await t.flow.signIn('g@e.invalid', FAKE_PASSWORD);
  for (const code of ['12345', '1234567', 'abcdef', '12 456', '']) {
    await t.flow.verifyTotp(code);
    assert.deepEqual(t.last(), { screen: 'mfa', data: { message: 'totp_input' } }, code);
  }
  assert.ok(!t.names().includes('challenge'));
  const v = setup({ verifyError: true });
  v.flow.start();
  await v.flow.signIn('g@e.invalid', FAKE_PASSWORD);
  await v.flow.verifyTotp(FAKE_TOTP);
  assert.deepEqual(v.last(), { screen: 'mfa', data: { message: 'totp_failed' } });
  const n = setup({ noFactor: true });
  n.flow.start();
  await n.flow.signIn('g@e.invalid', FAKE_PASSWORD);
  await n.flow.verifyTotp(FAKE_TOTP);
  assert.deepEqual(n.last(), { screen: 'error', data: { message: 'mfa_required' } });
});

test('7 aal2 になってから内容を取得し、許可のボタンを出す（呼び出しの順番）', async () => {
  const t = await toConsent();
  assert.deepEqual(t.names(), [
    'signInWithPassword', 'getAuthenticatorAssuranceLevel', 'listFactors', 'challenge', 'verify',
    'getAuthenticatorAssuranceLevel', 'getAuthorizationDetails',
  ]);
  assert.deepEqual(t.last(), {
    screen: 'consent',
    data: { clientName: 'MAKKI Gate - Codex', redirectUri: CODEX_REDIRECT, scope: 'openid email', canApprove: true },
  });
  assert.deepEqual(t.client.calls.find((c) => c.name === 'verify').args, { factorId: 'f1', challengeId: 'c1', code: FAKE_TOTP });
});

test('7 すでに aal2 のセッションなら、確認コードを飛ばして内容へ', async () => {
  const t = setup({ aalAfterSignIn: { currentLevel: 'aal2', nextLevel: 'aal2' } });
  t.flow.start();
  await t.flow.signIn('g@e.invalid', FAKE_PASSWORD);
  assert.equal(t.last().screen, 'consent');
});

// ---------- 8. 以前に同意済み（redirect_url だけが返る） ----------
// 2026-10-04 方針変更（Codex 第2レビューの MEDIUM）: client.id を確かめられないので、Phase 1 では fail closed。
// 以前は「Codex に戻る」ボタンで移動していたが、より厳しい期待値（移動しない・止まる）に書き換えた

test('8 同意済み（正しい Codex の戻り先）: 移動せず、確認できない旨の終了画面。許可も戻る操作もできない', async () => {
  const t = await toConsent({ details: { redirect_url: `${CODEX_REDIRECT}?code=prev&state=s` } });
  assert.deepEqual(t.last(), { screen: 'error', data: { message: 'previous_consent_unverifiable' } });
  assert.deepEqual(t.navigations, []);
  await t.flow.approve();
  assert.ok(!t.names().includes('approveAuthorization'));
  await t.flow.returnToClient();
  assert.deepEqual(t.navigations, []);
});

test('8 同意済みの redirect_url が許可リストと合わない場合も、同じく止める', async () => {
  const t = await toConsent({ details: { redirect_url: 'http://evil.example/?code=x' } });
  assert.deepEqual(t.last(), { screen: 'error', data: { message: 'previous_consent_unverifiable' } });
  await t.flow.returnToClient();
  assert.deepEqual(t.navigations, []);
});

// ---------- 9. 許可と拒否 ----------

test('9 許可: skipBrowserRedirect 付きで呼び、検査した redirect_url へ、ログアウトのあとに移動', async () => {
  const t = await toConsent();
  await t.flow.approve();
  const call = t.client.calls.find((c) => c.name === 'approveAuthorization');
  assert.deepEqual(call.args, [AUTH_ID, { skipBrowserRedirect: true }]);
  assert.deepEqual(t.navigations, [`${CODEX_REDIRECT}?code=abc&state=xyz`]);
  const n = t.names();
  assert.ok(n.lastIndexOf('getAuthenticatorAssuranceLevel') < n.indexOf('approveAuthorization'), '許可の直前にも aal2 を確かめる');
  assert.deepEqual(t.client.calls.find((c) => c.name === 'signOut').args, { scope: 'local' });
  assert.deepEqual(t.last(), { screen: 'done', data: { message: 'returning' } });
});

test('9 拒否: skipBrowserRedirect 付きで呼び、Codex の戻り先へ error を返す', async () => {
  const t = await toConsent();
  await t.flow.deny();
  assert.deepEqual(t.client.calls.find((c) => c.name === 'denyAuthorization').args, [AUTH_ID, { skipBrowserRedirect: true }]);
  assert.deepEqual(t.navigations, [`${CODEX_REDIRECT}?error=access_denied&state=xyz`]);
});

test('9 一度決めたら、もう一度押しても何も起きない（二重送信の防止）', async () => {
  const t = await toConsent();
  await Promise.all([t.flow.approve(), t.flow.approve(), t.flow.deny()]);
  assert.equal(t.names().filter((n) => n === 'approveAuthorization').length, 1);
  assert.ok(!t.names().includes('denyAuthorization'));
  assert.equal(t.navigations.length, 1);
});

test('9 許可の直前に aal2 でなくなっていたら、許可しない', async () => {
  const t = await toConsent();
  t.client.auth.mfa.getAuthenticatorAssuranceLevel = async () => ({ data: { currentLevel: 'aal1', nextLevel: 'aal2' }, error: null });
  await t.flow.approve();
  assert.ok(!t.names().includes('approveAuthorization'));
  assert.deepEqual(t.last(), { screen: 'error', data: { message: 'mfa_required' } });
});

test('9 Supabase がエラーを返したとき（ログイン・内容・許可・拒否）は決まった鍵だけ', async () => {
  const s = setup({ signInError: true });
  s.flow.start();
  await s.flow.signIn('g@e.invalid', FAKE_PASSWORD);
  assert.deepEqual(s.last(), { screen: 'signin', data: { message: 'signin_failed' } });
  assert.deepEqual((await toConsent({ detailsError: true })).last(), { screen: 'error', data: { message: 'details_failed' } });
  const a = await toConsent({ approveError: true });
  await a.flow.approve();
  assert.deepEqual(a.last(), { screen: 'error', data: { message: 'approve_failed' } });
  const d = await toConsent({ denyError: true });
  await d.flow.deny();
  assert.deepEqual(d.last(), { screen: 'error', data: { message: 'deny_failed' } });
});

test('9 Supabase のクライアントが例外を投げても、決まった鍵の画面になる', async () => {
  const t = setup();
  t.client.auth.signInWithPassword = async () => { throw new Error('boom secret'); };
  t.flow.start();
  await t.flow.signIn('g@e.invalid', FAKE_PASSWORD);
  assert.deepEqual(t.last(), { screen: 'error', data: { message: 'unexpected' } });
});

// ---------- 12. ログアウトの失敗 ----------

test('12 ログアウトが失敗（エラーの値・例外）しても、移動は止めず、生のエラーも出さない', async () => {
  for (const opt of [{ signOutError: true }, { signOutThrows: true }]) {
    const t = await toConsent(opt);
    await t.flow.approve();
    assert.deepEqual(t.navigations, [`${CODEX_REDIRECT}?code=abc&state=xyz`], JSON.stringify(opt));
    assert.deepEqual(t.last(), { screen: 'done', data: { message: 'returning' } });
  }
});

// ---------- 11（本体の部分）: 埋め込みの判定 ----------

test('11 最上位の画面でないとき・判定できないときは「埋め込み」とみなす', () => {
  const top = {};
  top.self = top;
  top.top = top;
  assert.equal(isTopLevel(top), true);
  assert.equal(isTopLevel({ self: {}, top: {} }), false);
  const throwing = { self: {}, get top() { throw new Error('cross-origin'); } };
  assert.equal(isTopLevel(throwing), false);
});

test('表示用の文字列: 制御文字を空白にし、長すぎる値は切る。文字列でなければ空', () => {
  assert.equal(displayText('a\u0000b\nc'), 'a b c');
  assert.equal([...displayText('あ'.repeat(500))].length, 121);
  assert.equal(displayText(null), '');
  assert.equal(displayText({ toString: () => 'x' }), '');
});
