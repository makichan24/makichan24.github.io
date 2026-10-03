// =============================================
// MAKKI Gate 同意画面の本体（画面と Supabase から切り離した部分。Node でテストする）
// 正本: Supabase OAuth Server の公式の流れ（getAuthorizationDetails -> approve / deny -> redirect_url へ移動）
// 守ること:
//   - password / TOTP / token / session / authorization_id を console に出さない（このファイルは console を使わない）
//   - Supabase の生のエラーを画面に出さない（画面に渡すのは決まったメッセージの鍵だけ）
//   - AAL2 を確かめる前は、許可（approve）へ進まない
//   - 移動先は Supabase が返した redirect_url だけ。許可リストの戻り先と完全に一致するときだけ移動する
// =============================================

// Supabase Auth の authorization_id は crypto.SecureAlphanumeric(32)＝小文字の base32 で32文字（supabase/auth の実装で確認）
export const AUTHORIZATION_ID_RE = /^[a-z2-7]{32}$/;

// 許可（approve）してよいアプリ: Supabase の getAuthorizationDetails が返す client.id と redirect_uri の「組」で照合する。
// - Phase 1 の静的な許可リスト。client_id（＝client.id）は秘密ではないが、知らないアプリや、戻り先だけを似せた
//   アプリを許可させないための追加防御として、組で固定する（OAuth 上の正本の redirect_uri の検証は Supabase 側）
// - 将来 Claude Code / ChatGPT を追加するときは、ここに組を足す必要がある（Supabase で OAuth App を作ったあと）
// - 値は利用者の入力から作らない。照合に使うのは getAuthorizationDetails の返り値だけ。client.id は console に出さない
export const ALLOWED_CLIENTS = Object.freeze([
  Object.freeze({ clientId: '499a3bbd-2d13-4f0f-9afa-5f1ec277fd19', redirectUri: 'http://127.0.0.1:43127/callback/H2ERSOpTdH_S' }), // MAKKI Gate - Codex
]);
export const ALLOWED_REDIRECT_URIS = Object.freeze(ALLOWED_CLIENTS.map((c) => c.redirectUri));

const MAX_URL_LENGTH = 4096;
const TOTP_RE = /^[0-9]{6}$/;

// URL の検索部分から authorization_id を1つだけ取り出す。無い・複数・形が違うときは null
export function readAuthorizationId(search) {
  let params;
  try {
    params = new URLSearchParams(typeof search === 'string' ? search : '');
  } catch {
    return null;
  }
  const all = params.getAll('authorization_id');
  if (all.length !== 1) return null;
  return AUTHORIZATION_ID_RE.test(all[0]) ? all[0] : null;
}

// Supabase が返した redirect_uri が、許可リストのどれかと文字列として完全に一致するか
export function matchAllowedRedirectUri(uri, allowed = ALLOWED_REDIRECT_URIS) {
  if (typeof uri !== 'string') return null;
  return allowed.includes(uri) ? uri : null;
}

// getAuthorizationDetails の返り値の client.id と redirect_uri の組が、許可リストの組と両方とも完全に一致するときだけ、
// その戻り先を返す。client.id が無い・知らない・戻り先だけ一致・client.id だけ一致は、すべて null（許可できない）
export function matchAllowedClient(details, allowedClients = ALLOWED_CLIENTS) {
  if (!details || typeof details !== 'object') return null;
  const clientId = details.client && typeof details.client === 'object' ? details.client.id : undefined;
  const redirectUri = details.redirect_uri;
  if (typeof clientId !== 'string' || clientId === '' || typeof redirectUri !== 'string') return null;
  const hit = allowedClients.find((c) => c.clientId === clientId && c.redirectUri === redirectUri);
  return hit ? hit.redirectUri : null;
}

// Supabase が返した移動先（redirect_url）が、期待する戻り先と origin + パスで完全に一致するか。
// 文字列としても「戻り先そのもの」か「戻り先 + ?...」で始まることを求める（URL の解釈の違いを突く書き方を防ぐ）
export function isSafeReturnUrl(redirectUrl, expectedRedirectUri) {
  if (typeof redirectUrl !== 'string' || typeof expectedRedirectUri !== 'string') return false;
  if (redirectUrl.length === 0 || redirectUrl.length > MAX_URL_LENGTH) return false;
  // 空白・制御文字・バックスラッシュを含む値は扱わない
  if (/[\s\\\u0000-\u001f\u007f]/.test(redirectUrl)) return false;
  if (!(redirectUrl === expectedRedirectUri || redirectUrl.startsWith(expectedRedirectUri + '?'))) return false;
  let got;
  let want;
  try {
    got = new URL(redirectUrl);
    want = new URL(expectedRedirectUri);
  } catch {
    return false;
  }
  return got.protocol === want.protocol &&
    (got.protocol === 'http:' || got.protocol === 'https:') &&
    got.username === '' && got.password === '' &&
    got.hostname === want.hostname &&
    got.port === want.port &&
    got.pathname === want.pathname &&
    got.hash === '';
}

// 埋め込まれていない（最上位の画面である）か。判定できないときは「埋め込まれている」とみなす
export function isTopLevel(win) {
  try {
    return win.self === win.top;
  } catch {
    return false;
  }
}

// 画面に出す外部の文字列（アプリの名前など）を短く切る。描画は必ず textContent で行う
export function displayText(value, max = 120) {
  if (typeof value !== 'string') return '';
  const chars = [...value.replace(/[\u0000-\u001f\u007f]/g, ' ')];
  return chars.length > max ? chars.slice(0, max).join('') + '…' : chars.join('');
}

// ---------------------------------------------------------------
// 状態の移り変わり
//   client: supabase-js のクライアント（auth.signInWithPassword / auth.mfa.* / auth.oauth.* / auth.signOut）
//   view.show(screen, data): 画面の切り替え（data は決まった鍵と、表示用に切った文字列だけ）
//   navigate(url): 移動（location.replace）
// 画面: loading / error / signin / mfa / consent / done
// ---------------------------------------------------------------
export function createConsentFlow({ client, view, navigate, search, allowedClients = ALLOWED_CLIENTS }) {
  const authorizationId = readAuthorizationId(search);
  const initialState = () => ({ aal2: false, details: null, expectedRedirect: null, decided: false });
  let busy = false;
  let terminated = false;
  let state = initialState();

  // 再試行できない終了: フローの状態を初期化し（許可できる状態を残さない）、以後の操作を受け付けず、
  // エラー画面を出してから、この同意画面のローカルのセッションを破棄する（signOut の失敗は外へ出さない）
  const fail = async (message) => {
    terminated = true;
    state = initialState();
    view.show('error', { message });
    await signOutQuietly();
  };

  // 例外もエラーの値も、外へは決まった鍵だけを出す
  const guarded = (fn) => async (...args) => {
    // authorization_id が不正なとき・再試行できない終了のあとは、どの操作も受け付けない（Supabase を呼ばない）
    if (authorizationId === null || terminated || busy || state.decided) return;
    busy = true;
    try {
      await fn(...args);
    } catch {
      await fail('unexpected');
    } finally {
      busy = false;
    }
  };

  async function currentAal() {
    const { data, error } = await client.auth.mfa.getAuthenticatorAssuranceLevel();
    if (error || !data) return { current: null, next: null };
    return { current: data.currentLevel ?? null, next: data.nextLevel ?? null };
  }

  async function signOutQuietly() {
    try {
      const r = await client.auth.signOut({ scope: 'local' });
      return !(r && r.error);
    } catch {
      return false;
    }
  }

  async function finish(url) {
    state = { ...state, decided: true };
    view.show('done', { message: 'returning' });
    // 同意画面のセッションだけを終わらせる。失敗しても移動は止めない（セッションはメモリだけにあり、移動で消える）
    await signOutQuietly();
    navigate(url);
  }

  async function loadDetails() {
    const aal = await currentAal();
    if (aal.current !== 'aal2') return fail('mfa_required');
    state = { ...state, aal2: true };
    const { data, error } = await client.auth.oauth.getAuthorizationDetails(authorizationId);
    if (error || !data || typeof data !== 'object') return fail('details_failed');

    // 以前に同意済み（redirect_url だけが返る応答）: client.id を確かめられないので、Phase 1 では必ず止める（fail closed）。
    // redirect_url が正しい Codex の戻り先に見えても移動しない。URL の query などから client_id を補って信用することもしない。
    // 将来 Supabase 側で信頼できる client の確認方法が確立できた場合だけ、この経路を再び有効にする（残課題）
    if (!('authorization_id' in data)) return fail('previous_consent_unverifiable');

    if (data.authorization_id !== authorizationId) return fail('details_failed');
    // 許可できるのは client.id と redirect_uri の組が許可リストと一致するときだけ（拒否はどのアプリでもできる）
    const expected = matchAllowedClient(data, allowedClients);
    state = { ...state, details: data, expectedRedirect: expected };
    view.show('consent', {
      clientName: displayText(data.client?.name),
      redirectUri: displayText(data.redirect_uri, 200),
      scope: displayText(data.scope, 200),
      canApprove: expected !== null,
    });
  }

  return {
    authorizationId,

    start() {
      // まだログインしていない（セッションが無い）ので、ここでは signOut を呼ばない
      if (authorizationId === null) {
        terminated = true;
        return view.show('error', { message: 'invalid_request' });
      }
      view.show('signin', {});
    },

    signIn: guarded(async (email, password) => {
      if (typeof email !== 'string' || typeof password !== 'string' || email.trim() === '' || password === '') {
        return view.show('signin', { message: 'signin_input' });
      }
      const { error } = await client.auth.signInWithPassword({ email: email.trim(), password });
      if (error) return view.show('signin', { message: 'signin_failed' });
      const aal = await currentAal();
      if (aal.current === 'aal2') return loadDetails();
      if (aal.next === 'aal2') return view.show('mfa', {});
      // Gate の利用者は TOTP が必須。TOTP が無い利用者は先へ進ませない（fail がセッションを破棄する）
      return fail('mfa_required');
    }),

    verifyTotp: guarded(async (code) => {
      if (typeof code !== 'string' || !TOTP_RE.test(code)) return view.show('mfa', { message: 'totp_input' });
      const { data: factors, error: listError } = await client.auth.mfa.listFactors();
      const factor = !listError && factors && Array.isArray(factors.totp)
        ? factors.totp.find((f) => f && f.status === 'verified')
        : undefined;
      if (!factor) return fail('mfa_required');
      const { data: challenge, error: challengeError } = await client.auth.mfa.challenge({ factorId: factor.id });
      if (challengeError || !challenge) return view.show('mfa', { message: 'totp_failed' });
      const { error: verifyError } = await client.auth.mfa.verify({ factorId: factor.id, challengeId: challenge.id, code });
      if (verifyError) return view.show('mfa', { message: 'totp_failed' });
      return loadDetails();
    }),

    approve: guarded(async () => {
      // AAL2 を確かめる前・許可リストにない戻り先では、許可しない
      if (!state.aal2 || !state.details || state.expectedRedirect === null) return;
      const aal = await currentAal();
      if (aal.current !== 'aal2') return fail('mfa_required');
      const { data, error } = await client.auth.oauth.approveAuthorization(authorizationId, { skipBrowserRedirect: true });
      if (error || !data || !isSafeReturnUrl(data.redirect_url, state.expectedRedirect)) return fail('approve_failed');
      await finish(data.redirect_url);
    }),

    deny: guarded(async () => {
      if (!state.details) return;
      const { data, error } = await client.auth.oauth.denyAuthorization(authorizationId, { skipBrowserRedirect: true });
      if (error || !data) return fail('deny_failed');
      // 許可リストの戻り先なら、拒否の結果を Codex に返す。知らない戻り先へは移動しない
      if (state.expectedRedirect !== null && isSafeReturnUrl(data.redirect_url, state.expectedRedirect)) {
        return finish(data.redirect_url);
      }
      state = { ...state, decided: true };
      await signOutQuietly();
      view.show('done', { message: 'denied' });
    }),

    // 「以前に同意済みなら Codex に戻る」は Phase 1 では無効（上の fail closed を参照）。呼ばれても何もしない
    returnToClient: async () => {},
  };
}
