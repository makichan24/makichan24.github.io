// テスト用の偽物（Supabase のクライアント・画面・移動）。本物の鍵・パスワードは使わない
import { ALLOWED_CLIENTS, createConsentFlow } from '../oauth/consent/consent-core.js';

export const AUTH_ID = 'abcdefghijklmnopqrstuvwxyz234567';
export const CODEX_REDIRECT = 'http://127.0.0.1:43127/callback/H2ERSOpTdH_S';
export const FAKE_PASSWORD = 'test-only-password-DO-NOT-LEAK-91';
export const FAKE_TOTP = '123456';
export const FAKE_TOKEN = 'eyJhbGciOiJFUzI1NiJ9.ZmFrZS1hY2Nlc3MtdG9rZW4.c2lnLWZha2U';
export const RAW_ERROR = 'internal supabase error detail: relation auth.sessions xyz-leak-77';
// 許可リストの Codex の client.id（getAuthorizationDetails が返す値として使う）
export const CODEX_CLIENT_ID = ALLOWED_CLIENTS[0].clientId;
export const OTHER_CLIENT_ID = '00000000-0000-4000-8000-0000000000aa';

export function details(over = {}) {
  return {
    authorization_id: AUTH_ID,
    redirect_uri: CODEX_REDIRECT,
    client: { id: CODEX_CLIENT_ID, name: 'MAKKI Gate - Codex', uri: '', logo_uri: '' },
    user: { id: 'u', email: 'gate@example.invalid' },
    scope: 'openid email',
    ...over,
  };
}

// 呼び出しを記録し、決めた値を返す偽の supabase-js クライアント
export function fakeClient(opts = {}) {
  const calls = [];
  const rec = (name, args) => calls.push({ name, args });
  let aal = opts.aalAfterSignIn ?? { currentLevel: 'aal1', nextLevel: 'aal2' };
  const err = (e) => ({ data: null, error: e });
  const client = {
    calls,
    auth: {
      signInWithPassword: async (args) => {
        rec('signInWithPassword', args);
        if (opts.signInError) return err({ message: RAW_ERROR, status: 400 });
        return { data: { session: { access_token: FAKE_TOKEN, refresh_token: 'r-fake' } }, error: null };
      },
      signOut: async (args) => {
        rec('signOut', args);
        if (opts.signOutThrows) throw new Error(RAW_ERROR);
        if (opts.signOutError) return { error: { message: RAW_ERROR } };
        return { error: null };
      },
      mfa: {
        getAuthenticatorAssuranceLevel: async () => {
          rec('getAuthenticatorAssuranceLevel');
          if (opts.aalError) return err({ message: RAW_ERROR });
          return { data: aal, error: null };
        },
        listFactors: async () => {
          rec('listFactors');
          if (opts.noFactor) return { data: { all: [], totp: [] }, error: null };
          return { data: { all: [{ id: 'f1', status: 'verified' }], totp: [{ id: 'f1', factor_type: 'totp', status: 'verified' }] }, error: null };
        },
        challenge: async (args) => {
          rec('challenge', args);
          if (opts.challengeError) return err({ message: RAW_ERROR });
          return { data: { id: 'c1', type: 'totp', expires_at: 0 }, error: null };
        },
        verify: async (args) => {
          rec('verify', args);
          if (opts.verifyError) return err({ message: RAW_ERROR });
          aal = opts.aalAfterVerify ?? { currentLevel: 'aal2', nextLevel: 'aal2' };
          return { data: { access_token: FAKE_TOKEN }, error: null };
        },
      },
      oauth: {
        getAuthorizationDetails: async (id) => {
          rec('getAuthorizationDetails', id);
          if (opts.detailsError) return err({ message: RAW_ERROR });
          return { data: opts.details ?? details(), error: null };
        },
        approveAuthorization: async (id, o) => {
          rec('approveAuthorization', [id, o]);
          if (opts.approveError) return err({ message: RAW_ERROR });
          return { data: { redirect_url: opts.approveUrl ?? `${CODEX_REDIRECT}?code=abc&state=xyz` }, error: null };
        },
        denyAuthorization: async (id, o) => {
          rec('denyAuthorization', [id, o]);
          if (opts.denyError) return err({ message: RAW_ERROR });
          return { data: { redirect_url: opts.denyUrl ?? `${CODEX_REDIRECT}?error=access_denied&state=xyz` }, error: null };
        },
      },
    },
  };
  return client;
}

export function setup(opts = {}, search = `?authorization_id=${AUTH_ID}`) {
  const client = fakeClient(opts);
  const screens = [];
  const navigations = [];
  const flow = createConsentFlow({
    client,
    view: { show: (screen, data) => screens.push({ screen, data: { ...data } }) },
    navigate: (url) => navigations.push(url),
    search,
  });
  return { client, flow, screens, navigations, last: () => screens.at(-1), names: () => client.calls.map((c) => c.name) };
}

// 画面までたどり着く手順
export async function toConsent(opts = {}) {
  const t = setup(opts);
  t.flow.start();
  await t.flow.signIn('gate@example.invalid', FAKE_PASSWORD);
  await t.flow.verifyTotp(FAKE_TOTP);
  return t;
}
