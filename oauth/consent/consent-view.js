// =============================================
// MAKKI Gate 同意画面の描画。外から来た文字列は textContent だけで描画する（innerHTML は使わない）
// 表示する文言は、決まった鍵から引く（Supabase の生のエラーは画面に出さない）
// =============================================

export const SCREENS = ['loading', 'error', 'signin', 'mfa', 'consent', 'done'];

export const MESSAGES = Object.freeze({
  invalid_request: 'この画面は、アプリからの接続の途中でだけ開けます。アプリから接続をやり直してください。',
  unexpected: '処理を続けられませんでした。アプリから接続をやり直してください。',
  signin_input: 'メールアドレスとパスワードを入力してください。',
  signin_failed: 'ログインできませんでした。入力を確かめて、もう一度お試しください。',
  mfa_required: '確認コード（TOTP）での確認が必要です。アプリから接続をやり直してください。',
  totp_input: '6桁の数字を入力してください。',
  totp_failed: '確認コードで確認できませんでした。新しいコードで、もう一度お試しください。',
  details_failed: '接続の内容を読み込めませんでした。アプリから接続をやり直してください。',
  unexpected_redirect: '戻り先が想定と違うため、処理を止めました。',
  previous_consent_unverifiable: '以前の認可情報を確認できないため、この認可は続けられません。',
  approve_failed: '許可を完了できませんでした。アプリから接続をやり直してください。',
  deny_failed: '拒否を完了できませんでした。アプリから接続をやり直してください。',
  returning: 'アプリに戻ります。',
  denied: '接続を拒否しました。この画面は閉じて大丈夫です。',
});

export function messageFor(key) {
  return Object.prototype.hasOwnProperty.call(MESSAGES, key) ? MESSAGES[key] : MESSAGES.unexpected;
}

// byId(id): 要素を返す関数（ブラウザでは document.getElementById）
export function render(byId, screen, data = {}) {
  const target = SCREENS.includes(screen) ? screen : 'error';
  for (const s of SCREENS) {
    const el = byId(`screen-${s}`);
    if (el) el.hidden = s !== target;
  }
  // 画面が変わるたびに、パスワードと確認コードの入力欄を空にする
  for (const id of ['password', 'totp']) {
    const el = byId(id);
    if (el) el.value = '';
  }
  const setText = (id, text) => {
    const el = byId(id);
    if (el) el.textContent = text;
  };
  const message = data.message === undefined ? '' : messageFor(data.message);

  switch (target) {
    case 'error':
      setText('error-message', message || MESSAGES.unexpected);
      break;
    case 'signin':
      setText('signin-message', message);
      break;
    case 'mfa':
      setText('mfa-message', message);
      break;
    case 'consent': {
      setText('client-name', typeof data.clientName === 'string' && data.clientName !== '' ? data.clientName : '（名前なし）');
      setText('redirect-uri', typeof data.redirectUri === 'string' ? data.redirectUri : '');
      setText('scope', typeof data.scope === 'string' && data.scope !== '' ? data.scope : '（指定なし）');
      const approve = byId('approve');
      const canApprove = data.canApprove === true;
      if (approve) {
        approve.hidden = !canApprove;
        approve.disabled = !canApprove;
      }
      const note = byId('approve-unavailable');
      if (note) note.hidden = canApprove;
      break;
    }
    case 'done':
      setText('done-message', message);
      break;
    default:
      break;
  }
}
