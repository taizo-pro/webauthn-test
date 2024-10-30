// src/app/registration.ts

/**
 * WebAuthnを使用してユーザーのパスキーを登録します。
 * @returns 登録に成功した場合はtrue、失敗した場合はfalse
 */
export async function registerPasskey(): Promise<boolean> {
  try {
    // サーバーから登録用のオプションを取得
    const response = await fetch('/api/register/options');
    if (!response.ok) {
      throw new Error('登録オプションの取得に失敗しました。');
    }
    const options = await response.json();

    // Base64URLエンコードされたチャレンジとユーザーIDをArrayBufferに変換
    options.challenge = base64urlToBuffer(options.challenge);
    options.user.id = base64urlToBuffer(options.user.id);

    // パスキーを生成
    const credential = await navigator.credentials.create({ publicKey: options });

    if (!credential) {
      throw new Error('パスキーの作成に失敗しました。');
    }

    // サーバーにパスキー情報を送信して検証・保存
    const attestationResponse = (credential as PublicKeyCredential).response as AuthenticatorAttestationResponse;
    const clientDataJSON = bufferToBase64url(attestationResponse.clientDataJSON);
    const attestationObject = bufferToBase64url(attestationResponse.attestationObject);

    const verificationResponse = await fetch('/api/register/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: credential.id,
        type: credential.type,
        clientDataJSON,
        attestationObject,
      }),
    });

    const verificationResult = await verificationResponse.json();

    if (verificationResult.success) {
      return true;
    }
    console.error('サーバー側での検証に失敗:', verificationResult.message);
    return false;
  } catch (error) {
    console.error('パスキーの登録に失敗しました:', error);
    return false;
  }
}

/**
 * Base64URL文字列をArrayBufferに変換します。
 * @param base64url Base64URL文字列
 * @returns ArrayBuffer
 */
function base64urlToBuffer(base64url: string): ArrayBuffer {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(base64);
  const buffer = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    buffer[i] = binary.charCodeAt(i);
  }
  return buffer.buffer;
}

/**
 * ArrayBufferをBase64URL文字列に変換します。
 * @param buffer ArrayBuffer
 * @returns Base64URL文字列
 */
function bufferToBase64url(buffer: ArrayBuffer): string {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}