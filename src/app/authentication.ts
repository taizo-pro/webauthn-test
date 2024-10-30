import { deriveSymmetricKey } from './crypto';

/**
 * WebAuthnを使用してユーザーを認証し、共通鍵を生成します。
 * @returns 生成されたCryptoKeyまたはnull
 */
export async function authenticateAndDeriveKey(): Promise<CryptoKey | null> {
  try {
    // サーバーから認証用のチャレンジとユーザーの認証器情報を取得
    const authenticationOptions = await fetch('/api/authenticate/options').then(res => res.json());
    console.log("🔑 Authentication Options:", authenticationOptions);

    const assertion = await navigator.credentials.get({ publicKey: authenticationOptions });

    // サーバーにアサーション情報を送信して検証
    const isValid = await verifyAssertionWithServer(assertion);

    if (isValid) {
      // 鍵導出
      const symmetricKey = await deriveSymmetricKey(authenticationOptions.challenge);
      return symmetricKey;
    }

    return null;
  } catch (error) {
    console.error('認証に失敗しました:', error);
    return null;
  }
}

/**
 * サーバーでアサーションを検証します。
 * @param assertion ユーザーのアサーション情報
 * @returns 検証成功時にtrue、それ以外はfalse
 */
async function verifyAssertionWithServer(assertion: Credential | null): Promise<boolean> {
  console.log("🔍 Assertion:", assertion);
  try {
    if (!assertion) return false;

    const attestationResponse = (assertion as PublicKeyCredential).response as AuthenticatorAssertionResponse;
    const clientDataJSON = bufferToBase64url(attestationResponse.clientDataJSON);
    const authenticatorData = bufferToBase64url(attestationResponse.authenticatorData);
    const signature = bufferToBase64url(attestationResponse.signature);
    const userHandle = attestationResponse.userHandle ? bufferToBase64url(attestationResponse.userHandle) : null;

    const verificationResponse = await fetch('/api/authenticate/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        id: assertion.id,
        type: assertion.type,
        clientDataJSON,
        authenticatorData,
        signature,
        userHandle,
      }),
    });

    const verificationResult = await verificationResponse.json();

    return verificationResult.success;
  } catch (error) {
    console.error('サーバー側でのアサーション検証に失敗しました:', error);
    return false;
  }
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