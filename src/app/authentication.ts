// authentication.ts

import { deriveSymmetricKey } from './crypto';

/**
 * WebAuthnを使用してユーザーを認証し、共通鍵を生成します。
 * @returns 生成されたCryptoKeyまたはnull
 */
export async function authenticateAndDeriveKey(): Promise<CryptoKey | null> {
  try {
    // サーバーから送られるチャレンジを取得（例として固定値を使用）
    const challenge = new Uint8Array(32); // 実際にはサーバーから受け取る
    console.log("🍣 ~ file: authentication.ts:13 ~ authenticateAndDeriveKey ~ challenge:", challenge);

    const publicKey: PublicKeyCredentialRequestOptions = {
      challenge: challenge,
      timeout: 60000,
      allowCredentials: [], // サーバーからユーザーに関連付けられた認証器情報を取得
      userVerification: 'required',
    };
    console.log("🍣 ~ file: authentication.ts:21 ~ authenticateAndDeriveKey ~ publicKey:", publicKey);

    const assertion = await navigator.credentials.get({ publicKey });

    // サーバーにアサーション情報を送信して検証
    const isValid = await verifyAssertionWithServer(assertion);

    if (isValid) {
      // 鍵導出
      const symmetricKey = await deriveSymmetricKey(challenge.buffer);
      console.log("🍣 ~ file: authentication.ts:32 ~ authenticateAndDeriveKey ~ symmetricKey:", symmetricKey);
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
  console.log("🍣 ~ file: authentication.ts:49 ~ verifyAssertionWithServer ~ assertion:", assertion);
  // サーバーとの通信ロジックを実装
  // ここでは仮にtrueを返す
  return true;
}