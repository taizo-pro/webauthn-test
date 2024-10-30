/**
 * 鍵導出関数を使用して共通鍵を生成します。
 * @param baseKey 基礎となる鍵（例：サーバーから送られたチャレンジや認証器の情報）
 * @returns 生成されたCryptoKey
 */
export async function deriveSymmetricKey(baseKey: ArrayBuffer): Promise<CryptoKey> {
  // HKDFを使用して共通鍵を派生
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    baseKey,
    { name: 'HKDF' },
    false,
    ['deriveKey']
  );

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(16), // 固定またはランダムなソルト
      info: new TextEncoder().encode('encryption key'),
    },
    keyMaterial,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['encrypt', 'decrypt']
  );

  return derivedKey;
}