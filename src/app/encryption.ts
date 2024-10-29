// encryption.ts

/**
 * データを暗号化します。
 * @param data 暗号化するデータ
 * @param key 暗号化キー
 * @returns IVと暗号化データを結合したArrayBuffer
 */
export async function encryptData(data: string, key: CryptoKey): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const encodedData = encoder.encode(data);
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96ビットのIV

  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    encodedData
  );

  // IVと暗号化データを結合
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);
  return combined.buffer;
}

/**
 * データを復号化します。
 * @param encryptedData 暗号化されたデータ（IVと暗号文が結合されたもの）
 * @param key 復号化キー
 * @returns 復号化された文字列
 */
export async function decryptData(encryptedData: ArrayBuffer, key: CryptoKey): Promise<string> {
  const data = new Uint8Array(encryptedData);
  const iv = data.slice(0, 12); // 最初の12バイトをIVとして取得
  const ciphertext = data.slice(12);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    ciphertext
  );

  const decoder = new TextDecoder();
  return decoder.decode(decrypted);
}