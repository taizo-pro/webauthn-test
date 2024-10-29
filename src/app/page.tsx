"use client";

import React, { useState } from 'react';
import { authenticateAndDeriveKey } from './authentication';
import { encryptData, decryptData } from './encryption';

export default function Home() {
  const [status, setStatus] = useState('');
  const [encrypted, setEncrypted] = useState<string>('');
  const [decrypted, setDecrypted] = useState<string>('');
  const [symmetricKey, setSymmetricKey] = useState<CryptoKey | null>(null);

  const handleUnlock = async () => {
    const key = await authenticateAndDeriveKey();
    console.log("🍣 ~ file: page.tsx:15 ~ handleUnlock ~ key:", key);
    if (key) {
      setSymmetricKey(key);
      setStatus('ロックが解除されました。');
    } else {
      setStatus('認証に失敗しました。');
    }
  };

  // 暗号化する処理
  const handleEncrypt = async () => {
    if (!symmetricKey) {
      setStatus('ロックを解除してください。');
      return;
    }
    const dataToEncrypt = 'これは機密データです。';
    const encryptedBuffer = await encryptData(dataToEncrypt, symmetricKey);
    const encryptedString = btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
    setEncrypted(encryptedString);
    setStatus('データが暗号化されました。');
  };

  // 復号化する処理
  const handleDecrypt = async () => {
    if (!symmetricKey) {
      setStatus('ロックを解除してください。');
      return;
    }
    try {
      const encryptedBuffer = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0)).buffer;
      const decryptedData = await decryptData(encryptedBuffer, symmetricKey);
      setDecrypted(decryptedData);
      setStatus('データが復号化されました。');
    } catch (error) {
      console.error(error);
      setStatus('復号化に失敗しました。');
    }
  };

  const handleLock = () => {
    setSymmetricKey(null);
    setStatus('ロックされました。');
    setEncrypted('');
    setDecrypted('');
  };

  return (
    <div>
      <h1>暗号化テスト</h1>
      <div>
        {/* biome-ignore lint/a11y/useButtonType: <explanation> */}
        <button onClick={handleUnlock} style={{ backgroundColor: 'blue', color: 'white' }}>ロック解除</button>
        {/* biome-ignore lint/a11y/useButtonType: <explanation> */}
        <button onClick={handleLock} style={{ backgroundColor: 'red', color: 'white' }}>ロック</button>
      </div>
      <div>
        {/* biome-ignore lint/a11y/useButtonType: <explanation> */}
        <button onClick={handleEncrypt} style={{ backgroundColor: 'blue', color: 'white' }}>データを暗号化</button>
        {/* biome-ignore lint/a11y/useButtonType: <explanation> */}
        <button onClick={handleDecrypt} style={{ backgroundColor: 'red', color: 'white' }}>データを復号化</button>
      </div>
      <div>
        <p>{status}</p>
        {encrypted && <p>暗号化データ: {encrypted}</p>}
        {decrypted && <p>復号化データ: {decrypted}</p>}
      </div>
    </div>
  );
}
