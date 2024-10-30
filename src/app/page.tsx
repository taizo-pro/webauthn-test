"use client";

import React, { useState } from 'react';
import { authenticateAndDeriveKey } from './authentication';
import { encryptData, decryptData } from './encryption';
import { registerPasskey } from './registration';

export default function Home() {
  const [status, setStatus] = useState('');
  const [encrypted, setEncrypted] = useState<string>('');
  const [decrypted, setDecrypted] = useState<string>('');
  const [symmetricKey, setSymmetricKey] = useState<CryptoKey | null>(null);

  const handleUnlock = async () => {
    const key = await authenticateAndDeriveKey();
    console.log("🔓 Unlock Key:", key);
    if (key) {
      setSymmetricKey(key);
      setStatus('ロックが解除されました。');
    } else {
      setStatus('認証に失敗しました。');
    }
  };

  const handleRegister = async () => {
    const success = await registerPasskey();
    if (success) {
      setStatus('パスキーが正常に登録されました。');
    } else {
      setStatus('パスキーの登録に失敗しました。');
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
      <h1>WebAuthn パスキー登録・認証</h1>
      <div>
        {/* biome-ignore lint/a11y/useButtonType: <explanation> */}
        <button onClick={handleRegister} style={{ backgroundColor: 'green', color: 'white', marginRight: '10px' }}>
          パスキーを登録
        </button>
        {/* biome-ignore lint/a11y/useButtonType: <explanation> */}
        <button onClick={handleUnlock} style={{ backgroundColor: 'blue', color: 'white', marginRight: '10px' }}>
          ロック解除
        </button>
        {/* biome-ignore lint/a11y/useButtonType: <explanation> */}
        <button onClick={handleLock} style={{ backgroundColor: 'red', color: 'white', marginRight: '10px' }}>
          ロック
        </button>
      </div>
      <div style={{ marginTop: '20px' }}>
        {/* biome-ignore lint/a11y/useButtonType: <explanation> */}
        <button onClick={handleEncrypt} style={{ backgroundColor: 'blue', color: 'white', marginRight: '10px' }}>
          データを暗号化
        </button>
        {/* biome-ignore lint/a11y/useButtonType: <explanation> */}
        <button onClick={handleDecrypt} style={{ backgroundColor: 'red', color: 'white' }}>
          データを復号化
        </button>
      </div>
      <div style={{ marginTop: '20px' }}>
        <p>{status}</p>
        {encrypted && <p>暗号化データ: {encrypted}</p>}
        {decrypted && <p>復号化データ: {decrypted}</p>}
      </div>
    </div>
  );
}