import { useState } from "react";

/**
 * RSA鍵ペアの生成と管理を行うカスタムフック
 */
export default function useDeriveRSAKey() {
	// const [RSAKeyPair, setRSAKeyPair] = useState<CryptoKeyPair>();
	const [publicRSAKeyBase64, setPublicRSAKeyBase64] = useState<string>("");
	const [privateRSAKeyBase64, setPrivateRSAKeyBase64] = useState<string>("");

	/**
	 * RSA-OAEP鍵ペアを生成し、Base64エンコードされた形式で保存する
	 * @throws {Error} 鍵の生成に失敗した場合
	 */
	const generateRSAKeyPair = async (): Promise<{
		publicRSAKeyBase64: string;
		privateRSAKeyBase64: string;
	}> => {
		try {
			// WebCrypto APIを使用して2048ビットのRSA-OAEP鍵ペアを生成
			const generatedKeyPair = await crypto.subtle.generateKey(
				{
					name: "RSA-OAEP",
					modulusLength: 2048,
					publicExponent: new Uint8Array([1, 0, 1]),
					hash: "SHA-256",
				},
				true,
				["encrypt", "decrypt"],
			);

			// 秘密鍵をPKCS#8形式でエクスポート
			const privateRSAKeyRaw = await crypto.subtle.exportKey(
				"pkcs8",
				generatedKeyPair.privateKey,
			);

			// 公開鍵をSPKI形式でエクスポート
			const publicRSAKeyRaw = await crypto.subtle.exportKey(
				"spki",
				generatedKeyPair.publicKey,
			);

			// setRSAKeyPair(generatedKeyPair);
			// 秘密鍵をBase64エンコード
			setPrivateRSAKeyBase64(
				btoa(String.fromCharCode(...new Uint8Array(privateRSAKeyRaw))),
			);
			// 公開鍵をBase64エンコード
			setPublicRSAKeyBase64(
				btoa(String.fromCharCode(...new Uint8Array(publicRSAKeyRaw))),
			);

			return {
				publicRSAKeyBase64: btoa(String.fromCharCode(...new Uint8Array(publicRSAKeyRaw))),
				privateRSAKeyBase64: btoa(String.fromCharCode(...new Uint8Array(privateRSAKeyRaw))),
			};
		} catch (err) {
			console.error("鍵ペアの生成に失敗しました:", err);
			throw err;
		}
	};

	/**
	 * RSA公開鍵を使用してデータ（ユーザーキー）を暗号化する
	 * @param {CryptoKey} publicKey - 暗号化に使用する公開鍵
	 * @param {string} data - 暗号化する文字列データ（ユーザーキー）
	 * @returns {Promise<string>} Base64エンコードされた暗号化データ
	 */
	const encryptByRSA = async (
		publicKey: CryptoKey,
		data: string,
	): Promise<string> => {
		const encoded = new TextEncoder().encode(data);
		const encrypted = await crypto.subtle.encrypt(
			{
				name: "RSA-OAEP",
			},
			publicKey,
			encoded,
		);
		return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
	};

	/**
	 * RSA秘密鍵を使用して公開鍵で暗号化されたデータ（ユーザーキー）を復号する
	 * @param {CryptoKey} privateKey - 復号に使用する秘密鍵
	 * @param {string} encryptedBase64 - Base64エンコードされた暗号化データ（ユーザーキー）
	 * @returns {Promise<string>} 復号された文字列データ
	 */
	const decryptByRSA = async (
		privateKey: CryptoKey,
		encryptedBase64: string,
	): Promise<string> => {
		const encrypted = Uint8Array.from(atob(encryptedBase64), (c) =>
			c.charCodeAt(0),
		);
		const decrypted = await crypto.subtle.decrypt(
			{
				name: "RSA-OAEP",
			},
			privateKey,
			encrypted,
		);
		return new TextDecoder().decode(decrypted);
	};

	return {
		// RSAKeyPair,
		publicRSAKeyBase64,
		privateRSAKeyBase64,
		generateRSAKeyPair,
		encryptByRSA,
		decryptByRSA,
	};
}