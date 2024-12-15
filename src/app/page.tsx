"use client";

import { useState } from "react";

// PRF拡張機能の型定義
declare global {
	interface AuthenticationExtensionsClientInputs {
		prf?: {
			eval: {
				first: ArrayBuffer;
			};
		};
	}

	interface AuthenticationExtensionsClientOutputs {
		prf?: {
			results: {
				first: ArrayBuffer;
			};
		};
	}
}

export default function Home() {
	const [extensionResults, setExtensionResults] = useState<string>("");
	const [registrationResult, setRegistrationResult] = useState<string>("");
	const [signResult, setSignResult] = useState<string>("");
	const [inputText, setInputText] = useState<string>("");
	const [prfEncryptedData, setPrfEncryptedData] = useState<ArrayBuffer>();
	const [prfKey, setPrfKey] = useState<CryptoKey>();
	const [prfDecryptedData, setPrfDecryptedData] = useState<string>("");
	const [nonce, setNonce] = useState<Uint8Array>();

	// ユーティリティ関数
	const hashToArrayBuffer = async (value: string) => {
		const data = new TextEncoder().encode(value);
		const hash = await crypto.subtle.digest("SHA-256", data);
		return hash;
	};

	// パスキー登録
	const handleRegister = async () => {
		const userId = "00000000-0000-0000-0000-000000000001";
		const userIdArrayBuffer = await hashToArrayBuffer(userId);
		// ref. https://github.com/bitwarden/clients/blob/main/libs/common/src/auth/services/webauthn-login/webauthn-login-prf-key.service.ts#L9
		const LoginWithPrfSalt = "passwordless-login";
		const prfSalt = await hashToArrayBuffer(LoginWithPrfSalt);

		try {
			const pubKeyCredential = (await navigator.credentials.create({
				publicKey: {
					// 署名の正当性を検証するためのランダムな文字列
					// 攻撃者に入手されると公開鍵がすり替えられてしまうので、サーバで生成する
					// 仕様では16文字以上の長さを持つランダムな文字列であることが推奨されている
					challenge: new Uint8Array([1]),

					// 認証サーバの情報
					rp: {
						// RPの識別子。通常はドメイン名
						id: window.location.hostname,
						// RPの表示名
						name: "WebAuthn Test",
					},

					// ユーザーの情報
					user: {
						// ユーザーの識別子
						id: new Uint8Array(userIdArrayBuffer),
						// ユーザー名。通常はメールアドレス
						name: "test@example.com",
						// ユーザーの表示名
						displayName: "テストユーザー",
					},

					// 公開鍵のパラメータ
					// 作成する公開鍵の種類とアルゴリズムを指定する配列
					// algはアルゴリズムのID（例：-7 は ECDSA with SHA-256）
					// ref. https://www.iana.org/assignments/cose/cose.xhtml#algorithms
					// typeは"public-key"固定
					// ref. https://developer.mozilla.org/ja/docs/Web/API/CredentialsContainer/create#pubkeycredparams
					pubKeyCredParams: [
						{ alg: -8, type: "public-key" },
						{ alg: -7, type: "public-key" },
					],

					// 認証器の選択基準を指定する
					authenticatorSelection: {
						// 認証器がプラットフォームに内装されているか、クロスプラットフォームかを指定する
						// ref. https://developer.mozilla.org/ja/docs/Web/API/CredentialsContainer/create#authenticatorattachment
						authenticatorAttachment: "platform",

						// ユーザーの認証が必要かどうかを指定する
						// ref. https://developer.mozilla.org/ja/docs/Web/API/CredentialsContainer/create#userverification
						userVerification: "required",
					},

					// PRF (Pseudo Random Function) 拡張機能
					// 認証器から暗号鍵を導出するための設定
					// ref. https://w3c.github.io/webauthn/#prf-extension
					extensions: {
						prf: {
							// eval: 現在の認証器から直接鍵を導出
							// evalByCredential: 特定の認証情報IDを指定して鍵を導出
							eval: {
								// PRF導出に使用するソルト値
								// ソルトは暗号鍵の導出過程で使用される追加のランダムデータ
								// 同じユーザー/認証器でも、異なるソルトを使うと異なる鍵が導出される
								first: prfSalt,
							},
						},
					},
				},
			})) as PublicKeyCredential;

			// AuthenticatorAttestationResponseとして型アサーション
			const attestationResponse =
				pubKeyCredential.response as AuthenticatorAttestationResponse;

			// // attestationObjectから公開鍵情報を取得できます
			// const attestationObject = attestationResponse.attestationObject;

			// getPublicKeyを使用して公開鍵を取得
			const publicKeyData = attestationResponse.getPublicKey();

			console.log("パスキー登録成功:", pubKeyCredential);
			const authExtensionResults = pubKeyCredential.getClientExtensionResults();
			if (!authExtensionResults.prf) {
				throw new Error("PRF拡張機能がサポートされていません");
			}
			const inputKeyMaterial = new Uint8Array(
				authExtensionResults.prf.results.first,
			);

			setExtensionResults(JSON.stringify(authExtensionResults, null, 2));
			setRegistrationResult(JSON.stringify(inputKeyMaterial, null, 2));
		} catch (err) {
			setExtensionResults(`エラーが発生しました: ${err}`);
		}
	};

	// パスキーログイン
	const handleAuthenticate = async () => {
		// ref. https://github.com/bitwarden/clients/blob/main/libs/common/src/auth/services/webauthn-login/webauthn-login-prf-key.service.ts#L9
		const LoginWithPrfSalt = "passwordless-login";
		const prfSalt = await hashToArrayBuffer(LoginWithPrfSalt);

		try {
			const authCredential = (await navigator.credentials.get({
				publicKey: {
					challenge: new Uint8Array([9, 0, 1, 2]),
					rpId: window.location.hostname,
					userVerification: "required",
					extensions: {
						prf: {
							eval: {
								first: prfSalt,
							},
						},
					},
				},
			})) as PublicKeyCredential;

			const authExtensionResults = authCredential.getClientExtensionResults();
			if (!authExtensionResults.prf) {
				throw new Error("PRF拡張機能がサポートされていません");
			}
			const inputKeyMaterial = new Uint8Array(
				authExtensionResults.prf.results.first,
			);
			setSignResult(JSON.stringify(inputKeyMaterial, null, 2));

			// PRF対称鍵を作るための鍵を導出する
			const keyDerivationKey = await crypto.subtle.importKey(
				// 鍵のフォーマット (例: "raw", "pkcs8", "spki", "jwk")
				"raw",
				// 鍵のデータ
				inputKeyMaterial,
				// 鍵導出アルゴリズム（例: "AES-GCM", "HKDF"）
				"HKDF",
				// 鍵をエクスポート可能にするか (true または false)
				false,
				// 鍵の利用目的 (例: ["encrypt", "decrypt", "sign", "verify"])
				["deriveKey"],
			);

			const label = "encryption key";
			const info = new TextEncoder().encode(label);
			const salt = new Uint8Array();

			// PRF対称鍵を導出する
			const encryptionKey = await crypto.subtle.deriveKey(
				{ name: "HKDF", info, salt, hash: "SHA-256" },
				keyDerivationKey,
				{ name: "AES-GCM", length: 256 },
				false,
				["encrypt", "decrypt"],
			);
			setPrfKey(encryptionKey);
		} catch (err) {
			console.error("認証エラー:", err);
		}
	};

	// RSA秘密鍵の暗号化
	const handleRSAEncrypt = async () => {
		try {
			// 乱数。パスキーごとに生成する。復号化時に必要であるためサーバーに保存する
			const nonce = crypto.getRandomValues(new Uint8Array(12));
			setNonce(nonce);
			// 暗号化したいデータを暗号化する
			const encrypted = await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv: nonce },
				prfKey as CryptoKey,
				// FIXME: 一旦inputTextを使っているが、RSA秘密鍵を暗号化する
				new TextEncoder().encode(inputText),
			);
			setPrfEncryptedData(encrypted);
		} catch (err) {
			console.error("暗号化エラー:", err);
		}
	};

	// RSA秘密鍵の復号化
	const handleRSADecrypt = async () => {
		await handleAuthenticate();
		const decrypted = await crypto.subtle.decrypt(
			// nonceは暗号化時に使用したものと同じでないと復号化できない
			{ name: "AES-GCM", iv: nonce },
			prfKey as CryptoKey,
			// PRF暗号化済みRSA秘密鍵のこと
			// 本来はサーバから取得してくる
			prfEncryptedData as ArrayBuffer,
		);
		setPrfDecryptedData(new TextDecoder().decode(decrypted));
	};

	return (
		<div className="min-h-screen bg-gray-100 flex items-center justify-center p-4">
			<div className="bg-white shadow-lg rounded-lg p-6 w-full max-w-md">
				<h2 className="text-2xl font-bold text-center mb-6 text-indigo-600">
					WebAuthnテスト🔐
				</h2>
				<div className="space-y-4">
					<div className="flex flex-col sm:flex-row gap-4">
						<button
							type="button"
							onClick={handleRegister}
							className="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white py-2 px-4 rounded shadow focus:outline-none focus:ring-2 focus:ring-indigo-500"
						>
							パスキー新規登録
						</button>
						<button
							type="button"
							onClick={handleAuthenticate}
							className="flex-1 bg-teal-600 hover:bg-teal-700 text-white py-2 px-4 rounded shadow focus:outline-none focus:ring-2 focus:ring-teal-500"
						>
							パスキーログイン
						</button>
					</div>

					<input
						type="text"
						value={inputText}
						onChange={(e) => setInputText(e.target.value)}
						placeholder="暗号化したいテキストを入力してください"
						className="w-full p-3 border rounded text-gray-800 focus:outline-none focus:ring-2 focus:ring-indigo-500"
					/>

					<div className="flex flex-col sm:flex-row gap-4">
						<button
							type="button"
							onClick={handleRSAEncrypt}
							className="flex-1 bg-purple-600 hover:bg-purple-700 text-white py-2 px-4 rounded shadow focus:outline-none focus:ring-2 focus:ring-purple-500"
						>
							暗号化
						</button>
						<button
							type="button"
							onClick={handleRSADecrypt}
							className="flex-1 bg-yellow-500 hover:bg-yellow-600 text-white py-2 px-4 rounded shadow focus:outline-none focus:ring-2 focus:ring-yellow-400"
						>
							復号化
						</button>
					</div>

					<div className="space-y-4">
						{extensionResults && (
							<div className="bg-gray-50 p-3 rounded border">
								<h3 className="font-semibold text-gray-700 mb-1">
									PRF対応結果:
								</h3>
								<pre className="whitespace-pre-wrap text-sm text-gray-600">
									{extensionResults}
								</pre>
							</div>
						)}
						{registrationResult && (
							<div className="bg-gray-50 p-3 rounded border">
								<h3 className="font-semibold text-gray-700 mb-1">
									登録時の疑似乱数生成結果:
								</h3>
								<details className="whitespace-pre-wrap text-sm text-gray-600">
									{registrationResult}
								</details>
							</div>
						)}
						{signResult && (
							<div className="bg-gray-50 p-3 rounded border">
								<h3 className="font-semibold text-gray-700 mb-1">
									ログイン時の疑似乱数生成結果:
								</h3>
								<details className="whitespace-pre-wrap text-sm text-gray-600">
									{signResult}
								</details>
							</div>
						)}
						{inputText && (
							<div className="bg-gray-50 p-3 rounded border">
								<h3 className="font-semibold text-gray-700 mb-1">暗号化対象</h3>
								<pre className="whitespace-pre-wrap break-words text-sm text-gray-600">
									{inputText}
								</pre>
							</div>
						)}

						{prfEncryptedData && (
							<div className="bg-gray-50 p-3 rounded border">
								<h3 className="font-semibold text-gray-700 mb-1">暗号化結果</h3>
								<pre className="whitespace-pre-wrap break-words text-sm text-gray-600">
									{btoa(
										String.fromCharCode(...new Uint8Array(prfEncryptedData)),
									)}
								</pre>
							</div>
						)}

						{prfDecryptedData && (
							<div className="bg-gray-50 p-3 rounded border">
								<h3 className="font-semibold text-gray-700 mb-1">復号化結果</h3>
								<pre className="whitespace-pre-wrap text-sm text-gray-600">
									{prfDecryptedData}
								</pre>
							</div>
						)}
					</div>
				</div>
			</div>
		</div>
	);
}
