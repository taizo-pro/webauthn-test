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
	const [encryptedData, setEncryptedData] = useState<string>("");
	const [decryptedData, setDecryptedData] = useState<string>("");

	// ユーティリティ関数
	const hashToArrayBuffer = async (userId: string) => {
		const data = new TextEncoder().encode(userId);
		const hash = await crypto.subtle.digest("SHA-256", data);
		return hash;
	};

	const prfSalt = new Uint8Array(new Array(32).fill(1)).buffer;

	// パスキー登録
	const handleRegister = async () => {
		const userId = "00000000-0000-0000-0000-000000000001";
		const userIdArrayBuffer = await hashToArrayBuffer(userId);

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

	// パスキー認証と暗号化
	const handleAuthenticate = async () => {
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

			// 暗号化処理
			const nonce = crypto.getRandomValues(new Uint8Array(12));
			const encrypted = await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv: nonce },
				encryptionKey,
				new TextEncoder().encode(inputText),
			);

			// Base64形式で表示用に変換
			const encryptedBase64 = btoa(
				String.fromCharCode(...new Uint8Array(encrypted)),
			);
			setEncryptedData(encryptedBase64);

			// 復号化テスト
			const decrypted = await crypto.subtle.decrypt(
				{ name: "AES-GCM", iv: nonce },
				encryptionKey,
				encrypted,
			);
			setDecryptedData(new TextDecoder().decode(decrypted));
		} catch (err) {
			console.error("認証エラー:", err);
		}
	};

	return (
		<div className="p-4">
			<h2 className="text-xl font-bold mb-4">WebAuthnテスト🔐</h2>
			<div className="space-y-4">
				{/* biome-ignore lint/a11y/useButtonType: <explanation> */}
				<button
					onClick={handleRegister}
					className="bg-blue-500 text-white px-4 py-2 rounded w-full"
				>
					パスキー新規登録
				</button>
				<div className="space-y-2">
					<textarea
						value={inputText}
						onChange={(e) => setInputText(e.target.value)}
						placeholder="暗号化したいテキストを入力してください"
						className="w-full p-2 border rounded text-black"
						rows={3}
					/>
					{/* biome-ignore lint/a11y/useButtonType: <explanation> */}
					<button
						onClick={handleAuthenticate}
						className="bg-green-500 text-white px-4 py-2 rounded w-full"
					>
						パスキーログインと暗号化
					</button>
				</div>

				<div className="flex">
					<div>
						{/* 結果表示エリア */}
						{extensionResults && (
							<div className="mt-4 p-4 rounded">
								<h3 className="font-bold mb-2">PRF対応結果:</h3>
								<pre className="whitespace-pre-wrap">{extensionResults}</pre>
							</div>
						)}

						{registrationResult && (
							<div className="mt-4 p-4 rounded">
								<h3 className="font-bold mb-2">
									登録時の疑似乱数生成結果:
								</h3>
								<pre className="whitespace-pre-wrap">{registrationResult}</pre>
							</div>
						)}
					</div>
					<div>
						{signResult && (
							<div className="mt-4 p-4 rounded">
								<h3 className="font-bold mb-2">
									ログイン時の疑似乱数生成結果:
								</h3>
								<pre className="whitespace-pre-wrap">{signResult}</pre>
							</div>
						)}
						{inputText && (
							<div className="mt-4 p-4 rounded">
								<h3 className="font-bold mb-2">暗号化対象</h3>
								<pre className="whitespace-pre-wrap break-all">{inputText}</pre>
							</div>
						)}

						{encryptedData && (
							<div className="mt-4 p-4 rounded">
								<h3 className="font-bold mb-2">暗号化結果</h3>
								<pre className="whitespace-pre-wrap break-all">
									{encryptedData}
								</pre>
							</div>
						)}

						{decryptedData && (
							<div className="mt-4 p-4 rounded">
								<h3 className="font-bold mb-2">復号化結果</h3>
								<pre className="whitespace-pre-wrap">{decryptedData}</pre>
							</div>
						)}
					</div>
				</div>
			</div>
		</div>
	);
}
