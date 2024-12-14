"use client";

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
			const credential = await navigator.credentials.create({
				publicKey: {
					challenge: new Uint8Array([1]),
					rp: {
						name: "WebAuthn Test",
						id: window.location.hostname,
					},
					user: {
						id: new Uint8Array(userIdArrayBuffer),
						name: "test@example.com",
						displayName: "テストユーザー",
					},
					pubKeyCredParams: [
						{ alg: -8, type: "public-key" },
						{ alg: -7, type: "public-key" },
					],
					authenticatorSelection: {
						userVerification: "required",
					},
					extensions: {
						prf: {
							eval: {
								first: prfSalt,
							},
						},
					},
				},
			});

			console.log("登録成功:", credential);
			const extensionResults = (
				credential as PublicKeyCredential
			)?.getClientExtensionResults();
			console.log("拡張機能の結果:", extensionResults);
		} catch (err) {
			console.error("登録エラー:", err);
		}
	};

	// パスキー認証と暗号化
	const handleAuthenticate = async () => {
		try {
			const authCredential = await navigator.credentials.get({
				publicKey: {
					challenge: new Uint8Array([9, 0, 1, 2]),
					rpId: "localhost",
					userVerification: "required",
					extensions: {
						prf: {
							eval: {
								first: prfSalt,
							},
						},
					},
				},
			});

			// biome-ignore lint/suspicious/noExplicitAny: <explanation>
			const authExtensionResults: any = (
				authCredential as PublicKeyCredential
			).getClientExtensionResults();
			const inputKeyMaterial = new Uint8Array(
				authExtensionResults.prf.results.first,
			);

			// 鍵導出
			const keyDerivationKey = await crypto.subtle.importKey(
				"raw",
				inputKeyMaterial,
				"HKDF",
				false,
				["deriveKey"],
			);

			const label = "encryption key";
			const info = new TextEncoder().encode(label);
			const salt = new Uint8Array();

			const encryptionKey = await crypto.subtle.deriveKey(
				{ name: "HKDF", info, salt, hash: "SHA-256" },
				keyDerivationKey,
				{ name: "AES-GCM", length: 256 },
				false,
				["encrypt", "decrypt"],
			);

			// 暗号化テスト
			const nonce = crypto.getRandomValues(new Uint8Array(12));
			const testData = "テスト秘密データ";
			const encrypted = await crypto.subtle.encrypt(
				{ name: "AES-GCM", iv: nonce },
				encryptionKey,
				new TextEncoder().encode(testData),
			);

			// 復号化テスト
			const decrypted = await crypto.subtle.decrypt(
				{ name: "AES-GCM", iv: nonce },
				encryptionKey,
				encrypted,
			);

			console.log("復号化結果:", new TextDecoder().decode(decrypted));
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
				{/* biome-ignore lint/a11y/useButtonType: <explanation> */}
				<button
					onClick={handleAuthenticate}
					className="bg-green-500 text-white px-4 py-2 rounded w-full"
				>
					パスキーログイン
				</button>
			</div>
		</div>
	);
}
