/**
ユーザー認証のアサーションを検証するAPIエンドポイントが現時点で提供されていないようです。以下に、認証アサーションを検証するファイルの例を示します。
 */

import { type NextRequest, NextResponse } from "next/server";
import * as crypto from "node:crypto";

// 仮のデータストア（実際にはデータベースやセッションストアを使用）
const authenticateChallenges: { [key: string]: string } = {};
// biome-ignore lint/suspicious/noExplicitAny: <explanation>
const userCredentials: { [key: string]: any } = {}; // ユーザーIDごとの認証情報

/**
 * POSTリクエストに応答して、ユーザー認証のアサーションを検証します。
 */
export async function POST(request: NextRequest) {
	const { id, type, clientDataJSON, authenticatorData, signature, userHandle } =
		await request.json();

	// 必要なフィールドが存在するか確認
	if (!id || !type || !clientDataJSON || !authenticatorData || !signature) {
		return NextResponse.json(
			{ success: false, message: "不正なリクエストデータです。" },
			{ status: 400 },
		);
	}

	try {
		// クライアントデータのデコード
		const clientData = Buffer.from(clientDataJSON, "base64url");
		const authenticatorDataBuffer = Buffer.from(authenticatorData, "base64url");
		const signatureBuffer = Buffer.from(signature, "base64url");

		const clientDataJSONParsed = JSON.parse(clientData.toString("utf-8"));

		// クライアントデータタイプの検証
		if (clientDataJSONParsed.type !== "webauthn.get") {
			return NextResponse.json(
				{ success: false, message: "不正なクライアントデータタイプです。" },
				{ status: 400 },
			);
		}

		const userId = userHandle || "unique-user-id"; // 実際のユーザー識別方法を使用

		// チャレンジの検証
		const expectedChallenge = authenticateChallenges[userId];
		if (clientDataJSONParsed.challenge !== expectedChallenge) {
			return NextResponse.json(
				{ success: false, message: "チャレンジが一致しません。" },
				{ status: 400 },
			);
		}

		// 公開鍵の取得
		const publicKey = userCredentials[userId].publicKey; // 実装が必要

		// 署名の検証
		const verify = crypto.createVerify("SHA256");
		verify.update(Buffer.from(clientDataJSON, "base64url"));
		verify.end();
		const isValid = verify.verify(publicKey, signatureBuffer);

		if (isValid) {
			return NextResponse.json({ success: true });
		}

		return NextResponse.json(
			{ success: false, message: "署名の検証に失敗しました。" },
			{ status: 400 },
		);

	} catch (error) {
		console.error("認証アサーションの検証中にエラーが発生しました:", error);
		return NextResponse.json(
			{ success: false, message: "認証アサーションの検証に失敗しました。" },
			{ status: 500 },
		);
	}
}

/*
改善点・注意点:
公開鍵の取得と管理: 実際のアプリケーションでは、ユーザーごとの公開鍵をデータベースから安全に取得する必要があります。
署名の検証: 現在の例では署名の検証を行っていますが、リライングパーティID（RP ID）の確認や、その他のセキュリティチェックも必要です。
チャレンジの管理: 認証用チャレンジがセッションやデータベースに正しく保存されていることを確認し、再利用されないようにします。
*/
