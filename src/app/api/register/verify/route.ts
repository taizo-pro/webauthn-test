
/**
 * パスキー登録の検証を行うAPIエンドポイントです。クライアントから送信されたアサーション情報を検証し、登録を完了させます。
 */
import { type NextRequest, NextResponse } from "next/server";
import * as crypto from "node:crypto";

// 仮のデータストア（実際にはデータベースやセッションストアを使用）
// biome-ignore lint/suspicious/noExplicitAny: <explanation>
const userCredentials: { [key: string]: any } = {};

/**
 * POSTリクエストに応答して、パスキー登録の検証を行います。
 */
export async function POST(request: NextRequest) {
	const { id, type, clientDataJSON, attestationObject } = await request.json();

	// 必要なフィールドが存在するか確認
	if (!id || !type || !clientDataJSON || !attestationObject) {
		return NextResponse.json(
			{ success: false, message: "不正なリクエストデータです。" },
			{ status: 400 },
		);
	}

	try {
		// クライアントデータのデコード
		const clientData = Buffer.from(clientDataJSON, "base64url");
		// const attestation = Buffer.from(attestationObject, "base64url");

		const clientDataJSONParsed = JSON.parse(clientData.toString("utf-8"));

		// クライアントデータタイプの検証
		if (clientDataJSONParsed.type !== "webauthn.create") {
			return NextResponse.json(
				{ success: false, message: "不正なクライアントデータタイプです。" },
				{ status: 400 },
			);
		}

		// チャレンジの検証（仮）
		// 実際にはセッションやデータベースから保存されたチャレンジを取得して比較します
		const userId = "unique-user-id"; // 実際にはユーザーを特定する方法を使用
		const expectedChallenge = "expected-challenge"; // 保存されたチャレンジ

		if (clientDataJSONParsed.challenge !== expectedChallenge) {
			return NextResponse.json(
				{ success: false, message: "チャレンジが一致しません。" },
				{ status: 400 },
			);
		}

		// アサーションオブジェクトの検証（詳細な実装が必要）
		// - アサーションを解析
		// - 公開鍵を取得
		// - 署名を検証
		// - リライングパーティのIDを確認
		// - 証明書チェーンを検証

		// 仮に成功とみなします
		userCredentials[id] = {
			type,
			attestationObject,
			clientDataJSON,
			// 他の必要な情報を保存
		};

		return NextResponse.json({ success: true });
	} catch (error) {
		console.error("アサーションの検証中にエラーが発生しました:", error);
		return NextResponse.json(
			{ success: false, message: "アサーションの検証に失敗しました。" },
			{ status: 500 },
		);
	}
}

/*
改善点・注意点:
チャレンジの正確な検証: 現在、期待されるチャレンジがハードコードされています。実際には、セッションやデータベースから取得したチャレンジとクライアントから送信されたチャレンジを比較する必要があります。
詳細なアサーションの検証: 署名の検証や公開鍵の登録、証明書チェーンの検証など、セキュリティに直結する詳細な検証が未実装です。これらを適切に実装することで、セキュアな認証が可能になります。
ユーザー管理の強化: ユーザーごとに認証器情報や公開鍵を管理する仕組みを導入する必要があります。
*/