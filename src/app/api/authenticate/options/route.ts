/**
ユーザー認証用のオプションを提供するAPIエンドポイントが現時点で提供されていないようです。以下に、認証オプションを提供するファイルの例を示します。
 */
import { type NextRequest, NextResponse } from "next/server";
import * as crypto from "node:crypto";

// 仮のデータストア（実際にはデータベースやセッションストアを使用）
const authenticateChallenges: { [key: string]: string } = {};
// biome-ignore lint/suspicious/noExplicitAny: <explanation>
const userCredentials: { [key: string]: any } = {}; // ユーザーIDごとの認証情報

/**
 * GETリクエストに応答して、ユーザー認証用のオプションを返します。
 */
export async function GET(request: NextRequest) {
	// ユーザーの特定方法（例としてクエリパラメータを使用）
	const userId = request.nextUrl.searchParams.get("userId");
	if (!userId || !userCredentials[userId]) {
		return NextResponse.json(
			{ success: false, message: "ユーザーが見つかりません。" },
			{ status: 400 },
		);
	}

	// ランダムなチャレンジを生成
	const challenge = crypto.randomBytes(32);

	// 認証オプションの作成
	const authenticationOptions = {
		challenge: challenge.toString("base64url"),
		timeout: 60000,
		// biome-ignore lint/suspicious/noExplicitAny: <explanation>
		allowCredentials: userCredentials[userId].credentials.map((cred: any) => ({
			type: "public-key",
			id: cred.id,
		})),
		userVerification: "required",
	};

	// チャレンジを保存（検証時に使用）
	authenticateChallenges[userId] = challenge.toString("base64url");

	return NextResponse.json(authenticationOptions);
}
