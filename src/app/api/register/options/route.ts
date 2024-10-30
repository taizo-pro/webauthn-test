/*
パスキー登録用のオプションを提供するAPIエンドポイントです。
クライアントからの登録リクエストに対して、必要な登録オプションを生成して返します
*/

import { type NextRequest, NextResponse } from "next/server";
import * as crypto from "node:crypto";

// 仮のデータストア（実際にはデータベースやセッションストアを使用）
const registerChallenges: { [key: string]: string } = {};

/**
 * GETリクエストに応答して、パスキー登録用のオプションを返します。
 */
export async function GET(request: NextRequest) {
	// ランダムなチャレンジを生成
	const challenge = crypto.randomBytes(32);

	// ユーザーIDを生成または取得（例として固定値を使用）
	const userId = crypto.randomBytes(16);

	// ユーザー情報の設定（実際には認証システムと連携）
	const user = {
		id: userId.toString("base64url"),
		name: "user@example.com",
		displayName: "User Example",
	};

	// WebAuthn登録オプションの作成
	const registerOptions = {
		challenge: challenge.toString("base64url"),
		rp: {
			name: "Your App Name",
		},
		user: user,
		pubKeyCredParams: [
			{
				type: "public-key",
				alg: -7, // "ES256" algorithm
			},
		],
		timeout: 60000,
		attestation: "none",
	};

	// チャレンジを保存（認証時に検証）
	registerChallenges[user.id] = challenge.toString("base64url");

	return NextResponse.json(registerOptions);
}

/*
改善点・注意点:
チャレンジの保存: 現在、チャレンジはメモリ内に保存されています。実際のアプリケーションでは、セッションストアやデータベースに保存し、ユーザーごとに管理する必要があります。
ユーザーIDの生成方法: 固定値を使用していますが、実際には認証システムと連携して動的にユーザーIDを管理します。
*/