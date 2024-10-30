// registerOptions.ts

import type { NextApiRequest, NextApiResponse } from "next";
import * as crypto from "crypto";

export default function handler(req: NextApiRequest, res: NextApiResponse) {
	if (req.method === "GET") {
		// ランダムなチャレンジを生成
		const challenge = crypto.randomBytes(32).toString("base64");

		// セッションやデータベースにチャレンジを保存（後続の検証で使用）
		// ここでは簡略化のため省略します

		res.status(200).json({
			challenge: Buffer.from(challenge, "base64"),
			rp: {
				name: "Your App Name",
			},
			user: {
				id: Buffer.from("unique-user-id"),
				name: "user@example.com",
				displayName: "User Example",
			},
			pubKeyCredParams: [
				{
					type: "public-key",
					alg: -7, // "ES256" algorithm
				},
			],
			timeout: 60000,
			attestation: "none",
		});
	} else {
		res.status(405).end(); // Method Not Allowed
	}
}
