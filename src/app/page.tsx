"use client";

export default function Home() {
	return (
		<div className="p-4">
			<h2 className="text-xl font-bold mb-4">WebAuthnテスト🔐</h2>
			<div className="space-y-4">
				<button className="bg-blue-500 text-white px-4 py-2 rounded w-full">
					パスキー新規登録
				</button>
				<button className="bg-green-500 text-white px-4 py-2 rounded w-full">
					パスキーログイン
				</button>
			</div>
		</div>
	);
}
