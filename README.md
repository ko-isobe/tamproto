# tamproto

- OTrP (TEEP Protocol)のTAM側の試験実装（HTTP Server)

# 起動方法
## Dockerなし
+ ```npm install```を実行し、必要なnpmパッケージをインストール
+ ```node app.js ```で実行開始
+ Ctrl+Cで終了できます。
## Dockerあり
+ ```docker build -t tamproto .```にてDockerイメージをビルド
+ ```docker run -p 8433:8433 -p 8888:8888 tamproto```でコンテナを起動
+ Ctrl+Cでコンテナから抜けたのち、```docker stop```でコンテナを停止させてください

# APIエンドポイント
- ```http://<Machine HostIP>:8888/api/tam```がAPIエンドポイントです
- 上記URIは、POSTリクエストを受け付け、レスポンスします。
- HTTPは8888ポートで待ち受け、HTTPSは8433ポートで待ち受けます。
- HTTPSに必要な鍵や証明書は``key``ディレクトリに格納されています。
- 現状は下記のように動作します。
-- Bodyを空にしてPOST→ダミーのJSONオブジェクトを返却(TAMの初期化を実施する)
-- Bodyに何かオブジェクトを入れてPOST→空のレスポンスを204で返却

# プログラム構造
- Node.jsのWebフレームワークであるExpressを利用しています
- 上述のAPIは、``routes/apis.js``に実装されています。

# TODOリスト
- TAMのTA管理UI
- TAMの実機能の実装