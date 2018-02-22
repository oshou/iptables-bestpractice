## 本レポジトリについて
iptables設定時のテンプレートレポジトリ

## 基本方針
- 対象
  - 新規にiptable設定を行うサーバに対して導入を検討する。
  - 既存で既にiptables適用済の場合は必要部分のみ追加設定を行う。
- ポリシー
  - INPUT,FORWARDは基本拒否(DROP)、必要なものだけ許可する。
  - OUTPUTは基本許可(ACCEPT)
  - 不特定多数にINPUT許可しなければいけない場合はプロトコル単位で許可。HTTP、HTTPS等を想定
- SSHアクセス設定
  - Ansibleサーバ以外のホストから短時間に10回以上の連続アクセスが行われた場合は、接続元IP毎に平均10秒間に1回のアクセス制限をかける。
  - アクセス制限は5分毎に解除される。
- 設定後のSSHアクセス締め出し防止
  - スクリプト実行後に30秒立つと自動でロールバックされる。
  - 確定する場合はCtrl+C
  - スクリプト実行時に旧設定のバックアップが取得されます。新設定確定後に元に戻したい場合は以下手順で復元可能です。
    - $ iptables-restore < バックアップファイル名

## 参考サイト
- http://qiita.com/suin/items/5c4e21fa284497782f71
- http://falsandtru.hatenablog.com/entry/iptables-firewall
