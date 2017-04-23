# iptables-bestpractice

# 基本方針
- ポリシー
  - INPUT,FORWARDは基本拒否、使うものだけ通す
  - OUTPUTは基本防止
  - 不特定多数にINPUT許可しなければ行けない場合はport単位で許可。HTTP、HTTPSを想定。
- 設定時の締め出し防止
  - スクリプト実行後に30秒立つと自動でロールバックする。
  - 確定する場合はCtrl+C。

## 参考サイト
- http://qiita.com/suin/items/5c4e21fa284497782f71
- http://falsandtru.hatenablog.com/entry/iptables-firewall
