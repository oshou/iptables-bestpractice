#!/bin/bash

# PATH
PATH=/sbin:/usr/sbin:/bin:/usr/bin

#=====(要修正箇所-START)=================================================

######################################################
# IP定義
######################################################

# 全てのIPを表す設定を定義
ANY="0.0.0.0/0"

# 内部ネットワークとして許可する範囲
# **必要に応じてアンコメントアウト**
# LOCAL_NETS=(
#  "xxx.xxx.xxx.xxx"
#  "xxx.xxx.xxx.xxx"
# )

# アクセス許可ホスト(配列) 監視サーバIP等を記載
# **必要に応じてアンコメントアウト**
# ALLOW_HOSTS=(
#  "xxx.xxx.xxx.xxx"
#  "xxx.xxx.xxx.xxx"
#  "xxx.xxx.xxx.xxx"
# )

# アクセス拒否ホスト(配列)
# **必要に応じてアンコメントアウト**
# DENY_HOSTS=(
#  "xxx.xxx.xxx.xxx"
#  "xxx.xxx.xxx.xxx"
#  "xxx.xxx.xxx.xxx"
# )


######################################################
# (要定義)Port定義
######################################################
SSH=22
FTP=20,21
DNS=53
SMTP=25,465,587
POP3=110,995
IMAP=143,993
HTTP=80,443
IDENT=113
NTP=123
MYSQL=3306
NETBIOS=135,137,138,139,445
DHCP=67,68

#=====(要修正箇所-END)===================================================


######################################################
# 関数定義
######################################################
# ルール適用前の初期化
initialize(){
  iptables -F # テーブル初期化
  iptables -X # チェーン解除
  iptables -Z # パケットカウンタ・バイトカウンタをゼロリセット
  iptables -P INPUT ACCEPT # 設定のため一時ポリシー変更
  iptables -P OUTPUT ACCEPT # 設定のため一時ポリシー変更
  iptables -P FORWARD ACCEPT # 設定のため一時ポリシー変更
}

# ルール適用後の反映処理
finalize(){
  /etc/init.d/iptables save &&
  /etc/init.d/iptables restart &&
  return 0
  return 1
}


##################################################################################
# iptablesの初期化
##################################################################################
initialize


##################################################################################
# 基本ポリシーの設定
##################################################################################
# INPUT,FORWARDはホワイトリスト方式で許可,OUTPUTは基本全て許可
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP


##################################################################################
# 信頼できるホストの許可
##################################################################################
# ループバックアドレスの許可
iptables -A INPUT -i lo -j ACCEPT

# ローカルネットワークの許可
if [ "$LOCAL_NETS[@]" != "" ]
then
  for local_net in ${LOCAL_NETS[@]}
  do
    iptables -A INPUT -p tcp -s $local_net -j ACCEPT
  done
fi

# アクセス許可ホストの許可設定
if [ "$ALLOW_HOSTS[@]" != "" ]
then
  for allow_host in ${ALLOW_HOSTS[@]}
  do
    iptables -A INPUT -p tcp -s $allow_host -j ACCEPT
  done
fi

# 確立済のパケット通信は全て許可
iptables -A INPUT -p tcp -m state --state ESTABLISHED,RELATED -j ACCEPT


##################################################################################
# 信頼できないホストの拒否
##################################################################################
# アクセス拒否ホストの拒否設定
if [ "$DENY_HOSTS[@]" != ""  ]
then
  for deny_host in ${DENY_HOSTS[@]}
  do
    iptables -A INPUT -s $deny_host -m limit --limit 1/s -j LOG --log-prefix "deny_hosts: "
    iptables -A INPUT -s $deny_host -j DROP
  done
fi


##################################################################################
# 攻撃対策：StealthScan
##################################################################################
iptables -N STEALTH_SCAN
iptables -A STEALTH_SCAN -j LOG --log-prefix "stealth_scan: "
iptables -A STEALTH_SCAN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j STEALTH_SCAN
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j STEALTH_SCAN


##################################################################################
# 攻撃対策：フラグメントパケットによるポートスキャン、DOS攻撃
##################################################################################
iptables -A INPUT -f -j LOG --log-prefix "fragment_packet: "
iptables -A INPUT -f -j DROP


##################################################################################
# 攻撃対策：Ping of Death
##################################################################################
iptables -N PING_OF_DEATH
iptables -A PING_OF_DEATH -p icmp --icmp-type echo-request \
    -m hashlimit                     \
    --hashlimit 1/s                  \
    --hashlimit-burst 10             \
    --hashlimit-htable-expire 300000 \
    --hashlimit-mode srcip           \
    --hashlimit-name t_PING_OF_DEATH \
    -j RETURN
iptables -A PING_OF_DEATH -j LOG --log-prefix "ping_of_death: "
iptables -A PING_OF_DEATH -j DROP
iptables -A INPUT -p icmp --icmp-type echo-request -j PING_OF_DEATH


##################################################################################
# 攻撃対策：SYN Flood Attack
# * 初回100回は制限無し
# * 101回目以降は1秒間に1回ずつアクセス
# * 接続試行回数は接続元IP毎に区別してカウントされる。
# * 接続試行回数のカウントは5分置きにリセットされる
##################################################################################
iptables -N SYN_FLOOD
iptables -A SYN_FLOOD -p tcp --syn \
    -m hashlimit                     \
    --hashlimit 200/s                \
    --hashlimit-burst 3              \
    --hashlimit-htable-expire 300000 \
    --hashlimit-mode srcip           \
    --hashlimit-name t_SYN_FLOOD     \
    -j RETURN
iptables -A SYN_FLOOD -j LOG --log-prefix "syn_flood: "
iptables -A SYN_FLOOD -j DROP
iptables -A INPUT -p tcp --syn -j SYN_FLOOD


##################################################################################
# 攻撃対策：HTTP Dos/DDos
# * 初回100回は制限無し
# * 101回目以降は1秒間に1回ずつアクセス
# * 接続試行回数は接続元IP毎に区別してカウントされる。
# * 接続試行回数のカウントは5分置きにリセットされる
##################################################################################
iptables -N HTTP_DOS
iptables -A HTTP_DOS -p tcp -m multiport --dports $HTTP \
    -m hashlimit                     \
    --hashlimit 1/s                  \
    --hashlimit-burst 100            \
    --hashlimit-htable-expire 300000 \
    --hashlimit-mode srcip           \
    --hashlimit-name t_HTTP_DOS      \
    -j RETURN
iptables -A HTTP_DOS -j LOG --log-prefix "http_dos: "
iptables -A HTTP_DOS -j DROP
iptables -A INPUT -p tcp -m multiport --dports $HTTP -j HTTP_DOS


##################################################################################
# 攻撃対策：SSH Brute force(パスワード総当り攻撃)
# * パスワード認証使用時に設定
# * 初回10回は制限無し
# * 11回目以降は10秒間に1回ずつアクセス
# * 接続試行回数は接続元IP毎に区別してカウントされる。
# * 接続試行回数のカウントは30分置きにリセットされる
##################################################################################
iptables -N SSH_BRUTE_FORCE
iptables -A SSH_BRUTE_FORCE -p tcp -m multiport --dports $SSH \
    -m hashlimit                        \
    --hashlimit 6/m                     \
    --hashlimit-burst 10                \
    --hashlimit-htable-expire 300000    \
    --hashlimit-mode srcip              \
    --hashlimit-name t_SSH_BF           \
    -j RETURN
iptables -A SSH_BRUTE_FORCE -j LOG --log-prefix "ssh_brute_force: "
iptables -A SSH_BRUTE_FORCE -j REJECT
iptables -A INPUT -p tcp -m multiport --dports $SSH -j SSH_BRUTE_FORCE


##################################################################################
# 攻撃対策：FTP Brute force
# * パスワード認証使用時に設定
# * 初回10回は制限無し
# * 11回目以降は10秒間に1回ずつアクセス
# * 接続試行回数は接続元IP毎に区別してカウントされる。
# * 接続試行回数のカウントは30分置きにリセットされる
##################################################################################
iptables -N FTP_BRUTE_FORCE
iptables -A FTP_BRUTE_FORCE -p tcp -m multiport --dports $FTP \
    -m hashlimit                        \
    --hashlimit 6/m                     \
    --hashlimit-burst 10                \
    --hashlimit-htable-expire 1800000   \
    --hashlimit-mode srcip              \
    --hashlimit-name t_FTP_BF           \
    -j RETURN

iptables -A FTP_BRUTE_FORCE -j LOG --log-prefix "ftp_brute_force: "
iptables -A FTP_BRUTE_FORCE -j REJECT
iptables -A INPUT -p tcp -m multiport --dports $FTP -j FTP_BRUTE_FORCE


##################################################################################
# 攻撃対策：IDENT port probe
##################################################################################
iptables -A INPUT -p tcp -m multiport --dports $IDENT -j REJECT --reject-with tcp-reset


##################################################################################
# 攻撃対策：ブロードキャスト、マルチキャスト宛のパケットの破棄
##################################################################################
iptables -A INPUT -d 192.168.1.255 -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 192.168.1.255 -j DROP
iptables -A INPUT -d 255.255.255.255 -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 255.255.255.255 -j DROP
iptables -A INPUT -d 224.0.0.1 -j LOG --log-prefix "drop_broadcast: "
iptables -A INPUT -d 224.0.0.1 -j DROP


##################################################################################
# 全ホストからの入力許可 ( ANY -> SELF )
##################################################################################

# ICMP
iptables -A INPUT -p icmp -j ACCEPT

# SSH
# **必要に応じてコメントアウト**
iptables -A INPUT -p tcp -m multiport --dports $SSH -j ACCEPT

# FTP
# iptables -A INPUT -p tcp -m multiport --dports $FTP -j ACCEPT

# HTTP,HTTPS
# **必要に応じてアンコメントアウト**
# iptables -A INPUT -p tcp -m multiport --dports $HTTP -j ACCEPT

# DNS
# **必要に応じてアンコメントアウト**
# iptables -A INPUT -p tcp -m multiport --dports $DNS -j ACCEPT

# SMTP
# iptables -A INPUT -p tcp -m multiport --dports $SMTP -j ACCEPT

# POP3
# iptables -A INPUT -p tcp -m multiport --dports $POP3 -j ACCEPT

# IMAP
# iptables -A INPUT -p tcp -m multiport --dports $IMAP -j ACCEPT


##################################################################################
# その他ホストはロギングして破棄
##################################################################################
iptables -A INPUT -j LOG --log-prefix "drop: "
iptables -A INPUT -j DROP


##################################################################################
# SSH締め出し回避策
# * Ctrl+C押下でiptables設定確定
# * Ctrl+C押下しなければ30秒後に設定前の状態へ自動でリセットされる
##################################################################################
trap `finalize && exit 0`
echo "In 60 seconds iptables will be automatically reset."
echo "Don't forget to test new SSH connection!"
echo "If there is no problem then press Ctrl-C to finish."
sleep 30
echo "rollback..."
initialize
