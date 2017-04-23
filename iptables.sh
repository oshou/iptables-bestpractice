#!/bin/bash

##################################################################################
# PATH定義
##################################################################################
PATH=/sbin:/usr/sbin:/bin:/usr/bin


##################################################################################
# IP定義
##################################################################################

# 内部ネットワークとして許可する範囲
# **必要に応じてアンコメントアウト**
LOCAL_NETS=(
  "xxx.xxx.xxx.xxx"
  "xxx.xxx.xxx.xxx"
  "xxx.xxx.xxx.xxx"
)

DNS_SERVER=(
  "xxx.xxx.xxx.xxx"
  "xxx.xxx.xxx.xxx"
)

NTP_SERVER=(
  "xxx.xxx.xxx.xxx"
  "xxx.xxx.xxx.xxx"
)

# ホワイトリスト (アクセス無条件許可)
# **必要に応じてアンコメントアウト**
# * 監視サーバIP等
WHITE_LIST=(
  "xxx.xxx.xxx.xxx"
  "xxx.xxx.xxx.xxx"
  "xxx.xxx.xxx.xxx"
)

# ブラックリスト (アクセス無条件拒否)
# **必要に応じてアンコメントアウト**
# BLACK_LIST=(
#  "xxx.xxx.xxx.xxx"
#  "xxx.xxx.xxx.xxx"
#  "xxx.xxx.xxx.xxx"
# )



##################################################################################
# Port定義
##################################################################################
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


##################################################################################
# 関数定義
##################################################################################

# 初期化前の初回バックアップ
backup(){
  iptables-save > iptables-`date "+%Y%m%d_%H%M%S"`.bak
  echo 'backup complete! > iptables-`date "+%Y%m%d_%H%M%S"`!'
}

# ルール適用前の初期化
initialize(){
  iptables -P INPUT ACCEPT # 設定のため一時ポリシー変更
  iptables -P OUTPUT ACCEPT # 設定のため一時ポリシー変更
  iptables -P FORWARD ACCEPT # 設定のため一時ポリシー変更
  iptables -F # テーブル初期化
  iptables -X # チェーン解除
  iptables -Z # パケットカウンタ・バイトカウンタをゼロリセット
  echo 'iptables initialize complete!'
}

# ルール適用後の反映処理
finalize(){
  /etc/init.d/iptables save &&
  /etc/init.d/iptables restart &&
  return 0
  return 1
}


##################################################################################
# iptablesのバックアップ & 初期化
##################################################################################
backup
initialize


##################################################################################
# 基本ポリシーの設定
# * INPUT,FORWARDはホワイトリスト方式で許可,OUTPUTは基本全て許可
##################################################################################
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP


##################################################################################
# 無条件許可する通信の設定
##################################################################################

# ループバックアドレスの許可
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i lo -j FORWARD

# セッション確立後のパケット疎通は許可
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# DNSサーバとの通信
if [ "$DNS_SERVER[@]" != "" ]
then
  for dnsserver in ${NAME_SERVER[@]}
  do
    iptables -A INPUT -s $dnsserver -p udp -m multiport --dports $DNS -j ACCEPT
    iptables -A FORWARD -s $dnsserver -p udp -m multiport --dports $DNS -j ACCEPT
    iptables -A FORWARD -d $dnsserver -p udp -m multiport --dports $DNS -j ACCEPT
    echo "DNS-SERVER: $dnsserver"
  done
fi

# NTPサーバとの通信
if [ "$NTP_SERVER[@]" != "" ]
then
  for ntpserver in ${NTP_SERVER[@]}
  do
    iptables -A INPUT -s $ntpserver -p udp -m multiport --dports $NTP -j ACCEPT
    iptables -A FORWARD -s $ntpserver -p udp -m multiport --dports $NTP -j ACCEPT
    iptables -A FORWARD -d $ntpserver -p udp -m multiport --dports $NTP -j ACCEPT
    echo "NTP-SERVER: $ntpserver"
  done
fi

# 外部とのicmp通信
iptables -A INPUT -p icmp -j ACCEPT

# ローカルネットワークの許可
if [ "$LOCAL_NETS[@]" != "" ]
then
  for local_net in ${LOCAL_NETS[@]}
  do
    iptables -A INPUT -p tcp -s $local_net -m multiport --dport $SSH \
      -m hashlimit                        \
      --hashlimit 6/m                     \
      --hashlimit-burst 10                \
      --hashlimit-htable-expire 300000    \
      --hashlimit-mode srcip              \
      --hashlimit-name t_SSH_BF           \
 	    -j ACCEPT
    iptables -A INPUT -p tcp -s $local_net -m multiport ! --dport $SSH -j ACCEPT
  done
fi

# アクセス許可ホストの許可設定
if [ "$WHITE_LIST[@]" != "" ]
then
  for white_list_host in ${WHITE_LIST[@]}
  do
    iptables -A INPUT -p tcp -s $white_list_host -m multiport --dport $SSH \
      -m hashlimit                        \
      --hashlimit 6/m                     \
      --hashlimit-burst 10                \
      --hashlimit-htable-expire 300000    \
      --hashlimit-mode srcip              \
      --hashlimit-name t_SSH_BF           \
      -j ACCEPT
    iptables -A INPUT -p tcp -s $white_list_host -m multiport ! --dport $SSH -j ACCEPT
  done
fi


##################################################################################
# 無条件拒否する通信の設定
##################################################################################
# アクセス拒否ホストの拒否設定
if [ "$BLACK_LIST[@]" != ""  ]
then
  for black_list_host in ${BLACK_LIST[@]}
  do
    iptables -A INPUT -s $black_list_host -m limit --limit 1/s -j LOG --log-prefix "deny_hosts: "
    iptables -A INPUT -s $black_list_host -j DROP
  done
fi

##################################################################################
# 条件付き許可通信の設定
##################################################################################
# (ALL-ACCESS) HTTP,HTTPS
# **必要に応じてアンコメントアウト**
# iptables -A INPUT -p tcp -m multiport --dports $HTTP -j ACCEPT


##################################################################################
# SSH締め出し回避策
# * Ctrl+C押下でiptables設定確定
# * Ctrl+C押下しなければ30秒後に設定前の状態へ自動でリセットされる
##################################################################################
trap `finalize && exit 0`
echo "In 30 seconds iptables will be automatically reset."
echo "Don't forget to test new SSH connection!"
echo "If there is no problem then press Ctrl-C to finish."
sleep 30
echo "rollback..."
initialize
