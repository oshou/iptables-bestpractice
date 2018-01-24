#!/bin/bash

##################################################################################
# @@ Define @@
##################################################################################

#--------------------------------------------------------------------------------
# PATH
#--------------------------------------------------------------------------------
PATH=/sbin:/usr/sbin:/bin:/usr/bin


#--------------------------------------------------------------------------------
# Allowed IP
#--------------------------------------------------------------------------------
DNS_SERVER=(
  "xxx.xxx.xxx.xxx"
  "xxx.xxx.xxx.xxx"
)

NTP_SERVER=(
  "xxx.xxx.xxx.xxx"
  "xxx.xxx.xxx.xxx"
)

PROVISION_SERVER=(
  "xxx.xxx.xxx.xxx"
  "xxx.xxx.xxx.xxx"
)

# 内部ネットワークとして許可する範囲
# **必要に応じてアンコメントアウト**
LOCAL_NETS=(
  "xxx.xxx.xxx.xxx/xx"
  "xxx.xxx.xxx.xxx/xx"
  "xxx.xxx.xxx.xxx/xx"
)

# **必要に応じてアンコメントアウト**
# * 監視サーバIP等
WHITE_LIST=(
  "xxx.xxx.xxx.xxx/xx"
  "xxx.xxx.xxx.xxx/xx"
  "xxx.xxx.xxx.xxx/xx"
)

#--------------------------------------------------------------------------------
# Denied IP
#--------------------------------------------------------------------------------
# if necessary Uncomment out
#
# BLACK_LIST=(
#  "xxx.xxx.xxx.xxx"
#  "xxx.xxx.xxx.xxx"
#  "xxx.xxx.xxx.xxx"
# )



#--------------------------------------------------------------------------------
# Port
#--------------------------------------------------------------------------------
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


#--------------------------------------------------------------------------------
# Function
#--------------------------------------------------------------------------------
# backup(): backup iptables config
backup(){
  iptables-save > iptables-`date "+%Y%m%d_%H%M%S"`.bak
  echo 'backup complete! > iptables-`date "+%Y%m%d_%H%M%S"`!'
}

# initialize(): initialize policy setting
initialize(){
  iptables -P INPUT ACCEPT # 設定のため一時ポリシー変更
  iptables -P OUTPUT ACCEPT # 設定のため一時ポリシー変更
  iptables -P FORWARD ACCEPT # 設定のため一時ポリシー変更
  iptables -F # テーブル初期化
  iptables -X # チェーン解除
  iptables -Z # パケットカウンタ・バイトカウンタをゼロリセット
  echo 'iptables initialize complete!'
}

# finalize(): apply new rule
finalize(){
  /etc/init.d/iptables save &&
  /etc/init.d/iptables restart &&
  return 0
  return 1
}


##################################################################################
# @@ Configuration @@
##################################################################################
#--------------------------------------------------------------------------------
# Backup iptables config && Init
#--------------------------------------------------------------------------------
backup
initialize


#--------------------------------------------------------------------------------
# Policy initial setting
# * INPUT,FORWARD : ALL DROP
# * OUTPUT        : ALL ACCEPT
#--------------------------------------------------------------------------------
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP


#--------------------------------------------------------------------------------
# Allow specific IP/network
#--------------------------------------------------------------------------------

# ローカルインターフェースの許可
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i lo -j FORWARD

# セッション確立済パケットの許可
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# ICMPパケット(ping等)の許可
iptables -A INPUT -p icmp -j ACCEPT

# DNSサーバとの通信許可
if [ "$DNS_SERVER[@]" != "" ]
then
  for dnsserver in ${DNS_SERVER[@]}
  do
    iptables -A INPUT -s $dnsserver -p udp -m multiport --dports $DNS -j ACCEPT
    iptables -A FORWARD -s $dnsserver -p udp -m multiport --dports $DNS -j ACCEPT
    iptables -A FORWARD -d $dnsserver -p udp -m multiport --dports $DNS -j ACCEPT
    echo "DNS-SERVER: $dnsserver"
  done
fi

# NTPサーバとの通信許可
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

# プロビジョニングサーバからの通信の許可
if [ "$PROVISION_SERVER[@]" != "" ]
then
  for provisionserver in ${PROVISION_SERVER[@]}
  do
    iptables -A INPUT -s $provisionserver -p tcp -m multiport --dports $SSH -j ACCEPT
    echo "PROVISION-SERVER: $provisionserver"
  done
fi


# ローカルネットワークの許可
# * SSHアクセスは連続アクセスは10回まで許可、超過した場合はIP毎に平均10秒に1回ペースに制限を行う。
# * 連続アクセス上限は5分毎に定期的にリセットを行う。
if [ "$LOCAL_NETS[@]" != "" ]
then
  for local_net in ${LOCAL_NETS[@]}
  do
    iptables -A INPUT -p tcp -s $local_net -m multiport --dports $SSH \
      -m hashlimit                        \
      --hashlimit 6/m                     \
      --hashlimit-burst 10                \
      --hashlimit-htable-expire 300000    \
      --hashlimit-mode srcip              \
      --hashlimit-name t_SSH_BF           \
 	    -j ACCEPT
    iptables -A INPUT -p tcp -s $local_net -m multiport ! --dports $SSH -j ACCEPT
  done
fi

# ホワイトリストIP/ネットワーク帯の通信許可
# * SSHアクセスは連続アクセスは10回まで許可、超過した場合はIP毎に平均10秒に1回ペースに制限を行う。
# * 連続アクセス上限は5分毎に定期的にリセットを行う。
if [ "$WHITE_LIST[@]" != "" ]
then
  for white_list_host in ${WHITE_LIST[@]}
  do
    iptables -A INPUT -p tcp -s $white_list_host -m multiport --dports $SSH \
      -m hashlimit                        \
      --hashlimit 6/m                     \
      --hashlimit-burst 10                \
      --hashlimit-htable-expire 300000    \
      --hashlimit-mode srcip              \
      --hashlimit-name t_SSH_BF           \
      -j ACCEPT
    iptables -A INPUT -p tcp -s $white_list_host -m multiport ! --dports $SSH -j ACCEPT
  done
fi

#--------------------------------------------------------------------------------
# Allow specific protocol to ALL access
# ex) http, https...
#--------------------------------------------------------------------------------
# For HTTP,HTTPS
# iptables -A INPUT -p tcp -m multiport --dports $HTTP -j ACCEPT

# For FTP
# iptables -A INPUT -p tcp -m multiport --dports $FTP -j ACCEPT


#--------------------------------------------------------------------------------
# Deny specific IP/network & deny_logging
#--------------------------------------------------------------------------------
if [ "$BLACK_LIST[@]" != ""  ]
then
  for black_list_host in ${BLACK_LIST[@]}
  do
    iptables -A INPUT -s $black_list_host -m limit --limit 1/s -j LOG --log-prefix "deny_hosts: "
    iptables -A INPUT -s $black_list_host -j DROP
  done
fi


#--------------------------------------------------------------------------------
# Commit
# * Ctrl+C押下で新iptables設定適用完了
# * 押さない場合は30秒経過で過去の設定に自動ロールバック
#--------------------------------------------------------------------------------
trap `finalize && exit 0`
echo "In 30 seconds iptables will be automatically reset."
echo "Don't forget to test new SSH connection!"
echo "If there is no problem then press Ctrl-C to finish."
sleep 30
echo "rollback..."
initialize
