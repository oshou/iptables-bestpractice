#!/bin/bash

##################################################################################
# @@ Definition @@                                                               #
##################################################################################

#--------------------------------------------------------------------------------#
# PATH                                                                           #
#--------------------------------------------------------------------------------#
PATH=/sbin:/usr/sbin:/bin:/usr/bin


#--------------------------------------------------------------------------------#
# Allowed IP                                                                     #
#--------------------------------------------------------------------------------#
# ex) allow all port
LOCAL_NETS=(
  "xxx.xxx.xxx.xxx/xx"
  "xxx.xxx.xxx.xxx/xx"
  "xxx.xxx.xxx.xxx/xx"
)

# ex) allow ssh access server, monitoring server...
WHITE_LIST=(
  "xxx.xxx.xxx.xxx/xx"
  "xxx.xxx.xxx.xxx/xx"
  "xxx.xxx.xxx.xxx/xx"
)
DNS_SERVER=(
  "xxx.xxx.xxx.xxx/xx"
  "xxx.xxx.xxx.xxx/xx"
)

NTP_SERVER=(
  "xxx.xxx.xxx.xxx/xx"
  "xxx.xxx.xxx.xxx/xx"
)

PROVISION_SERVER=(
  "xxx.xxx.xxx.xxx/xx"
  "xxx.xxx.xxx.xxx/xx"
)


#--------------------------------------------------------------------------------#
# Denied IP                                                                      #
#--------------------------------------------------------------------------------#
# if necessary Uncomment out
#
# BLACK_LIST=(
#  "xxx.xxx.xxx.xxx/xx"
#  "xxx.xxx.xxx.xxx/xx"
#  "xxx.xxx.xxx.xxx/xx"
# )


#--------------------------------------------------------------------------------#
# Port                                                                           #
#--------------------------------------------------------------------------------#
SSH=22
FTP_DATA=20
FTP_CONTROL=21
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

#--------------------------------------------------------------------------------#
# Role                                                                           #
#--------------------------------------------------------------------------------#
IS_ENABLE_HTTP=true
IS_ENABLE_FTP=true

#--------------------------------------------------------------------------------#
# Function                                                                       #
#--------------------------------------------------------------------------------#
# backup(): backup iptables config
backup(){
  iptables-save > iptables-`date "+%Y%m%d_%H%M%S"`.bak
  echo 'backup complete! > iptables-`date "+%Y%m%d_%H%M%S"`!'
}

# initialize(): initialize policy setting
initialize(){
  # All policy initialize(all access)
  iptables -P INPUT ACCEPT
  iptables -P OUTPUT ACCEPT
  iptables -P FORWARD ACCEPT

  # All table initialize
  iptables -F

  # All chain initialize
  iptables -X

  # Reset Transfer Counter(Packet, Byte)
  iptables -Z

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
# @@ Configuration @@                                                            #
##################################################################################
#--------------------------------------------------------------------------------#
# Backup iptables config && Init                                                 #
#--------------------------------------------------------------------------------#
backup
initialize


#--------------------------------------------------------------------------------#
# Policy initial setting                                                         #
# * INPUT,FORWARD : ALL DROP                                                     #
# * OUTPUT        : ALL ACCEPT                                                   #
#--------------------------------------------------------------------------------#
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP


#--------------------------------------------------------------------------------#
# Allow specific IP/network                                                      #
#--------------------------------------------------------------------------------#
# Local Interface Access
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -i lo -j FORWARD

# Established Access
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# ICMP access
iptables -A INPUT -p icmp -j ACCEPT


# Local access (all ports)
if [ "$LOCAL_NETS[@]" != "" ]
then
  for local_net in ${LOCAL_NETS[@]}
  do
    iptables -A INPUT -s $local_net -j ACCEPT
  done
fi


# White List Access(all ports)
# * SSH port: 連続アクセスは10回まで許可、超過した場合はIP毎に平均10秒に1回ペースに制限を行う。連続アクセス上限は5分毎に定期的にリセットを行う。
# * Other   : 全許可、制限無し
if [ "$WHITE_LIST[@]" != "" ]
then
  for white_list_host in ${WHITE_LIST[@]}
  do
    # ssh port
    iptables -A INPUT -p tcp -s $white_list_host -m multiport --dports $SSH \
      -m hashlimit                        \
      --hashlimit 6/m                     \
      --hashlimit-burst 10                \
      --hashlimit-htable-expire 300000    \
      --hashlimit-mode srcip              \
      --hashlimit-name t_SSH_BF           \
      -j ACCEPT
    # other
    iptables -A INPUT -s $white_list_host -m multiport ! --dports $SSH -j ACCEPT
  done
fi

# DNS access
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

# NTP access
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

# Provisioning access
if [ "$PROVISION_SERVER[@]" != "" ]
then
  for provisionserver in ${PROVISION_SERVER[@]}
  do
    iptables -A INPUT -s $provisionserver -p tcp -m multiport --dports $SSH -j ACCEPT
    echo "PROVISION-SERVER: $provisionserver"
  done
fi


#--------------------------------------------------------------------------------#
# Allow specific protocol to ALL access                                          #
# ex) http, https...                                                             #
#--------------------------------------------------------------------------------#
# For HTTP
if [ $IS_ENABLE_HTTP ]; then
  iptables -A INPUT -p tcp -m multiport --dports $HTTP -j ACCEPT
fi

# For FTP
if [ $IS_ENABLE_FTP ]; then
  iptables -A INPUT -p tcp -m multiport --dports $FTP_DATA,$FTP_CONTROL -j ACCEPT
fi


#--------------------------------------------------------------------------------#
# Deny specific IP/network & deny_logging                                        #
#--------------------------------------------------------------------------------#
if [ "$BLACK_LIST[@]" != "" ]
then
  for black_list_host in ${BLACK_LIST[@]}
  do
    iptables -A INPUT -s $black_list_host -m limit --limit 1/s -j LOG --log-prefix "deny_hosts: "
    iptables -A INPUT -s $black_list_host -j DROP
  done
fi


#--------------------------------------------------------------------------------#
# Commit                                                                         #
# * Ctrl+C              --> itpables config apply                                #
# * No reaction for 30s --> iptables config rollback                             #
#--------------------------------------------------------------------------------#
trap `finalize && exit 0`
echo "In 30 seconds iptables will be automatically reset."
echo "Don't forget to test new SSH connection!"
echo "If there is no problem then press Ctrl-C to finish."
sleep 30
echo "rollback..."
initialize
