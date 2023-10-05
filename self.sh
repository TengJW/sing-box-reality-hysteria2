#!/bin/bash

# Function to print characters with delay
print_with_delay() {
    text="$1"
    delay="$2"
    for ((i = 0; i < ${#text}; i++)); do
        echo -n "${text:$i:1}"
        sleep $delay
    done
    echo
}
#notice
show_notice() {
    local message="$1"

    echo "#######################################################################################################################"
    echo "                                                                                                                       "
    echo "                                ${message}                                                                             "
    echo "                                                                                                                       "
    echo "#######################################################################################################################"
}
# Introduction animation
print_with_delay "sing-reality-hy2-wss-box by 绵阿羊" 0.05
echo ""
echo ""
# install base
install_base(){
  # Check if jq is installed, and install it if not
  if ! command -v jq &> /dev/null; then
      echo "jq is not installed. Installing..."
      if [ -n "$(command -v apt)" ]; then
          apt update > /dev/null 2>&1
          apt install -y jq > /dev/null 2>&1
      elif [ -n "$(command -v yum)" ]; then
          yum install -y epel-release
          yum install -y jq
      elif [ -n "$(command -v dnf)" ]; then
          dnf install -y jq
      else
          echo "Cannot install jq. Please install jq manually and rerun the script."
          exit 1
      fi
  fi
}
# regenrate cloudflaed argo
regenarte_cloudflaed_argo(){
  pid=$(pgrep -f cloudflaed)
  if [ -n "$pid" ]; then
    # 终止进程
    kill "$pid"
  fi

  vmess_port=$(jq -r '.inbounds[2].listen_port' /root/sbox/sbconfig_server.json)
  #生成地址
  /root/sbox/cloudflaed-linux tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version auto --protocol h2mux>argo.log 2>&1 &
  sleep 2
  clear
  echo 等待cloudflare argo生成地址
  sleep 5
  #连接到域名
  argo=$(cat argo.log | grep trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')
  echo "$argo" | base64 > /root/sbox/argo.txt.b64
  rm -rf argo.log

  }
# download singbox and cloudflaed
download_singbox(){
  arch=$(uname -m)
  echo "Architecture: $arch"
  # Map architecture names
  case ${arch} in
      x86_64)
          arch="amd64"
          ;;
      aarch64)
          arch="arm64"
          ;;
      armv7l)
          arch="armv7"
          ;;
  esac
  # Fetch the latest (including pre-releases) release version number from GitHub API
  # 正式版
  #latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | grep -Po '"tag_name": "\K.*?(?=")' | head -n 1)
  #beta版本
  latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | grep -Po '"tag_name": "\K.*?(?=")' | sort -V | tail -n 1)
  latest_version=${latest_version_tag#v}  # Remove 'v' prefix from version number
  echo "Latest version: $latest_version"
  # Detect server architecture
  # Prepare package names
  package_name="sing-box-${latest_version}-linux-${arch}"
  # Prepare download URL
  url="https://github.com/SagerNet/sing-box/releases/download/${latest_version_tag}/${package_name}.tar.gz"
  # Download the latest release package (.tar.gz) from GitHub
  curl -sLo "/root/${package_name}.tar.gz" "$url"

  # Extract the package and move the binary to /root
  tar -xzf "/root/${package_name}.tar.gz" -C /root
  mv "/root/${package_name}/sing-box" /root/sbox

  # Cleanup the package
  rm -r "/root/${package_name}.tar.gz" "/root/${package_name}"

  # Set the permissions
  chown root:root /root/sbox/sing-box
  chmod +x /root/sbox/sing-box
}

# download singbox and cloudflaed
download_cloudflaed(){
  arch=$(uname -m)
  # Map architecture names
  case ${arch} in
      x86_64)
          cf_arch="amd64"
          ;;
      aarch64)
          cf_arch="arm64"
          ;;
      armv7l)
          cf_arch="arm"
          ;;
  esac

  # install cloudflaed linux
  cf_url="https://github.com/cloudflare/cloudflaed/releases/latest/download/cloudflaed-linux-${cf_arch}"
  curl -sLo "/root/sbox/cloudflaed-linux" "$cf_url"
  chmod +x /root/sbox/cloudflaed-linux
  echo ""
}


# client configuration
show_client_configuration() {
  hasdomain=$(cat /root/sbox/hasdomain.log)
  if [[ $hasdomain -eq 1 ]]; then
    if [[ -f /root/sbox/cert/cert.pem && -f /root/sbox/cert/private.key ]] && [[ -s /root/sbox/cert/cert.pem && -s /root/sbox/cert/private.key ]] && [[ -f /root/sbox/cert/ca.log ]]; then
      server_name=$(cat /root/sbox/cert/ca.log)
      insecure=0
      bool_insecure=false
    fi
  else
    if [[ -f /root/sbox/self-cert/cert.pem && -f /root/sbox/self-cert/private.key ]] && [[ -s /root/sbox/self-cert/cert.pem && -s /root/sbox/self-cert/private.key ]] && [[ -f /root/sbox/self-cert/ca.log ]]; then
      server_name=$(cat /root/sbox/self-cert/ca.log)
      insecure=1
      bool_insecure=true
    fi
  fi
  current listen port
  current_listen_port=$(jq -r '.inbounds[0].listen_port' /root/sbox/sbconfig_server.json)
  # Get current server name
  current_server_name=$(jq -r '.inbounds[0].tls.server_name' /root/sbox/sbconfig_server.json)
  # Get the UUID
  uuid=$(jq -r '.inbounds[0].users[0].uuid' /root/sbox/sbconfig_server.json)
  # Get the public key from the file, decoding it from base64
  public_key=$(base64 --decode /root/sbox/public.key.b64)
  # Get the short ID
  short_id=$(jq -r '.inbounds[0].tls.reality.short_id[0]' /root/sbox/sbconfig_server.json)
  # Retrieve the server IP address
  server_ip=$(curl -s4m8 ip.sb -k) || server_ip=$(curl -s6m8 ip.sb -k)
  echo ""
  echo ""
  show_notice "Reality 客户端通用链接" 
  echo ""
  echo ""
  server_link="vless://$uuid@$server_ip:$current_listen_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$current_server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#SING-BOX-Reality"
  echo ""
  echo ""
  echo "$server_link"
  echo ""
  echo ""
  # Print the server details
  show_notice "Reality 客户端通用参数" 
  echo ""
  echo ""
  echo "服务器ip: $server_ip"
  echo "监听端口: $current_listen_port"
  echo "UUID: $uuid"
  echo "域名SNI: $current_server_name"
  echo "Public Key: $public_key"
  echo "Short ID: $short_id"
  echo ""
  echo ""
  # Get current listen port
  hy_current_listen_port=$(jq -r '.inbounds[1].listen_port' /root/sbox/sbconfig_server.json)
  # Get current server name
  #hy_current_server_name=$(openssl x509 -in /root/sbox/self-cert/cert.pem -noout -subject -nameopt RFC2253 | awk -F'=' '{print $NF}')

  hy_current_server_name=$server_name
  # Get the password
  hy_password=$(jq -r '.inbounds[1].users[0].password' /root/sbox/sbconfig_server.json)
  # Generate the link
  
  hy2_server_link="hysteria2://$hy_password@$server_ip:$hy_current_listen_port?insecure=$insecure&sni=$hy_current_server_name"

  show_notice "Hysteria2 客户端通用链接" 
  echo ""
  echo "官方 hysteria2通用链接格式"
  echo ""
  echo "$hy2_server_link"
  echo ""
  echo ""   
  # Print the server details
  show_notice "Hysteria2 客户端通用参数" 
  echo ""
  echo ""  
  echo "服务器ip: $server_ip"
  echo "端口号: $hy_current_listen_port"
  echo "password: $hy_password"
  echo "域名SNI: $hy_current_server_name"
  echo "跳过证书验证: $bool_insecure"
  echo ""
  echo ""
  show_notice "Hysteria2 客户端yaml文件" 
cat << EOF

server: $server_ip:$hy_current_listen_port

auth: $hy_password

tls:
  sni: $hy_current_server_name
  insecure: $bool_insecure

# 可自己修改对应带宽，不添加则默认为bbr，否则使用hy2的brutal拥塞控制
# bandwidth:
#   up: 100 mbps
#   down: 100 mbps

fastOpen: true

socks5:
  listen: 127.0.0.1:50000

EOF

  
  vmess_uuid=$(jq -r '.inbounds[2].users[0].uuid' /root/sbox/sbconfig_server.json)
  ws_path=$(jq -r '.inbounds[2].transport.path' /root/sbox/sbconfig_server.json)
  if [[ $hasdomain -eq 1 ]]; then
    argo=$server_name
  else
    argo=$(base64 --decode /root/sbox/argo.txt.b64)
  fi

  show_notice "vmess ws 通用链接参数" 
  echo ""
  echo ""
  echo "以下为vmess链接，替换speed.cloudflare.com为自己的优选ip可获得极致体验,注意wss和ws早已过时，如果不套cdn不建议使用"
  echo ""
  echo ""
  echo 'vmess://'$(echo '{"add":"speed.cloudflare.com","aid":"0","host":"'$argo'","id":"'$vmess_uuid'","net":"ws","path":"'$ws_path'","port":"443","ps":"sing-box-vmess-tls","tls":"tls","type":"none","v":"2"}' | base64 -w 0)
  echo ""
  echo ""
  echo -e "端口 443 可改为 2053 2083 2087 2096 8443"
  echo ""
  echo ""
  echo 'vmess://'$(echo '{"add":"speed.cloudflare.com","aid":"0","host":"'$argo'","id":"'$vmess_uuid'","net":"ws","path":"'$ws_path'","port":"80","ps":"sing-box-vmess","tls":"","type":"none","v":"2"}' | base64 -w 0)
  echo ""
  echo ""
  echo -e "端口 80 可改为 8080 8880 2052 2082 2086 2095" 
  echo ""
  echo ""
  show_notice "clash-meta配置参数"
cat << EOF

port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
ipv6: true
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:        
  - name: Reality
    type: vless
    server: $server_ip
    port: $current_listen_port
    uuid: $uuid
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: $current_server_name
    client-fingerprint: chrome
    reality-opts:
      public-key: $public_key
      short-id: $short_id

  - name: Hysteria2
    type: hysteria2
    server: $server_ip
    port: $hy_current_listen_port
    #  up和down均不写或为0则使用BBR流控
    # up: "30 Mbps" # 若不写单位，默认为 Mbps
    # down: "200 Mbps" # 若不写单位，默认为 Mbps
    password: $hy_password
    sni: $hy_current_server_name
    skip-cert-verify: $bool_insecure
    alpn:
      - h3
  - name: Vmess
    type: vmess
    server: speed.cloudflare.com
    port: 443
    uuid: $vmess_uuid
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    client-fingerprint: chrome  
    skip-cert-verify: true
    servername: $argo
    network: ws
    ws-opts:
      path: $ws_path
      headers:
        Host: $argo

proxy-groups:
  - name: 节点选择
    type: select
    proxies:
      - 自动选择
      - Reality
      - Hysteria2
      - Vmess
      - DIRECT

  - name: 自动选择
    type: url-test #选出延迟最低的机场节点
    proxies:
      - Reality
      - Hysteria2
      - Vmess
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50


rules:
    - GEOIP,LAN,DIRECT
    - GEOIP,CN,DIRECT
    - MATCH,节点选择

EOF

show_notice "sing-box客户端配置参数"
cat << EOF
{
    "dns": {
        "servers": [
            {
                "tag": "remote",
                "address": "https://1.1.1.1/dns-query",
                "detour": "select"
            },
            {
                "tag": "local",
                "address": "https://223.5.5.5/dns-query",
                "detour": "direct"
            },
            {
                "address": "rcode://success",
                "tag": "block"
            }
        ],
        "rules": [
            {
                "outbound": [
                    "any"
                ],
                "server": "local"
            },
            {
                "disable_cache": true,
                "geosite": [
                    "category-ads-all"
                ],
                "server": "block"
            },
            {
                "clash_mode": "global",
                "server": "remote"
            },
            {
                "clash_mode": "direct",
                "server": "local"
            },
            {
                "geosite": "cn",
                "server": "local"
            }
        ],
        "strategy": "prefer_ipv4"
    },
    "inbounds": [
        {
            "type": "tun",
            "inet4_address": "172.19.0.1/30",
            "inet6_address": "2001:0470:f9da:fdfa::1/64",
            "sniff": true,
            "sniff_override_destination": true,
            "domain_strategy": "prefer_ipv4",
            "stack": "mixed",
            "strict_route": true,
            "mtu": 9000,
            "endpoint_independent_nat": true,
            "auto_route": true
        },
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "sniff": true,
            "sniff_override_destination": true,
            "domain_strategy": "prefer_ipv4",
            "listen_port": 2333,
            "users": []
        },
        {
            "type": "mixed",
            "tag": "mixed-in",
            "sniff": true,
            "sniff_override_destination": true,
            "domain_strategy": "prefer_ipv4",
            "listen": "127.0.0.1",
            "listen_port": 2334,
            "users": []
        }
    ],
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "secret": "",
      "store_selected": true
    }
  },
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "outbounds": [
    {
      "tag": "select",
      "type": "selector",
      "default": "urltest",
      "outbounds": [
        "urltest",
        "sing-box-reality",
        "sing-box-hysteria2",
        "sing-box-vmess"
      ]
    },
    {
      "type": "vless",
      "tag": "sing-box-reality",
      "uuid": "$uuid",
      "flow": "xtls-rprx-vision",
      "packet_encoding": "xudp",
      "server": "$server_ip",
      "server_port": $current_listen_port,
      "tls": {
        "enabled": true,
        "server_name": "$current_server_name",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "$public_key",
          "short_id": "$short_id"
        }
      }
    },
    {
            "type": "hysteria2",
            "server": "$server_ip",
            "server_port": $hy_current_listen_port,
            "tag": "sing-box-hysteria2",
            
            "up_mbps": 100,
            "down_mbps": 100,
            "password": "$hy_password",
            "tls": {
                "enabled": true,
                "server_name": "$hy_current_server_name",
                "insecure": $bool_insecure,
                "alpn": [
                    "h3"
                ]
            }
        },
        {
            "server": "speed.cloudflare.com",
            "server_port": 443,
            "tag": "sing-box-vmess",
            "tls": {
                "enabled": true,
                "server_name": "$argo",
                "insecure": true,
                "utls": {
                    "enabled": true,
                    "fingerprint": "chrome"
                }
            },
            "transport": {
                "headers": {
                    "Host": [
                        "$argo"
                    ]
                },
                "path": "$ws_path",
                "type": "ws"
            },
            "type": "vmess",
            "security": "auto",
            "uuid": "$vmess_uuid"
        },
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "block",
      "type": "block"
    },
    {
      "tag": "dns-out",
      "type": "dns"
    },
    {
      "tag": "urltest",
      "type": "urltest",
      "outbounds": [
        "sing-box-reality",
        "sing-box-hysteria2",
        "sing-box-vmess"
      ]
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {
        "geosite": "category-ads-all",
        "outbound": "block"
      },
      {
        "outbound": "dns-out",
        "protocol": "dns"
      },
      {
        "clash_mode": "direct",
        "outbound": "direct"
      },
      {
        "clash_mode": "global",
        "outbound": "select"
      },
      {
        "geoip": [
          "cn",
          "private"
        ],
        "outbound": "direct"
      },
      {
        "geosite": "geolocation-!cn",
        "outbound": "select"
      },
      {
        "geosite": "cn",
        "outbound": "direct"
      }
    ],
    "geoip": {
            "download_detour": "select"
        },
    "geosite": {
            "download_detour": "select"
        }
  }
}
EOF

}
#卸载全部配件
uninstall_singbox() {

          # Stop and disable sing-box service
          systemctl stop sing-box
          systemctl disable sing-box > /dev/null 2>&1

          # Remove files
          rm /etc/systemd/system/sing-box.service
          rm /root/sbox/sbconfig_server.json
          rm /root/sbox/sing-box
          rm /root/sbox/cloudflaed-linux
          rm /root/sbox/argo.txt.b64
          rm /root/sbox/public.key.b64
          rm /root/sbox/self-cert/private.key
          rm /root/sbox/self-cert/cert.pem
          rm -rf /root/sbox/self-cert/
          rm -rf /root/sbox/

          #卸载nginx
          bash <(curl -Ls https://raw.githubusercontent.com/vveg26/myself/main/BashScript/nginx-onekey/ngx.sh) --install

          #删除证书
          rm /root/sbox/cert/private.key
          rm /root/sbox/cert/cert.pem
          rm /root/sbox/cert/ca.log
          rm -rf /root/sbox/cert/

          echo "DONE!"
}

# 选择是否拥有域名
has_domain() {
  echo "请选择一个选项："
  echo "1. 【默认】我没域名 (hy2自签-reality偷别人-wss argo穿透)"
  echo "2. 我有域名 (hy2-wss-伪装站共用ca证书-reality偷自己)"
  read -p "请输入选项的编号【1-2】(默认: 1): " choice

  case $choice in
    2)
      hasdomain=1
      ;;
    *)
      hasdomain=0
      ;;
  esac
}


# 安装nginx
install_nginx(){
  bash <(curl -Ls https://raw.githubusercontent.com/vveg26/myself/main/BashScript/nginx-onekey/ngx.sh) --install
}


# 安装基础包
install_base


# Check if reality.json, sing-box, and sing-box.service already exist
if [ -f "/root/sbox/sbconfig_server.json" ] && [ -f "/root/sbox/sing-box" ] && [ -f "/root/sbox/public.key.b64" ] && [ -f "/root/sbox/argo.txt.b64" ] && [ -f "/etc/systemd/system/sing-box.service" ]; then

    echo "sing-box-reality-hysteria2-wss已经安装"
    echo ""
    echo "请选择选项:"
    echo ""
    echo "1. 重新安装"
    echo "2. 修改配置"
    echo "3. 显示客户端配置"
    echo "4. 卸载"
    echo "5. 更新sing-box内核"
    echo "6. 手动重启cloudflaed（vps重启之后需要执行一次这个来更新vmess）"
    echo ""
    read -p "Enter your choice (1-6): " choice

    case $choice in
        1)
          show_notice "开始卸载"    
          uninstall_singbox
          show_notice "开始安装"
        ;;
        2)
          #修改配置文件
          show_notice "开始修改reality端口号和域名"
          # Get current listen port
          current_listen_port=$(jq -r '.inbounds[0].listen_port' /root/sbox/sbconfig_server.json)

          # Ask for listen port
          read -p "请输入想要修改的端口号 (当前端口号为 $current_listen_port): " listen_port
          listen_port=${listen_port:-$current_listen_port}

          # Get current server name
          current_server_name=$(jq -r '.inbounds[0].tls.server_name' /root/sbox/sbconfig_server.json)

          # Ask for server name (sni)
          read -p "请输入想要偷取的域名 (当前域名为 $current_server_name): " server_name
          server_name=${server_name:-$current_server_name}
          echo ""
          # modifying hysteria2 configuration
          show_notice "开始修改hysteria2端口号"
          echo ""
          # Get current listen port
          hy_current_listen_port=$(jq -r '.inbounds[1].listen_port' /root/sbox/sbconfig_server.json)
          
          # Ask for listen port
          read -p "请属于想要修改的端口号 (当前端口号为 $hy_current_listen_port): " hy_listen_port
          hy_listen_port=${hy_listen_port:-$hy_current_listen_port}

          # Modify reality.json with new settings
          jq --arg listen_port "$listen_port" --arg server_name "$server_name" --arg hy_listen_port "$hy_listen_port" '.inbounds[1].listen_port = ($hy_listen_port | tonumber) | .inbounds[0].listen_port = ($listen_port | tonumber) | .inbounds[0].tls.server_name = $server_name | .inbounds[0].tls.reality.handshake.server = $server_name' /root/sbox/sbconfig_server.json > /root/sb_modified.json
          mv /root/sb_modified.json /root/sbox/sbconfig_server.json

          # Restart sing-box service
          systemctl restart sing-box
          # show client configuration
          show_client_configuration
          exit 0
        ;;
      3)  
          # show client configuration
          show_client_configuration
          exit 0
      ;;	
      4)
          uninstall_singbox
          exit 0
          ;;
      5)
          show_notice "更新sing-box内核"
          download_singbox
          # Check configuration and start the service
          if /root/sbox/sing-box check -c /root/sbox/sbconfig_server.json; then
              echo "Configuration checked successfully. Starting sing-box service..."
              systemctl daemon-reload
              systemctl enable sing-box > /dev/null 2>&1
              systemctl start sing-box
              systemctl restart sing-box
          fi
          echo ""  
          exit 1
          ;;
      6)
          regenarte_cloudflaed_argo
          echo "重新启动完成，查看新的vmess客户端信息"
          show_client_configuration
          exit 1
          ;;
      *)
          echo "Invalid choice. Exiting."
          exit 1
          ;;
	esac
	fi

hasdomain=0

#判断是否有域名
has_domain
# 创建sb文件夹
mkdir -p "/root/sbox/"
#下载sb
download_singbox

#记录是否选择证书
if [ $hasdomain -eq 0 ]; then
  echo 0 > /root/sbox/hasdomain.log
  download_cloudflaed
else
  echo 1 > /root/sbox/hasdomain.log
fi


# reality
echo "开始配置Reality"
echo ""
# Generate key pair
echo "自动生成基本参数"
echo ""
key_pair=$(/root/sbox/sing-box generate reality-keypair)
echo "Key pair生成完成"
echo ""

# Extract private key and public key
private_key=$(echo "$key_pair" | awk '/PrivateKey/ {print $2}' | tr -d '"')
public_key=$(echo "$key_pair" | awk '/PublicKey/ {print $2}' | tr -d '"')

# Save the public key in a file using base64 encoding
echo "$public_key" | base64 > /root/sbox/public.key.b64

# Generate necessary values
uuid=$(/root/sbox/sing-box generate uuid)
short_id=$(/root/sbox/sing-box generate rand --hex 8)
echo "uuid和短id 生成完成"
echo ""
# Ask for listen port
if [ $hasdomain -eq 0 ]; then
  read -p "请输入Reality端口号 (默认: 443): " listen_port
  listen_port=${listen_port:-443}
  # Ask for server name (sni)
  read -p "请输入想要偷取的域名 (default: itunes.apple.com): " server_name
  server_name=${server_name:-itunes.apple.com}

  #dest域名，与上方一致
  dest_server=$server_name
  #回落端口
  dest_port=443

  echo ""
else
  read -p "请输入Reality和wss和伪装站的共用的端口号 (默认: 443): " listen_port
  listen_port=${listen_port:-443}
  #read -p "请输入你的域名以供申请证书: " server_name
  read -p "请输入dest回落的ngx端口 (默认: 17443): " dest_port
  dest_port=${dest_port:-17443}
    echo ""
    echo -e " 1. 【默认】Acme 脚本自动申请"
    echo -e " 2. 自定义证书路径"
    echo ""
    read -rp "请输入选项 [1-2]: " certInput
    if [[ $certInput == 2 ]]; then
        read -p "请输入公钥文件 crt 的路径：" cert_path
        echo "公钥文件 crt 的路径：$cert_path "
        read -p "请输入密钥文件 key 的路径：" key_path
        echo "密钥文件 key 的路径：$key_path "
        read -p "请输入证书的域名：" domain
        echo "证书域名：$domain"
        hy_domain=$domain

    else
        cert_path="/root/sbox/cert/cert.pem"
        key_path="/root/sbox/cert/private.key"
        mkdir -p /root/sbox/cert/
        if [[ -f /root/sbox/cert/cert.pem && -f /root/sbox/cert/private.key ]] && [[ -s /root/sbox/cert/cert.pem && -s /root/sbox/cert/private.key ]] && [[ -f /root/sbox/cert/ca.log ]]; then
            domain=$(cat /root/sbox/cert/ca.log)
            echo "检测到原有域名：$domain 的证书，正在应用"
            server_name=$domain
            dest_server="127.0.0.1"
        else
            server_ip=$(curl -s4m8 ip.sb -k) || server_ip=$(curl -s6m8 ip.sb -k)
          
            read -p "请输入需要申请证书的域名：" domain
            [[ -z $domain ]] && echo "未输入域名，无法执行操作！" && exit 1
            echo "已输入的域名：$domain" && sleep 1
            domainIP=$(curl -sm8 ipget.net/?ip="${domain}")
            if [[ $domainIP == $server_ip ]]; then
                if [ -n "$(command -v apt)" ]; then
                    apt update
                    apt install -y curl wget sudo socat openssl cron
                    systemctl start cron
                    systemctl enable cron
                elif [ -n "$(command -v yum)" ]; then
                    yum install -y curl wget sudo socat openssl cronie
                    systemctl start crond
                    systemctl enable crond
                fi
                curl https://get.acme.sh | sh -s email=$(date +%s%N | md5sum | cut -c 1-16)@gmail.com
                source ~/.bashrc
                bash ~/.acme.sh/acme.sh --upgrade --auto-upgrade
                bash ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
                if [[ -n $(echo $server_ip | grep ":") ]]; then
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --listen-v6 --insecure
                else
                    bash ~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --insecure
                fi
                bash ~/.acme.sh/acme.sh --install-cert -d ${domain} --key-file /root/sbox/cert/private.key --fullchain-file /root/sbox/cert/cert.pem --ecc
                if [[ -f /root/sbox/cert/cert.pem && -f /root/sbox/cert/private.key ]] && [[ -s /root/sbox/cert/cert.pem && -s /root/sbox/cert/private.key ]]; then
                    echo $domain > /root/sbox/cert/ca.log
                    sed -i '/--cron/d' /etc/crontab >/dev/null 2>&1
                    echo "0 0 * * * root bash /root/.acme.sh/acme.sh --cron -f >/dev/null 2>&1" >> /etc/crontab
                    echo "证书申请成功! 脚本申请到的证书 (cert.crt) 和私钥 (private.key) 文件已保存到 /root 文件夹下"
                    echo "证书crt文件路径如下: /root/sbox/cert/cert.pem"
                    echo "私钥key文件路径如下: /root/sbox/cert/private.key"
                    server_name=$domain
                    dest_server="127.0.0.1"
                fi
            else
                echo "当前域名解析的IP与当前VPS使用的真实IP不匹配"
                exit 1
            fi
        fi
    fi
  echo ""
fi



echo ""


# hysteria2
echo "开始配置hysteria2"
echo ""
# Generate hysteria necessary values
hy_password=$(/root/sbox/sing-box generate rand --hex 8)

# Ask for listen port
read -p "请输入hysteria2监听端口 (default: 8443): " hy_listen_port
hy_listen_port=${hy_listen_port:-8443}
echo ""
# 自签证书
if [ $hasdomain -eq 0 ]; then
  # Ask for self-signed certificate domain
  read -p "输入自签证书域名 (default: bing.com): " hy_server_name
  hy_server_name=${hy_server_name:-bing.com}
  mkdir -p /root/sbox/self-cert/ && openssl ecparam -genkey -name prime256v1 -out /root/sbox/self-cert/private.key && openssl req -new -x509 -days 36500 -key /root/sbox/self-cert/private.key -out /root/sbox/self-cert/cert.pem -subj "/CN=${hy_server_name}"
  hy_cert_path="/root/sbox/self-cert/cert.pem"
  hy_key_path="/root/sbox/self-cert/private.key"
  echo $hy_server_name > /root/sbox/self-cert/ca.log

  echo ""
  echo "自签证书生成完成"
  echo ""
else
  hy_server_name=${server_name}
  hy_cert_path=$cert_path
  hy_key_path=$key_path
  echo ""
fi

# vmess ws
echo "开始配置vmess"
echo ""
vmess_uuid=$(/root/sbox/sing-box generate uuid)
if [ $hasdomain -eq 0 ]; then
  read -p "请输入vmess端口，默认为18443(和tunnel通信不暴露在外): " vmess_port
else
  read -p "请输入vmess端口，默认为18443(和nginx通信不暴露在外): " vmess_port
fi

vmess_port=${vmess_port:-18443}
echo ""
read -p "ws路径 (无需加斜杠,默认随机生成): " ws_path
ws_path=${ws_path:-$(/root/sbox/sing-box generate rand --hex 6)}

if [ $hasdomain -eq 0 ]; then
  pid=$(pgrep -f cloudflaed)
  if [ -n "$pid" ]; then
    # 终止进程
    kill "$pid"
  fi

  #生成地址
  /root/sbox/cloudflaed-linux tunnel --url http://localhost:$vmess_port --no-autoupdate --edge-ip-version auto --protocol h2mux>argo.log 2>&1 &
  sleep 2
  clear
  echo 等待cloudflare argo生成地址
  sleep 5
  #连接到域名
  argo=$(cat argo.log | grep trycloudflare.com | awk 'NR==2{print}' | awk -F// '{print $2}' | awk '{print $1}')
  echo "$argo" | base64 > /root/sbox/argo.txt.b64
  rm -rf argo.log
else
  vmess_server_name=$server_name
  vmess_cert_path=$cert_path
  vmess_key_path=$key_path

  install_nginx

  cat >/etc/nginx/nginx.conf<<EOF
pid /var/run/nginx.pid;
worker_processes auto;
worker_rlimit_nofile 51200;
events {
    worker_connections 1024;
    multi_accept on;
    use epoll;
}
http {
    server_tokens off;
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 120s;
    keepalive_requests 10000;
    types_hash_max_size 2048;
    include /etc/nginx/mime.types;
    access_log off;
    error_log /dev/null;

    server {
        listen $dest_port ssl http2;
        listen [::]:$dest_port ssl http2;
        server_name $server_name;
        ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4:!DHE;
        ssl_prefer_server_ciphers on;
        ssl_certificate $vmess_cert_path;
        ssl_certificate_key $vmess_key_path;        
        location / {
            proxy_pass https://www.bing.com; #伪装网址或者你改成自己的动态网站
            proxy_ssl_server_name on;
            proxy_redirect off;
            sub_filter_once off;
            sub_filter "www.bing.com" $server_name;
            proxy_set_header Host "www.bing.com";
            proxy_set_header Referer \$http_referer;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header User-Agent \$http_user_agent;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header Accept-Encoding "";
            proxy_set_header Accept-Language "zh-CN";
        }        
        location /$ws_path {
            proxy_redirect off;
            proxy_pass http://127.0.0.1:$vmess_port;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host \$http_host;
        }
    }
}

EOF
  #重启ngx
  systemctl reload nginx;
fi




# Retrieve the server IP address
server_ip=$(curl -s4m8 ip.sb -k) || server_ip=$(curl -s6m8 ip.sb -k)

# Create reality.json using jq
jq -n --arg listen_port "$listen_port" --arg dest_port "$dest_port" --arg dest_server "$dest_server" --arg vmess_port "$vmess_port" --arg vmess_uuid "$vmess_uuid"  --arg ws_path "$ws_path" --arg server_name "$server_name" --arg private_key "$private_key" --arg short_id "$short_id" --arg uuid "$uuid" --arg hy_listen_port "$hy_listen_port" --arg hy_password "$hy_password" --arg hy_cert_path "$hy_cert_path" --arg hy_key_path "$hy_key_path" --arg server_ip "$server_ip" '{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": ($listen_port | tonumber),
      "users": [
        {
          "uuid": $uuid,
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": $server_name,
          "reality": {
          "enabled": true,
          "handshake": {
            "server": $dest_server,
            "server_port": ($dest_port | tonumber)
          },
          "private_key": $private_key,
          "short_id": [$short_id]
        }
      }
    },
    {
        "type": "hysteria2",
        "tag": "hy2-in",
        "listen": "::",
        "listen_port": ($hy_listen_port | tonumber),
        "users": [
            {
                "password": $hy_password
            }
        ],
        "tls": {
            "enabled": true,
            "alpn": [
                "h3"
            ],
            "certificate_path": $hy_cert_path,
            "key_path": $hy_key_path
        }
    },
    {
        "type": "vmess",
        "tag": "vmess-in",
        "listen": "::",
        "listen_port": ($vmess_port | tonumber),
        "users": [
            {
                "uuid": $vmess_uuid,
                "alterId": 0
            }
        ],
        "transport": {
            "type": "ws",
            "path": $ws_path
        }
    }
  ],
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "block",
      "tag": "block"
    }
  ]
}' > /root/sbox/sbconfig_server.json



# Create sing-box.service
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/root/sbox/sing-box run -c /root/sbox/sbconfig_server.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF


# Check configuration and start the service
if /root/sbox/sing-box check -c /root/sbox/sbconfig_server.json; then
    echo "Configuration checked successfully. Starting sing-box service..."
    systemctl daemon-reload
    systemctl enable sing-box > /dev/null 2>&1
    systemctl start sing-box
    systemctl restart sing-box

    show_client_configuration


else
    echo "Error in configuration. Aborting"
fi
