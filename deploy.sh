#!/bin/bash

# --- 配置 ---
CONTAINER_NAME="aisbuild"
IMAGE_NAME="ghcr.io/wuchen0309/aisbuild:latest"
HOST_PORT="7860"
ENV_FILE="app.env"
# 默认代理为空，稍后会询问用户
PROXY_URL=""

# --- 环境检查 ---
if [ ! -f "$ENV_FILE" ]; then
    echo "❌ 错误: 环境文件 '$ENV_FILE' 不存在！"
    exit 1
fi

# ==========================================
# [交互 1] 检查或设置 API Key (必填)
# ==========================================
echo ""
echo "----------------------------------------------------"
echo "🔑 步骤 1/2: 检查 API Key 配置"
echo "----------------------------------------------------"

# 1. 尝试读取现有的 KEY (grep查找 -> cut取值 -> xargs去空格)
CURRENT_API_KEY=$(grep "^API_KEYS=" "$ENV_FILE" | cut -d'=' -f2- | xargs)

if [ -n "$CURRENT_API_KEY" ]; then
    # --- 情况 A: 配置文件里已经有值了 ---
    echo "✅ 检测到 app.env 中已配置 API Key，跳过输入。"
    echo "   (如需修改，请手动编辑 app.env 或清空该行后重新运行脚本)"
else
    # --- 情况 B: 配置文件里没有值，强制交互输入 ---
    echo "⚠️  未检测到有效的 API Key，请输入："
    
    USER_API_KEY=""
    # 循环直到用户输入有效内容
    while [ -z "$USER_API_KEY" ]; do
        read -p "👉 请输入 API Key (不能为空): " USER_API_KEY
        USER_API_KEY=$(echo "$USER_API_KEY" | xargs) # 去除前后空格

        if [ -z "$USER_API_KEY" ]; then
            echo "❌ 错误: API Key 不能为空，请重新输入！"
            echo ""
        fi
    done

    # 写入配置到 app.env
    if grep -q "^API_KEYS=" "$ENV_FILE"; then
        sed -i "s|^API_KEYS=.*|API_KEYS=$USER_API_KEY|" "$ENV_FILE"
    else
        echo -e "\nAPI_KEYS=$USER_API_KEY" >> "$ENV_FILE"
    fi
    echo "✅ API Key 已保存。"
fi


# ==========================================
# [交互 2] 设置网络代理 (选填)
# ==========================================
echo ""
echo "----------------------------------------------------"
echo "🌐 步骤 2/2: 配置网络代理 (可选)"
echo "----------------------------------------------------"
echo "如果您的服务器在国内，建议配置 HTTP 代理以确保能连接外网。"
echo "格式示例: http://127.0.0.1:7890"
read -p "请输入代理地址 (直接回车表示不使用代理): " USER_PROXY

# 去除空格
USER_PROXY=$(echo "$USER_PROXY" | xargs)

if [ -n "$USER_PROXY" ]; then
    PROXY_URL="$USER_PROXY"
    echo "✅ 已设置代理: $PROXY_URL"
else
    PROXY_URL=""
    echo "⏭️  未输入，将直接连接网络 (不使用代理)。"
fi
echo "----------------------------------------------------"
echo ""

# ==========================================
# [检测] 认证配置检查 (文件或环境变量)
# ==========================================
echo "🔐 检查认证配置..."

AUTH_VALID=false
AUTH_MOUNT=false

if [ -d "./auth" ]; then
    # 检查是否存在 auth-*.json 格式的文件
    AUTH_COUNT=$(find ./auth -maxdepth 1 -name "auth-*.json" -type f 2>/dev/null | wc -l)
    
    if [ "$AUTH_COUNT" -gt 0 ]; then
        echo "✅ 检测到 $AUTH_COUNT 个认证文件 (auth-*.json)"
        AUTH_VALID=true
        AUTH_MOUNT=true
    fi
fi

# 如果没有有效的认证文件，检查环境变量
if [ "$AUTH_VALID" = false ]; then
    # 检查 app.env 中是否配置了 AUTH_JSON_* 环境变量（有值且非空）
    AUTH_ENV_COUNT=$(grep -E "^AUTH_JSON_[0-9]+=" "$ENV_FILE" | grep -vE "^AUTH_JSON_[0-9]+=\s*$" | wc -l)
    
    if [ "$AUTH_ENV_COUNT" -gt 0 ]; then
        echo "✅ 检测到 $AUTH_ENV_COUNT 个环境变量认证配置 (AUTH_JSON_*)"
        AUTH_VALID=true
    fi
fi

# 双重检测都失败，中断部署
if [ "$AUTH_VALID" = false ]; then
    echo ""
    echo "❌ 错误: 未检测到有效的认证配置！"
    echo ""
    echo "   请通过以下任一方式配置认证信息："
    echo "   方式1: 在 ./auth 目录下放置 auth-1.json, auth-2.json 等文件"
    echo "   方式2: 在 $ENV_FILE 中设置 AUTH_JSON_1, AUTH_JSON_2 等环境变量"
    echo ""
    exit 1
fi

# ==========================================
# 开始部署逻辑
# ==========================================
echo ""
echo "🚀 开始部署容器: $CONTAINER_NAME"

# --- 更新镜像与清理旧容器 ---
echo "--> 拉取镜像并清理旧容器..."
docker pull $IMAGE_NAME || { echo "❌ 镜像拉取失败"; exit 1; }
docker stop $CONTAINER_NAME > /dev/null 2>&1
docker rm $CONTAINER_NAME > /dev/null 2>&1

# --- 构建启动参数 ---
declare -a DOCKER_OPTS
DOCKER_OPTS=(
    -d
    --name "$CONTAINER_NAME"
    -p "${HOST_PORT}:7860"
    --env-file "$ENV_FILE"
    --restart unless-stopped
)

# 挂载 auth 目录（如果前面检测到有效文件）
if [ "$AUTH_MOUNT" = true ]; then
    echo "--> 挂载 ./auth 目录 (并修正权限 1000:1000)"
    sudo chown -R 1000:1000 ./auth
    DOCKER_OPTS+=(-v "$(pwd)/auth:/app/auth")
fi

# 配置代理（如果用户在上一步设置了）
if [ -n "$PROXY_URL" ]; then
    echo "--> 注入代理环境变量..."
    DOCKER_OPTS+=(-e "HTTP_PROXY=${PROXY_URL}" -e "HTTPS_PROXY=${PROXY_URL}")
fi

# --- 启动容器 ---
echo "--> 启动新容器..."
docker run "${DOCKER_OPTS[@]}" "$IMAGE_NAME"

# --- 清理无用镜像 ---
docker image prune -f > /dev/null 2>&1

# --- 🔥 自动放行防火墙端口 ---
echo "--> 检查防火墙设置..."
if command -v ufw > /dev/null; then
    if ! sudo ufw status | grep -q "$HOST_PORT"; then
        echo "   检测到 UFW，正在放行端口 $HOST_PORT..."
        sudo ufw allow "$HOST_PORT"/tcp
    fi
elif command -v firewall-cmd > /dev/null; then
    if ! sudo firewall-cmd --list-ports | grep -q "$HOST_PORT/tcp"; then
        echo "   检测到 Firewalld，正在放行端口 $HOST_PORT..."
        sudo firewall-cmd --zone=public --add-port="$HOST_PORT"/tcp --permanent > /dev/null
        sudo firewall-cmd --reload > /dev/null
    fi
else
    echo "   ⚠️ 未检测到常用防火墙(UFW/Firewalld)，请手动确保端口 $HOST_PORT 已开放。"
fi

# --- 状态检查与输出 ---
echo "--> 等待服务启动..."
sleep 5

# 获取公网 IP
PUBLIC_IP=$(curl -s -4 --connect-timeout 3 ifconfig.me)
[ -z "$PUBLIC_IP" ] && PUBLIC_IP="127.0.0.1"

echo ""
echo "✅ 部署完成！"
echo "🌐 访问地址: http://${PUBLIC_IP}:${HOST_PORT}"
echo "📝 查看日志: docker logs -f $CONTAINER_NAME"