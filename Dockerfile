# ==========================================
# 第一阶段:构建层 (Builder)
# ==========================================
FROM node:18-slim AS builder
WORKDIR /app

# 安装工具
RUN apt-get update && apt-get install -y curl tar

# 下载 Camoufox
ARG CAMOUFOX_URL
RUN if [ -z "$CAMOUFOX_URL" ]; then echo "Error: URL is empty"; exit 1; fi && \
    curl -sSL ${CAMOUFOX_URL} -o camoufox.tar.gz && \
    tar -xzf camoufox.tar.gz && \
    chmod +x camoufox-linux/camoufox

# 安装 NPM 依赖
COPY package*.json ./
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_SKIP_DOWNLOAD=true \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=true
RUN npm install --omit=dev

# ==========================================
# 第二阶段:运行层 (Final)
# ==========================================
FROM node:18-slim
WORKDIR /app

# 1. 安装系统依赖 + cloudflared
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates fonts-liberation libasound2 libatk-bridge2.0-0 \
    libatk1.0-0 libc6 libcairo2 libcups2 libdbus-1-3 libexpat1 \
    libfontconfig1 libgbm1 libgcc1 libglib2.0-0 libgtk-3-0 libnspr4 \
    libnss3 libpango-1.0-0 libpangocairo-1.0-0 libstdc++6 libx11-6 \
    libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 \
    libxfixes3 libxi6 libxrandr2 libxrender1 libxss1 libxtst6 \
    lsb-release wget xdg-utils xvfb curl \
    && curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared \
    && chmod +x /usr/local/bin/cloudflared \
    && rm -rf /var/lib/apt/lists/*

# 2. 复制应用文件
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/camoufox-linux ./camoufox-linux
COPY --chown=node:node package*.json ./
COPY --chown=node:node unified-server.js black-browser.js ./

# 3. 创建启动脚本
COPY --chown=node:node <<'EOF' /app/start.sh
#!/bin/bash
set -e

echo "🚀 启动应用服务器..."
node unified-server.js &
APP_PID=$!

# 如果设置了 CLOUDFLARE_TUNNEL_TOKEN,则启动 cloudflared
if [ -n "$CLOUDFLARE_TUNNEL_TOKEN" ]; then
    echo "🔗 检测到 Cloudflare Tunnel Token,正在启动 tunnel..."
    cloudflared tunnel --no-autoupdate run --token "$CLOUDFLARE_TUNNEL_TOKEN" &
    TUNNEL_PID=$!
    echo "✅ Cloudflare Tunnel 已启动 (PID: $TUNNEL_PID)"
else
    echo "ℹ️  未设置 CLOUDFLARE_TUNNEL_TOKEN,跳过 tunnel 启动"
fi

# 等待应用进程
wait $APP_PID
EOF

RUN chmod +x /app/start.sh

# 4. 创建 auth 目录
RUN mkdir -p ./auth && chown node:node ./auth

# 5. 启动配置
USER node
EXPOSE 7860 9998
ENV CAMOUFOX_EXECUTABLE_PATH=/app/camoufox-linux/camoufox
CMD ["/app/start.sh"]
