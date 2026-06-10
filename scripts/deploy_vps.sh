#!/usr/bin/env bash
# =============================================================================
# WAF Honeypot Collector — VPS 一键部署脚本
# 用法:
#   sudo bash scripts/deploy_vps.sh
#
# 在目标目录执行（脚本会自动复制到 APP_DIR）：
#   cd /opt/waf-honeypot-collector
#   git pull
#   bash scripts/deploy_vps.sh
#
# 环境变量（均可覆盖）:
#   APP_DIR       — 项目安装目录（默认 /opt/waf-honeypot-collector）
#   APP_USER      — 运行用户（默认 ubuntu）
#   APP_GROUP     — 运行用户组（默认 ubuntu）
#   ENV_FILE      — 环境变量文件（默认 /etc/waf-honeypot-collector.env）
#   CONFIG_FILE   — 配置文件路径（默认 $APP_DIR/config.yaml）
# =============================================================================
set -euo pipefail

# ─── 默认变量 ────────────────────────────────────────────────────────────────
APP_DIR="${APP_DIR:-/opt/waf-honeypot-collector}"
APP_USER="${APP_USER:-ubuntu}"
APP_GROUP="${APP_GROUP:-ubuntu}"
ENV_FILE="${ENV_FILE:-/etc/waf-honeypot-collector.env}"
CONFIG_FILE="${CONFIG_FILE:-$APP_DIR/config.yaml}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ─── 前置检查 ────────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
    error "请以 root 用户运行此脚本（或使用 sudo）"
    exit 1
fi

# 检查当前目录是否存在项目文件
if [ ! -f "main.py" ] || [ ! -f "requirements.txt" ]; then
    error "未找到 main.py 或 requirements.txt"
    error "请在项目根目录执行此脚本：cd /path/to/waf-honeypot-collector && bash scripts/deploy_vps.sh"
    exit 1
fi

# ─── 复制项目到 APP_DIR（如果不是已在目标位置） ─────────────────────────────
CURRENT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
if [ "$CURRENT_DIR" != "$APP_DIR" ]; then
    info "复制项目文件到 $APP_DIR ..."
    mkdir -p "$APP_DIR"
    cp -r "$CURRENT_DIR"/. "$APP_DIR/"
    info "项目文件已复制到 $APP_DIR"
fi

# ─── 修正目录权限 ────────────────────────────────────────────────────────────
info "修正目录权限: $APP_DIR (${APP_USER}:${APP_GROUP})"
sudo chown -R "${APP_USER}:${APP_GROUP}" "$APP_DIR"

# ─── 创建 Python venv ────────────────────────────────────────────────────────
if [ ! -d "$APP_DIR/venv" ]; then
    info "创建 Python virtualenv ..."
    python3 -m venv "$APP_DIR/venv"
else
    info "virtualenv 已存在，跳过创建"
fi

# ─── 安装依赖 ────────────────────────────────────────────────────────────────
info "安装 Python 依赖 ..."
"$APP_DIR/venv/bin/pip" install --upgrade pip -q
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt" -q

# ─── 配置文件 ────────────────────────────────────────────────────────────────
if [ ! -f "$CONFIG_FILE" ]; then
    info "从 config.yaml.example 创建 $CONFIG_FILE ..."
    cp "$APP_DIR/config.yaml.example" "$CONFIG_FILE"
    sudo chown "${APP_USER}:${APP_GROUP}" "$CONFIG_FILE"
else
    info "配置文件已存在: $CONFIG_FILE"
fi

# ─── 创建必要目录 ────────────────────────────────────────────────────────────
mkdir -p "$APP_DIR/data" "$APP_DIR/logs" "$APP_DIR/reports" "$APP_DIR/data/backups"
sudo chown -R "${APP_USER}:${APP_GROUP}" "$APP_DIR/data" "$APP_DIR/logs" "$APP_DIR/reports"

# ─── 环境变量文件 ────────────────────────────────────────────────────────────
if [ ! -f "$ENV_FILE" ]; then
    info "创建环境变量文件: $ENV_FILE ..."
    cat > "$ENV_FILE" << 'EOF'
HFISH_API_TOKEN=
HFISH_PASSWORD=
DEEPSEEK_API_KEY=
EOF
    sudo chown "root:${APP_GROUP}" "$ENV_FILE"
    sudo chmod 640 "$ENV_FILE"
    warn "请编辑 $ENV_FILE 填入真实 Token / API Key"
    warn "  安全权限已设置为 chmod 640"
else
    info "环境变量文件已存在: $ENV_FILE"
fi

# ─── 初始化数据库 ────────────────────────────────────────────────────────────
info "初始化数据库 ..."
"$APP_DIR/venv/bin/python" "$APP_DIR/main.py" --config "$CONFIG_FILE" init-db

# ─── 生成 systemd 服务文件 ──────────────────────────────────────────────────

# SafeLine Syslog Receiver
info "生成 systemd 服务: waf-honeypot-safeline ..."
cat > /etc/systemd/system/waf-honeypot-safeline.service << SERVICE
[Unit]
Description=WAF Honeypot Collector - SafeLine Syslog Receiver
Documentation=https://github.com/wzw57/waf-honeypot-collector
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_GROUP}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/venv/bin/python ${APP_DIR}/main.py --config ${CONFIG_FILE} recv-safeline
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=-${ENV_FILE}

# 安全加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=${APP_DIR}/data ${APP_DIR}/logs ${APP_DIR}/reports

[Install]
WantedBy=multi-user.target
SERVICE

# Web Dashboard
info "生成 systemd 服务: waf-honeypot-web ..."
cat > /etc/systemd/system/waf-honeypot-web.service << SERVICE
[Unit]
Description=WAF Honeypot Collector - Web Dashboard
Documentation=https://github.com/wzw57/waf-honeypot-collector
After=network.target

[Service]
Type=simple
User=${APP_USER}
Group=${APP_GROUP}
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/venv/bin/python ${APP_DIR}/main.py --config ${CONFIG_FILE} web
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=-${ENV_FILE}

# 安全加固
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=${APP_DIR}/data ${APP_DIR}/logs ${APP_DIR}/reports

[Install]
WantedBy=multi-user.target
SERVICE

# ─── 启动服务 ────────────────────────────────────────────────────────────────
info "重新加载 systemd 配置 ..."
systemctl daemon-reload

info "启用并启动服务 ..."
systemctl enable --now waf-honeypot-safeline
systemctl enable --now waf-honeypot-web

# ─── 完成提示 ────────────────────────────────────────────────────────────────
echo ""
info "=============================================="
info "  WAF Honeypot Collector 部署完成！"
info "=============================================="
echo ""
info "已启动的服务:"
info "  ✅ waf-honeypot-safeline  — SafeLine Syslog 接收 (UDP :1514)"
info "  ✅ waf-honeypot-web       — Web Dashboard (127.0.0.1:8000)"
info ""
info "查看服务状态:"
info "  systemctl status waf-honeypot-safeline --no-pager"
info "  systemctl status waf-honeypot-web --no-pager"
info ""
info "查看实时日志:"
info "  journalctl -u waf-honeypot-safeline -f"
info "  journalctl -u waf-honeypot-web -f"
info ""
info "Web Dashboard 访问方式（SSH 隧道）:"
info "  ssh -L 8000:127.0.0.1:8000 ${APP_USER}@YOUR_VPS_IP"
info "  然后浏览器访问: http://127.0.0.1:8000"
echo ""
warn "安全注意事项:"
warn "  - SafeLine 真实接入需要云安全组和防火墙放行 UDP 1514"
warn "  - HFish 未自动启动，单独配置后手动启用"
warn "  - 编辑 $ENV_FILE 填入真实 Token / API Key"
warn "  - Web Dashboard 默认仅监听 127.0.0.1，不直接暴露公网"
echo ""
