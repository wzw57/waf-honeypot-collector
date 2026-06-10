# 部署与运维文档

项目路径假设：`/home/ubuntu/waf-honeypot-collector`  
运行用户：`ubuntu`

---

## 目录

1. [环境要求](#1-环境要求)
2. [从零部署](#2-从零部署)
3. [配置](#3-配置)
4. [systemd 服务](#4-systemd-服务)
5. [服务管理](#5-服务管理)
6. [日志查看](#6-日志查看)
7. [数据库备份](#7-数据库备份)
8. [常见问题](#8-常见问题)

---

## 1. 环境要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Ubuntu 20.04+ / Debian 11+ |
| Python | 3.10+ |
| 内存 | ≥512MB（推荐 1GB） |
| 磁盘 | ≥10GB（取决于日志量） |
| 网络 | 需能连接 SafeLine（UDP 1514）和 HFish API（HTTP） |

### 端口说明

| 端口 | 协议 | 用途 | 默认监听 |
|------|------|------|----------|
| 1514 | UDP | SafeLine Syslog 接收 | `0.0.0.0` |
| 8000 | TCP | Web Dashboard | `127.0.0.1` |

## 2. 从零部署

### 2.1 克隆项目

```bash
git clone https://github.com/wzw57/waf-honeypot-collector.git
cd waf-honeypot-collector
```

### 2.2 安装依赖

```bash
# 使用 venv（推荐）
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 或直接安装到系统
pip install pyyaml requests jinja2 fastapi uvicorn aiofiles
# 测试用（可选）
pip install pytest
```

### 2.3 配置

```bash
cp config.yaml.example config.yaml
vim config.yaml
```

至少修改以下配置：

```yaml
safeline:
  host: "0.0.0.0"      # Syslog 监听地址
  port: 1514             # Syslog 监听端口

hfish:
  api_url: "http://your-hfish-server:5000"  # HFish 地址
  auth_type: token
  # api_token 通过环境变量 HFISH_API_TOKEN 设置

web:
  host: "127.0.0.1"     # Dashboard 监听地址（默认仅本地）
  port: 8000
```

### 2.4 初始化数据库

```bash
python main.py init-db
```

### 2.5 验证采集

```bash
# 终端 1：启动 Syslog 接收
python main.py recv-safeline

# 终端 2：发送测试日志
python scripts/mock_syslog.py --count 5

# 终端 2：查看结果
python main.py show-latest
python main.py stats
```

## 3. 配置

### 3.1 环境变量

| 环境变量 | 用途 | 必需 |
|----------|------|------|
| `HFISH_API_TOKEN` | HFish API Token | 如果用 Token 认证 |
| `HFISH_PASSWORD` | HFish 登录密码 | 如果用密码认证 |
| `DEEPSEEK_API_KEY` | DeepSeek API 密钥 | 可选 |

### 3.2 配置文件结构

所有配置集中在 `config.yaml`，示例配置见 `config.yaml.example`。

**配置生效后无需重启 systemd 服务**：重新执行 `python main.py <command>` 时自动读取最新配置。

## 4. systemd 服务

项目提供 3 个 systemd 服务文件：

| 服务 | 文件 | 功能 |
|------|------|------|
| `waf-honeypot-safeline` | `deploy/waf-honeypot-safeline.service` | SafeLine Syslog 接收 |
| `waf-honeypot-hfish` | `deploy/waf-honeypot-hfish.service` | HFish 循环拉取 |
| `waf-honeypot-web` | `deploy/waf-honeypot-web.service` | Web Dashboard |

### 4.1 安装服务

```bash
sudo cp deploy/waf-honeypot-safeline.service /etc/systemd/system/
sudo cp deploy/waf-honeypot-hfish.service /etc/systemd/system/
sudo cp deploy/waf-honeypot-web.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 4.2 设置环境变量

HFish Token 和 DeepSeek API Key 通过环境变量注入，有两种方式：

**方式 A：在 service 文件中设置（推荐）**

编辑 `/etc/systemd/system/waf-honeypot-hfish.service`，在 `[Service]` 段添加：

```ini
Environment=HFISH_API_TOKEN=your-token-here
```

编辑 `/etc/systemd/system/waf-honeypot-web.service`：

```ini
Environment=DEEPSEEK_API_KEY=your-key-here
```

然后 `sudo systemctl daemon-reload`。

**方式 B：写入 /etc/environment**

```bash
echo 'HFISH_API_TOKEN=your-token-here' | sudo tee -a /etc/environment
echo 'DEEPSEEK_API_KEY=your-key-here' | sudo tee -a /etc/environment
```

## 5. 服务管理

### 5.1 启动/停止/重启

```bash
# 启动所有服务
sudo systemctl start waf-honeypot-safeline
sudo systemctl start waf-honeypot-hfish
sudo systemctl start waf-honeypot-web

# 停止单个服务
sudo systemctl stop waf-honeypot-safeline

# 重启
sudo systemctl restart waf-honeypot-web

# 查看状态
sudo systemctl status waf-honeypot-safeline
```

### 5.2 开机自启

```bash
sudo systemctl enable waf-honeypot-safeline
sudo systemctl enable waf-honeypot-hfish
sudo systemctl enable waf-honeypot-web
```

### 5.3 一键启动全部

```bash
for svc in waf-honeypot-safeline waf-honeypot-hfish waf-honeypot-web; do
    sudo systemctl enable --now "$svc"
done
```

## 6. 日志查看

```bash
# 实时日志
sudo journalctl -u waf-honeypot-safeline.service -f

# 最近 100 条
sudo journalctl -u waf-honeypot-hfish.service -n 100 --no-pager

# 按日期过滤
sudo journalctl -u waf-honeypot-web.service --since "2026-06-10" --until "2026-06-11"

# 查看错误级别
sudo journalctl -u waf-honeypot-safeline.service -p err -b
```

## 7. 数据库备份

### 7.1 手动备份

```bash
# 使用备份脚本
bash scripts/backup_db.sh

# 或直接使用 sqlite3
sqlite3 data/collector.db ".backup 'data/backups/collector_$(date +%Y%m%d).db'"
```

### 7.2 定时自动备份（crontab）

```bash
# 编辑 crontab
crontab -e

# 每天凌晨 2 点备份
0 2 * * * /home/ubuntu/waf-honeypot-collector/scripts/backup_db.sh --auto

# 也可使用 sqlite3 直接备份
0 2 * * * sqlite3 /home/ubuntu/waf-honeypot-collector/data/collector.db ".backup '/home/ubuntu/waf-honeypot-collector/data/backups/collector_$(date +\%Y\%m\%d).db'"
```

### 7.3 备份文件管理

建议定期清理旧备份，例如保留 30 天：

```bash
find /home/ubuntu/waf-honeypot-collector/data/backups -name "*.db" -mtime +30 -delete
```

## 8. 常见问题

### Q1: Syslog 端口（1514）权限不足

UDP 端口 1514 > 1024，不需要 root 权限。如果使用 < 1024 的端口，需要 root 或以 capability 方式启动。

### Q2: Web Dashboard 无法访问

首先确认监听地址：

```bash
# 查看实际监听
ss -tlnp | grep 8000
```

如果监听在 `127.0.0.1:8000`，只能本地访问。远程访问请使用 SSH 隧道：

```bash
# 本地执行
ssh -L 8000:127.0.0.1:8000 ubuntu@your-vps-ip
# 本地浏览器打开 http://127.0.0.1:8000
```

### Q3: 数据库文件过大

数据库按天增长，建议：
1. 定期备份并从生产环境清理旧数据；
2. 调整 SafeLine 日志发送频率；
3. 监控磁盘使用。

### Q4: 服务异常退出

所有 systemd 服务配置了 `Restart=on-failure`，异常退出后 10 秒自动重启。

查看退出原因：

```bash
sudo journalctl -u waf-honeypot-safeline.service -n 50 --no-pager
```

### Q5: HFish 拉取报错

检查：
1. `api_url` 配置是否正确；
2. `api_path` 是否匹配 HFish 版本（如不确定，F12 确认）；
3. Token/密码是否正确；
4. HFish 服务是否正常运行。

### Q6: 安全注意事项

1. Web Dashboard 默认只监听 `127.0.0.1`，不暴露公网；
2. API Key / Token 从环境变量读取，不写入代码或配置文件；
3. `config.yaml` 已被 `.gitignore` 排除，不会提交到 Git；
4. 如果确实需要公网访问 Dashboard，建议加 Nginx 反向代理 + Basic Auth。
