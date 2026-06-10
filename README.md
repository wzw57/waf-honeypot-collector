# WAF Honeypot Collector

基于 SafeLine WAF 与 HFish 蜜罐的轻量级安全事件采集与关联分析平台。

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![SQLite](https://img.shields.io/badge/SQLite-003B57?logo=sqlite)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 项目简介

对接 **SafeLine（雷池 WAF）** 和 **HFish（蜜罐）** 两类安全数据源，实现从日志采集、标准化、IOC 提取、攻击源画像、关联分析到报告生成的安全运营闭环。项目全栈使用 Python + SQLite，适合 **低配置 VPS（1 vCPU / 1GB RAM）** 部署。

### 核心链路

```
SafeLine WAF ──Syslog──┐
                        ├──→ 原始日志 → 标准化 → IOC提取 → 攻击画像 → 关联分析 → ATT&CK映射 → 报告
HFish 蜜罐  ──API───┘
```

---

## 功能特性

| 类别 | 功能 | 说明 |
|------|------|------|
| 📥 采集 | SafeLine Syslog 接收 | UDP 1514，原始报文完整保留 |
| 📥 采集 | HFish API 拉取 | 支持 Token/密码认证，自动去重 |
| 🔄 处理 | 事件标准化 | 异构日志统一为标准化事件模型 |
| 🎯 IOC | 威胁指标提取 | IP/URI/URL/Host/UA/Payload/敏感路径 |
| 👤 画像 | 攻击源画像 | 按 IP 聚合，风险评分 + 标签 + 协议分布 |
| 🔗 分析 | 关联分析 | 多源命中、多阶段攻击、扫描行为检测 |
| 🗺️ 映射 | ATT&CK 映射 | 规则引擎映射 T1595/T1190/T1110/T1059 |
| 📄 报告 | Markdown 报告 | 按 IP 生成含 IOC / ATT&CK / 处置建议的报告 |
| 🤖 AI | DeepSeek 辅助 | 可选接入，生成摘要 / Payload 解释 |
| 🌐 Web | Dashboard | FastAPI + Bootstrap 5 + ECharts 可视化 |
| 🚀 部署 | systemd 托管 | 3 个服务文件，支持自动重启 |

---

## 快速开始

### 安装 & 运行 (5 步)

```bash
# 1. 创建 virtualenv 并安装依赖
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. 配置
cp config.yaml.example config.yaml
vim config.yaml

# 3. 初始化数据库
python main.py init-db

# 4. 启动 Syslog 接收
python main.py recv-safeline

# 5. 另一个终端发送测试日志
python scripts/mock_syslog.py --count 5
python main.py stats
```

---

## 数据流

```
┌──────────┐   UDP Syslog    ┌──────────────┐
│ SafeLine ├───────────────→ │              │
│   WAF    │    :1514/udp   │              │
└──────────┘                │  collectors/ │
                            │              │   raw_safeline_logs
┌──────────┐   REST API     │  safeline_   │ ────────────────→ ┌──────────┐
│  HFish   ├───────────────→ │  syslog.py   │                  │  SQLite  │
│  蜜罐     │   HTTP/JSON    │              │                  │  (data/  │
└──────────┘                │  hfish_api.py │   raw_hfish_     │collector │
                            │              │ ────────────────→ │  .db)    │
                            └──────┬───────┘                  └──────────┘
                                   │
                                   ▼
                            ┌──────────────┐
                            │   parsers/   │
                            │  safeline_   │
                            │  parser.py   │
                            │              │
                            │   hfish_     │
                            │  parser.py   │
                            └──────┬───────┘
                                   │
                                   ▼
                            ┌──────────────┐    normalized_events
                            │  analyzers/  │ ──────────────────→ ┌──────────┐
                            │  normalizer  │                     │  SQLite  │
                            └──────┬───────┘                     └──────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    ▼              ▼              ▼
             ┌──────────┐  ┌──────────┐  ┌────────────┐
             │   IOC    │  │ 攻击源    │  │  关联分析   │
             │  提取    │  │ 画像     │  │            │
             └────┬─────┘  └────┬─────┘  └─────┬──────┘
                  │             │              │
                  ▼             ▼              ▼
             ┌──────────┐  ┌──────────┐  ┌────────────┐
             │  iocs    │  │attacker_ │  │  tags /    │
             │  表      │  │profiles  │  │  is_multi  │
             └──────────┘  └──────────┘  └────────────┘
                                   │
                                   ▼
                            ┌──────────────┐    ┌────────────┐
                            │  ATT&CK      │    │  Markdown  │
                            │  映射        │───→│  报告      │
                            └──────────────┘    └────────────┘
```

---

## CLI 使用示例

### 初始化与采集

```bash
python main.py init-db                       # 初始化数据库
python main.py recv-safeline                  # 启动 Syslog 接收
python main.py collect-hfish                  # 单次拉取 HFish
python main.py collect-hfish-loop --interval 60  # 循环拉取
```

### 查看数据

```bash
python main.py stats                          # 统计概览
python main.py show-latest                    # 最近事件
python main.py show-latest --mode raw_safeline # 原始 Syslog
python main.py show-ip --ip 10.0.0.1          # 按 IP 查询
```

### 分析

```bash
python main.py normalize                      # 标准化事件
python main.py extract-ioc                    # 提取 IOC
python main.py build-profiles                 # 构建画像
python main.py correlate                      # 关联分析
python main.py map-attack                     # ATT&CK 映射
```

### 报告与 AI

```bash
python main.py show-profile --ip 10.0.0.1     # 查看画像
python main.py top-ip                         # Top 攻击源
python main.py report --ip 10.0.0.1           # 生成报告
python main.py report --all --output reports/ # 生成全部报告
python main.py ai-summary --ip 10.0.0.1       # AI 摘要（需配置 Key）
python main.py report --ip 10.0.0.1 --with-ai # 报告集成 AI
```

### Web Dashboard

```bash
python main.py web                            # 启动 Web（127.0.0.1:8000）
```

---

## Web Dashboard

> 启动后访问 `http://127.0.0.1:8000` 即可查看 Dashboard 页面。
> 截图待补充。

| 页面 | 功能 |
|------|------|
| 概览 `/` | 统计卡片 + 数据源/风险等级饼图 |
| 事件 `/events` | 标准化事件筛选与分页 |
| Top IP `/top-ip` | 按事件数或风险评分排序 |
| IP 详情 `/profile/{ip}` | 完整画像 + 时间线 + IOC |
| IOC 列表 `/iocs` | 按类型筛选 |
| 攻击类型 `/attack-types` | ECharts 饼图 |
| 趋势 `/trends` | ECharts 折线图 |
| 高风险 `/high-risk` | high/critical IP |
| 报告 `/report/{ip}` | 在线查看报告 |

> **⚠️ 安全说明：** Dashboard 默认仅监听 `127.0.0.1`，不暴露公网。可通过 SSH 隧道访问：
> ```bash
> ssh -L 8000:127.0.0.1:8000 ubuntu@your-vps-ip
> ```

> **CDN 依赖说明：** Dashboard 使用 CDN 加载 Bootstrap 5 / ECharts 5，如离线运行请替换为本地静态文件。

---

## VPS 部署

项目提供一键部署脚本，自动完成环境配置、systemd 服务注册和启动。

### 快速部署

```bash
# 在目标 VPS 上克隆项目
sudo mkdir -p /opt && sudo chown ubuntu:ubuntu /opt
cd /opt
git clone https://github.com/wzw57/waf-honeypot-collector.git
cd waf-honeypot-collector

# 一键部署（需要 sudo）
bash scripts/deploy_vps.sh
```

部署脚本会自动：

1. 安装 Python 依赖到 virtualenv
2. 创建配置文件和环境变量文件
3. 初始化 SQLite 数据库
4. 注册并启动以下 systemd 服务

| 服务 | 功能 | 状态 |
|------|------|------|
| `waf-honeypot-safeline` | SafeLine Syslog 接收 (UDP :1514) | ✅ 自动启动 |
| `waf-honeypot-web` | Web Dashboard (127.0.0.1:8000) | ✅ 自动启动 |

### 部署后操作

```bash
# 编辑配置和环境变量
sudo vim /opt/waf-honeypot-collector/config.yaml
sudo vim /etc/waf-honeypot-collector.env
# 修改后需要重启对应服务
sudo systemctl restart waf-honeypot-safeline
sudo systemctl restart waf-honeypot-web

# 查看状态
systemctl status waf-honeypot-safeline --no-pager
systemctl status waf-honeypot-web --no-pager

# 查看日志
journalctl -u waf-honeypot-safeline -f
journalctl -u waf-honeypot-web -f
```

### 访问 Web Dashboard

```bash
# 通过 SSH 隧道访问（本地执行）
ssh -L 8000:127.0.0.1:8000 ubuntu@YOUR_VPS_IP
# 本地浏览器打开 http://127.0.0.1:8000
```

### 安全注意事项

- 🛡️ **SafeLine 真实接入**需要云安全组和系统防火墙放行 **UDP 1514** 端口
- 🛡️ **HFish** 未在部署脚本中自动启动，需单独配置后手动 `systemctl start waf-honeypot-hfish`
- 🛡️ **Web Dashboard** 默认仅监听 `127.0.0.1`，不直接暴露公网
- 🛡️ 编辑 `/etc/waf-honeypot-collector.env` 填入真实 Token / API Key

---

## 项目结构

```
├── main.py                 # CLI 入口
├── config.yaml.example     # 示例配置
├── requirements.txt        # 依赖清单
├── app/                    # 基础设施
│   ├── config.py           # YAML 配置加载
│   ├── db.py               # SQLite 操作封装
│   ├── logger.py           # 日志配置
│   └── utils.py            # 工具函数
├── collectors/             # 数据采集
│   ├── safeline_syslog.py  # SafeLine Syslog 接收
│   └── hfish_api.py        # HFish API 客户端
├── parsers/                # 日志解析
│   ├── safeline_parser.py  # Syslog JSON 提取
│   └── hfish_parser.py     # HFish 字段提取
├── analyzers/              # 分析引擎
│   ├── normalizer.py       # 事件标准化
│   ├── normalizer_runner.py# 标准化执行器
│   ├── ioc_extractor.py    # IOC 提取
│   ├── profiler.py         # 攻击源画像
│   ├── risk_scorer.py      # 风险评分
│   ├── correlator.py       # 关联分析
│   └── attack_mapper.py    # ATT&CK 映射
├── ai/                     # AI 辅助
│   ├── deepseek_client.py  # DeepSeek API 客户端
│   └── prompts.py          # Prompt 模板
├── reports/                # 报告生成
│   ├── markdown_report.py  # Markdown 报告
│   └── templates/          # Jinja2 模板
├── web/                    # Web Dashboard
│   ├── server.py           # FastAPI 应用
│   ├── routes.py           # 路由
│   ├── templates/          # 页面模板
│   └── static/             # 静态文件
├── scripts/                # 辅助脚本
│   ├── mock_syslog.py      # Syslog 发送模拟
│   └── backup_db.sh        # 数据库备份
├── tests/                  # 测试（113 个）
├── deploy/                 # systemd 服务文件
└── docs/                   # 文档
```

---

## 技术栈

| 类别 | 技术 | 用途 |
|------|------|------|
| 语言 | Python 3.10+ | 主开发语言 |
| 数据库 | SQLite | 数据持久化（零依赖） |
| 配置 | YAML | 配置文件 |
| CLI | argparse | 命令行接口 |
| 测试 | pytest | 单元测试（113 个） |
| HTTP | requests | API 客户端 |
| Web（可选） | FastAPI + Jinja2 + Bootstrap 5 | Web Dashboard |
| 图表（可选） | ECharts 5 | Dashboard 可视化 |
| AI（可选） | DeepSeek API | 辅助研判 |
| 部署 | systemd | 服务托管 |

---

## 安全声明

- ✅ 本项目仅用于 **安全运营学习** 和 **授权环境** 下的攻击流量观测
- ✅ API Key / Token 从 **环境变量** 读取，不写入代码或配置文件
- ✅ `config.yaml` 已被 `.gitignore` 排除，**不会提交 Git**
- ✅ Web Dashboard 默认仅监听 `127.0.0.1`，**不直接暴露公网**
- ❌ 不进行主动漏洞扫描
- ❌ 不进行自动封禁
- ❌ 不实现木马/免杀/攻击工具

---

## 项目边界

本项目 **不是** 完整商业 SOC / SIEM，以下功能不在范围内：

- ❌ 多租户权限系统
- ❌ 实时告警推送
- ❌ 分布式部署
- ❌ 自动响应/封禁
- ❌ 大规模资产测绘
- ❌ Docker 容器化（可选但非依赖）
- ❌ ELK / Kafka / Redis 集成

---

## 许可证

MIT License — 详见 [LICENSE](LICENSE) 文件。

---

## 参考链接

- [SafeLine 雷池 WAF](https://github.com/chaitin/SafeLine)
- [HFish 蜜罐](https://github.com/hacklcx/HFish)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [DeepSeek API](https://platform.deepseek.com/)
