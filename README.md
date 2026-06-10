# WAF Honeypot Collector

基于 SafeLine WAF 与 HFish 蜜罐的轻量级安全事件采集与关联分析平台。

## 项目简介

对接 SafeLine（雷池 WAF）和 HFish（蜜罐）的安全日志，实现：

1. **日志采集** — Syslog 接收 WAF 日志，API 拉取蜜罐日志
2. **原始保存** — 完整保留原始日志，支持溯源和重解析
3. **事件标准化** — 将异构日志统一为标准事件格式
4. **IOC 提取** — 自动化提取威胁情报指标
5. **攻击源画像** — 按 IP 聚合攻击行为，构建攻击者画像
6. **关联分析** — 识别多源命中、多阶段攻击
7. **ATT&CK 映射** — 映射到 MITRE ATT&CK 框架
8. **报告生成** — 输出结构化 Markdown 安全分析报告
9. **AI 辅助研判**（可选）— 接入 DeepSeek API 生成分析摘要

## 快速开始

### 安装

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置
cp config.yaml.example config.yaml
vim config.yaml
```

### Phase 1: SafeLine Syslog 接收

```bash
# 3. 初始化数据库
python main.py init-db

# 4. 启动 SafeLine Syslog 接收（前台阻塞）
python main.py recv-safeline

# 5. 另一个终端使用 mock 工具发送测试日志
python scripts/mock_syslog.py --count 5

# 6. 查看入库日志
python main.py show-latest --mode raw_safeline

# 7. 查看统计
python main.py stats
```

### Phase 2: HFish 蜜罐接入与事件标准化

```bash
# 8. 单次拉取 HFish 攻击日志
python main.py collect-hfish

# 9. 循环拉取 HFish 日志（前台阻塞，默认间隔 60 秒）
python main.py collect-hfish-loop

# 10. 标准化待处理的原始日志
python main.py normalize

# 11. 查看标准化事件
python main.py show-latest

# 12. 按 IP 查询
python main.py show-ip --ip 10.0.0.1
```

### SafeLine WAF 配置

在 SafeLine 管理界面配置 Syslog 转发：

| 配置项 | 值 |
|--------|-----|
| 类型 | Syslog (UDP) |
| 地址 | 你的 VPS IP |
| 端口 | 1514 |

### HFish 蜜罐配置

在 `config.yaml` 中配置 HFish 接入信息：

```yaml
hfish:
  enabled: true
  api_url: "http://your-hfish-server:5000"
  auth_type: token
  api_token: ""               # 从环境变量 HFISH_API_TOKEN 读取
  api_path: "/api/v1/attack"  # ⚠️ 随 HFish 版本可能变化
  interval: 60
```

> **⚠️ 注意：** HFish API 的 `api_path` 在不同版本中可能不同。默认值 `/api/v1/attack` 基于常见版本，但不保证在所有版本中可用。
>
> **建议：** 登录 HFish 后台，打开浏览器开发者工具（F12）→ Network 标签，找到攻击日志相关的 API 请求，确认实际路径后配置到 `api_path`。
>
> 如果 HFish 启用了认证，请优先使用 Token 方式（`auth_type: token`），Token 设置到环境变量 `HFISH_API_TOKEN`。账号密码方式（`auth_type: password`）作为备选。

### Mock 测试

```bash
# 发送 10 条默认样本
python scripts/mock_syslog.py --count 10

# 指定目标地址和端口
python scripts/mock_syslog.py --host 192.168.1.100 --port 1514

# 控制发送间隔
python scripts/mock_syslog.py --count 100 --interval 0.1

# 发送无 JSON 的无效报文（测试解析失败不崩溃）
python scripts/mock_syslog.py --count 3 --invalid
```

## CLI 命令

### 已实现命令（Phase 0-2）

| 命令 | 说明 |
|------|------|
| `init-db` | 初始化数据库 |
| `recv-safeline` | 启动 SafeLine Syslog 接收 |
| `show-latest` | 查看最近事件（支持 `--source`, `--mode` 筛选） |
| `stats` | 查看扩展统计信息（含所有数据源） |
| `collect-hfish` | 单次拉取 HFish 日志 |
| `collect-hfish-loop` | 循环拉取 HFish 日志（`--interval` 指定间隔） |
| `normalize` | 标准化待处理的原始日志（支持 `--source` 筛选） |
| `show-ip --ip 1.2.3.4` | 按 IP 查询标准化事件 |

### 规划中命令（后续 Phase）

| 命令 | 说明 | 计划阶段 |
|------|------|----------|
| `collect-hfish` | 单次拉取 HFish 日志 | Phase 2 |
| `collect-hfish-loop` | 循环拉取 HFish 日志 | Phase 2 |
| `normalize` | 标准化事件 | Phase 3 |
| `extract-ioc` | 提取 IOC | Phase 3 |
| `build-profiles` | 构建攻击源画像 | Phase 3 |
| `correlate` | 关联分析 | Phase 3 |
| `map-attack` | ATT&CK 映射 | Phase 4 |
| `report --ip 1.2.3.4` | 生成报告 | Phase 4 |
| `ai-summary --ip 1.2.3.4` | AI 辅助研判 | Phase 5 |
| `web` | 启动 Web Dashboard | Phase 6 |
| `ai-summary --ip 1.2.3.4` | AI 辅助研判 | Phase 5 |
| `web` | 启动 Web Dashboard | Phase 6 |

## 项目结构

```
├── main.py               # CLI 入口
├── app/                   # 基础设施（config, db, logger, utils）
├── collectors/            # 数据采集器
├── parsers/               # 日志解析器
├── analyzers/             # 分析引擎
├── reports/               # 报告生成
├── ai/                    # AI 辅助（可选）
├── web/                   # Web Dashboard（可选）
├── scripts/               # 辅助脚本（mock_syslog 等）
├── tests/                 # 测试
├── deploy/                # 部署配置
└── docs/                  # 文档
```

## 技术栈

- Python 3.10+ / SQLite / YAML
- requests / PyYAML / argparse
- pytest / FastAPI（可选）/ Bootstrap（可选）

## 安全声明

- 本项目仅用于安全运营学习和授权环境下的攻击流量观测
- 不进行主动漏洞扫描
- 不进行自动封禁
- 不提交真实配置和 API Key 到 Git
- Web Dashboard 默认仅监听 127.0.0.1

## License

MIT
