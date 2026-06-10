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

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 配置
cp config.yaml.example config.yaml
vim config.yaml

# 3. 初始化数据库
python main.py init-db

# 4. 启动 SafeLine Syslog 接收
python main.py recv-safeline

# 5. 拉取 HFish 日志（单次）
python main.py collect-hfish
```

## CLI 命令

| 命令 | 说明 |
|------|------|
| `init-db` | 初始化数据库 |
| `recv-safeline` | 启动 SafeLine Syslog 接收 |
| `collect-hfish` | 单次拉取 HFish 日志 |
| `collect-hfish-loop` | 循环拉取 HFish 日志 |
| `normalize` | 标准化事件 |
| `extract-ioc` | 提取 IOC |
| `build-profiles` | 构建攻击源画像 |
| `correlate` | 关联分析 |
| `map-attack` | ATT&CK 映射 |
| `report --ip 1.2.3.4` | 生成报告 |
| `ai-summary --ip 1.2.3.4` | AI 辅助研判 |
| `web` | 启动 Web Dashboard |

## 项目结构

```
├── main.py               # CLI 入口
├── app/                   # 基础设施（config, db, logger）
├── collectors/            # 数据采集器
├── parsers/               # 日志解析器
├── analyzers/             # 分析引擎
├── reports/               # 报告生成
├── ai/                    # AI 辅助（可选）
├── web/                   # Web Dashboard（可选）
├── scripts/               # 辅助脚本
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
