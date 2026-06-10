# 基于 WAF 与蜜罐的安全事件采集与关联分析平台

## 开发计划文档

**项目代号：** waf-honeypot-collector

**版本：** v1.0

**日期：** 2026-06-10

**前置文档：** `docs/requirements.md`

---

## 目录

1. [开发总体原则](#一开发总体原则)
2. [技术选型](#二技术选型)
3. [最终项目目录结构](#三最终项目目录结构)
4. [Phase 0：项目初始化与文档建设](#phase-0项目初始化与文档建设)
5. [Phase 1：SafeLine Syslog MVP](#phase-1safeline-syslog-mvp)
6. [Phase 2：HFish API 接入与事件标准化](#phase-2hfish-api-接入与事件标准化)
7. [Phase 3：IOC、攻击画像与关联分析](#phase-3ioc攻击画像与关联分析)
8. [Phase 4：ATT&CK 映射与 Markdown 报告](#phase-4attck-映射与-markdown-报告)
9. [Phase 5：DeepSeek API 辅助研判](#phase-5deepseek-api-辅助研判)
10. [Phase 6：Web Dashboard](#phase-6web-dashboard)
11. [Phase 7：部署与运维](#phase-7部署与运维)
12. [Phase 8：项目打磨与简历包装](#phase-8项目打磨与简历包装)
13. [下一步执行建议](#十三下一步执行建议)

---

## 一、开发总体原则

### 1.1 核心开发顺序

```
先接数据 → 再做分析 → 先 CLI → 再 Web → 先规则 → 再 AI
```

1. **先原始日志，再标准化事件** — 保留一切原始数据，再考虑结构化；
2. **先 CLI，再 Web** — 功能先通过命令行可用，再考虑可视化；
3. **先规则分析，再 AI 辅助** — 核心判断由规则引擎完成，AI 仅做辅助；
4. **先最小可用版本，再逐步增强** — 每个阶段产出可运行、可验证的成果。

### 1.2 阶段开发纪律

1. 每个阶段都必须有**可运行成果**；
2. 每个阶段完成后必须 **Git commit**，打上阶段标签；
3. **不跨阶段开发** — 当前阶段未完成不进入下一阶段；
4. 不引入重型依赖；
5. 不把 API Key、Token、密码写入代码；
6. 不把真实配置提交 Git；
7. 不自动封禁 IP；
8. 不做主动扫描；
9. 不暴露 Web Dashboard 到公网；
10. 所有原始日志必须保留。

### 1.3 代码质量要求

1. **模块职责单一**：一个模块只做一件事；
2. **Collector、Parser、Normalizer、Analyzer 完全解耦**；
3. 配置集中管理（`config.yaml`），代码中不散落配置常量；
4. 数据库操作集中封装（`app/db.py`），业务代码不直接拼接 SQL；
5. 日志统一输出（`app/logger.py`），所有模块使用同一日志配置；
6. 关键函数必须写 docstring；
7. 异常必须有处理逻辑，不允许顶层裸抛。

---

## 二、技术选型

### 2.1 使用清单

| 类别 | 技术 | 版本要求 | 用途 |
|------|------|----------|------|
| 语言 | Python | 3.10+ | 主开发语言 |
| 数据库 | SQLite | 内置 | 数据持久化 |
| 配置 | YAML | — | 配置文件格式 |
| CLI 框架 | argparse（标准库） | 内置 | 命令行参数解析 |
| 日志 | logging（标准库） | 内置 | 统一日志输出 |
| HTTP 客户端 | requests | 第三方 | HFish API 调用 / DeepSeek API 调用 |
| YAML 解析 | PyYAML | 第三方 | 加载 config.yaml |
| 测试框架 | pytest | 第三方 | 单元测试和集成测试 |
| Web 框架 | FastAPI | Phase 6+ | Web Dashboard 后端 |
| 模板引擎 | Jinja2 | Phase 6+ | Web 页面渲染 |
| 前端 UI | Bootstrap 5 | Phase 6+ | Web 页面样式 |
| AI 接入 | OpenAI-compatible SDK 或 requests | Phase 5+ | DeepSeek API 调用 |

### 2.2 禁止使用清单

| 技术 | 原因 |
|------|------|
| Docker | 增加部署复杂度，低配 VPS 资源有限 |
| Redis | 重型缓存，本项目 SQLite 足够 |
| Kafka | 消息队列，超出本项目需求 |
| ELK（Elasticsearch / Logstash / Kibana） | 重量级日志方案，资源消耗大 |
| Celery | 分布式任务队列，单机不需要 |
| MySQL / PostgreSQL | 重型关系数据库，SQLite 完全胜任 |
| MongoDB | 文档数据库，SQLite + JSON 字段可替代 |
| Vue / React | 大型前端框架，Bootstrap + Jinja2 即可 |
| Node.js | 引入不必要的运行时依赖 |

### 2.3 依赖清单（requirements.txt）

```txt
# Phase 1-5 核心依赖
PyYAML>=6.0
requests>=2.28.0

# Phase 2 可选
# 无新增依赖

# Phase 5 可选（DeepSeek API）
# openai>=1.0.0  或直接使用 requests

# Phase 6 Web Dashboard
# fastapi>=0.104.0
# uvicorn>=0.24.0
# jinja2>=3.1.2
# aiofiles>=23.2.1

# 开发/测试依赖
# pytest>=7.4.0

# 运行：pip install pyyaml requests
# 全功能：pip install pyyaml requests fastapi uvicorn jinja2 aiofiles
# 测试：pip install pytest
```

---

## 三、最终项目目录结构

### 3.1 完整目录树

```
waf-honeypot-collector/
│
├── main.py                          # CLI 入口，分发子命令
├── requirements.txt                 # Python 依赖清单
├── config.yaml.example              # 示例配置文件（不含真实密钥）
├── README.md                        # 项目说明文档
├── CLAUDE.md                        # Claude Code 项目上下文配置
├── .gitignore                       # Git 忽略规则
│
├── docs/                            # 项目文档目录
│   ├── requirements.md              # 需求文档
│   ├── development_plan.md          # 开发计划（本文档）
│   ├── architecture.md              # 架构设计文档（Phase 8）
│   └── deployment.md                # 部署运维文档（Phase 7）
│
├── app/                             # 核心应用模块
│   ├── __init__.py                  # 包初始化
│   ├── config.py                    # 配置加载（YAML -> dict）
│   ├── db.py                        # 数据库初始化与操作封装
│   ├── logger.py                    # 日志统一配置
│   └── utils.py                     # 通用工具函数
│
├── collectors/                      # 数据采集器
│   ├── __init__.py                  # 包初始化
│   ├── safeline_syslog.py           # SafeLine Syslog UDP 接收服务
│   └── hfish_api.py                 # HFish API 客户端（拉取与循环）
│
├── parsers/                         # 日志解析器
│   ├── __init__.py                  # 包初始化
│   ├── safeline_parser.py           # SafeLine Syslog -> 结构化字段
│   └── hfish_parser.py              # HFish JSON -> 结构化字段
│
├── analyzers/                       # 安全分析引擎
│   ├── __init__.py                  # 包初始化
│   ├── normalizer.py                # 事件标准化：原始->统一格式
│   ├── ioc_extractor.py             # IOC 提取
│   ├── profiler.py                  # 攻击源画像构建
│   ├── correlator.py                # 关联分析引擎
│   ├── attack_mapper.py             # ATT&CK 映射
│   └── risk_scorer.py               # 风险评分引擎
│
├── reports/                         # 报告生成模块
│   ├── __init__.py                  # 包初始化
│   ├── markdown_report.py           # Markdown 报告生成器
│   └── templates/                   # 报告模板
│       └── ip_report.md.j2          # IP 报告 Jinja2 模板
│
├── ai/                              # AI 辅助分析（可选）
│   ├── __init__.py                  # 包初始化
│   ├── deepseek_client.py           # DeepSeek API 客户端
│   └── prompts.py                   # AI Prompt 模板
│
├── web/                             # Web Dashboard（可选）
│   ├── __init__.py                  # 包初始化
│   ├── server.py                    # FastAPI 应用入口
│   ├── routes.py                    # Web 路由定义
│   ├── templates/                   # Jinja2 页面模板
│   │   ├── base.html                # 基础布局
│   │   ├── index.html               # 首页概览
│   │   ├── events.html              # 事件列表
│   │   └── ip_detail.html           # IP 详情页
│   └── static/                      # 静态资源
│       └── style.css                # 自定义样式
│
├── scripts/                         # 辅助脚本（非核心模块）
│   ├── mock_syslog.py               # 模拟 SafeLine Syslog 发送
│   ├── replay_samples.py            # 重放测试样本
│   └── export_samples.py            # 从数据库导出样本
│
├── tests/                           # 测试目录
│   ├── __init__.py                  # 包初始化
│   ├── conftest.py                  # pytest 共享 fixture
│   ├── fixtures/                    # 测试样本数据
│   │   ├── safeline_samples.json    # SafeLine 样本日志
│   │   └── hfish_samples.json       # HFish 样本日志
│   ├── test_safeline_parser.py      # SafeLine Parser 单元测试
│   ├── test_hfish_parser.py         # HFish Parser 单元测试
│   ├── test_normalizer.py           # Normalizer 单元测试
│   └── test_ioc_extractor.py        # IOC Extractor 单元测试
│
├── deploy/                          # 部署配置文件
│   ├── waf-honeypot-safeline.service  # SafeLine Receiver systemd 服务
│   ├── waf-honeypot-hfish.service     # HFish Collector systemd 服务
│   └── waf-honeypot-web.service       # Web Dashboard systemd 服务
│
└── data/                            # 数据文件（Git 忽略）
    ├── collector.db                 # SQLite 数据库文件
    └── backups/                     # 数据库备份目录
```

### 3.2 目录职责说明

| 目录/文件 | 职责 |
|-----------|------|
| `main.py` | 唯一 CLI 入口。根据子命令分发到对应模块，不包含业务逻辑 |
| `app/` | 基础设施：配置加载、数据库连接、日志配置、通用工具 |
| `collectors/` | 数据采集层：对接外部数据源（SafeLine Syslog / HFish API），负责数据接收和拉取 |
| `parsers/` | 解析层：将原始日志从数据源格式解析为结构化字段，不关心存储 |
| `analyzers/` | 分析层：标准化、IOC 提取、画像、关联、ATT&CK 映射、风险评分 |
| `reports/` | 报告生成层：将分析结果组装为 Markdown 报告 |
| `ai/` | AI 辅助层：封装 DeepSeek API 调用、Prompt 管理、结果缓存 |
| `web/` | Web 展示层：FastAPI 应用、路由、模板、静态文件 |
| `scripts/` | 调试和辅助工具：Mock Syslog、样本重放、数据导出 |
| `tests/` | 测试代码和测试样本数据 |
| `deploy/` | 部署配置：systemd 服务文件 |
| `data/` | 运行时数据：SQLite 数据库文件、备份 |

### 3.3 目录创建顺序

```
Phase 0:  main.py, requirements.txt, config.yaml.example, README.md, CLAUDE.md,
          .gitignore, docs/, app/, data/
Phase 1:  collectors/safeline_syslog.py, parsers/safeline_parser.py,
          scripts/mock_syslog.py, tests/fixtures/
Phase 2:  collectors/hfish_api.py, parsers/hfish_parser.py,
          analyzers/normalizer.py
Phase 3:  analyzers/ioc_extractor.py, analyzers/profiler.py,
          analyzers/correlator.py, analyzers/risk_scorer.py
Phase 4:  analyzers/attack_mapper.py, reports/
Phase 5:  ai/
Phase 6:  web/
Phase 7:  deploy/
Phase 8:  文档完善、refine
```

---

## Phase 0：项目初始化与文档建设

### 4.1 本阶段目标

搭建项目骨架，完成基础设施和文档建设，使项目具备 Git 仓库基础和可运行的最小框架。

### 4.2 需要创建的文件

| 文件 | 说明 |
|------|------|
| `.gitignore` | 忽略 Python 缓存、数据库、配置文件、日志、虚拟环境 |
| `CLAUDE.md` | Claude Code 项目上下文配置 |
| `README.md` | 项目说明，包含简介、架构、快速开始、CLI 说明 |
| `config.yaml.example` | 示例配置文件，含所有配置项和注释，不含真实密钥 |
| `requirements.txt` | Python 依赖清单 |
| `main.py` | CLI 入口，支持 `init-db` 命令 |
| `docs/requirements.md` | 需求文档（已存在） |
| `docs/development_plan.md` | 开发计划文档（本文档） |
| `app/__init__.py` | 空包初始化文件 |
| `app/config.py` | 配置加载模块，支持读取 `config.yaml` 并返回字典 |
| `app/db.py` | 数据库初始化，创建所有核心表结构 |
| `app/logger.py` | 日志配置，统一日志格式 |
| `data/` | 数据存储目录（placeholder） |

### 4.3 `.gitignore` 内容建议

```gitignore
# Python
__pycache__/
*.py[cod]
*.egg-info/
dist/
build/
*.egg
.venv/
venv/

# IDE
.vscode/
.idea/

# 配置文件（含真实密钥）
config.yaml

# 数据库
data/collector.db
data/backups/

# 日志
logs/
*.log

# 报告输出
reports/output/

# OS
.DS_Store
Thumbs.db
```

### 4.4 `CLAUDE.md` 内容建议

```markdown
# waf-honeypot-collector

## 项目概述
基于 SafeLine WAF 与 HFish 蜜罐的轻量级安全事件采集与关联分析平台。

## 技术栈
- Python 3.10+ / SQLite / YAML / argparse / logging
- FastAPI + Jinja2 + Bootstrap（Phase 6+）
- pytest / requests / PyYAML

## 开发原则
- 先原始日志，再标准化事件
- 先 CLI，再 Web
- 先规则分析，再 AI 辅助
- 每个阶段完成后必须 git commit
- 不跨阶段开发

## 目录结构
- app/ — 基础设施（config, db, logger）
- collectors/ — 数据采集
- parsers/ — 日志解析
- analyzers/ — 分析引擎
- reports/ — 报告生成
- ai/ — AI 辅助（可选）
- web/ — Web Dashboard（可选）
- tests/ — 测试

## 配置
- 配置文件名: config.yaml
- 示例配置: config.yaml.example
- API Key 从环境变量读取，不写入代码
```

### 4.5 验收标准

1. [ ] `git init` 完成，`.gitignore` 生效；
2. [ ] `python main.py init-db` 可正常执行且不报错；
3. [ ] 数据库文件 `data/collector.db` 生成成功；
4. [ ] 数据库包含所有预期表（Phase 0 创建 `raw_safeline_logs` + `raw_hfish_events` 两张基础表）；
5. [ ] `config.yaml.example` 包含所有配置项的结构和注释；
6. [ ] `main.py --help` 显示所有已注册的子命令。

### 4.6 本阶段不做

- ❌ 任何日志采集功能
- ❌ 任何事件解析
- ❌ 任何分析功能
- ❌ 安装第三方依赖（仅创建 requirements.txt）
- ❌ HFish API 接入
- ❌ Web Dashboard

### 4.7 给 Claude Code 的 Phase 0 执行提示词

```
请执行 Phase 0：项目初始化与文档建设。

当前文档 docs/requirements.md 和 docs/development_plan.md 已完成。

请完成以下任务：

1. 初始化 Git 仓库；
2. 创建 .gitignore 文件；
3. 创建 CLAUDE.md 文件；
4. 创建 README.md 初始版本；
5. 创建 config.yaml.example（包含所有配置项，注释完整，不含真实密钥）；
6. 创建 requirements.txt（pyyaml, requests, pytest）；
7. 创建 app/__init__.py；
8. 创建 app/config.py，实现 YAML 配置加载函数 load_config(path)；
9. 创建 app/db.py，实现：
   - init_db() 函数，创建 raw_safeline_logs 和 raw_hfish_events 两张表；
   - get_connection() 函数，返回数据库连接；
10. 创建 app/logger.py，实现日志配置 setup_logging(level)；
11. 创建 main.py，注册 init-db 子命令；
12. 创建 data/ 目录（放入 .gitkeep）。

要求：
- 配置文件路径默认值为项目根目录下的 config.yaml；
- 数据库路径默认值为 data/collector.db；
- 所有文件编码 UTF-8；
- 代码中包含 docstring 和关键注释；
- 执行 python main.py init-db 验证数据库能正常初始化；
- 完成后 git add + git commit，提交信息为 "Phase 0: 项目初始化与文档建设"。

不要做 Phase 1 的任何内容（不要写 Syslog 接收、不要写 mock_syslog）。
```

---

## Phase 1：SafeLine Syslog MVP

### 5.1 本阶段目标

实现 SafeLine WAF Syslog 日志接入的最小可用版本。能够接收 SafeLine 通过 UDP Syslog 发出的日志，完整保存原始报文，并尝试提取 JSON 结构。

**本阶段只做 SafeLine，不做 HFish，不做 IOC，不做 AI，不做 Web。**

### 5.2 模块设计

#### 5.2.1 数据流

```
SafeLine WAF ──UDP Syslog──→ collectors/safeline_syslog.py
                                       │
                                       ▼
                              raw_safeline_logs 表
                                       │
                              parsers/safeline_parser.py
                                       │
                              JSON 提取 + 解析状态标记
```

#### 5.2.2 模块分工

| 模块 | 文件 | 职责 |
|------|------|------|
| Collector | `collectors/safeline_syslog.py` | 启动 UDP Socket 监听，接收 Syslog 报文，写入原始日志表 |
| Parser | `parsers/safeline_parser.py` | 从 Syslog 报文中提取 JSON 部分，尝试解析字段 |
| CLI 接口 | `main.py` | 注册 `recv-safeline`、`show-latest`、`stats` 子命令 |

### 5.3 文件清单

| 文件 | 创建/修改 | 说明 |
|------|----------|------|
| `collectors/__init__.py` | 新建 | 包初始化 |
| `collectors/safeline_syslog.py` | 新建 | Syslog UDP 接收服务 |
| `parsers/__init__.py` | 新建 | 包初始化 |
| `parsers/safeline_parser.py` | 新建 | SafeLine 日志解析器 |
| `scripts/__init__.py` | 新建 | 包初始化 |
| `scripts/mock_syslog.py` | 新建 | 模拟 Syslog 发送脚本 |
| `tests/__init__.py` | 新建 | 包初始化 |
| `tests/conftest.py` | 新建 | pytest fixture：测试用数据库 |
| `tests/fixtures/safeline_samples.json` | 新建 | SafeLine 样本日志 |
| `tests/test_safeline_parser.py` | 新建 | Parser 单元测试 |
| `main.py` | 修改 | 注册 Phase 1 子命令 |
| `app/config.py` | 修改 | 补充 SafeLine 配置项默认值 |

### 5.4 数据表设计

#### raw_safeline_logs

此表在 Phase 0 的 `init-db` 中创建，Phase 1 确保字段完整。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 自增主键 |
| `received_at` | TEXT | NOT NULL | 接收时间（ISO 8601） |
| `sender_ip` | TEXT | NULLABLE | 发送源 IP（UDP 包来源地址） |
| `raw_message` | TEXT | NOT NULL | Syslog 原始报文全文 |
| `parsed_json` | TEXT | NULLABLE | 从 Syslog 提取的 JSON 部分（如有） |
| `parse_status` | TEXT | NOT NULL DEFAULT 'pending' | 解析状态：`pending`/`parsed`/`failed`/`partial` |
| `error_message` | TEXT | NULLABLE | 解析错误信息 |
| `created_at` | TEXT | NOT NULL | 记录创建时间 |

索引：

```sql
CREATE INDEX idx_safeline_parse_status ON raw_safeline_logs(parse_status);
CREATE INDEX idx_safeline_received_at ON raw_safeline_logs(received_at);
```

### 5.5 CLI 设计

| 命令 | 功能 | 示例 |
|------|------|------|
| `init-db` | 初始化数据库（Phase 0 已实现） | `python main.py init-db` |
| `recv-safeline` | 启动 Syslog 接收服务（前台阻塞，Ctrl+C 退出） | `python main.py recv-safeline` |
| `recv-safeline --port 514` | 指定端口 | `python main.py recv-safeline --port 514` |
| `show-latest` | 显示最近 N 条原始日志 | `python main.py show-latest` |
| `show-latest --limit 50` | 指定显示条数 | `python main.py show-latest --limit 50` |
| `stats` | 显示基本统计信息 | `python main.py stats` |

全局参数：

- `--config PATH`：指定配置文件路径
- `--debug`：覆盖日志级别为 DEBUG

### 5.6 Mock 调试方式

使用 `scripts/mock_syslog.py` 模拟 SafeLine 发送 Syslog 报文：

```bash
# 启动接收端（终端 1）
python main.py recv-safeline

# 发送模拟日志（终端 2）
python scripts/mock_syslog.py --host 127.0.0.1 --port 1514
python scripts/mock_syslog.py --host 127.0.0.1 --port 1514 --file tests/fixtures/safeline_samples.json
python scripts/mock_syslog.py --host 127.0.0.1 --port 1514 --count 100 --interval 0.5
```

### 5.7 测试流程

1. **单元测试**：`pytest tests/test_safeline_parser.py`
   - 测试有效 JSON 提取；
   - 测试无效 Syslog 不崩溃，返回 `failed` 状态；
   - 测试字段缺失场景；
   - 测试字段类型异常场景。
2. **集成测试**：
   - 启动 `recv-safeline`；
   - 使用 `mock_syslog.py` 发送样本；
   - 使用 `show-latest` 验证日志入库；
   - 使用 `stats` 验证统计信息。
3. **容错测试**：
   - 发送非 JSON 字符串；
   - 发送超长报文；
   - 发送空报文；
   - 同时在多个终端发送。

### 5.8 验收标准

1. [ ] `python main.py recv-safeline` 启动后监听 `0.0.0.0:1514/udp`；
2. [ ] 发送 Syslog 报文后，`show-latest` 能显示入库日志；
3. [ ] 原始日志完整保存在 `raw_message` 字段，不截断；
4. [ ] JSON 被正确提取到 `parsed_json` 字段；
5. [ ] 无效 Syslog 不崩溃，`parse_status` 正确标记为 `failed`；
6. [ ] `mock_syslog.py` 可正常发送测试数据；
7. [ ] `pytest tests/test_safeline_parser.py -v` 全部通过；
8. [ ] Ctrl+C 可优雅退出 `recv-safeline`。

### 5.9 本阶段不做

- ❌ HFish 任何功能
- ❌ 事件标准化（`normalized_events` 表）
- ❌ IOC 提取
- ❌ 攻击画像
- ❌ 关联分析
- ❌ ATT&CK 映射
- ❌ AI 辅助分析
- ❌ Web Dashboard

### 5.10 给 Claude Code 的 Phase 1 执行提示词

```
请执行 Phase 1：SafeLine Syslog MVP。

当前文档已完成，Phase 0 的基础结构（main.py, app/config.py, app/db.py, app/logger.py）已就位。

请完成以下任务：

1. 创建 collectors/__init__.py；
2. 创建 collectors/safeline_syslog.py：
   - 实现 SafeLineSyslogReceiver 类；
   - 创建 UDP Socket 监听配置端口（默认 0.0.0.0:1514）；
   - 接收 Syslog 报文，提取发送方 IP；
   - 调用 db 模块将原始报文写入 raw_safeline_logs 表；
   - 调用 parser 尝试解析 JSON；
   - 记录解析状态（pending/parsed/failed/partial）；
   - 实现优雅退出（signal handler 处理 SIGINT/SIGTERM）；
   - 单条日志解析异常不崩溃；
3. 创建 parsers/__init__.py；
4. 创建 parsers/safeline_parser.py：
   - 实现 parse_syslog_message(raw_message) 函数；
   - 从 Syslog 报文中提取 JSON 部分（查找第一个 { 到最后一个 }）；
   - 尝试 json.loads 解析；
   - 返回提取的 JSON 字符串、解析状态、错误信息；
   - 严格不抛出异常，所有异常捕获后返回 failed 状态；
5. 修改 main.py，注册以下子命令：
   - recv-safeline：启动 Syslog 接收服务；
   - show-latest：显示最近 N 条原始日志；
   - stats：显示总量、解析状态统计；
6. 创建 scripts/__init__.py；
7. 创建 scripts/mock_syslog.py：
   - 支持 --host, --port, --count, --interval 参数；
   - 支持 --file 从样本文件读取内容发送；
   - 无文件时发送内置模拟 Syslog 报文；
8. 创建 tests/__init__.py；
9. 创建 tests/conftest.py（提供临时数据库 fixture）；
10. 创建 tests/fixtures/safeline_samples.json（至少 5 条不同场景的样本）；
11. 创建 tests/test_safeline_parser.py（至少 5 个测试用例覆盖正常/异常场景）。

测试验证：
- python main.py recv-safeline --debug 启动服务；
- 新终端执行 python scripts/mock_syslog.py --count 5；
- python main.py show-latest 可见入库日志；
- python main.py stats 显示统计；
- pytest tests/test_safeline_parser.py -v 全部通过。

完成后 git commit，提交信息为 "Phase 1: SafeLine Syslog MVP"。
```

---

## Phase 2：HFish API 接入与事件标准化

### 6.1 本阶段目标

接入 HFish 蜜罐事件 API，完成两数据源的事件标准化，建立统一事件模型。

### 6.2 模块设计

#### 6.2.1 数据流

```
HFish API ──HTTP──→ collectors/hfish_api.py
                           │
                           ▼
                  raw_hfish_events 表
                           │
                  parsers/hfish_parser.py
                           │
                           ▼
             ┌── parsers/safeline_parser.py ──┐
             │                                 │
             ▼                                 ▼
      analyzers/normalizer.py ───→ normalized_events 表
```

#### 6.2.2 模块分工

| 模块 | 文件 | 职责 |
|------|------|------|
| Collector | `collectors/hfish_api.py` | HFish API 客户端，支持单次拉取和循环拉取 |
| Parser | `parsers/hfish_parser.py` | 解析 HFish JSON 为结构化字段 |
| Normalizer | `analyzers/normalizer.py` | 将 SafeLine 和 HFish 结构化数据统一为标准化格式 |
| CLI 接口 | `main.py` | 注册 Phase 2 子命令 |

### 6.3 文件清单

| 文件 | 创建/修改 | 说明 |
|------|----------|------|
| `collectors/hfish_api.py` | 新建 | HFish API 客户端 |
| `parsers/hfish_parser.py` | 新建 | HFish 日志解析器 |
| `analyzers/__init__.py` | 新建 | 包初始化 |
| `analyzers/normalizer.py` | 新建 | 事件标准化引擎 |
| `tests/fixtures/hfish_samples.json` | 新建 | HFish 样本日志 |
| `tests/test_hfish_parser.py` | 新建 | HFish Parser 单元测试 |
| `tests/test_normalizer.py` | 新建 | Normalizer 单元测试 |
| `main.py` | 修改 | 注册 Phase 2 子命令 |
| `app/config.py` | 修改 | 补充 HFish 配置项 |
| `app/db.py` | 修改 | 新增 `raw_hfish_events`、`normalized_events` 表的初始化 |

### 6.4 数据表设计

#### raw_hfish_events

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 自增主键 |
| `raw_data` | TEXT | NOT NULL | API 返回的完整 JSON |
| `event_id` | TEXT | UNIQUE | HFish 事件唯一 ID（用于去重） |
| `parse_status` | TEXT | NOT NULL DEFAULT 'pending' | 解析状态 |
| `error_message` | TEXT | NULLABLE | 解析错误信息 |
| `received_at` | TEXT | NOT NULL | 拉取时间（ISO 8601） |
| `created_at` | TEXT | NOT NULL | 记录创建时间 |

索引：

```sql
CREATE UNIQUE INDEX idx_hfish_event_id ON raw_hfish_events(event_id);
CREATE INDEX idx_hfish_parse_status ON raw_hfish_events(parse_status);
```

#### normalized_events

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 自增主键 |
| `source` | TEXT | NOT NULL | 数据源：`safeline` / `hfish` |
| `source_event_id` | TEXT | NULLABLE | 原始事件 ID |
| `event_time` | TEXT | NOT NULL | 事件时间（ISO 8601） |
| `src_ip` | TEXT | NOT NULL | 攻击者源 IP |
| `src_port` | INTEGER | NULLABLE | 源端口 |
| `dst_ip` | TEXT | NULLABLE | 目标 IP |
| `dst_port` | INTEGER | NULLABLE | 目标端口 |
| `protocol` | TEXT | NULLABLE | 协议 |
| `http_method` | TEXT | NULLABLE | HTTP 方法 |
| `host` | TEXT | NULLABLE | Host |
| `uri` | TEXT | NULLABLE | URI |
| `user_agent` | TEXT | NULLABLE | User-Agent |
| `attack_type` | TEXT | NULLABLE | 攻击类型 |
| `severity` | TEXT | NULLABLE | 严重级别 |
| `payload` | TEXT | NULLABLE | Payload |
| `raw_table` | TEXT | NOT NULL | 来源原始表名 |
| `raw_id` | INTEGER | NOT NULL | 来源原始表记录 ID |
| `created_at` | TEXT | NOT NULL | 本条记录创建时间 |

索引：

```sql
CREATE INDEX idx_normalized_src_ip ON normalized_events(src_ip);
CREATE INDEX idx_normalized_event_time ON normalized_events(event_time);
CREATE INDEX idx_normalized_source ON normalized_events(source);
CREATE INDEX idx_normalized_attack_type ON normalized_events(attack_type);
CREATE INDEX idx_normalized_ip_time ON normalized_events(src_ip, event_time);
CREATE UNIQUE INDEX idx_normalized_source_event ON normalized_events(source, source_event_id);
```

### 6.5 配置新增项

```yaml
hfish:
  enabled: true
  api_url: "http://your-hfish-server:5000"
  auth_type: token          # token | password
  api_token: ""             # 留空，从环境变量 HFISH_API_TOKEN 读取
  username: ""              # auth_type=password 时使用
  password: ""              # 留空，从环境变量 HFISH_PASSWORD 读取
  api_path: /api/v1/attack
  interval: 60              # 循环拉取间隔（秒）
  page_size: 100
  enable_normalization: true
```

### 6.6 CLI 设计

| 命令 | 功能 | 示例 |
|------|------|------|
| `collect-hfish` | 单次拉取 HFish 攻击日志 | `python main.py collect-hfish` |
| `collect-hfish-loop` | 循环拉取（前台阻塞） | `python main.py collect-hfish-loop` |
| `collect-hfish-loop --interval 120` | 指定拉取间隔 | `python main.py collect-hfish-loop --interval 120` |
| `normalize` | 对未标准化的原始日志执行标准化 | `python main.py normalize` |
| `normalize --source safeline` | 仅标准化 SafeLine | `python main.py normalize --source safeline` |
| `show-ip --ip 1.2.3.4` | 显示指定 IP 的事件 | `python main.py show-ip --ip 1.2.3.4` |
| `show-latest` | 显示最近 N 条标准化事件 | `python main.py show-latest`（增强，现支持原始/标准化切换） |
| `stats` | 统计信息增强 | `python main.py stats`（增加数据源分布统计） |

### 6.7 HFish API 适配策略

1. **认证方式**：先尝试 Token 认证；若未配置 Token，回退到账号密码认证；
2. **分页拉取**：使用 `page` 和 `page_size` 参数遍历所有页；
3. **超时设置**：HTTP 请求超时默认 15 秒，可配置；
4. **重试策略**：请求失败等待下次拉取周期，不自动重试（避免雪崩效应）；
5. **接口适配**：HFish API 返回格式变化时，记录警告日志，不崩溃。

### 6.8 去重策略

1. **基于 `event_id` 去重**：`raw_hfish_events` 表的 `event_id` 字段设置 UNIQUE 约束；
2. **SQLite 层面去重**：插入时使用 `INSERT OR IGNORE`，重复 `event_id` 自动跳过；
3. **日志记录**：去重跳过的记录记录 DEBUG 级别日志，方便调试；
4. **全量拉取**：每次拉取 API 当前所有数据，不维护拉取游标（HFish API 不保证线性递增）。

### 6.9 测试流程

1. **单元测试**：
   - `pytest tests/test_hfish_parser.py` — 测试 HFish JSON 解析；
   - `pytest tests/test_normalizer.py` — 测试 SafeLine 和 HFish 到统一格式的转换；
   - 测试无效 JSON、缺失字段、字段类型异常等容错场景。
2. **Mock 测试**：
   - 使用样本文件模拟 HFish API 响应（无需真实 HFish 实例）；
   - 验证 `collect-hfish` 在无 HFish 环境下降级输出提示信息。
3. **去重验证**：
   - 重复拉取同一批样本，验证入库记录不重复。

### 6.10 验收标准

1. [ ] `collect-hfish` 可执行（无 HFish 时输出提示信息，不崩溃）；
2. [ ] HFish 原始 JSON 完整入库到 `raw_hfish_events`；
3. [ ] `event_id` 去重生效，重复拉取不产生重复记录；
4. [ ] `normalize` 将 SafeLine 和 HFish 事件正确标准化为统一格式；
5. [ ] `normalized_events` 表数据可通过 `show-ip --ip X.X.X.X` 查询；
6. [ ] `stats` 显示 SafeLine/HFish 的事件数量分布；
7. [ ] `pytest tests/test_hfish_parser.py -v` 全部通过；
8. [ ] `pytest tests/test_normalizer.py -v` 全部通过。

### 6.11 本阶段不做

- ❌ IOC 提取
- ❌ 攻击画像
- ❌ 关联分析
- ❌ ATT&CK 映射
- ❌ 报告生成
- ❌ AI 辅助分析

### 6.12 给 Claude Code 的 Phase 2 执行提示词

```
请执行 Phase 2：HFish API 接入与事件标准化。

Phase 1 已完成，SafeLine Syslog 接收和原始日志入库功能已就位。

请完成以下任务：

1. 创建 collectors/hfish_api.py：
   - 实现 HFishCollector 类；
   - 支持 Token 认证（优先）和账号密码认证（回退）；
   - 实现 fetch_once() 单次拉取方法；
   - 实现 fetch_loop(interval) 循环拉取方法；
   - API URL、Token/密码从配置和环境变量读取；
   - 分页拉取，每页条数可配置；
   - 使用 INSERT OR IGNORE 基于 event_id 去重；
   - 完整保存原始 JSON 到 raw_data 字段；
   - 所有异常捕获记录日志，不崩溃；

2. 创建 parsers/hfish_parser.py：
   - 实现 parse_hfish_event(raw_json) 函数；
   - 从 HFish 事件中提取 attacker_ip, attacker_port, protocol, target_port,
     username, password, command, event_time, event_id 等字段；
   - 容错：字段缺失不崩溃，返回 partial 状态；

3. 创建 analyzers/__init__.py；
4. 创建 analyzers/normalizer.py：
   - 实现 normalize_safeline(parsed_data) → 标准化事件字典；
   - 实现 normalize_hfish(parsed_data) → 标准化事件字典；
   - 实现 normalize_pending() 遍历未标准化的原始记录进行标准化；
   - 已标准化的记录（parse_status != 'pending'）跳过；
   - 标准化结果写入 normalized_events 表；
   - 原始记录的 parse_status 更新为 'normalized'；

5. 修改 app/db.py，init_db() 新增 raw_hfish_events 和 normalized_events 表；

6. 修改 main.py，注册以下子命令：
   - collect-hfish（单次拉取）
   - collect-hfish-loop（循环拉取，--interval 参数）
   - normalize（标准化待处理事件）
   - show-ip --ip X.X.X.X（查询 IP 相关事件）
   - 增强 show-latest 支持 --source 过滤

7. 创建 tests/fixtures/hfish_samples.json（至少 5 条不同场景样本）；
8. 创建 tests/test_hfish_parser.py（至少 5 个测试用例）；
9. 创建 tests/test_normalizer.py（至少 5 个测试用例覆盖两数据源）。

测试验证：
- pytest tests/test_hfish_parser.py -v
- pytest tests/test_normalizer.py -v
- python main.py normalize（对已有 safeline 日志做标准化）
- python main.py show-latest
- python main.py stats

完成后 git commit，提交信息为 "Phase 2: HFish API 接入与事件标准化"。
```

---

## Phase 3：IOC、攻击画像与关联分析

### 7.1 本阶段目标

让项目从日志采集器升级为安全事件分析平台。实现 IOC 提取、攻击源画像构建、风险评分和基础关联分析。

**风险评分必须由规则引擎完成，不由 AI 决定。**

### 7.2 模块设计

#### 7.2.1 数据流

```
normalized_events 表
    │
    ├──→ analyzers/ioc_extractor.py ──→ iocs 表
    │
    ├──→ analyzers/profiler.py ──→ attacker_profiles 表
    │
    ├──→ analyzers/risk_scorer.py ──→ 更新 attacker_profiles.risk_score
    │
    └──→ analyzers/correlator.py ──→ 更新 attacker_profiles.tags, is_multi_source
```

#### 7.2.2 模块分工

| 模块 | 文件 | 职责 |
|------|------|------|
| IOC Extractor | `analyzers/ioc_extractor.py` | 从标准化事件中提取各类 IOC |
| Profiler | `analyzers/profiler.py` | 构建和更新攻击源画像 |
| Risk Scorer | `analyzers/risk_scorer.py` | 基于规则计算风险评分和等级 |
| Correlator | `analyzers/correlator.py` | 多源关联、多阶段攻击、扫描行为识别 |

### 7.3 文件清单

| 文件 | 创建/修改 | 说明 |
|------|----------|------|
| `analyzers/ioc_extractor.py` | 新建 | IOC 提取引擎 |
| `analyzers/profiler.py` | 新建 | 攻击源画像构建 |
| `analyzers/risk_scorer.py` | 新建 | 风险评分引擎 |
| `analyzers/correlator.py` | 新建 | 关联分析引擎 |
| `tests/test_ioc_extractor.py` | 新建 | IOC 提取单元测试 |
| `main.py` | 修改 | 注册 Phase 3 子命令 |
| `app/db.py` | 修改 | 新增 `iocs`、`attacker_profiles` 表初始化 |

### 7.4 数据表设计

#### iocs

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 自增主键 |
| `ioc_type` | TEXT | NOT NULL | IOC 类型：ip/uri/url/host/user_agent/payload/filename/suspicious_path/hfish_username/hfish_password |
| `ioc_value` | TEXT | NOT NULL | IOC 值 |
| `source` | TEXT | NOT NULL | 来源数据源 |
| `src_ip` | TEXT | NULLABLE | 关联的攻击源 IP |
| `normalized_event_id` | INTEGER | NULLABLE | 关联的标准化事件 ID |
| `first_seen` | TEXT | NOT NULL | 首次出现时间 |
| `last_seen` | TEXT | NOT NULL | 最近出现时间 |
| `count` | INTEGER | NOT NULL DEFAULT 1 | 出现次数 |
| `context` | TEXT | NULLABLE | 额外上下文（JSON） |
| `created_at` | TEXT | NOT NULL | 记录创建时间 |
| UNIQUE(ioc_type, ioc_value) | — | — | 同类型同值的 IOC 合并为一条记录 |

索引：

```sql
CREATE UNIQUE INDEX idx_iocs_type_value ON iocs(ioc_type, ioc_value);
CREATE INDEX idx_iocs_src_ip ON iocs(src_ip);
CREATE INDEX idx_iocs_event_id ON iocs(normalized_event_id);
```

#### attacker_profiles

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 自增主键 |
| `src_ip` | TEXT | UNIQUE NOT NULL | 攻击源 IP |
| `first_seen` | TEXT | NOT NULL | 首次出现时间 |
| `last_seen` | TEXT | NOT NULL | 最近活跃时间 |
| `safeline_count` | INTEGER | NOT NULL DEFAULT 0 | SafeLine 事件数 |
| `hfish_count` | INTEGER | NOT NULL DEFAULT 0 | HFish 事件数 |
| `total_count` | INTEGER | NOT NULL DEFAULT 0 | 事件总数 |
| `attack_types` | TEXT | NULLABLE | 攻击类型及次数（JSON） |
| `protocols` | TEXT | NULLABLE | 协议分布（JSON） |
| `is_multi_source` | INTEGER | NOT NULL DEFAULT 0 | 是否多源命中（0/1） |
| `risk_score` | INTEGER | NOT NULL DEFAULT 0 | 风险评分（0-100） |
| `risk_level` | TEXT | NOT NULL DEFAULT 'low' | 风险等级 |
| `tags` | TEXT | NULLABLE | 风险标签（JSON 数组） |
| `last_event_time` | TEXT | NULLABLE | 最近一次事件时间 |
| `updated_at` | TEXT | NOT NULL | 画像更新时间 |

索引：

```sql
CREATE UNIQUE INDEX idx_profiles_ip ON attacker_profiles(src_ip);
CREATE INDEX idx_profiles_risk ON attacker_profiles(risk_score);
CREATE INDEX idx_profiles_count ON attacker_profiles(total_count);
```

### 7.5 IOC 提取规则

| IOC 类型 | 提取来源 | 提取规则 |
|----------|----------|----------|
| `ip` | `normalized_events.src_ip` | 正则校验 IPv4 格式；可选是否排除私有地址 |
| `uri` | `normalized_events.uri` | 排除常见静态资源后缀（.jpg/.png/.css/.js/.ico/.svg） |
| `url` | host + uri | http://{host}{uri} 拼接 |
| `host` | `normalized_events.host` | 直接提取 |
| `user_agent` | `normalized_events.user_agent` | 提取并尝试识别工具指纹（sqlmap/curl/nmap 等） |
| `payload` | `normalized_events.payload` | 截断至最大长度（默认 4096） |
| `filename` | uri 路径最后一段 | 排除 `/` 结尾的纯路径 |
| `suspicious_path` | uri | 正则匹配：`\.git`, `\.env`, `/web-inf/`, `/admin/`, `/backup/`, `/wp-admin/` 等 |
| `hfish_username` | `normalized_events.payload` | HFish 事件中提取 username 字段 |
| `hfish_password` | `normalized_events.payload` | HFish 事件中提取 password 字段 |

### 7.6 风险评分规则

风险评分 = 基础分 + 各项加分，上限 100 分。

| 评分规则 | 加分 | 说明 |
|----------|------|------|
| 命中 SafeLine WAF | +10/事件 | 每条标准化事件 |
| 命中 HFish 蜜罐 | +15/事件 | 蜜罐命中通常意味着主动探测或攻击 |
| 多源命中 | +30 | 同一 IP 同时出现在 SafeLine 和 HFish |
| 高频事件（>50 条/小时） | +15 | 短时间大量事件 |
| SQL 注入攻击 | +20 | 攻击类型为 SQL 注入 |
| XSS 攻击 | +15 | 攻击类型为 XSS |
| 敏感文件探测 | +15 | 访问 `.git/`、`.env` 等敏感路径 |
| SSH 爆破 | +20 | HFish 中 SSH 协议登录尝试 |
| Redis/MySQL 爆破 | +20 | HFish 中对应协议登录尝试 |
| 多协议探测（≥3 种） | +15 | 使用 3 种及以上协议 |
| 多阶段攻击 | +25 | 同时满足 Web 探测 + 服务爆破 |

**风险等级：**

| 等级 | 评分区间 |
|------|----------|
| 低 Low | 0-19 |
| 中 Medium | 20-49 |
| 高 High | 50-79 |
| 严重 Critical | 80-100 |

### 7.7 风险标签规则

| 标签 | 触发条件 | 实现方式 |
|------|----------|----------|
| `Web 扫描` | 事件 attack_type 包含 scan/dirbust/directory 关键词 | 字符串匹配 |
| `SQL 注入尝试` | attack_type 包含 sql/injection/sqli | 字符串匹配 |
| `XSS 尝试` | attack_type 包含 xss | 字符串匹配 |
| `敏感文件探测` | uri 匹配敏感路径正则 | 正则匹配 |
| `弱口令爆破` | HFish 事件中同一 IP + 同一协议出现 ≥3 次不同密码 | 计数统计 |
| `多协议探测` | 同一 IP 使用 ≥3 种不同协议 | 协议去重计数 |
| `多源命中` | 同一 IP 同时出现在 SafeLine 和 HFish 日志中 | SQL JOIN 查询 |
| `高频攻击源` | 同一 IP 事件数 > 50/小时 | 时间窗口计数 |
| `高风险攻击源` | risk_score ≥ 50 | 评分阈值判断 |

### 7.8 关联分析规则

| 规则 | 实现方式 | 输出 |
|------|----------|------|
| CORR-001 多源命中 | 查询同一 IP 是否在两个数据源均有事件 | 标记 is_multi_source, 加标签 |
| CORR-002 多类型攻击 | 同一 IP 去重 attack_type 超过阈值 | 添加标签，提升评分 |
| CORR-003 多阶段攻击 | SafeLine 事件在前 + HFish 非 HTTP 协议事件在后 | 标记关联对，添加标签 |
| CORR-004 扫描行为 | 高频访问 + 敏感路径 + 多个不同 URI | 添加 Web 扫描标签 |
| CORR-005 Payload 检测 | payload 字段匹配 SQL/XSS/CMD 正则 | 确认攻击类型标签 |

### 7.9 测试流程

1. **单元测试**：
   - `pytest tests/test_ioc_extractor.py` — 测试每种 IOC 类型的提取；
   - 测试无效/边界输入（空字段、超长文本、特殊字符）。
2. **规则测试**：
   - 构造多源命中场景，验证 `is_multi_source` 正确标记；
   - 构造高频场景，验证风险评分正确累加；
   - 验证风险等级分界点正确（19→low, 20→medium 等）。
3. **集成测试**：
   - `python main.py extract-ioc` → `python main.py build-profiles` → `python main.py correlate`；
   - 验证数据一致性和幂等性（重复运行结果不翻倍）。

### 7.10 验收标准

1. [ ] `extract-ioc` 从现有标准化事件中正确提取 IOC；
2. [ ] 同一类型+同一值的 IOC 合并为一条记录，`count` 累加；
3. [ ] `build-profiles` 构建的攻击源画像字段准确；
4. [ ] 风险评分计算符合规则预期，不出现超出 0-100 范围的值；
5. [ ] 风险等级按区间正确划分；
6. [ ] `correlate` 正确识别多源命中 IP；
7. [ ] `show-profile --ip X.X.X.X` 显示完整画像信息；
8. [ ] `top-ip` 显示 Top N 攻击源 IP；
9. [ ] 重复运行分析命令（extract-ioc / build-profiles / correlate）不产生重复数据；
10. [ ] `pytest tests/test_ioc_extractor.py -v` 全部通过。

### 7.11 本阶段不做

- ❌ ATT&CK 映射
- ❌ 报告生成
- ❌ AI 辅助分析
- ❌ Web Dashboard

### 7.12 给 Claude Code 的 Phase 3 执行提示词

```
请执行 Phase 3：IOC、攻击画像与关联分析。

Phase 2 已完成，SafeLine 和 HFish 的日志接入和标准化已就位，normalized_events 表有数据。

请完成以下任务：

1. 创建 analyzers/ioc_extractor.py：
   - 实现 extract_iocs(event_row) → 返回 IOC 字典列表；
   - 支持提取 ip/uri/url/host/user_agent/payload/filename/suspicious_path/hfish_username/hfish_password；
   - 同类型同值 IOC 使用 INSERT OR REPLACE 合并，count 累加；
   - 实现 extract_all_pending() 处理所有未提取 IOC 的标准化事件；

2. 创建 analyzers/profiler.py：
   - 实现 build_profile(src_ip) 从 normalized_events 聚合数据；
   - 实现 build_all_profiles(rebuild=False) 全量重建画像；
   - 实现 update_profile(event_row) 增量更新单条事件对应的画像；
   - 统计 safeline_count, hfish_count, total_count, attack_types, protocols；

3. 创建 analyzers/risk_scorer.py：
   - 实现 calculate_score(profile_data, events) → (score, level)；
   - 完全基于规则计算，不接受 AI 输入；
   - 实现所有评分规则，上限 100 分；
   - 根据评分区间返回风险等级；

4. 创建 analyzers/correlator.py：
   - 实现 correlate_all() 执行所有关联规则；
   - CORR-001：多源命中检测（JOIN 查询同一 IP 在 SafeLine 和 HFish 均有数据）；
   - CORR-002：多类型攻击检测；
   - CORR-003：多阶段攻击检测（Web 探测 + 服务爆破时间序列）；
   - CORR-004：扫描行为检测（高频 + 敏感路径）；
   - CORR-005：Payload 特征检测；
   - 关联结果更新 attacker_profiles 的 tags 和 is_multi_source 字段；

5. 修改 app/db.py，init_db() 新增 iocs 和 attacker_profiles 表；

6. 修改 main.py，注册以下子命令：
   - extract-ioc
   - build-profiles（支持 --rebuild 参数）
   - show-profile --ip X.X.X.X
   - top-ip（支持 --sort risk_score|total_count，默认 top 10）
   - correlate

7. 创建 tests/test_ioc_extractor.py：
   - 测试所有 IOC 类型的提取；
   - 测试无效输入（None/空字符串/异常格式）；
   - 测试 payload 截断；
   - 测试敏感路径正则匹配；
   - 至少 8 个测试用例。

测试验证：
- python main.py extract-ioc
- python main.py build-profiles
- python main.py correlate
- python main.py show-profile --ip <测试IP>
- python main.py top-ip
- pytest tests/test_ioc_extractor.py -v

完成后 git commit，提交信息为 "Phase 3: IOC、攻击画像与关联分析"。
```

---

## Phase 4：ATT&CK 映射与 Markdown 报告

### 8.1 本阶段目标

实现 MITRE ATT&CK 映射和结构化的 Markdown 安全报告生成，形成安全运营闭环。

### 8.2 模块设计

#### 8.2.1 数据流

```
normalized_events + attacker_profiles
    │
    ├──→ analyzers/attack_mapper.py ──→ attack_mappings 表（可选）
    │
    └──→ reports/markdown_report.py
              │
              ▼
        Markdown 报告文件
```

#### 8.2.2 模块分工

| 模块 | 文件 | 职责 |
|------|------|------|
| Attack Mapper | `analyzers/attack_mapper.py` | 基于规则将攻击行为映射到 ATT&CK 技术 |
| Report Generator | `reports/markdown_report.py` | 按 IP 生成完整 Markdown 分析报告 |
| Report Template | `reports/templates/ip_report.md.j2` | 报告模板（Jinja2） |

### 8.3 文件清单

| 文件 | 创建/修改 | 说明 |
|------|----------|------|
| `analyzers/attack_mapper.py` | 新建 | ATT&CK 规则映射 |
| `reports/__init__.py` | 新建 | 包初始化 |
| `reports/markdown_report.py` | 新建 | Markdown 报告生成 |
| `reports/templates/ip_report.md.j2` | 新建 | 报告 Jinja2 模板 |
| `main.py` | 修改 | 注册 Phase 4 子命令 |
| `app/db.py` | 修改 | 新增 `attack_mappings` 表初始化（可选） |

### 8.4 报告模板结构

报告使用 Jinja2 模板 `ip_report.md.j2` 生成，包含以下章节：

```markdown
# 攻击源分析报告

## 1. 摘要
- **攻击源 IP：** {{ ip }}
- **风险评分：** {{ profile.risk_score }}/100
- **风险等级：** {{ profile.risk_level }}
- **风险标签：** {{ profile.tags | join(', ') }}
- **数据源：** {{ '多源命中' if profile.is_multi_source else '单源' }}

## 2. 时间信息
- **首次出现：** {{ profile.first_seen }}
- **最近活跃：** {{ profile.last_seen }}
- **活跃时长：** {{ duration }}

## 3. 数据源命中
| 数据源 | 事件数 |
|--------|--------|
| SafeLine WAF | {{ profile.safeline_count }} |
| HFish 蜜罐 | {{ profile.hfish_count }} |

## 4. 攻击类型分布
{% for type, count in attack_types %}
- **{{ type }}**：{{ count }} 次
{% endfor %}

## 5. 攻击时间线
| 时间 | 数据源 | 攻击类型 | 目标 |
|------|--------|----------|------|
{% for event in timeline %}
| {{ event.event_time }} | {{ event.source }} | {{ event.attack_type }} | {{ event.uri or event.protocol }} |
{% endfor %}

## 6. IOC 列表
| 类型 | 值 | 首次出现 |
|------|-----|----------|
{% for ioc in iocs %}
| {{ ioc.ioc_type }} | `{{ ioc.ioc_value }}` | {{ ioc.first_seen }} |
{% endfor %}

## 7. ATT&CK 映射
| 攻击行为 | 技术 ID | 技术名称 |
|----------|---------|----------|
{% for mapping in attack_mappings %}
| {{ mapping.attack_behavior }} | {{ mapping.technique_id }} | {{ mapping.technique_name }} |
{% endfor %}

## 8. 处置建议
{{ remediation }}

## 9. 原始事件索引
- SafeLine 原始日志 ID 列表：{{ safeline_raw_ids }}
- HFish 原始事件 ID 列表：{{ hfish_raw_ids }}
```

### 8.5 ATT&CK 映射规则

| 攻击行为/攻击类型 | 匹配条件 | MITRE 技术 ID | MITRE 技术名称 |
|------------------|----------|---------------|---------------|
| 扫描探测 | attack_type 包含 scan/dirbust/directory/probe/探测 | T1595 | Active Scanning |
| Web 漏洞利用 | attack_type 包含 sql/xss/rce/lfi/command/注入 | T1190 | Exploit Public-Facing Application |
| 暴力破解 | protocol 为 SSH/Redis/MySQL 且 attack_type 包含 brute/auth/爆破 | T1110 | Brute Force |
| 密码猜测 | 存在 username/password 字段值 | T1110.001 | Password Guessing |
| 命令执行 | attack_type 包含 command/exec/rce/payload 含命令特征 | T1059 | Command and Scripting Interpreter |
| 凭据尝试 | source=hfish 且存在 username/password | T1555 | Credentials from Password Stores |

### 8.6 CLI 设计

| 命令 | 功能 | 示例 |
|------|------|------|
| `map-attack` | 对所有未映射的事件执行 ATT&CK 映射 | `python main.py map-attack` |
| `map-attack --rebuild` | 重建全部映射 | `python main.py map-attack --rebuild` |
| `report --ip 1.2.3.4` | 生成指定 IP 的报告，输出到终端 | `python main.py report --ip 1.2.3.4` |
| `report --ip 1.2.3.4 --output report.md` | 导出到文件 | `python main.py report --ip 1.2.3.4 --output report.md` |
| `report --ip 1.2.3.4 --output reports/output/` | 自动命名导出到目录 | `python main.py report --ip 1.2.3.4 --output reports/output/` |
| `report --all` | 为所有画像 IP 生成报告 | `python main.py report --all` |

### 8.7 测试流程

1. **单元测试**：
   - 测试每个 attack_type 到 ATT&CK 技术的映射；
   - 测试未知攻击类型的降级处理（映射为 `T1595 Active Scanning` 或 `Unknown`）；
   - 测试报告模板渲染（使用模拟数据）；
2. **集成测试**：
   - `python main.py map-attack` 验证映射结果写入；
   - `python main.py report --ip <测试IP>` 验证报告完整输出。

### 8.8 验收标准

1. [ ] `map-attack` 对现有标准化事件完成 ATT&CK 映射；
2. [ ] 映射结果正确关联到攻击行为；
3. [ ] 未知攻击类型有合理的默认映射；
4. [ ] `report --ip X.X.X.X` 生成完整的 Markdown 报告；
5. [ ] 报告包含全部 9 个章节，数据准确；
6. [ ] `report --ip X.X.X.X --output file.md` 正确写入文件；
7. [ ] `report --all` 对所有 IP 生成报告。

### 8.9 本阶段不做

- ❌ AI 辅助分析
- ❌ Web Dashboard
- ❌ 自动报告推送（邮件/IM）

### 8.10 给 Claude Code 的 Phase 4 执行提示词

```
请执行 Phase 4：ATT&CK 映射与 Markdown 报告。

Phase 3 已完成，IOC 提取、攻击画像、风险评分和关联分析已就位。

请完成以下任务：

1. 创建 analyzers/attack_mapper.py：
   - 实现 map_event_to_attack(event_row) → (technique_id, technique_name)；
   - 基于 attack_type 和 source 字段做规则匹配；
   - 实现 map_all_pending() 处理所有未映射的标准化事件；
   - 实现映射表（至少 6 组基础映射）；
   - 映射结果写入 attack_mappings 表；

2. 创建 reports/__init__.py；
3. 创建 reports/templates/ip_report.md.j2（Jinja2 模板，包含 9 个章节）；
4. 创建 reports/markdown_report.py：
   - 实现 generate_report(ip) → markdown 字符串；
   - 从 attacker_profiles 获取画像摘要；
   - 从 normalized_events 获取攻击时间线；
   - 从 iocs 获取关联 IOC；
   - 从 attack_mappings 获取 ATT&CK 映射；
   - 生成处置建议（基于规则模板：按风险等级和标签输出建议）；
   - 实现 generate_all() 为所有画像 IP 生成报告；
   - 支持 --output 参数指定输出路径；

5. 修改 app/db.py，init_db() 新增 attack_mappings 表；

6. 修改 main.py，注册以下子命令：
   - map-attack（支持 --rebuild）
   - report --ip X.X.X.X（支持 --output, --all）

测试验证：
- python main.py map-attack
- python main.py report --ip <测试IP>
- python main.py report --ip <测试IP> --output reports/output/test.md
- python main.py report --all

完成后 git commit，提交信息为 "Phase 4: ATT&CK 映射与 Markdown 报告"。
```

---

## Phase 5：DeepSeek API 辅助研判

### 9.1 本阶段目标

接入 DeepSeek API，让系统可以生成更自然的安全研判摘要和报告正文。

**AI 只做辅助，不参与核心规则判断。**

### 9.2 模块设计

#### 9.2.1 数据流

```
用户请求 ──→ ai/prompts.py（组装结构化摘要）
                 │
                 ▼
         ai/deepseek_client.py（API 调用）
                 │
                 ▼
         AI 响应 → 缓存 → 嵌入报告
```

#### 9.2.2 模块分工

| 模块 | 文件 | 职责 |
|------|------|------|
| API 客户端 | `ai/deepseek_client.py` | DeepSeek API HTTP 调用封装 |
| Prompt 管理 | `ai/prompts.py` | 各类 Prompt 模板定义 |
| 缓存 | `ai_analysis_cache` 表（可选） | 缓存 AI 结果避免重复调用 |

### 9.3 文件清单

| 文件 | 创建/修改 | 说明 |
|------|----------|------|
| `ai/__init__.py` | 新建 | 包初始化 |
| `ai/deepseek_client.py` | 新建 | DeepSeek API 客户端 |
| `ai/prompts.py` | 新建 | Prompt 模板 |
| `main.py` | 修改 | 注册 `ai-summary` 子命令 |
| `app/db.py` | 修改 | 新增 `ai_analysis_cache` 表初始化（可选） |

### 9.4 DeepSeek 配置设计

```yaml
deepseek:
  enabled: false                  # 默认禁用
  provider: deepseek              # 供应商标识
  base_url: "https://api.deepseek.com"
  model: "deepseek-chat"          # 模型名称
  api_key_env: "DEEPSEEK_API_KEY" # 环境变量名
  timeout: 30                     # 请求超时（秒）
  max_tokens: 1200                # 最大生成 Token 数
```

API Key 从环境变量 `DEEPSEEK_API_KEY` 读取，**不写入代码，不提交 Git**。

### 9.5 Prompt 设计原则

| 原则 | 说明 |
|------|------|
| 结构化输入 | 只传入结构化的攻击摘要数据，不传原始全文日志 |
| 明确的角色 | System Prompt 设定安全分析师角色 |
| 输出格式控制 | 要求 AI 按指定 Markdown 格式输出 |
| 不暴露密钥 | Prompt 中不包含任何凭证信息 |
| 不替代规则 | Prompt 明确禁止 AI 修改评分或做决断 |
| 可降级 | AI 调用失败时使用规则生成的默认文本 |

### 9.6 AI 输入数据结构

```python
{
    "ip": "1.2.3.4",
    "risk_score": 65,
    "risk_level": "high",
    "tags": ["多源命中", "SQL 注入尝试", "SSH 爆破"],
    "total_events": 128,
    "safeline_events": 80,
    "hfish_events": 48,
    "attack_types": {
        "SQL Injection": 35,
        "Directory Scan": 28,
        "SSH Brute Force": 40,
        "XSS": 15,
        "Sensitive File Probe": 10
    },
    "protocols": ["HTTP", "SSH", "Redis"],
    "first_seen": "2026-06-01T10:00:00",
    "last_seen": "2026-06-10T08:30:00",
    "is_multi_source": true,
    "sample_payloads": ["' OR 1=1 --", "<script>alert(1)</script>"],
    "sample_usernames": ["root", "admin"],
    "ioc_count": 15
}
```

### 9.7 AI 输出内容

| 输出类型 | 说明 |
|----------|------|
| 攻击行为摘要 | 2-3 段自然语言描述该 IP 的攻击行为模式 |
| Payload 解释 | 对典型 Payload 进行技术解释 |
| 报告正文润色 | 将结构化报告改写为安全运营报告风格 |
| 处置建议 | 基于攻击行为的推荐处置步骤 |

### 9.8 安全限制

| 限制 | 实现方式 |
|------|----------|
| AI 不修改风险评分 | 评分仅由规则引擎写入，AI 输出不写回评分字段 |
| AI 不执行命令 | `deepseek_client.py` 只做 HTTP API 调用，不调用 subprocess |
| AI 不自动封禁 | 本项目不实现封禁功能 |
| AI 不删除日志 | 无日志删除接口暴露给 AI 模块 |
| AI 不直接处理原始日志 | 传入的是结构化摘要，非原始全文 |
| API Key 安全 | 从环境变量读取，不硬编码 |
| 超时保护 | HTTP 请求设置 timeout，超时后降级 |
| 降级策略 | AI 不可用时使用规则生成默认文本 |

### 9.9 CLI 设计

| 命令 | 功能 | 示例 |
|------|------|------|
| `ai-summary --ip 1.2.3.4` | 使用 AI 生成攻击摘要 | `python main.py ai-summary --ip 1.2.3.4` |
| `report --ip 1.2.3.4 --with-ai` | 报告集成 AI 研判内容 | `python main.py report --ip 1.2.3.4 --with-ai` |

### 9.10 测试流程

1. **Mock 测试**：
   - 使用 Mock HTTP 响应模拟 DeepSeek API，不依赖真实 API；
   - 测试 API 超时降级；
   - 测试 API 返回异常的降级处理。
2. **集成测试**：
   - 配置 `DEEPSEEK_API_KEY` 环境变量后测试真实 API 调用（可选）；
   - 验证 AI 输出正确嵌入报告。
3. **缓存测试**：
   - 重复请求同一 IP，验证缓存命中，不重复调用 API。

### 9.11 验收标准

1. [ ] `ai-summary --ip X.X.X.X` 在有 API Key 时可生成摘要；
2. [ ] API Key 从环境变量读取，不在代码/配置中明文存储；
3. [ ] AI 调用超时/失败时输出提示信息，不阻塞主流程；
4. [ ] `report --with-ai` 生成包含 AI 研判内容的报告；
5. [ ] 报告中的 AI 部分与规则部分清晰分离（标注来源）；
6. [ ] 缓存机制有效（可选）；
7. [ ] AI 不修改 risk_score / risk_level 字段。

### 9.12 本阶段不做

- ❌ AI 替代规则引擎
- ❌ AI 直接接触原始全文日志
- ❌ AI 修改风险评分
- ❌ AI 自动封禁
- ❌ AI 删除任何数据
- ❌ Web Dashboard 集成 AI 功能

### 9.13 给 Claude Code 的 Phase 5 执行提示词

```
请执行 Phase 5：DeepSeek API 辅助研判。

Phase 4 已完成，ATT&CK 映射和 Markdown 报告生成已就位。

请完成以下任务：

1. 创建 ai/__init__.py；
2. 创建 ai/prompts.py：
   - 实现 get_system_prompt() —— 安全分析师角色设定；
   - 实现 get_summary_prompt(ip_data) —— 生成攻击行为摘要的 prompt；
   - 实现 get_payload_explain_prompt(payloads) —— 解释 Payload 的 prompt；
   - 实现 get_remediation_prompt(profile) —— 生成处置建议的 prompt；
   - Prompt 中明确禁止 AI 修改评分、执行命令、访问敏感信息；

3. 创建 ai/deepseek_client.py：
   - 实现 DeepSeekClient 类；
   - __init__ 从配置和环境变量读取 API Key 和参数；
   - 实现 chat_completion(messages, **kwargs) → response_text；
   - 实现 generate_summary(ip_data) → 攻击摘要；
   - 实现 explain_payload(payloads) → Payload 解释；
   - 实现 generate_remediation(profile) → 处置建议；
   - 所有方法设置 timeout，异常捕获后返回 None + 日志；
   - 可选：实现 AI 分析结果缓存（ai_analysis_cache 表）；

4. 修改 reports/markdown_report.py：
   - 支持 --with-ai 参数；
   - AI 可用时用 AI 生成攻击摘要和处置建议；
   - AI 不可用时使用规则生成的默认文本；
   - AI 输出内容在报告中标注 [AI 辅助生成]；

5. 修改 main.py，注册以下子命令：
   - ai-summary --ip X.X.X.X
   - 增强 report 支持 --with-ai 参数

6. 修改 app/db.py，可选新增 ai_analysis_cache 表。

测试验证：
- python main.py ai-summary --ip <测试IP>（无 API Key 时输出提示）
- python main.py report --ip <测试IP> --with-ai
- 验证 AI 内容在报告中正确显示
- 验证无 API Key 时正常降级

完成后 git commit，提交信息为 "Phase 5: DeepSeek API 辅助研判"。
```

---

## Phase 6：Web Dashboard

### 10.1 本阶段目标

实现轻量 Web 管理界面，提供可视化安全数据浏览，让项目适合展示和答辩。

### 10.2 模块设计

#### 10.2.1 架构

```
用户浏览器 ←→ FastAPI (uvicorn) ←→ SQLite
                  │
            Jinja2 模板
                  │
            Bootstrap 5 前端
```

#### 10.2.2 模块分工

| 模块 | 文件 | 职责 |
|------|------|------|
| 应用入口 | `web/server.py` | FastAPI 应用创建、uvicorn 启动 |
| 路由 | `web/routes.py` | 所有页面路由和 API 数据接口 |
| 模板 | `web/templates/` | Jinja2 页面模板 |
| 静态文件 | `web/static/` | CSS、JS 等静态资源 |

### 10.3 文件清单

| 文件 | 创建/修改 | 说明 |
|------|----------|------|
| `web/__init__.py` | 新建 | 包初始化 |
| `web/server.py` | 新建 | FastAPI 应用 + uvicorn 启动 |
| `web/routes.py` | 新建 | 路由定义 |
| `web/templates/base.html` | 新建 | 基础布局模板 |
| `web/templates/index.html` | 新建 | 首页概览 |
| `web/templates/events.html` | 新建 | 事件列表页 |
| `web/templates/ip_detail.html` | 新建 | IP 详情页 |
| `web/templates/iocs.html` | 新建 | IOC 列表页 |
| `web/templates/top_ip.html` | 新建 | Top 攻击源 |
| `web/templates/attack_types.html` | 新建 | 攻击类型分布 |
| `web/templates/trends.html` | 新建 | 趋势视图 |
| `web/templates/high_risk.html` | 新建 | 高风险 IP |
| `web/static/style.css` | 新建 | 自定义样式 |
| `main.py` | 修改 | 注册 `web` 子命令 |
| `config.yaml.example` | 修改 | 新增 web 配置项 |

### 10.4 页面设计

| 页面 | 路由 | 功能 |
|------|------|------|
| 首页概览 | `/` | 统计卡片：总事件数、攻击源 IP 数、IOC 数、高风险 IP 数；简单趋势图 |
| 事件列表 | `/events` | 标准化事件表格，支持按来源、攻击类型、IP 筛选，分页 |
| Top 攻击源 | `/top-ip` | 按事件数/风险评分排序的 IP 列表 |
| 攻击类型分布 | `/attack-types` | 攻击类型饼图/柱状图 |
| 趋势视图 | `/trends` | SafeLine/HFish 事件日趋势折线图 |
| 高风险 IP | `/high-risk` | 风险等级为高/严重的 IP 列表 |
| IP 详情 | `/profile/{ip}` | 单 IP 完整画像、事件时间线、IOC、ATT&CK 映射 |
| IOC 列表 | `/iocs` | IOC 表格，支持按类型筛选 |
| 报告下载 | `/report/{ip}` | 在线查看 + 下载 Markdown 报告 |

### 10.5 路由设计

```python
# 页面路由
GET  /                              # 首页概览
GET  /events                        # 事件列表（支持 ?source=&attack_type=&ip=&page= 参数）
GET  /events/{event_id}             # 事件详情
GET  /top-ip                        # Top 攻击源（支持 ?sort=risk_score|total_count）
GET  /attack-types                  # 攻击类型分布
GET  /trends                        # 趋势视图
GET  /high-risk                     # 高风险 IP
GET  /profile/{ip}                  # IP 详情画像
GET  /iocs                          # IOC 列表（支持 ?type=&ip= 参数）
GET  /report/{ip}                   # 报告在线查看

# 数据 API（用于图表异步加载）
GET  /api/stats                     # 首页统计数据
GET  /api/attack-types-distribution # 攻击类型分布数据
GET  /api/trends                    # 趋势数据
GET  /api/events                    # 事件列表 JSON
```

### 10.6 安全要求

| 要求 | 说明 |
|------|------|
| 监听地址 | 默认 `127.0.0.1`，不暴露公网 |
| 配置项 | web.host 和 web.port 可在 config.yaml 中配置 |
| 不实现认证 | 网络层隔离（SSH隧道/VPN）替代用户认证 |
| 只读界面 | Dashboard 不提供数据修改、删除、配置变更功能 |

### 10.7 SSH 隧道访问方式

```bash
# 在本地机器执行
ssh -L 8080:127.0.0.1:8080 ubuntu@your-vps-ip

# 本地浏览器打开
http://127.0.0.1:8080
```

### 10.8 测试流程

1. **功能测试**：
   - `python main.py web` 启动服务；
   - 浏览器访问 `http://127.0.0.1:8000` 验证各页面正常渲染；
   - 测试分页、筛选功能；
   - 测试报告下载。
2. **数据验证**：
   - 验证首页统计数字与 `stats` 命令输出一致；
   - 验证 IP 详情内容与 `show-profile` 命令输出一致。
3. **内存测试**：
   - 长时间运行验证内存无显著增长。

### 10.9 验收标准

1. [ ] `python main.py web` 启动 FastAPI 服务；
2. [ ] 默认监听 `127.0.0.1:8000`；
3. [ ] 首页统计卡片数据正确；
4. [ ] 事件列表可正常分页和筛选；
5. [ ] IP 详情页显示完整画像；
6. [ ] IOC 列表可筛选；
7. [ ] 报告页面可在线查看和下载；
8. [ ] 页面使用 Bootstrap 5，移动端适配良好；
9. [ ] 服务启动后内存占用 ≤512MB。

### 10.10 本阶段不做

- ❌ 用户认证/登录系统
- ❌ 配置修改界面
- ❌ 实时推送（WebSocket）
- ❌ 公网直接暴露
- ❌ 复杂的图表交互（仅基础 ECharts）

### 10.11 给 Claude Code 的 Phase 6 执行提示词

```
请执行 Phase 6：Web Dashboard。

Phase 5 已完成，DeepSeek API 辅助分析和报告生成已就位。

请完成以下任务：

1. 创建 web/__init__.py；
2. 创建 web/server.py：
   - FastAPI 应用；
   - 配置 Jinja2 模板目录和静态文件目录；
   - 注册路由；
   - uvicorn.run 启动，监听地址和端口从配置读取；
3. 创建 web/routes.py：
   - 实现所有页面路由（/、/events、/top-ip、/attack-types、/trends、/high-risk、/profile/{ip}、/iocs、/report/{ip}）；
   - 实现数据 API 路由（/api/stats、/api/attack-types-distribution、/api/trends）；
   - 数据从 SQLite 查询，不缓存（轻量设计）；
4. 创建 web/templates/base.html：
   - Bootstrap 5 CDN；
   - 导航栏（所有页面链接）；
   - 内容块（{% block content %}）；
5. 创建 web/templates/index.html（统计卡片 + 趋势图）；
6. 创建 web/templates/events.html（事件表格 + 筛选 + 分页）；
7. 创建 web/templates/ip_detail.html（完整 IP 画像）；
8. 创建 web/templates/iocs.html（IOC 表格 + 类型筛选）；
9. 创建 web/templates/top_ip.html（Top 攻击源表格）；
10. 创建 web/templates/attack_types.html（攻击类型分布图）；
11. 创建 web/templates/trends.html（趋势折线图）；
12. 创建 web/templates/high_risk.html（高风险 IP 列表）；
13. 创建 web/static/style.css（自定义样式）；
14. 修改 main.py，注册 web 子命令。

要求：
- 使用 Bootstrap 5（CDN 加载）；
- 图表使用 ECharts 5（CDN 加载）；
- 默认监听 127.0.0.1:8000；
- 所有页面响应式设计；
- 无需用户认证。

测试验证：
- pip install fastapi uvicorn jinja2 aiofiles
- python main.py web
- 浏览器访问 http://127.0.0.1:8000
- 检查各页面数据正确性

完成后 git commit，提交信息为 "Phase 6: Web Dashboard"。
```

---

## Phase 7：部署与运维

### 11.1 本阶段目标

让项目可以作为 VPS 常驻服务稳定运行，支持 systemd 托管、日志管理和数据库备份。

### 11.2 systemd 文件设计

#### SafeLine Receiver 服务

文件：`deploy/waf-honeypot-safeline.service`

```ini
[Unit]
Description=WAF Honeypot Collector - SafeLine Syslog Receiver
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/waf-honeypot-collector
ExecStart=/usr/bin/python3 /home/ubuntu/waf-honeypot-collector/main.py recv-safeline
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

#### HFish Collector 服务

文件：`deploy/waf-honeypot-hfish.service`

```ini
[Unit]
Description=WAF Honeypot Collector - HFish API Collector
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/waf-honeypot-collector
ExecStart=/usr/bin/python3 /home/ubuntu/waf-honeypot-collector/main.py collect-hfish-loop
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1
Environment=HFISH_API_TOKEN=your-token-here

[Install]
WantedBy=multi-user.target
```

#### Web Dashboard 服务

文件：`deploy/waf-honeypot-web.service`

```ini
[Unit]
Description=WAF Honeypot Collector - Web Dashboard
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/waf-honeypot-collector
ExecStart=/usr/bin/python3 /home/ubuntu/waf-honeypot-collector/main.py web
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

### 11.3 部署命令

```bash
# 项目路径
PROJECT_DIR=/home/ubuntu/waf-honeypot-collector

# 安装依赖
cd $PROJECT_DIR
pip install -r requirements.txt

# 复制配置文件
cp config.yaml.example config.yaml
# 编辑 config.yaml 填入真实配置
vim config.yaml

# 初始化数据库
python main.py init-db

# 复制 systemd 服务文件
sudo cp deploy/waf-honeypot-safeline.service /etc/systemd/system/
sudo cp deploy/waf-honeypot-hfish.service /etc/systemd/system/
sudo cp deploy/waf-honeypot-web.service /etc/systemd/system/

# 重新加载 systemd
sudo systemctl daemon-reload

# 启动服务
sudo systemctl enable waf-honeypot-safeline.service
sudo systemctl enable waf-honeypot-hfish.service
sudo systemctl enable waf-honeypot-web.service
sudo systemctl start waf-honeypot-safeline.service
sudo systemctl start waf-honeypot-hfish.service
sudo systemctl start waf-honeypot-web.service
```

### 11.4 日志查看命令

```bash
# SafeLine Receiver 日志
sudo journalctl -u waf-honeypot-safeline.service -f

# HFish Collector 日志
sudo journalctl -u waf-honeypot-hfish.service -f

# Web Dashboard 日志
sudo journalctl -u waf-honeypot-web.service -f

# 查看最近 100 条
sudo journalctl -u waf-honeypot-safeline.service -n 100 --no-pager
```

### 11.5 数据库备份命令

```bash
# 手动备份
cp /home/ubuntu/waf-honeypot-collector/data/collector.db \
   /home/ubuntu/waf-honeypot-collector/data/backups/collector_$(date +%Y%m%d_%H%M%S).db

# 使用 SQLite 在线备份（推荐，避免数据损坏）
sqlite3 /home/ubuntu/waf-honeypot-collector/data/collector.db \
  ".backup '/home/ubuntu/waf-honeypot-collector/data/backups/collector_$(date +%Y%m%d).db'"

# crontab 定时备份（每天凌晨 2 点）
# 0 2 * * * sqlite3 /home/ubuntu/waf-honeypot-collector/data/collector.db ".backup '/home/ubuntu/waf-honeypot-collector/data/backups/collector_$(date +\%Y\%m\%d).db'"
```

### 11.6 服务管理命令

```bash
# 启动
sudo systemctl start waf-honeypot-safeline

# 停止
sudo systemctl stop waf-honeypot-safeline

# 重启
sudo systemctl restart waf-honeypot-safeline

# 状态
sudo systemctl status waf-honeypot-safeline

# 开机自启
sudo systemctl enable waf-honeypot-safeline

# 取消自启
sudo systemctl disable waf-honeypot-safeline
```

### 11.7 验收标准

1. [ ] 三个 systemd 服务文件创建完毕；
2. [ ] 按部署文档可从零部署完成；
3. [ ] 服务启动后通过 `systemctl status` 确认正常运行；
4. [ ] `journalctl` 可查看各服务日志；
5. [ ] 模拟服务崩溃后，`Restart=on-failure` 自动重启生效；
6. [ ] 数据库备份命令可正常执行；
7. [ ] 部署文档内容完整，可指导从零开始搭建。

### 11.8 本阶段不做

- ❌ 新的功能开发
- ❌ Docker 容器化
- ❌ Ansible/Puppet 自动化部署
- ❌ 监控告警系统
- ❌ 日志集中管理（ELK）
- ❌ 性能调优

### 11.9 给 Claude Code 的 Phase 7 执行提示词

```
请执行 Phase 7：部署与运维。

Phase 6 已完成，Web Dashboard 已就位。

请完成以下任务：

1. 创建 deploy/ 目录；
2. 创建 deploy/waf-honeypot-safeline.service：
   - Type=simple, User=ubuntu
   - WorkingDirectory=/home/ubuntu/waf-honeypot-collector
   - ExecStart=python3 main.py recv-safeline
   - Restart=on-failure, RestartSec=10
   - StandardOutput=journal, StandardError=journal
3. 创建 deploy/waf-honeypot-hfish.service（同理，collect-hfish-loop）；
4. 创建 deploy/waf-honeypot-web.service（同理，web）；
5. 创建 docs/deployment.md：
   - 环境要求（Python 3.10+, pip）；
   - 从 GitHub clone 项目；
   - 安装依赖；
   - 配置 config.yaml；
   - 初始化数据库；
   - 复制 systemd 文件；
   - 启动/停止/重启服务；
   - 查看日志方法；
   - 数据库备份方法；
   - 常见问题排查（FAQ）；
6. 修改 .gitignore（保证 deploy/*.service 不被忽略）。

要求：
- systemd 文件中的环境变量占位使用 YOUR_TOKEN_HERE 等标记；
- 部署文档使用完整命令，可复制粘贴执行；
- 说明如果 Syslog 端口 < 1024 需 root 或 capability 配置。

测试验证：
- 确保 systemd 文件语法正确（systemd-analyze verify）
- 测试命令无需真实执行

完成后 git commit，提交信息为 "Phase 7: 部署与运维"。
```

---

## Phase 8：项目打磨与简历包装

### 12.1 本阶段目标

让项目具备 GitHub 展示价值和简历价值，完善文档、测试和项目描述。

### 12.2 README 结构建议

```markdown
# WAF Honeypot Collector

基于 SafeLine WAF 与 HFish 蜜罐的轻量级安全事件采集与关联分析平台

## 项目简介（2-3 句话）
## 架构图（ASCII 或图片）
## 功能特性（清单）
## 技术栈
## 快速开始（安装 → 配置 → 运行）
## CLI 使用示例
## Web Dashboard 截图（Phase 6+）
## 项目结构
## 配置说明
## 数据流说明
## 安全声明
## 项目边界（本项目不做什么）
## 许可证
## 参考链接（SafeLine/HFish/MITRE ATT&CK）
```

### 12.3 项目截图清单

| 截图 | 内容 |
|------|------|
| `docs/images/dashboard-overview.png` | Web Dashboard 首页概览 |
| `docs/images/dashboard-events.png` | 事件列表页 |
| `docs/images/dashboard-ip-detail.png` | IP 详情画像页 |
| `docs/images/dashboard-iocs.png` | IOC 列表 |
| `docs/images/cli-stats.png` | CLI `stats` 命令输出 |
| `docs/images/cli-report.png` | CLI `report` 命令生成的报告预览 |

### 12.4 示例报告清单

| 文件 | 内容 |
|------|------|
| `docs/examples/report-example.md` | 一份完整的 IP 分析报告示例 |

### 12.5 简历表述

**项目名称：** 基于 WAF 与蜜罐的安全事件采集与关联分析平台

**一段描述：**

> 基于 SafeLine WAF 与 HFish 蜜罐构建轻量级安全事件采集与关联分析平台，使用 Syslog 与 API 对接多源安全日志，实现原始日志采集、事件标准化、IOC 提取、攻击源画像、ATT&CK 映射和 Markdown 报告生成。项目支持低配置 VPS 部署，可用于公网攻击流量观测、安全事件研判和蓝队安全运营学习。

**亮点提炼：**

1. **多源日志接入**：通过 UDP Syslog 和 REST API 同时对接 WAF 和蜜罐两类异构安全数据源；
2. **事件标准化**：将异构日志统一为标准事件模型，支持上层分析引擎无损处理；
3. **攻击源画像**：基于规则引擎对攻击源 IP 进行风险评分、标签分类和多维度画像；
4. **关联分析**：识别多源命中、多阶段攻击等高级威胁行为；
5. **威胁情报映射**：将攻击行为映射到 MITRE ATT&CK 框架（T1595/T1190/T1110/T1059/T1555）；
6. **AI 辅助研判**（可选）：接入 DeepSeek API 实现智能化攻击摘要和处置建议生成；
7. **轻量部署**：全栈 Python + SQLite，适合 1 vCPU / 1GB RAM 低配 VPS。

**技术栈：** Python 3.10+ / SQLite / FastAPI / REST API / Syslog / YAML / pytest / MITRE ATT&CK

### 12.6 面试讲解要点

| 方向 | 讲解要点 |
|------|----------|
| 项目动机 | WAF 和蜜罐日志分散，无法关联分析同一攻击源，需要统一平台 |
| 架构设计 | Collector → Parser → Normalizer → Analyzer → Reporter 分层解耦 |
| 数据流设计 | 原始日志保留 → 标准化事件 → IOC 提取 → 画像构建 → 关联分析 → 报告输出 |
| 关键设计决策 | 为什么选 SQLite（轻量零依赖）、为什么不做自动封禁（明确项目边界） |
| 容错设计 | Syslog 解析失败不崩溃、API 拉取失败有重试和降级 |
| 安全设计 | API Key 从环境变量读取、配置文件不提交 Git、Web 监听 localhost |
| MITRE ATT&CK | 为什么要映射（行业标准威胁框架）、映射方式（规则引擎非 AI） |
| 风险评分 | 完全由规则引擎决定（加分项累加），AI 不参与评分决策 |
| AI 边界 | AI 只做辅助研判，不修改评分、不执行命令、不接触原始日志 |
| 项目难点 | 异构数据标准化、去重策略、多阶段攻击时间序列关联 |
| 可改进方向 | 接入更多数据源、支持实时告警、增加 Dashboard 认证 |

### 12.7 常见面试问题与回答

**Q1：为什么选择 SQLite 而不是 MySQL/PostgreSQL？**

> 项目定位是低配置 VPS 运行的单用户分析平台，SQLite 零依赖、零配置、零运维的特点非常适合。SQLite 单文件存储也方便备份和迁移。本项目的数据量级别（单日数十万条）完全在 SQLite 的能力范围内。

**Q2：如何保证 Syslog 接收不丢数据？**

> UDP 协议本身不保证可靠传输，但我们在应用层做了：1）固定缓冲区避免内存溢出；2）同步写入 SQLite 避免数据在内存中滞留；3）解析失败的数据仍然保留原始报文。如果需要更高的可靠性，可以扩展支持 TCP Syslog。

**Q3：AI 在这里的作用是什么？边界如何控制？**

> AI 只做辅助研判——生成攻击行为摘要、解释 Payload 含义、润色报告语言。核心判断（风险评分、攻击类型识别、关联规则）全部由规则引擎完成。AI 模块没有写回评分字段的权限，没有执行系统命令的能力，接触的是结构化摘要而非原始日志。

**Q4：多阶段攻击关联如何实现？**

> 通过时间序列分析：先查询同一 IP 在 SafeLine 中的 Web 攻击事件，再查询在 HFish 中的非 HTTP 协议事件（SSH/Redis/MySQL）。如果 Web 攻击事件时间戳早于服务爆破事件，且时间差在阈值内，则标记为多阶段攻击。

**Q5：这个项目和生产环境 SOC 的区别是什么？**

> 本项目定位是轻量级蓝队学习平台和辅助分析工具，不是生产级 SOC。它没有实时告警、分布式部署、多租户、自动化响应等企业级功能。但它的核心分析链路（采集→标准化→分析→报告）与 SOC 是相通的，可以作为理解安全运营平台工作原理的起点。

### 12.8 给 Claude Code 的 Phase 8 执行提示词

```
请执行 Phase 8：项目打磨与简历包装。

前 7 个 Phase 已全部完成。

请完成以下任务：

1. 完善 README.md：
   - 项目简介 + 架构图（ASCII art）
   - 功能特性清单
   - 技术栈
   - 快速开始（安装→配置→运行，5 步以内）
   - CLI 使用示例
   - Web Dashboard 说明 + 截图路径
   - 项目结构
   - 安全声明
   - 项目边界说明
   - 许可证（MIT）

2. 完善项目文档：
   - 检查所有 docstring 完整性；
   - 检查关键函数是否有类型注解；
   - 确保 config.yaml.example 注释完整；

3. 创建 docs/architecture.md：
   - 项目架构图（ASCII）；
   - 数据流图；
   - 模块依赖关系；
   - 表关系图；

4. 创建 docs/examples/report-example.md：
   - 使用现有数据生成一份示例报告；
   - 或使用模拟数据生成全量示例报告；

5. 审查代码质量：
   - 检查所有 except 是否记录了异常信息；
   - 检查数据库连接是否正确关闭；
   - 检查 main.py 退出码是否正确；
   - 检查配置文件字段与代码读取是否一致；

6. 提升测试覆盖率（如需要）。

要求：
- 不引入新的功能；
- 不改动现有业务逻辑；
- 纯文档 + 代码质量提升。

完成后 git commit，提交信息为 "Phase 8: 项目打磨与简历包装"。
```

---

## 十三、下一步执行建议

### 13.1 执行顺序

```
Phase 0 ──→ Phase 1 ──→ Phase 2 ──→ Phase 3 ──→ Phase 4 ──→ Phase 5 ──→ Phase 6 ──→ Phase 7 ──→ Phase 8
  (基础)      (WAF 采集)   (蜜罐+标准化) (分析引擎)  (ATT&CK+报告) (AI辅助)   (Web界面)   (部署)     (打磨)
```

### 13.2 关键依赖关系

| Phase | 依赖 | 说明 |
|-------|------|------|
| Phase 0 | 无 | 项目骨架 |
| Phase 1 | Phase 0 | 需要 app/db.py, app/config.py |
| Phase 2 | Phase 1 | 需要 app/db.py, 需要解析样本 |
| Phase 3 | Phase 2 | 需要 normalized_events 表有数据 |
| Phase 4 | Phase 3 | 需要 attacker_profiles, iocs 有数据 |
| Phase 5 | Phase 4 | 需要 report 框架 |
| Phase 6 | Phase 5 | 需要所有分析功能就位 |
| Phase 7 | Phase 6 | 需要完整项目 |
| Phase 8 | Phase 7 | 需要完整项目 |

### 13.3 立即行动

**建议立即让 Claude Code 执行 Phase 0：项目初始化与文档建设。**

Phase 0 完成后，项目将具备：

1. Git 仓库基础；
2. 配置文件框架；
3. 数据库初始化能力；
4. 日志系统；
5. 完整的文档基础。

之后按顺序进入 Phase 1，从 SafeLine Syslog 日志接入开始功能开发。

### 13.4 风险提示

1. **不要跳阶段开发**：Phase 3 需要 Phase 2 的 `normalized_events` 数据，跳过会导致分析引擎无数据可用；
2. **不要提前引入 Web**：Phase 0-5 都是 CLI，Web 放在 Phase 6 是为了确保所有数据和分析功能先就位；
3. **AI 不要提前接入**：Phase 5 的 AI 依赖 Phase 4 的报告框架，提前接入会导致对接成本增加；
4. **每个阶段完成后必须 commit**：方便回退和查看阶段进度；
5. **数据目录不要提交 Git**：`data/collector.db` 包含真实攻击数据，通过 `.gitignore` 排除。
