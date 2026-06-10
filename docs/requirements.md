# 基于 WAF 与蜜罐的安全事件采集与关联分析平台

## 需求文档

**项目代号：** waf-honeypot-collector

**版本：** v1.0

**日期：** 2026-06-10

---

## 目录

1. [项目背景](#一项目背景)
2. [项目定位](#二项目定位)
3. [技术约束](#三技术约束)
4. [数据源说明](#四数据源说明)
5. [功能需求](#五功能需求)
6. [CLI 设计](#六cli-设计)
7. [数据库设计](#七数据库设计)
8. [非功能需求](#八非功能需求)
9. [项目阶段规划](#九项目阶段规划)
10. [下一步](#十下一步)

---

## 一、项目背景

### 1.1 现有环境

当前拥有一台低配置 VPS，已部署以下安全组件：

| 组件 | 用途 |
|------|------|
| **SafeLine 雷池 WAF** | Web 应用防火墙，产生 Web 攻击日志 |
| **HFish 蜜罐** | 蜜罐系统，产生网络层攻击日志 |
| **Web 靶场** | 用于测试的 Web 漏洞靶场环境 |

### 1.2 安全数据现状

SafeLine WAF 可产生的攻击日志类型包括但不限于：

- SQL 注入
- 跨站脚本攻击（XSS）
- 敏感路径扫描
- 恶意 Payload
- 异常 HTTP 请求

HFish 蜜罐可产生的攻击日志类型包括但不限于：

- SSH 暴力破解
- Redis 未授权探测
- MySQL 弱口令尝试
- 协议扫描
- 自动化攻击行为

### 1.3 现有问题

1. **数据孤岛**：SafeLine 和 HFish 的日志分散在两个独立的平台，无统一视图；
2. **格式不统一**：两类日志字段结构、时间格式、攻击类型命名互不兼容；
3. **缺乏关联**：无法快速判断同一个攻击源 IP 是否同时触发 WAF 和蜜罐；
4. **缺少攻击源画像**：攻击者的行为模式、攻击偏好、活跃时间无聚合展现；
5. **缺少 IOC 提取**：未从原始日志中系统化提取威胁情报指标；
6. **缺少关联分析**：无法识别多阶段攻击、多源命中等高价值安全事件；
7. **缺乏项目闭环**：缺少一个可用于蓝队安全运营学习、实战训练和简历展示的完整项目。

### 1.4 解决目标

构建一个轻量级平台，实现以下完整链路：

**日志采集 → 原始保存 → 格式标准化 → IOC 提取 → 攻击源画像 → 关联分析 → 报告生成**

---

## 二、项目定位

### 2.1 项目定义

本项目是一个**轻量级蓝队安全运营平台**，聚焦安全日志的多源采集、标准化、关联分析与报告生成。

### 2.2 项目重点

1. **多源安全日志采集** — 同时接入 WAF 和蜜罐两类数据源；
2. **原始日志保留** — 不丢弃任何原始数据，支持重解析与溯源；
3. **事件标准化** — 将异构日志统一为标准事件格式；
4. **攻击源 IP 聚合** — 按 IP 维度聚合攻击行为，构建攻击者画像；
5. **WAF 与蜜罐日志关联** — 识别同时在两类设备上活动的攻击源；
6. **IOC 提取** — 从事件中自动化提取威胁情报指标；
7. **攻击画像** — 构建攻击者的行为特征、攻击偏好、风险评分；
8. **ATT&CK 映射** — 将攻击行为映射到 MITRE ATT&CK 框架；
9. **Markdown 报告生成** — 输出结构化的攻击源分析报告；
10. **AI 辅助研判（可选）** — 接入 DeepSeek API 辅助生成分析摘要和处置建议。

### 2.3 项目不做

以下内容不在本项目范围内：

1. ❌ 主动漏洞扫描
2. ❌ 自动化攻击
3. ❌ 木马开发
4. ❌ 免杀技术
5. ❌ 自动封禁 IP
6. ❌ 大规模资产测绘
7. ❌ 完整 SOC/SIEM 替代
8. ❌ 多租户权限系统
9. ❌ 实时告警推送
10. ❌ 分布式部署

---

## 三、技术约束

### 3.1 技术栈

| 类别 | 技术选型 | 说明 |
|------|----------|------|
| 语言 | **Python 3.10+** | 主流安全工具语言，生态丰富 |
| 数据库 | **SQLite** | 零依赖，适合低配 VPS |
| 配置 | **YAML** | 可读性强，支持注释 |
| CLI 框架 | **Python argparse / Click** | 标准 CLI 交互 |
| Web 框架 | **FastAPI + Jinja2 + Bootstrap** | 第二阶段引入，轻量高效 |
| 测试 | **pytest** | 主流 Python 测试框架 |

### 3.2 禁止依赖

以下组件不得作为本项目运行时依赖：

- ❌ Docker
- ❌ Redis
- ❌ Kafka
- ❌ ELK 全家桶（Elasticsearch / Logstash / Kibana）
- ❌ Celery
- ❌ MySQL / PostgreSQL
- ❌ MongoDB

### 3.3 运行环境约束

1. 项目必须适合**低配置 VPS**（1 vCPU / 1GB RAM / 20GB 磁盘级别）运行；
2. 所有 API Key、Token、密码、数据库密码**不得硬编码写入代码**；
3. 真实配置（含密钥、地址、凭证）**不得提交 Git 仓库**；
4. Web 后台默认只监听 `127.0.0.1`，**不得直接暴露公网**；
5. 项目应能在 `systemd` 下托管运行，支持异常退出后自动重启。

---

## 四、数据源说明

### 4.1 SafeLine WAF

#### 4.1.1 接入方式

**优先使用 Syslog 协议接收日志。**

- 监听地址：`0.0.0.0:1514/udp`（可配置）
- 协议：UDP Syslog（RFC 3164 / RFC 5424）
- 日志格式：Syslog 头部 + JSON 消息体
- 传输方向：SafeLine → 本平台（被动接收）

#### 4.1.2 接入要求

| 需求 | 说明 |
|------|------|
| 接收日志 | 启动 Syslog 服务监听 UDP 端口接收日志 |
| 保存原始日志 | 完整保存 Syslog 原文，不做任何截断 |
| JSON 提取 | 尝试从 Syslog 报文中提取 JSON 部分并解析 |
| 容错 | 解析失败时**不得丢弃原始日志**，标记解析状态即可 |
| 单条隔离 | 单条日志解析异常**不得导致程序崩溃** |
| 状态记录 | 每条日志记录解析状态（成功/失败/部分） |
| 存储 | 原始日志存入 `raw_safeline_logs` 表 |
| 标准化 | 解析完成的日志后续进入 `normalized_events` 表 |

#### 4.1.3 目标解析字段

按优先级从高到低列出，以下字段允许缺失：

| 字段 | 类型 | 说明 |
|------|------|------|
| `event_time` | datetime | 事件发生时间 |
| `src_ip` | string | 攻击者源 IP |
| `src_port` | integer | 攻击者源端口 |
| `dst_ip` | string | 目标服务器 IP |
| `dst_port` | integer | 目标端口 |
| `host` | string | HTTP Host 头 |
| `method` | string | HTTP 请求方法 |
| `uri` | string | 请求 URI 路径 |
| `query_string` | string | 请求查询参数 |
| `user_agent` | string | HTTP User-Agent |
| `attack_type` | string | 攻击类型/检测规则名称 |
| `severity` | string | 严重级别 |
| `rule_id` | string | 触发规则 ID |
| `payload` | string | 攻击 Payload（截断的部分） |
| `status_code` | integer | HTTP 响应状态码 |
| `event_id` | string | 事件唯一 ID |

### 4.2 HFish 蜜罐

#### 4.2.1 接入方式

**优先使用 API 接口拉取日志。**

- 接口协议：HTTP/HTTPS REST API
- 认证方式：Token 或 账号密码
- 数据格式：JSON
- 传输方向：本平台 → HFish API（主动拉取）

#### 4.2.2 接入要求

| 需求 | 说明 |
|------|------|
| 地址配置 | HFish API 地址从 `config.yaml` 读取 |
| Token 认证 | 支持 API Token 认证，优先于账号密码 |
| 账密认证 | 支持账号密码认证，作为 Token 不可用时的后备 |
| 接口配置 | 接口路径支持在配置文件中自定义 |
| 单次拉取 | 支持手动执行单次拉取 |
| 循环拉取 | 支持定时循环拉取（可配置间隔） |
| 去重 | 基于事件 ID 实现基础去重，避免重复入库 |
| 原始保存 | 原始 API 响应的 JSON 必须**完整保存** |
| 容错 | 拉取失败（网络/认证/解析）**不得导致程序崩溃** |
| 存储 | 原始日志存入 `raw_hfish_events` 表 |
| 标准化 | 解析完成的日志后续进入 `normalized_events` 表 |

#### 4.2.3 目标解析字段

以下字段允许缺失：

| 字段 | 类型 | 说明 |
|------|------|------|
| `event_id` | string | 事件唯一 ID |
| `event_time` | datetime | 事件发生时间 |
| `attacker_ip` | string | 攻击者 IP |
| `attacker_port` | integer | 攻击者端口 |
| `protocol` | string | 攻击协议类型（SSH/Redis/MySQL/HTTP 等） |
| `target_port` | integer | 蜜罐监听端口 |
| `username` | string | 爆破使用的用户名 |
| `password` | string | 爆破使用的密码 |
| `command` | string | 执行的命令 |
| `request_content` | string | 请求内容 |
| `user_agent` | string | User-Agent（如有） |
| `node_name` | string | 蜜罐节点名称 |
| `location` | string | 攻击者地理位置 |
| `event_type` | string | 事件类型 |
| `severity` | string | 严重级别 |

---

## 五、功能需求

### 5.1 配置管理

#### 5.1.1 配置文件

- 主配置文件：`config.yaml`
- 示例配置文件：`config.yaml.example`
- 示例配置应包含所有配置项的结构和注释，**不含真实密钥**

#### 5.1.2 配置加载规则

1. 程序启动时从指定路径加载 `config.yaml`；
2. 若未指定路径，默认从项目根目录加载；
3. 若文件不存在，提示用户从 `.example` 复制；
4. 配置项缺失时使用合理的默认值；
5. 无效配置值应在启动时报告，不强制退出。

#### 5.1.3 配置项清单

| 配置分组 | 配置项 | 类型 | 默认值 | 说明 |
|----------|--------|------|--------|------|
| app | name | string | waf-honeypot-collector | 应用名称 |
| app | version | string | 1.0.0 | 应用版本 |
| app | log_level | string | INFO | 日志级别（DEBUG/INFO/WARNING/ERROR） |
| app | log_dir | string | logs | 日志文件存储目录 |
| app | timezone | string | Asia/Shanghai | 时区 |
| database | path | string | data/collector.db | SQLite 数据库文件路径 |
| database | backup_dir | string | data/backups | 数据库备份目录 |
| safeline | enabled | bool | true | 是否启用 SafeLine 采集 |
| safeline | host | string | 0.0.0.0 | Syslog 监听地址 |
| safeline | port | integer | 1514 | Syslog 监听端口 |
| safeline | buffer_size | integer | 65536 | UDP 接收缓冲区 |
| safeline | enable_normalization | bool | true | 是否自动标准化 |
| hfish | enabled | bool | true | 是否启用 HFish 采集 |
| hfish | api_url | string | — | HFish API 基础 URL |
| hfish | auth_type | string | token | 认证方式（token/password） |
| hfish | api_token | string | — | API Token（从环境变量读取，非直接写入） |
| hfish | username | string | — | 登录用户名 |
| hfish | password | string | — | 登录密码（从环境变量读取） |
| hfish | api_path | string | /api/v1/attack | 攻击日志接口路径 |
| hfish | interval | integer | 60 | 循环拉取间隔（秒） |
| hfish | page_size | integer | 100 | 每页条数 |
| hfish | enable_normalization | bool | true | 是否自动标准化 |
| ioc | enabled | bool | true | 是否启用 IOC 提取 |
| profile | enabled | bool | true | 是否启用攻击画像 |
| correlation | enabled | bool | true | 是否启用关联分析 |
| deepseek | enabled | bool | false | 是否启用 DeepSeek API |
| deepseek | base_url | string | https://api.deepseek.com | API 地址 |
| deepseek | model | string | deepseek-chat | 模型名称 |
| deepseek | api_key_env | string | DEEPSEEK_API_KEY | 环境变量名 |
| deepseek | timeout | integer | 30 | 请求超时（秒） |
| deepseek | max_tokens | integer | 2048 | 最大生成 Token 数 |
| web | enabled | bool | false | 是否启用 Web Dashboard |
| web | host | string | 127.0.0.1 | 监听地址（默认仅本地） |
| web | port | integer | 8080 | 监听端口 |

#### 5.1.4 环境变量

| 环境变量 | 用途 |
|----------|------|
| `DEEPSEEK_API_KEY` | DeepSeek API 密钥 |
| `HFISH_API_TOKEN` | HFish API Token（当 auth_type=token 时使用） |
| `HFISH_PASSWORD` | HFish 密码（当 auth_type=password 时使用） |
| `SAFELINE_API_KEY` | SafeLine API 密钥（预留） |

### 5.2 原始日志采集

#### 5.2.1 设计原则

**必须保存所有原始日志。** 原因如下：

1. **可重解析**：当解析逻辑更新时，无需重新拉取/接收，可基于原始日志重跑；
2. **原始证据保留**：原始日志具备法律和取证上的证据价值，标准化过程可能丢失细节；
3. **避免信息损失**：标准化是有损的，原始数据是信息最完整的形态；
4. **调试支持**：字段格式变化或新增字段时，原始日志是调试的第一手资料；
5. **溯源能力**：安全事件溯源时，原始日志提供最底层的回溯依据。

#### 5.2.2 存储机制

- SafeLine 原始日志 → `raw_safeline_logs` 表
- HFish 原始日志 → `raw_hfish_events` 表
- 两张表均以自增 ID 为主键，保留接收/拉取时间戳
- 原始日志字段采用 TEXT 类型存储全文，不截断

### 5.3 事件标准化

#### 5.3.1 设计目标

将 SafeLine 和 HFish 两种异构数据源的事件统一为 `normalized_events` 表的标准格式，使上层分析模块无需关心数据来源。

#### 5.3.2 数据流

```
Raw SafeLine Log    ──→  Parser  ──→  Normalizer  ──→  normalized_events
Raw HFish Event     ──→  Parser  ──→  Normalizer  ──→  normalized_events
```

#### 5.3.3 统一字段定义

| 字段 | 类型 | 来源 | 说明 |
|------|------|------|------|
| `id` | integer | 自增 | 主键 |
| `source` | string | 自动 | 数据源标识：`safeline` / `hfish` |
| `source_event_id` | string | 原始 | 原始事件 ID |
| `event_time` | datetime | 解析 | 事件发生时间 |
| `src_ip` | string | 解析 | 攻击者源 IP |
| `src_port` | integer | 解析 | 攻击者源端口（可为空） |
| `dst_ip` | string | 解析 | 目标 IP（可为空） |
| `dst_port` | integer | 解析 | 目标端口（可为空） |
| `protocol` | string | 解析 | 协议类型（HTTP/SSH/Redis/MySQL 等） |
| `http_method` | string | 解析 | HTTP 请求方法（可为空） |
| `host` | string | 解析 | 目标主机名（可为空） |
| `uri` | string | 解析 | 请求 URI（可为空） |
| `user_agent` | string | 解析 | User-Agent（可为空） |
| `attack_type` | string | 映射 | 标准化攻击类型 |
| `severity` | string | 映射 | 严重级别（low/medium/high/critical） |
| `payload` | text | 解析 | 攻击 Payload（可为空） |
| `raw_table` | string | 自动 | 来源原始表名 |
| `raw_id` | integer | 自动 | 来源原始表记录 ID |
| `created_at` | datetime | 自动 | 本条记录创建时间 |

#### 5.3.4 标准化规则

1. 时间字段统一为 ISO 8601 格式，时区统一为配置指定时区；
2. IP 字段去除无效值（空字符串、`-`、`unknown`）；
3. 攻击类型按预定义映射表进行归一化（如 `sql_injection` → `SQL Injection`）；
4. 严重级别映射为统一的 `low/medium/high/critical` 四级；
5. 标准化失败的事件标记 `parse_status = failed`，不进入 `normalized_events`；
6. 数据流支持**幂等运行**：已标准化的事件不会重复处理。

### 5.4 IOC 提取

#### 5.4.1 功能描述

从标准化事件中自动化提取威胁情报指标（Indicator of Compromise），存入 `iocs` 表。

#### 5.4.2 IOC 类型

| IOC 类型 | 提取来源 | 示例 |
|----------|----------|------|
| `ip` | src_ip 字段 | 192.168.1.100 |
| `uri` | uri 字段 | /admin/login.php |
| `url` | host + uri 拼接 | http://example.com/admin |
| `host` | host 字段 | www.example.com |
| `user_agent` | user_agent 字段 | sqlmap/1.7 |
| `payload` | payload 字段 | ' OR 1=1 -- |
| `filename` | 从 uri 提取文件名 | config.php.bak |
| `suspicious_path` | 从 uri 匹配敏感路径 | /web-inf/, /.git/ |
| `hfish_username` | hfish 登录尝试用户名 | admin |
| `hfish_password` | hfish 登录尝试密码 | 123456 |
| `file_hash` | 预留 | — |

#### 5.4.3 提取规则

1. IP 通过正则校验 IPv4 合法性，排除私有/保留地址（可选配置）；
2. URI 按照路径层级提取，排除常见静态资源后缀；
3. URL 由 host + uri 拼接生成（协议默认为 HTTP）；
4. User-Agent 提取后做归一化指纹识别（如识别为 sqlmap、nmap、curl 等）；
5. Payload 按长度截断存储（可配置上限，默认 4096 字符）；
6. 敏感路径通过预定义规则匹配（`.git/`, `.env`, `/web-inf/`, `/admin/` 等）；
7. IOC 去重：同一类型 + 同一值在同一事件中只提取一次。

### 5.5 攻击源画像

#### 5.5.1 功能描述

按 `src_ip` 聚合所有关联的攻击行为，形成攻击源画像，存入 `attacker_profiles` 表。

#### 5.5.2 画像字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `src_ip` | string | 攻击源 IP（主键 / 唯一） |
| `first_seen` | datetime | 该 IP 首次出现时间 |
| `last_seen` | datetime | 该 IP 最近活跃时间 |
| `safeline_count` | integer | 命中 SafeLine WAF 的事件数 |
| `hfish_count` | integer | 命中 HFish 蜜罐的事件数 |
| `total_count` | integer | 事件总数 |
| `attack_types` | text | JSON 数组，攻击类型及次数统计 |
| `protocols` | text | JSON 数组，攻击协议及次数统计 |
| `is_multi_source` | bool | 是否同时命中 WAF 和蜜罐 |
| `risk_score` | integer | 风险评分（0-100） |
| `risk_level` | string | 风险等级（low/medium/high/critical） |
| `tags` | text | JSON 数组，风险标签列表 |
| `last_event_time` | datetime | 最近一次事件时间 |
| `updated_at` | datetime | 画像最后更新时间 |

#### 5.5.3 风险标签

| 标签 | 触发条件 |
|------|----------|
| `Web 扫描` | 检测到目录扫描、敏感路径探测行为 |
| `SQL 注入尝试` | 出现 SQL 注入攻击类型 |
| `XSS 尝试` | 出现 XSS 攻击类型 |
| `敏感文件探测` | 出现敏感文件路径访问 |
| `弱口令爆破` | 出现多次 SSH/Redis/MySQL 登录尝试 |
| `多协议探测` | 使用多种协议进行攻击 |
| `多源命中` | 同时命中 SafeLine WAF 和 HFish 蜜罐 |
| `高频攻击源` | 单位时间内事件频率超出阈值 |
| `高风险攻击源` | 风险评分高于高风险的阈值 |

#### 5.5.4 画像更新策略

1. 新增标准化事件时触发对应 IP 画像更新；
2. 批量更新使用 `INSERT OR REPLACE` 或 `UPSERT` 机制；
3. 画像更新为增量更新，不因单次事件重置已累计数据；
4. 提供手动全量重建功能（`build-profiles --rebuild`）。

### 5.6 关联分析

#### 5.6.1 功能描述

基于规则引擎对事件、画像进行交叉关联分析，识别高价值安全行为模式。

#### 5.6.2 关联规则

| 规则编号 | 规则名称 | 描述 | 触发动作 |
|----------|----------|------|----------|
| CORR-001 | **多源命中** | 同一 IP 同时命中 SafeLine 和 HFish | 标记 `is_multi_source = true`，添加标签 `多源命中`，大幅提升风险评分 |
| CORR-002 | **多类型攻击** | 同一 IP 短时间内触发多种不同类型攻击 | 提升风险评分，添加标签 `多类型攻击` |
| CORR-003 | **多阶段攻击** | 同一 IP 先触发 Web 探测（SafeLine），再触发 SSH/Redis/MySQL 爆破（HFish） | 标记关联事件对，添加标签 `多阶段攻击`，大幅提升评分 |
| CORR-004 | **扫描行为** | 同一 IP 高频访问敏感路径（SafeLine 日志中的目录遍历/敏感文件） | 添加标签 `Web 扫描`，提升风险评分 |
| CORR-005 | **Payload 检测** | 出现明显 SQL 注入、XSS、命令执行 Payload | 生成对应攻击标签，确认攻击类型 |

#### 5.6.3 关联分析触发时机

1. 事件标准化后自动触发；
2. 画像更新后触发跨源关联；
3. 支持全量重新关联（`correlate --rebuild`）。

### 5.7 风险评分

#### 5.7.1 设计原则

**风险评分由规则引擎决定，不由 AI 直接决定。** AI 仅用于辅助分析，不参与评分决策。

#### 5.7.2 评分规则

| 规则 | 加分 | 说明 |
|------|------|------|
| 命中 SafeLine WAF | +10 | 每一条标准化事件 |
| 命中 HFish 蜜罐 | +15 | 每一条标准化事件（蜜罐命中一般意味着主动探测或攻击） |
| 多源命中 | +30 | 同一 IP 同时出现在 SafeLine 和 HFish 中 |
| 高频事件（>50 条/小时） | +15 | 短时间大量事件 |
| SQL 注入攻击 | +20 | 攻击类型为 SQL 注入 |
| 敏感文件探测 | +15 | 访问 `.git/`、`.env` 等敏感路径 |
| SSH 爆破 | +20 | HFish 中检测到 SSH 协议登录尝试 |
| Redis/MySQL 爆破 | +20 | HFish 中检测到对应协议登录尝试 |
| 多协议探测 | +15 | 使用 3 种及以上协议 |
| 多阶段攻击 | +25 | 同时满足 Web 探测 + 服务爆破 |

#### 5.7.3 风险等级划分

| 等级 | 评分区间 | 说明 |
|------|----------|------|
| **低** Low | 0-19 | 少量偶然事件，可能是扫描器误触 |
| **中** Medium | 20-49 | 有明确攻击行为的 IP |
| **高** High | 50-79 | 攻击行为明确、活跃度高、多源命中 |
| **严重** Critical | 80-100 | 多阶段攻击、高危 Payload、大量多源事件 |

### 5.8 ATT&CK 映射

#### 5.8.1 设计原则

第一版使用**规则映射**，不做复杂推理。

#### 5.8.2 基础映射表

| 攻击行为 | MITRE ATT&CK 技术 | 技术 ID |
|----------|-------------------|---------|
| 目录扫描 / 端口扫描 / 服务探测 | Active Scanning | **T1595** |
| Web 漏洞利用（SQL 注入 / XSS / RCE） | Exploit Public-Facing Application | **T1190** |
| SSH / Redis / MySQL 暴力破解 | Brute Force | **T1110** |
| 密码猜测尝试 | Password Guessing | **T1110.001** |
| 命令执行尝试 | Command and Scripting Interpreter | **T1059** |
| 凭据尝试（登录蜜罐） | Credentials from Password Stores | **T1555** |

#### 5.8.3 映射存储

映射结果存入 `attack_mappings` 表（可选），包含：

- 关联的标准化事件 ID
- 攻击源 IP
- 攻击行为描述
- MITRE ATT&CK 技术 ID
- MITRE ATT&CK 技术名称
- 映射方式（`rule` / `manual`）

### 5.9 Markdown 报告生成

#### 5.9.1 功能描述

支持按攻击源 IP 生成结构化的 Markdown 安全分析报告。

#### 5.9.2 报告内容结构

| 章节 | 内容 | 数据来源 |
|------|------|----------|
| 1. 摘要 | 攻击源 IP、风险评分、风险等级、风险标签 | attacker_profiles |
| 2. 时间信息 | 首次出现时间、最近活跃时间、活跃时长 | attacker_profiles |
| 3. 数据源命中 | SafeLine 命中数、HFish 命中数、是否多源 | attacker_profiles |
| 4. 攻击类型分布 | 攻击类型及次数列表 | normalized_events |
| 5. 攻击时间线 | 按时间排列的攻击事件摘要 | normalized_events |
| 6. IOC 列表 | 关联的 IOC 清单 | iocs |
| 7. ATT&CK 映射 | 映射的 MITRE ATT&CK 技术列表 | attack_mappings |
| 8. 处置建议 | 基于风险等级和攻击行为的处置建议 | 规则模板 / AI 生成 |
| 9. 原始事件索引 | 指向原始日志的记录 ID 列表 | raw_safeline_logs / raw_hfish_events |

#### 5.9.3 报告命令

```bash
python main.py report --ip 1.2.3.4                    # 生成报告打印到终端
python main.py report --ip 1.2.3.4 --output report.md  # 生成报告保存到文件
python main.py report --ip 1.2.3.4 --format markdown    # 指定格式
```

### 5.10 DeepSeek API 辅助分析

#### 5.10.1 定位与边界

**定位：** AI 仅作为辅助研判工具，用于提升报告可读性和分析效率。

**AI 可以做的：**

| 用途 | 说明 |
|------|------|
| 生成攻击行为摘要 | 将结构化数据转为自然语言描述 |
| 解释 Payload | 对攻击 Payload 进行语义解释 |
| 生成报告正文 | 将画像数据撰写成安全运营报告 |
| 生成处置建议 | 基于攻击行为给出推荐处置措施 |
| 改写报告语言 | 将结构化数据改写成流畅的安全分析语言 |

**AI 绝对不允许做的：**

| 禁止行为 | 风险 |
|----------|------|
| ❌ 修改风险评分 | 评分应完全由规则引擎决定 |
| ❌ 自动封禁 IP | 本项目不包含自动封禁功能 |
| ❌ 删除日志 | 日志为原始证据，不可由 AI 删除 |
| ❌ 执行系统命令 | 安全风险，AI 不应有命令执行能力 |
| ❌ 读取密钥 | 密钥必须与环境变量隔离 |
| ❌ 直接处理全部原始敏感日志 | 原始日志量大且含敏感信息，应控制传入范围 |
| ❌ 替代规则引擎 | 规则引擎是核心，AI 不可替代 |

#### 5.10.2 配置参数

| 参数 | 说明 |
|------|------|
| `deepseek.enabled` | 是否启用 |
| `deepseek.provider` | 供应商标识（`deepseek`，预留兼容其他 API） |
| `deepseek.base_url` | API 地址 |
| `deepseek.model` | 模型名称 |
| `deepseek.api_key_env` | 环境变量名称（默认 `DEEPSEEK_API_KEY`） |
| `deepseek.timeout` | 请求超时秒数 |
| `deepseek.max_tokens` | 最大生成 Token 数 |

#### 5.10.3 安全要求

- API Key 必须通过环境变量 `DEEPSEEK_API_KEY` 读取；
- 传入 AI 的内容必须是经结构化和脱敏的摘要信息，非原始全文；
- AI 调用必须设置超时，超时不影响主流程；
- AI 调用异常必须有降级处理，不阻塞报告生成。

### 5.11 Web Dashboard

#### 5.11.1 定位

第二阶段实现的轻量 Web 管理界面，用于快速浏览安全事件和分析结果。

#### 5.11.2 功能页面

| 页面 | URL | 说明 |
|------|-----|------|
| 首页概览 | `/` | 统计看板：总事件数、攻击源 IP 数、IOC 数、高风险 IP 数 |
| 最近事件 | `/events` | 最近标准化事件列表，支持分页和筛选 |
| Top 攻击源 | `/top-ip` | 按事件数或风险评分排列的攻击源 IP 列表 |
| 攻击类型分布 | `/attack-types` | 攻击类型统计图表 |
| 趋势视图 | `/trends` | SafeLine / HFish 事件趋势折线图 |
| 高风险 IP | `/high-risk` | 风险等级为高和严重的攻击源 IP 列表 |
| 攻击源画像 | `/profile/{ip}` | 单 IP 详细信息、攻击行为时间线、IOC、ATT&CK 映射 |
| IOC 列表 | `/iocs` | 提取的 IOC 清单，支持按类型筛选 |
| 报告下载 | `/report/{ip}` | 在线查看和下载 Markdown 报告 |

#### 5.11.3 安全约束

- 默认只监听 `127.0.0.1`，不暴露公网；
- 如需远程访问，应通过 SSH 隧道、VPN 或反向代理；
- Dashboard 为只读界面，不提供配置修改功能；
- 不实现用户认证系统（通过网络层隔离保障安全）。

---

## 六、CLI 设计

### 6.1 基础命令（Phase 0-2）

| 命令 | 功能 | 阶段 |
|------|------|------|
| `python main.py init-db` | 初始化数据库，创建所有表结构 | Phase 0 |
| `python main.py recv-safeline` | 启动 SafeLine Syslog 接收服务（前台阻塞） | Phase 1 |
| `python main.py collect-hfish` | 单次拉取 HFish 攻击日志 | Phase 2 |
| `python main.py collect-hfish-loop` | 循环定时拉取 HFish 攻击日志（前台阻塞） | Phase 2 |
| `python main.py show-latest` | 显示最近 N 条标准化事件（默认 20） | Phase 2 |
| `python main.py stats` | 显示基本统计信息（总数、来源分布、攻击类型 TOP N） | Phase 2 |

### 6.2 扩展命令（Phase 3-5）

| 命令 | 功能 | 阶段 |
|------|------|------|
| `python main.py normalize` | 对未标准化的原始日志执行标准化处理 | Phase 3 |
| `python main.py extract-ioc` | 从标准化事件中提取 IOC | Phase 3 |
| `python main.py build-profiles` | 构建/更新攻击源画像 | Phase 3 |
| `python main.py correlate` | 执行关联分析 | Phase 3 |
| `python main.py show-ip --ip 1.2.3.4` | 显示指定 IP 的原始事件和标准化事件 | Phase 3 |
| `python main.py show-profile --ip 1.2.3.4` | 显示指定 IP 的攻击源画像详情 | Phase 3 |
| `python main.py top-ip` | 显示 Top N 攻击源 IP（按事件数或风险评分） | Phase 3 |
| `python main.py map-attack` | 执行 ATT&CK 映射 | Phase 4 |
| `python main.py report --ip 1.2.3.4` | 生成指定 IP 的 Markdown 分析报告 | Phase 4 |
| `python main.py ai-summary --ip 1.2.3.4` | 使用 AI 生成攻击摘要（需启用 DeepSeek） | Phase 5 |

### 6.3 Web 命令（Phase 6）

| 命令 | 功能 | 阶段 |
|------|------|------|
| `python main.py web` | 启动 Web Dashboard 服务 | Phase 6 |

### 6.4 CLI 设计要求

1. 所有命令支持 `--help` 参数；
2. 所有命令支持 `--config` 参数指定配置文件路径；
3. 支持 `--debug` 参数覆盖配置文件中的日志级别；
4. 退出码：0 表示成功，1 表示执行失败，2 表示参数错误；
5. 后台服务类命令（`recv-safeline`、`collect-hfish-loop`、`web`）前台阻塞运行，通过 `Ctrl+C` 或 SIGTERM 优雅退出；
6. 优雅退出需确保当前正在处理的数据不丢失。

---

## 七、数据库设计

### 7.1 设计原则

1. 使用 SQLite 作为唯一数据库引擎；
2. 每张表必须有自增 `id` 主键；
3. 时间字段统一使用 ISO 8601 文本格式（SQLite 无原生 datetime 类型）；
4. JSON 字段使用 TEXT 类型存储；
5. 按需创建索引，不提前过度索引；
6. 合理的字段默认值和空值策略。

### 7.2 表结构

#### 7.2.1 raw_safeline_logs — SafeLine 原始 Syslog

**作用：** 保存 SafeLine 通过 Syslog 发送的完整原始日志，供后续解析和溯源。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 自增主键 |
| `raw_data` | TEXT | NOT NULL | Syslog 原始报文全文 |
| `json_extracted` | TEXT | NULLABLE | 从 Syslog 提取的 JSON 部分（如有） |
| `parse_status` | TEXT | NOT NULL DEFAULT 'pending' | 解析状态：`pending`/`parsed`/`failed`/`partial` |
| `parse_error` | TEXT | NULLABLE | 解析错误信息 |
| `received_at` | TEXT | NOT NULL | 接收时间（ISO 8601） |
| `src_host` | TEXT | NULLABLE | 发送源主机标识（如有） |

**索引：** `(parse_status)`，`(received_at)`

#### 7.2.2 raw_hfish_events — HFish 原始日志

**作用：** 保存 HFish API 返回的完整原始 JSON 日志，供后续解析和溯源。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 自增主键 |
| `raw_data` | TEXT | NOT NULL | API 返回的完整 JSON |
| `event_id` | TEXT | UNIQUE | HFish 事件唯一 ID（用于去重） |
| `parse_status` | TEXT | NOT NULL DEFAULT 'pending' | 解析状态：`pending`/`parsed`/`failed`/`partial` |
| `parse_error` | TEXT | NULLABLE | 解析错误信息 |
| `received_at` | TEXT | NOT NULL | 拉取时间（ISO 8601） |

**索引：** `(event_id)` — UNIQUE，`(parse_status)`，`(received_at)`

#### 7.2.3 normalized_events — 标准化事件

**作用：** 统一的标准化事件表，所有上层分析基于此表进行。

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
| `protocol` | TEXT | NULLABLE | 协议（HTTP/SSH/Redis/MySQL/其他） |
| `http_method` | TEXT | NULLABLE | HTTP 请求方法 |
| `host` | TEXT | NULLABLE | HTTP Host |
| `uri` | TEXT | NULLABLE | 请求 URI |
| `user_agent` | TEXT | NULLABLE | User-Agent |
| `attack_type` | TEXT | NULLABLE | 攻击类型 |
| `severity` | TEXT | NULLABLE | 严重级别 |
| `payload` | TEXT | NULLABLE | 攻击 Payload |
| `raw_table` | TEXT | NOT NULL | 来源原始表名 |
| `raw_id` | INTEGER | NOT NULL | 来源原始表记录 ID |
| `created_at` | TEXT | NOT NULL | 本记录创建时间（ISO 8601） |

**索引：** `(src_ip)`，`(event_time)`，`(source)`，`(attack_type)`，`(src_ip, event_time)`

**唯一约束：** `(source, source_event_id)` — 同一数据源的事件 ID 唯一（source_event_id 非空时）

#### 7.2.4 iocs — 威胁情报指标

**作用：** 存储从标准化事件中提取的 IOC。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 自增主键 |
| `ioc_type` | TEXT | NOT NULL | IOC 类型 |
| `ioc_value` | TEXT | NOT NULL | IOC 值 |
| `source` | TEXT | NOT NULL | 来源数据源 |
| `src_ip` | TEXT | NULLABLE | 关联的攻击源 IP |
| `normalized_event_id` | INTEGER | NULLABLE | 关联的标准化事件 ID |
| `first_seen` | TEXT | NOT NULL | 首次出现时间 |
| `last_seen` | TEXT | NOT NULL | 最近出现时间 |
| `count` | INTEGER | NOT NULL DEFAULT 1 | 出现次数 |
| `context` | TEXT | NULLABLE | 上下文信息（JSON） |
| `created_at` | TEXT | NOT NULL | 记录创建时间 |

**索引：** `(ioc_type, ioc_value)` — UNIQUE，`(src_ip)`，`(normalized_event_id)`

#### 7.2.5 attacker_profiles — 攻击源画像

**作用：** 按 src_ip 聚合攻击行为，存储攻击源的综合画像。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 自增主键 |
| `src_ip` | TEXT | UNIQUE NOT NULL | 攻击源 IP |
| `first_seen` | TEXT | NOT NULL | 首次出现时间 |
| `last_seen` | TEXT | NOT NULL | 最近活跃时间 |
| `safeline_count` | INTEGER | NOT NULL DEFAULT 0 | SafeLine 事件数 |
| `hfish_count` | INTEGER | NOT NULL DEFAULT 0 | HFish 事件数 |
| `total_count` | INTEGER | NOT NULL DEFAULT 0 | 事件总数 |
| `attack_types` | TEXT | NULLABLE | 攻击类型分布（JSON） |
| `protocols` | TEXT | NULLABLE | 协议分布（JSON） |
| `is_multi_source` | INTEGER | NOT NULL DEFAULT 0 | 是否多源命中（0/1） |
| `risk_score` | INTEGER | NOT NULL DEFAULT 0 | 风险评分（0-100） |
| `risk_level` | TEXT | NOT NULL DEFAULT 'low' | 风险等级 |
| `tags` | TEXT | NULLABLE | 风险标签（JSON 数组） |
| `last_event_time` | TEXT | NULLABLE | 最近一次事件时间 |
| `updated_at` | TEXT | NOT NULL | 画像更新时间 |

**索引：** `(src_ip)` — UNIQUE，`(risk_score)`，`(total_count)`

#### 7.2.6 attack_mappings — ATT&CK 映射（可选）

**作用：** 存储攻击行为到 MITRE ATT&CK 技术的映射关系。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 自增主键 |
| `normalized_event_id` | INTEGER | NOT NULL | 关联的标准化事件 ID |
| `src_ip` | TEXT | NOT NULL | 攻击源 IP |
| `attack_behavior` | TEXT | NOT NULL | 攻击行为描述 |
| `technique_id` | TEXT | NOT NULL | MITRE ATT&CK 技术 ID |
| `technique_name` | TEXT | NOT NULL | MITRE ATT&CK 技术名称 |
| `mapping_type` | TEXT | NOT NULL DEFAULT 'rule' | 映射方式：`rule` / `manual` |
| `created_at` | TEXT | NOT NULL | 记录创建时间 |

**索引：** `(normalized_event_id)`，`(src_ip)`，`(technique_id)`

#### 7.2.7 ai_analysis_cache — AI 分析缓存（可选）

**作用：** 缓存 AI 分析结果，避免重复调用 API 浪费 Token。

| 字段 | 类型 | 约束 | 说明 |
|------|------|------|------|
| `id` | INTEGER | PRIMARY KEY AUTOINCREMENT | 自增主键 |
| `cache_key` | TEXT | UNIQUE NOT NULL | 缓存键（如 `summary:1.2.3.4`） |
| `input_hash` | TEXT | NOT NULL | 输入内容的哈希值 |
| `model` | TEXT | NOT NULL | 使用的 AI 模型 |
| `result` | TEXT | NOT NULL | AI 返回结果 |
| `usage` | TEXT | NULLABLE | Token 消耗信息（JSON） |
| `created_at` | TEXT | NOT NULL | 创建时间 |
| `expires_at` | TEXT | NULLABLE | 过期时间（NULL 表示永不过期） |

**索引：** `(cache_key)` — UNIQUE

### 7.3 表关系图（逻辑描述）

```
raw_safeline_logs ──┬──→ normalized_events ──┬──→ iocs
                    │                        │
raw_hfish_events  ──┘                        ├──→ attack_mappings
                                             │
                    attacker_profiles  ←─────┘
                                             │
                                             └──→ ai_analysis_cache
```

### 7.4 SQL 草案（DDL 示意）

以下为初步 SQL 建表草案，仅供参考，实现时可能调整：

```sql
CREATE TABLE IF NOT EXISTS raw_safeline_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_data TEXT NOT NULL,
    json_extracted TEXT,
    parse_status TEXT NOT NULL DEFAULT 'pending',
    parse_error TEXT,
    received_at TEXT NOT NULL,
    src_host TEXT
);

CREATE TABLE IF NOT EXISTS raw_hfish_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_data TEXT NOT NULL,
    event_id TEXT UNIQUE,
    parse_status TEXT NOT NULL DEFAULT 'pending',
    parse_error TEXT,
    received_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS normalized_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    source_event_id TEXT,
    event_time TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_ip TEXT,
    dst_port INTEGER,
    protocol TEXT,
    http_method TEXT,
    host TEXT,
    uri TEXT,
    user_agent TEXT,
    attack_type TEXT,
    severity TEXT,
    payload TEXT,
    raw_table TEXT NOT NULL,
    raw_id INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    source TEXT NOT NULL,
    src_ip TEXT,
    normalized_event_id INTEGER,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    context TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(ioc_type, ioc_value)
);

CREATE TABLE IF NOT EXISTS attacker_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip TEXT UNIQUE NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    safeline_count INTEGER NOT NULL DEFAULT 0,
    hfish_count INTEGER NOT NULL DEFAULT 0,
    total_count INTEGER NOT NULL DEFAULT 0,
    attack_types TEXT,
    protocols TEXT,
    is_multi_source INTEGER NOT NULL DEFAULT 0,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level TEXT NOT NULL DEFAULT 'low',
    tags TEXT,
    last_event_time TEXT,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attack_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    normalized_event_id INTEGER NOT NULL,
    src_ip TEXT NOT NULL,
    attack_behavior TEXT NOT NULL,
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    mapping_type TEXT NOT NULL DEFAULT 'rule',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ai_analysis_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cache_key TEXT UNIQUE NOT NULL,
    input_hash TEXT NOT NULL,
    model TEXT NOT NULL,
    result TEXT NOT NULL,
    usage TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT
);
```

---

## 八、非功能需求

### 8.1 轻量化

| 要求 | 说明 |
|------|------|
| 运行资源 | 内存占用控制在 256MB 以内（Web 模式不超过 512MB） |
| CPU | 空闲状态 CPU 占用率 < 1% |
| 磁盘 | 数据库按量增长，单日约 50-200MB（取决于攻击流量） |
| 进程数 | 单进程运行，不使用多进程/多 Worker |
| 启动时间 | 冷启动 < 3 秒 |

### 8.2 稳定性

| 要求 | 说明 |
|------|------|
| 解析容错 | 任何日志解析失败不得导致程序崩溃，记录错误后继续处理下一条 |
| 网络容错 | API 请求失败（超时/断连/HTTP 5xx）记录日志并等待下一个拉取周期 |
| 数据库容错 | 数据库操作异常记录详细日志，不得静默吞没异常 |
| 优雅退出 | 接收 SIGTERM/SIGINT 时完成当前处理再退出 |
| systemd 兼容 | 提供 systemd service 示例文件，支持 `Restart=on-failure` |
| 内存安全 | Syslog 接收使用固定缓冲区，HFish 拉取使用流式处理，避免全量加载 |
| 长时间运行 | 无状态循环，长时间运行不得有累积性内存增长 |

### 8.3 可测试性

| 要求 | 说明 |
|------|------|
| Mock Syslog | 提供 `mock_syslog.py` 测试工具，可发送模拟 Syslog 报文 |
| 真实样本 | `tests/fixtures/` 目录保存 SafeLine 和 HFish 的样本日志 |
| 单元测试 | Parser 和 Normalizer 必须写单元测试 |
| 测试框架 | 使用 `pytest` |
| 测试隔离 | 每个测试用例使用独立的临时数据库 |
| CI 兼容 | 测试无需外部依赖（不依赖 SafeLine/HFish 实例） |

### 8.4 安全性

| 要求 | 说明 |
|------|------|
| 密钥管理 | API Key、Token、密码一律从环境变量读取，禁止硬编码 |
| Git 安全 | `config.yaml` 被 `.gitignore` 排除，仅提交 `config.yaml.example` |
| 网络暴露 | Web Dashboard 默认仅监听 `127.0.0.1` |
| 无主动攻击 | 本平台不进行主动扫描、漏洞探测、自动封禁 |
| 使用限制 | 测试流量仅限于自有 VPS、自有靶场或获得授权的外部环境 |
| 最小权限 | 程序不以 root 运行（Syslog 端口 < 1024 需提权时单独说明） |

### 8.5 可维护性

| 要求 | 说明 |
|------|------|
| 模块化 | 项目目录结构清晰，模块职责单一 |
| 解耦 | Collector（采集）、Parser（解析）、Normalizer（标准化）、Analyzer（分析）完全解耦 |
| 配置集中 | 所有配置集中在 `config.yaml`，代码中不散落配置常量 |
| 数据库封装 | 数据库操作集中在 `db/` 模块，业务代码不直接执行 SQL |
| 日志统一 | 使用 Python logging 模块，统一日志格式和输出 |
| 文档 | 提供完整 README，包含安装、配置、运行、开发指南 |
| 注释 | 关键函数和复杂逻辑必须写 docstring 和行内注释 |

---

## 九、项目阶段规划

### Phase 0：项目初始化与文档建设

**阶段目标：** 搭建项目骨架，完成基础设施和文档。

**核心功能：**
- 创建项目目录结构
- `README.md` 项目说明
- `docs/requirements.md` 需求文档
- `docs/development_plan.md` 开发计划
- `config.yaml.example` 示例配置
- `.gitignore` 配置
- `requirements.txt` 依赖清单
- 数据库初始化脚本 `init-db`

**验收标准：**
- 项目基础骨架可运行 `python main.py init-db`
- 数据库文件正确生成，包含所有预期表结构
- 需求文档和开发计划评审通过

**本阶段不做：**
- ❌ 任何日志采集功能
- ❌ 任何事件解析
- ❌ 任何分析功能

---

### Phase 1：SafeLine Syslog MVP

**阶段目标：** 实现 SafeLine WAF 日志的 Syslog 接收和原始存储。

**核心功能：**
- UDP Syslog 服务监听
- 原始 Syslog 报文完整保存到 `raw_safeline_logs`
- JSON 提取与解析尝试
- 解析状态记录
- `python main.py recv-safeline` 命令
- `mock_syslog.py` 测试工具
- `tests/fixtures/safeline_sample.log`

**验收标准：**
- 可接收 SafeLine 发送的真实 Syslog 日志
- 原始日志完整入库
- JSON 解析成功/失败状态正确记录
- 解析失败不崩溃

**本阶段不做：**
- ❌ HFish 接入
- ❌ 事件标准化
- ❌ IOC 提取
- ❌ 任何分析功能

---

### Phase 2：HFish API 接入与事件标准化

**阶段目标：** 实现 HFish 蜜罐日志的 API 拉取，完成两数据源的事件标准化。

**核心功能：**
- HFish API 客户端（支持 Token 和账密认证）
- 单次拉取与循环拉取
- 事件去重
- 原始日志完整保存到 `raw_hfish_events`
- SafeLine 日志解析器
- HFish 日志解析器
- 事件标准化 Normalizer
- `python main.py collect-hfish` / `collect-hfish-loop`
- `python main.py show-latest` / `stats`
- `tests/fixtures/hfish_sample.json`

**验收标准：**
- HFish 日志正确拉取并入库
- 去重机制生效，重复拉取不产生重复记录
- SafeLine 和 HFish 事件正确标准化为统一格式
- 标准化事件可查询和统计

**本阶段不做：**
- ❌ IOC 提取
- ❌ 攻击画像
- ❌ 关联分析
- ❌ ATT&CK 映射

---

### Phase 3：IOC、攻击画像与关联分析

**阶段目标：** 实现 IOC 提取、攻击源画像构建和基础关联分析。

**核心功能：**
- IOC 提取引擎
- 攻击源画像构建与更新
- 风险评分规则引擎
- 关联分析引擎（多源命中、多阶段攻击、扫描检测）
- `python main.py normalize` / `extract-ioc`
- `python main.py build-profiles` / `correlate`
- `python main.py show-ip` / `show-profile` / `top-ip`

**验收标准：**
- IOC 正确提取并去重存储
- 攻击源画像准确聚合攻击行为
- 风险评分符合规则预期
- 关联分析正确识别多源命中 IP
- 画像更新不影响已有数据

**本阶段不做：**
- ❌ ATT&CK 映射
- ❌ 报告生成
- ❌ AI 辅助分析

---

### Phase 4：ATT&CK 映射与 Markdown 报告

**阶段目标：** 实现 MITRE ATT&CK 映射和结构化的 Markdown 安全报告生成。

**核心功能：**
- 规则引擎 ATT&CK 映射
- 攻击行为 -> 技术 ID 映射表
- 单 IP 完整报告生成
- Markdown 报告模板
- `python main.py map-attack` / `report`

**验收标准：**
- 常见攻击行为正确映射到 ATT&CK 技术
- 报告内容完整、格式规范
- 报告可保存为独立的 Markdown 文件

**本阶段不做：**
- ❌ AI 辅助分析
- ❌ Web Dashboard

---

### Phase 5：DeepSeek API 辅助研判

**阶段目标：** 接入 DeepSeek API，实现 AI 辅助的安全分析报告生成。

**核心功能：**
- DeepSeek API 客户端
- AI 调用结果缓存
- 攻击行为摘要生成
- Payload 解释
- 处置建议生成
- `python main.py ai-summary`

**验收标准：**
- AI 调用成功返回结果
- 报告中的 AI 部分与规则部分清晰分离
- AI 调用超时/失败不影响主流程
- 缓存机制有效减少重复调用

**本阶段不做：**
- ❌ AI 替代规则引擎
- ❌ AI 直接接触原始日志
- ❌ AI 修改任何评分或数据

---

### Phase 6：Web Dashboard

**阶段目标：** 实现轻量 Web 管理界面，提供可视化安全数据浏览。

**核心功能：**
- FastAPI 应用
- 首页概览看板
- 事件列表与筛选
- 攻击源 IP TOP 榜
- 攻击类型分布（ECharts 图表）
- 趋势图
- 单 IP 画像页面
- IOC 列表
- 报告在线查看与下载

**验收标准：**
- 所有页面正确渲染和加载数据
- 分页、筛选功能正常
- 仅监听 127.0.0.1
- 内存占用控制在 512MB 以内

**本阶段不做：**
- ❌ 用户认证系统
- ❌ 配置修改功能
- ❌ 公网暴露

---

### Phase 7：部署与运维

**阶段目标：** 完善项目部署文档、日志运维和 systemd 托管。

**核心功能：**
- systemd service 配置文件
- 日志轮转配置
- 数据库备份脚本
- 部署文档（从零开始搭建完整环境）
- 运维常见问题 FAQ

**验收标准：**
- 按部署文档从零部署可正常运行
- systemd 托管服务自动重启生效
- 日志轮转正常工作

**本阶段不做：**
- ❌ 新的功能开发

---

### Phase 8：项目打磨与简历包装

**阶段目标：** 完善项目质量，撰写技术文章和简历描述。

**核心功能：**
- 单元测试覆盖率提升
- 代码评审与重构
- 类型注解
- 技术博客（可选）
- 简历项目描述文案
- 项目架构图

**验收标准：**
- 测试覆盖率达到预期目标
- 代码风格一致、类型注解完整
- 简历描述可准确传达项目价值

**本阶段不做：**
- ❌ 新的功能开发

---

## 十、下一步

本文档为 `waf-honeypot-collector` 项目的完整需求定义文档，描述了项目的背景、目标、功能需求、技术约束、CLI 设计、数据库设计和阶段规划。

**下一步工作：**

编写 `docs/development_plan.md` — 开发计划文档。

该文档应将本需求文档中的各阶段细化为具体的开发任务和子任务，包括：

1. 每个阶段的详细任务拆解；
2. 任务之间的依赖关系；
3. 预计工时；
4. 代码模块结构设计；
5. 数据流设计；
6. 文件组织结构；
7. 每个模块的接口定义；
8. 测试策略。

`docs/development_plan.md` 完成后即可进入 Phase 0 的代码开发阶段。
