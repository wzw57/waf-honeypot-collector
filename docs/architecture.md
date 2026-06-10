# 项目架构

## 整体架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                               WAF Honeypot Collector                        │
│                                                                             │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────────┐ │
│   │  采集层       │    │  解析层       │    │  分析层                      │ │
│   │              │    │              │    │                              │ │
│   │ safeline_    │───→│ safeline_    │───→│ normalizer  → normalized     │ │
│   │ syslog.py    │    │ parser.py    │    │              _events         │ │
│   │  (UDP :1514) │    │              │    │                              │ │
│   │              │    │              │    │ ioc_extractor  →  iocs       │ │
│   │ hfish_api.py │───→│ hfish_parser │───→│                              │ │
│   │  (REST API)  │    │ .py          │    │ profiler  →  attacker_      │ │
│   └──────────────┘    └──────────────┘    │              profiles        │ │
│                                            │                              │ │
│   ┌──────────────┐                         │ risk_scorer  →  risk_score   │ │
│   │  Web Layer   │                         │                              │ │
│   │              │                         │ correlator  →  tags /        │ │
│   │ FastAPI +    │                         │               is_multi_source│ │
│   │ Jinja2 +     │                         │                              │ │
│   │ Bootstrap 5  │                         │ attack_mapper  →  attack_    │ │
│   │              │                         │                 mappings     │ │
│   │ uvicorn      │                         └──────────────────────────────┘
│   │ :8000        │                                     │
│   └──────────────┘                                     ▼
│                                              ┌──────────────────┐
│   ┌──────────────┐                           │  报告/展示层      │
│   │ AI Layer     │                           │                  │
│   │              │                           │ markdown_report  │
│   │ DeepSeek     │                           │ .py → .md 报告    │
│   │ API Client   │                           │                  │
│   └──────────────┘                           │ Web Dashboard   │
│                                              │ (页面 + 图表)     │
│   ┌──────────────┐                           └──────────────────┘
│   │ 基础设施      │
│   │              │
│   │ config.py    │
│   │ db.py        │
│   │ logger.py    │
│   │ utils.py     │
│   └──────────────┘
└─────────────────────────────────────────────────────────────────────────────┘
```

## 模块依赖关系

```
main.py
  ├── app/          (被所有模块依赖)
  │   ├── config.py   →  PyYAML
  │   ├── db.py       →  sqlite3
  │   ├── logger.py   →  logging
  │   └── utils.py    →  json / re
  │
  ├── collectors/
  │   ├── safeline_syslog.py  →  app/, parsers/safeline_parser.py
  │   └── hfish_api.py        →  app/, requests
  │
  ├── parsers/
  │   ├── safeline_parser.py  →  json
  │   └── hfish_parser.py     →  json, hashlib
  │
  ├── analyzers/
  │   ├── normalizer.py       →  app/
  │   ├── normalizer_runner.py→  app/, parsers/, analyzers/normalizer.py
  │   ├── ioc_extractor.py    →  app/
  │   ├── profiler.py         →  app/, analyzers/risk_scorer.py
  │   ├── risk_scorer.py      →  app/
  │   ├── correlator.py       →  app/, analyzers/risk_scorer.py
  │   └── attack_mapper.py    →  app/
  │
  ├── ai/
  │   ├── deepseek_client.py  →  app/, ai/prompts.py, requests
  │   └── prompts.py          →  (纯数据，无依赖)
  │
  ├── reports/
  │   ├── markdown_report.py  →  app/, analyzers/attack_mapper.py, jinja2
  │   └── templates/ip_report.md.j2
  │
  ├── web/
  │   ├── server.py           →  web/routes.py, fastapi, uvicorn
  │   ├── routes.py           →  app/, reports/, fastapi
  │   ├── templates/          →  Jinja2
  │   └── static/             →  CSS
  │
  ├── scripts/
  │   ├── mock_syslog.py      →  socket
  │   └── backup_db.sh        →  sqlite3
  │
  └── tests/                  →  pytest, analyzers/, parsers/, app/
```

## 数据表关系

```
raw_safeline_logs
  ├── id (PK)
  ├── received_at
  ├── sender_ip
  ├── raw_message
  ├── parsed_json
  ├── parse_status
  └── error_message

raw_hfish_events
  ├── id (PK)
  ├── raw_data
  ├── event_id (UNIQUE)
  ├── parse_status
  └── error_message

normalized_events
  ├── id (PK)
  ├── source           → "safeline" | "hfish"
  ├── src_ip           ─────→ attacker_profiles.src_ip
  ├── attack_type
  ├── severity
  └── raw_table        → 指向 raw_safeline_logs | raw_hfish_events
      raw_id           → 对应原始表记录 ID

iocs
  ├── id (PK)
  ├── ioc_type + ioc_value (UNIQUE)
  ├── src_ip           → attacker_profiles.src_ip
  └── normalized_event_id → normalized_events.id

attacker_profiles
  ├── src_ip (UNIQUE PK)
  ├── risk_score
  ├── tags
  └── is_multi_source

attack_mappings
  ├── id (PK)
  ├── normalized_event_id → normalized_events.id
  └── technique_id     → MITRE ATT&CK

ioc_extraction_status
  ├── normalized_event_id (UNIQUE) → normalized_events.id
  └── extracted_at

ai_analysis_cache
  ├── cache_key (UNIQUE)
  ├── result
  └── expires_at
```

## 数据流（详细）

```
SafeLine WAF
    │ UDP Syslog (port 1514)
    ▼
safeline_syslog.py  ──写入──→ raw_safeline_logs 表
    │                           │
    ▼                           ▼
safeline_parser.py           normalizer.py
    │                           │
    └──────JSON 提取───────→  normalized_events 表
                                    │
                    ┌───────────────┼──────────────────┐
                    ▼               ▼                  ▼
            ioc_extractor.py   profiler.py        attack_mapper.py
                    │               │                  │
                    ▼               ▼                  ▼
                iocs 表        attacker_profiles   attack_mappings
                                   │
                                   ▼
                            correlator.py
                                   │
                                   ▼
                           tags / is_multi_source
                                   │
                                   ▼
                          markdown_report.py → .md 报告
                          web/routes.py      → HTML 页面
```
