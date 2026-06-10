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
- scripts/ — 辅助脚本

## 配置
- 配置文件名: config.yaml
- 示例配置: config.yaml.example
- API Key 从环境变量读取，不写入代码
