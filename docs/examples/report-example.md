# 攻击源分析报告

## 1. 摘要

| 项目 | 值 |
|------|-----|
| **攻击源 IP** | 10.0.0.1 |
| **风险评分** | 85/100 |
| **风险等级** | critical |
| **风险标签** | SQL 注入尝试, 敏感文件探测, 高风险攻击源, Web 扫描, 高危 Payload |
| **数据源命中** | 单源 |

## 2. 时间信息

| 项目 | 值 |
|------|-----|
| **首次出现** | 2026-06-10T11:55:37Z |
| **最近活跃** | 2026-06-10T11:55:37Z |
| **活跃时长** | 2026-06-10T11:55:37Z → 2026-06-10T11:55:37Z |

## 3. 数据源命中

| 数据源 | 事件数 |
|--------|--------|
| SafeLine WAF | 3 |
| HFish 蜜罐 | 0 |

## 4. 攻击类型分布



- **SQL Injection**：3 次



## 5. 攻击时间线

| 时间 | 数据源 | 攻击类型 | 目标 |
|------|--------|----------|------|


| 2026-06-10T11:55:37Z | safeline | SQL Injection | /wp-admin/admin-ajax.php |

| 2026-06-10T11:55:37Z | safeline | SQL Injection | /admin/login.php |

| 2026-06-10T11:55:37Z | safeline | SQL Injection | /wp-admin/admin-ajax.php |



## 6. IOC 列表

| 类型 | 值 | 首次出现 |
|------|-----|----------|


| ip | `10.0.0.1` | 2026-06-10T03:55:53Z |

| user_agent | `Mozilla/5.0 (compatible; sqlmap/1.7)` | 2026-06-10T03:55:53Z |

| user_agent | `[tool] sqlmap` | 2026-06-10T03:55:53Z |

| uri | `/wp-admin/admin-ajax.php` | 2026-06-10T03:55:53Z |

| url | `http://www.target.com/wp-admin/admin-ajax.php` | 2026-06-10T03:55:53Z |

| payload | `1' UNION SELECT * FROM users--` | 2026-06-10T03:55:53Z |

| suspicious_path | `/wp-admin/admin-ajax.php` | 2026-06-10T03:55:53Z |

| uri | `/admin/login.php` | 2026-06-10T03:55:53Z |

| url | `http://www.target.com/admin/login.php` | 2026-06-10T03:55:53Z |

| payload | `1' OR '1'='1` | 2026-06-10T03:55:53Z |

| suspicious_path | `/admin/login.php` | 2026-06-10T03:55:53Z |



## 7. ATT&CK 映射

| 攻击行为 | 技术 ID | 技术名称 |
|----------|---------|----------|


| SQL 注入攻击 | T1190 | Exploit Public-Facing Application |

| SQL 注入攻击 | T1190 | Exploit Public-Facing Application |

| SQL 注入攻击 | T1190 | Exploit Public-Facing Application |





## 8. 处置建议

- 该攻击源风险等级为 **高风险**，建议立即将 IP 加入WAF黑名单进行封禁。
- 检测到 SQL 注入尝试，请检查 WAF 规则是否覆盖该攻击向量，并确认相关接口是否存在注入漏洞。
- 检测到 Web 扫描行为，建议确认是否为授权测试，若非授权测试应采取 IP 临时封禁策略。
- 检测到敏感文件/路径探测行为，请确认 `.git`、`.env`、备份文件等是否已在 Web 访问中排除。
- 检测到高危攻击 Payload，建议原始日志留存备查，并确认业务系统是否存在对应漏洞。

## 9. 原始事件索引

- **SafeLine 原始日志 ID 列表**: 5, 4, 3
- **HFish 原始事件 ID 列表**: 无

---

*报告生成时间: 2026-06-10T04:47:35Z*
*数据来源: SafeLine WAF + HFish 蜜罐*
