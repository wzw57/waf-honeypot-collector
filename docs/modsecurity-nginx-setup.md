# Nginx + ModSecurity + OWASP CRS 部署文档

本文档说明如何在 Ubuntu 上部署 Nginx + ModSecurity + OWASP CRS，
为 waf-honeypot-collector 提供免费、开源、可控的 WAF 日志来源。

---

## 1. 安装依赖

```bash
sudo apt update
sudo apt install -y nginx libnginx-mod-http-modsecurity git curl
```

> **注意**：不同发行版的 ModSecurity 包路径可能不同。
> 安装后用 `find` 确认实际路径：
> ```bash
> find /etc -name "modsecurity.conf" -o -name "main.conf" 2>/dev/null
> ```

## 2. 启用 ModSecurity

Ubuntu 下 `libnginx-mod-http-modsecurity` 包的常见配置路径：

| 文件 | 说明 |
|------|------|
| `/etc/nginx/modsec/main.conf` | Nginx ModSecurity 入口配置 |
| `/etc/modsecurity/modsecurity.conf` | ModSecurity 核心配置 |
| `/usr/share/modsecurity-crs/` | OWASP CRS 规则目录（如系统包自带） |

### 2.1 启用核心规则引擎

编辑 `/etc/modsecurity/modsecurity.conf`，确保：

```apache
SecRuleEngine On
```

### 2.2 配置审计日志

编辑 `/etc/nginx/modsec/main.conf`（或 `/etc/modsecurity/modsecurity.conf`），
确认或添加以下配置：

```apache
SecAuditEngine RelevantOnly
SecAuditLog /var/log/modsec_audit.log
SecAuditLogFormat Native
SecAuditLogParts ABIJDEFHZ
```

### 2.3 下载 OWASP CRS（如果系统未自带）

```bash
cd /opt
sudo git clone https://github.com/coreruleset/coreruleset.git owasp-crs
sudo chown -R www-data:www-data /opt/owasp-crs
```

### 2.4 在主配置中引用 CRS

编辑 `/etc/nginx/modsec/main.conf`，添加：

```apache
Include /etc/modsecurity/modsecurity.conf

# 如果系统自带 CRS
Include /usr/share/modsecurity-crs/crs-setup.conf.example
Include /usr/share/modsecurity-crs/rules/*.conf

# 如果从 GitHub 下载
# Include /opt/owasp-crs/crs-setup.conf.example
# Include /opt/owasp-crs/rules/*.conf
```

> **注意**：`crs-setup.conf.example` 可能需要先复制为 `.conf`：
> ```bash
> sudo cp /usr/share/modsecurity-crs/crs-setup.conf.example /usr/share/modsecurity-crs/crs-setup.conf
> ```

## 3. Nginx 站点启用 ModSecurity

编辑你的 Nginx 站点配置（如 `/etc/nginx/sites-available/default`）：

```nginx
server {
    listen 80 default_server;
    server_name _;

    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    location / {
        root /var/www/html;
        index index.html;
    }
}
```

### 3.1 测试配置并重载

```bash
sudo nginx -t
sudo systemctl reload nginx
```

## 4. 验证 ModSecurity 是否生效

使用低风险测试请求：

```bash
# SQL 注入测试（单引号，无破坏性）
curl -v "http://localhost/?id=1%27"

# XSS 测试
curl -v "http://localhost/?q=%3Cscript%3Ealert(1)%3C/script%3E"
```

检查是否返回 403 以及审计日志是否生成：

```bash
# 查看 ModSecurity 审计日志
sudo tail -f /var/log/modsec_audit.log

# 查看 Nginx 错误日志
sudo tail -f /var/log/nginx/error.log
```

> **⚠️ 安全边界**：上述测试 payload 均为低风险标准测试字符串，
> 不包含破坏性指令、不利用漏洞、不执行命令。

## 5. 配置日志读取权限

waf-honeypot-collector 以 `ubuntu` 用户运行，需要读取审计日志的权限：

```bash
# 方法 A：将 ubuntu 加入 adm 组
sudo usermod -aG adm ubuntu

# 方法 B：设置 ACL（推荐）
sudo setfacl -m u:ubuntu:r /var/log/modsec_audit.log

# 确保日志文件权限
sudo chmod 640 /var/log/modsec_audit.log
```

## 6. 配置 Collector

在 `config.yaml` 中启用 ModSecurity 采集：

```yaml
modsecurity:
  enabled: true
  audit_log_path: "/var/log/modsec_audit.log"
  mode: "file"
  interval: 30
  read_from_end: true
  state_file: "data/modsecurity_state.json"
  enable_normalization: true
```

## 7. 采集日志

```bash
# 单次采集
python main.py --config config.yaml collect-modsecurity

# 循环采集
python main.py --config config.yaml collect-modsecurity-loop --interval 30
```

## 8. 标准化与分析

```bash
# 标准化
python main.py --config config.yaml normalize

# 后续分析
python main.py --config config.yaml extract-ioc
python main.py --config config.yaml build-profiles
python main.py --config config.yaml correlate
python main.py --config config.yaml map-attack

# 查看结果
python main.py --config config.yaml stats
python main.py --config config.yaml show-latest | head -20
```

## 9. 作为 systemd 服务运行

```bash
sudo systemctl enable --now waf-honeypot-modsecurity
journalctl -u waf-honeypot-modsecurity -f
```

## 10. 常见问题

### Q1: ModSecurity 未生效，仍返回 200

检查：
1. `SecRuleEngine On` 是否已设置
2. Nginx 配置中 `modsecurity on;` 是否添加
3. 确认 `nginx -t` 通过并重载

### Q2: 审计日志为空

检查：
1. `SecAuditEngine RelevantOnly` — 改为 `SecAuditEngine On` 测试
2. 确认日志路径权限
3. 确认 SecAuditLogParts 包含所需段

### Q3: 403 Forbidden 过多

如果 CRS 默认规则过于严格，可以调整：

```apache
SecAction "id:900000,phase:1,pass,nolog,setvar:tx.paranoia_level=1"
```

在 `crs-setup.conf` 中将 paranoia_level 设为 1（最低）。

### Q4: logrotate 后采集中断

waf-honeypot-collector 的 state 管理支持 logrotate 检测：
- inode 变化自动识别；
- 按 `read_from_end` 策略重新开始采集。

无需额外配置。
