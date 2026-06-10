#!/usr/bin/env bash
# =============================================================================
# WAF Honeypot Collector — 数据库备份脚本
# 用法:
#   ./scripts/backup_db.sh                    # 备份到默认目录
#   ./scripts/backup_db.sh /path/to/backup    # 备份到指定目录
#   ./scripts/backup_db.sh --auto             # 自动命名（供 crontab 使用）
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DB_PATH="${SCRIPT_DIR}/data/collector.db"
BACKUP_DIR="${1:-${SCRIPT_DIR}/data/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# 如果给了 --auto，使用日期命名（不含时间，便于按天轮转）
if [ "${1:-}" = "--auto" ]; then
    BACKUP_DIR="${2:-${SCRIPT_DIR}/data/backups}"
    TIMESTAMP=$(date +%Y%m%d)
fi

mkdir -p "${BACKUP_DIR}"

if [ ! -f "${DB_PATH}" ]; then
    echo "[WARN] 数据库文件不存在: ${DB_PATH}"
    exit 0
fi

BACKUP_FILE="${BACKUP_DIR}/collector_${TIMESTAMP}.db"

# 使用 SQLite .backup 命令进行在线安全备份
sqlite3 "${DB_PATH}" ".backup '${BACKUP_FILE}'"

# 压缩（可选）
# gzip "${BACKUP_FILE}"

echo "[OK] 数据库备份完成: ${BACKUP_FILE}"
echo "     大小: $(du -h "${BACKUP_FILE}" | cut -f1)"
