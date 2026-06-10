#!/usr/bin/env bash
# =============================================================================
# WAF Honeypot Collector — 数据库备份脚本
# 用法:
#   ./scripts/backup_db.sh                    # 备份到默认目录
#   ./scripts/backup_db.sh /path/to/backup    # 备份到指定目录
#   ./scripts/backup_db.sh --auto             # 自动命名（供 crontab 使用）
#
# 环境变量:
#   RETENTION_DAYS — 备份保留天数（默认 30，设为 0 不清理）
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DB_PATH="${SCRIPT_DIR}/data/collector.db"
BACKUP_DIR="${1:-${SCRIPT_DIR}/data/backups}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS="${RETENTION_DAYS:-30}"

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

echo "[OK] 数据库备份完成: ${BACKUP_FILE}"
echo "     大小: $(du -h "${BACKUP_FILE}" | cut -f1)"

# 清理超过保留天数的旧备份
if [ "${RETENTION_DAYS}" -gt 0 ] 2>/dev/null; then
    CLEANUP_COUNT=$(find "${BACKUP_DIR}" -maxdepth 1 -name "collector_*.db" -mtime "+${RETENTION_DAYS}" -type f -print | wc -l)
    if [ "${CLEANUP_COUNT}" -gt 0 ]; then
        find "${BACKUP_DIR}" -maxdepth 1 -name "collector_*.db" -mtime "+${RETENTION_DAYS}" -type f -delete
        echo "[INFO] 已清理 ${CLEANUP_COUNT} 个超过 ${RETENTION_DAYS} 天的旧备份"
    fi
fi
