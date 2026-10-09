#!/usr/bin/env bash
# Starts a local ClickHouse server for Immune (data under .immune/clickhouse). Requires `clickhouse` binary (brew install --cask clickhouse).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA="$ROOT/.immune/clickhouse"
mkdir -p "$DATA"
if curl -s "http://localhost:8123/ping" >/dev/null 2>&1; then echo "ClickHouse already up on :8123"; exit 0; fi
cat > "$DATA/config.xml" <<XML
<clickhouse>
  <logger><level>warning</level><console>1</console></logger>
  <http_port>8123</http_port>
  <tcp_port>9000</tcp_port>
  <listen_host>127.0.0.1</listen_host>
  <path>$DATA/data/</path>
  <tmp_path>$DATA/tmp/</tmp_path>
  <user_files_path>$DATA/user_files/</user_files_path>
  <format_schema_path>$DATA/format_schemas/</format_schema_path>
  <mark_cache_size>268435456</mark_cache_size>
  <max_server_memory_usage_to_ram_ratio>0.5</max_server_memory_usage_to_ram_ratio>
  <users>
    <default><password></password><networks><ip>::/0</ip></networks><profile>default</profile><quota>default</quota><access_management>1</access_management></default>
  </users>
  <profiles><default/></profiles>
  <quotas><default/></quotas>
</clickhouse>
XML
echo "Starting ClickHouse (data: $DATA)"
exec clickhouse server --config-file="$DATA/config.xml"
