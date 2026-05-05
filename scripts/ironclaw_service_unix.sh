#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:-status}"
HOST_ADDRESS="${IRONCLAW_SERVICE_HOST:-127.0.0.1}"
PORT="${IRONCLAW_SERVICE_PORT:-8000}"
APP_IMPORT="${IRONCLAW_APP_IMPORT:-app.main:app}"
LOG_LEVEL="${IRONCLAW_LOG_LEVEL:-info}"
RELOAD="${IRONCLAW_SERVICE_RELOAD:-0}"
JSON_OUTPUT="${IRONCLAW_SERVICE_JSON:-0}"
START_TIMEOUT_SECONDS="${IRONCLAW_START_TIMEOUT_SECONDS:-20}"
STOP_TIMEOUT_SECONDS="${IRONCLAW_STOP_TIMEOUT_SECONDS:-10}"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${PROJECT_ROOT}/.ironclaw"
PID_FILE="${RUN_DIR}/ironclaw-service.pid"
LOG_FILE="${RUN_DIR}/ironclaw-service.log"

usage() {
  cat <<'EOF'
Usage:
  scripts/ironclaw_service_unix.sh [start|stop|restart|status] [options]

Options:
  --host <host>           Bind host, default 127.0.0.1
  --port <port>           Bind port, default 8000
  --app <import>          ASGI import path, default app.main:app
  --log-level <level>     Uvicorn log level, default info
  --reload                Enable uvicorn reload
  --json                  Print JSON result
  --start-timeout <sec>   Startup timeout, default 20
  --stop-timeout <sec>    Stop timeout, default 10
  -h, --help              Show help

Examples:
  scripts/ironclaw_service_unix.sh start
  scripts/ironclaw_service_unix.sh status --json
  scripts/ironclaw_service_unix.sh restart --reload
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    start|stop|restart|status)
      ACTION="$1"
      shift
      ;;
    --host)
      HOST_ADDRESS="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    --app)
      APP_IMPORT="$2"
      shift 2
      ;;
    --log-level)
      LOG_LEVEL="$2"
      shift 2
      ;;
    --reload)
      RELOAD="1"
      shift
      ;;
    --json)
      JSON_OUTPUT="1"
      shift
      ;;
    --start-timeout)
      START_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    --stop-timeout)
      STOP_TIMEOUT_SECONDS="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[ironclaw-service] unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

mkdir -p "$RUN_DIR"

resolve_python() {
  local venv_python="${PROJECT_ROOT}/.venv/bin/python"
  if [[ -x "$venv_python" ]]; then
    printf '%s\n' "$venv_python"
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    command -v python3
    return 0
  fi

  if command -v python >/dev/null 2>&1; then
    command -v python
    return 0
  fi

  echo "[ironclaw-service] python executable not found" >&2
  exit 1
}

PYTHON_BIN="$(resolve_python)"

is_pid_running() {
  local pid="$1"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

read_pid() {
  if [[ -f "$PID_FILE" ]]; then
    local pid
    pid="$(head -n 1 "$PID_FILE" | tr -d '[:space:]')"
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      printf '%s\n' "$pid"
      return 0
    fi
  fi
  return 1
}

remove_pid_file() {
  rm -f "$PID_FILE"
}

port_is_open() {
  local host="$1"
  local port="$2"

  if command -v python3 >/dev/null 2>&1; then
    python3 - "$host" "$port" <<'PY' >/dev/null 2>&1
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(0.5)
try:
    sock.connect((host, port))
except OSError:
    sys.exit(1)
else:
    sys.exit(0)
finally:
    sock.close()
PY
    return $?
  fi

  if command -v nc >/dev/null 2>&1; then
    nc -z "$host" "$port" >/dev/null 2>&1
    return $?
  fi

  return 1
}

print_state() {
  local action="$1"
  local running="$2"
  local pid="$3"

  if [[ "$JSON_OUTPUT" == "1" ]]; then
    cat <<EOF
{
  "action": "${action}",
  "state": {
    "running": ${running},
    "pid": ${pid:-null},
    "host": "${HOST_ADDRESS}",
    "port": ${PORT},
    "pid_file": "${PID_FILE}",
    "log_file": "${LOG_FILE}"
  }
}
EOF
    return 0
  fi

  echo "[ironclaw-service] action: ${action}"
  echo "[ironclaw-service] running: ${running}"
  echo "[ironclaw-service] pid: ${pid:-null}"
  echo "[ironclaw-service] host: ${HOST_ADDRESS}"
  echo "[ironclaw-service] port: ${PORT}"
  echo "[ironclaw-service] pid_file: ${PID_FILE}"
  echo "[ironclaw-service] log_file: ${LOG_FILE}"
}

status_service() {
  local pid=""
  if pid="$(read_pid)"; then
    if is_pid_running "$pid" && port_is_open "$HOST_ADDRESS" "$PORT"; then
      print_state "status" "true" "$pid"
      return 0
    fi
  fi

  remove_pid_file
  print_state "status" "false" ""
}

start_service() {
  local existing_pid=""
  if existing_pid="$(read_pid)"; then
    if is_pid_running "$existing_pid" && port_is_open "$HOST_ADDRESS" "$PORT"; then
      print_state "start" "true" "$existing_pid"
      return 0
    fi
    remove_pid_file
  fi

  local -a cmd
  cmd=("$PYTHON_BIN" -m uvicorn "$APP_IMPORT" --host "$HOST_ADDRESS" --port "$PORT" --log-level "$LOG_LEVEL")
  if [[ "$RELOAD" == "1" ]]; then
    cmd+=(--reload)
  fi

  (
    cd "$PROJECT_ROOT"
    export PYTHONPATH="$PROJECT_ROOT${PYTHONPATH:+:$PYTHONPATH}"
    nohup "${cmd[@]}" >>"$LOG_FILE" 2>&1 &
    echo $! >"$PID_FILE"
  )

  local pid=""
  pid="$(read_pid || true)"
  if [[ -z "$pid" ]]; then
    echo "[ironclaw-service] failed to record service pid" >&2
    exit 1
  fi

  local deadline=$((SECONDS + START_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    if ! is_pid_running "$pid"; then
      remove_pid_file
      echo "[ironclaw-service] service exited early; check log ${LOG_FILE}" >&2
      exit 1
    fi

    if port_is_open "$HOST_ADDRESS" "$PORT"; then
      print_state "start" "true" "$pid"
      return 0
    fi

    sleep 1
  done

  stop_service_internal >/dev/null 2>&1 || true
  echo "[ironclaw-service] service did not become ready within ${START_TIMEOUT_SECONDS} seconds" >&2
  exit 1
}

stop_service_internal() {
  local pid=""
  if ! pid="$(read_pid)"; then
    remove_pid_file
    return 0
  fi

  if ! is_pid_running "$pid"; then
    remove_pid_file
    return 0
  fi

  kill -TERM "$pid" >/dev/null 2>&1 || true

  local deadline=$((SECONDS + STOP_TIMEOUT_SECONDS))
  while (( SECONDS < deadline )); do
    if ! is_pid_running "$pid"; then
      remove_pid_file
      return 0
    fi
    sleep 1
  done

  kill -KILL "$pid" >/dev/null 2>&1 || true
  remove_pid_file
  return 0
}

stop_service() {
  local pid=""
  pid="$(read_pid || true)"
  stop_service_internal
  print_state "stop" "false" ""
}

restart_service() {
  stop_service_internal
  ACTION="restart"
  start_service
}

case "$ACTION" in
  start)
    start_service
    ;;
  stop)
    stop_service
    ;;
  restart)
    restart_service
    ;;
  status)
    status_service
    ;;
  *)
    echo "[ironclaw-service] unsupported action: ${ACTION}" >&2
    usage >&2
    exit 1
    ;;
esac