#!/usr/bin/env python3
"""
KeeVault XC - Local Zero-Knowledge MCP Server & Chrome Extension HTTP Bridge
============================================================================
- Runs an HTTP Bridge on http://127.0.0.1:18455 for the KeeVault XC Chrome Extension
- Exposes Model Context Protocol (MCP JSON-RPC 2.0 over stdio) for AI Agents (Antigravity, Claude, Cursor)
- Security Guarantee (Blind Autofill):
  AI Agents can see which accounts exist (Title, URL, Username, 2FA availability) ONLY when
  the user has unlocked the vault with the Master Password and enabled the 'MCP para IA (ON)' switch.
  Passwords NEVER leave the Chrome Extension and NEVER enter the AI prompt/context!
"""

from __future__ import annotations

import json
import os
import pathlib
import socket
import sys
import threading
import time
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

ROOT_DIR = pathlib.Path(__file__).resolve().parent
STATE_FILE = ROOT_DIR / "bridge_state.json"
BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 18455

_mem_lock = threading.Lock()
_bridge_memory: dict[str, Any] = {
    "hasVault": False,
    "unlocked": False,
    "permanentUnlock": True,
    "mcpEnabled": True,
    "lastHeartbeat": 0.0,
    "entries": [],
    "pendingCommands": [],
    "commandResults": {},
}


def _save_state_snapshot() -> None:
    try:
        with _mem_lock:
            snap = {
                "hasVault": _bridge_memory["hasVault"],
                "unlocked": _bridge_memory["unlocked"],
                "permanentUnlock": _bridge_memory["permanentUnlock"],
                "mcpEnabled": _bridge_memory["mcpEnabled"],
                "lastHeartbeat": _bridge_memory["lastHeartbeat"],
                "entries": _bridge_memory["entries"],
            }
        STATE_FILE.write_text(json.dumps(snap, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass


class BridgeHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return  # Silence HTTP access logs to keep stdio clean for MCP JSON-RPC

    def _send_cors_headers(self, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_OPTIONS(self) -> None:
        self._send_cors_headers(200)

    def do_GET(self) -> None:
        if self.path == "/status":
            with _mem_lock:
                online = (time.time() - _bridge_memory["lastHeartbeat"]) < 15.0
                payload = {
                    "ok": True,
                    "extensionConnected": online,
                    "hasVault": _bridge_memory["hasVault"],
                    "unlocked": _bridge_memory["unlocked"],
                    "permanentUnlock": _bridge_memory["permanentUnlock"],
                    "mcpEnabled": _bridge_memory["mcpEnabled"],
                    "entries": _bridge_memory["entries"] if (_bridge_memory["unlocked"] and _bridge_memory["mcpEnabled"]) else [],
                }
            self._send_cors_headers(200)
            self.wfile.write(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
            return

        self._send_cors_headers(404)
        self.wfile.write(b'{"ok":false,"error":"not_found"}')

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            body = {}

        if self.path == "/extension-sync":
            with _mem_lock:
                _bridge_memory["hasVault"] = bool(body.get("hasVault", False))
                _bridge_memory["unlocked"] = bool(body.get("unlocked", False))
                _bridge_memory["permanentUnlock"] = bool(body.get("permanentUnlock", True))
                _bridge_memory["mcpEnabled"] = bool(body.get("mcpEnabled", True))
                _bridge_memory["lastHeartbeat"] = time.time()
                _bridge_memory["entries"] = body.get("entries", []) if isinstance(body.get("entries"), list) else []
                pending = list(_bridge_memory["pendingCommands"])
                _bridge_memory["pendingCommands"].clear()

            _save_state_snapshot()
            self._send_cors_headers(200)
            self.wfile.write(json.dumps({"ok": True, "pendingCommands": pending}, ensure_ascii=False).encode("utf-8"))
            return

        if self.path == "/command-result":
            cmd_id = body.get("id")
            if cmd_id:
                with _mem_lock:
                    _bridge_memory["commandResults"][cmd_id] = body
            self._send_cors_headers(200)
            self.wfile.write(b'{"ok":true}')
            return

        if self.path == "/enqueue-command":
            cmd_id = str(uuid.uuid4())
            cmd = {
                "id": cmd_id,
                "action": body.get("action"),
                "entryId": body.get("entryId"),
                "openUrlIfNeeded": bool(body.get("openUrlIfNeeded", True)),
            }
            with _mem_lock:
                _bridge_memory["pendingCommands"].append(cmd)

            # Wait up to 9 seconds for the Chrome Extension to execute and reply
            deadline = time.time() + 9.0
            result = None
            while time.time() < deadline:
                with _mem_lock:
                    if cmd_id in _bridge_memory["commandResults"]:
                        result = _bridge_memory["commandResults"].pop(cmd_id)
                        break
                time.sleep(0.15)

            self._send_cors_headers(200)
            if result is None:
                self.wfile.write(
                    json.dumps(
                        {
                            "ok": False,
                            "error": "Tempo limite aguardando resposta da extensão KeeVault XC no Chrome. Verifique se o Chrome está aberto.",
                        },
                        ensure_ascii=False,
                    ).encode("utf-8")
                )
            else:
                self.wfile.write(json.dumps(result, ensure_ascii=False).encode("utf-8"))
            return

        self._send_cors_headers(404)
        self.wfile.write(b'{"ok":false}')


def ensure_http_bridge_running() -> None:
    """Starts the local HTTP bridge on 127.0.0.1:18455 if not already listening."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.3)
    in_use = sock.connect_ex((BRIDGE_HOST, BRIDGE_PORT)) == 0
    sock.close()
    if in_use:
        return

    def _serve() -> None:
        try:
            srv = ThreadingHTTPServer((BRIDGE_HOST, BRIDGE_PORT), BridgeHTTPHandler)
            srv.serve_forever()
        except Exception:
            pass

    threading.Thread(target=_serve, daemon=True).start()
    time.sleep(0.15)


def http_get_bridge_status() -> dict[str, Any]:
    ensure_http_bridge_running()
    try:
        with urllib.request.urlopen(f"http://{BRIDGE_HOST}:{BRIDGE_PORT}/status", timeout=2.0) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception as exc:
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"ok": False, "error": str(exc)}


def http_enqueue_bridge_command(action: str, entry_id: str, open_url: bool = True) -> dict[str, Any]:
    ensure_http_bridge_running()
    req = urllib.request.Request(
        f"http://{BRIDGE_HOST}:{BRIDGE_PORT}/enqueue-command",
        data=json.dumps({"action": action, "entryId": entry_id, "openUrlIfNeeded": open_url}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=11.0) as r:
        return json.loads(r.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# MCP JSON-RPC 2.0 Server Implementation
# ---------------------------------------------------------------------------
MCP_TOOLS = [
    {
        "name": "keevault_status",
        "description": (
            "Verifica o estado do cofre de senhas KeeVault XC no Chrome (se está destrancado com a Senha Mestra, "
            "se o modo Permanente está ativo, se o acesso MCP para IA está ligado e quantas contas estão disponíveis para login)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "keevault_list_logins",
        "description": (
            "Lista as contas/credenciais disponíveis no cofre KeeVault XC para fazer login nos sites. "
            "SEGURANÇA ZERO-KNOWLEDGE: Retorna apenas id, title, username, url, domain e hasTotp (a senha nunca é exposta em texto puro)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {
                    "type": "string",
                    "description": "Filtro opcional por domínio, nome do site ou usuário (ex: 'google', 'github').",
                }
            },
        },
    },
    {
        "name": "keevault_autofill_login",
        "description": (
            "Executa o Preenchimento Cego (Blind Autofill) de uma credencial diretamente na aba do Google Chrome "
            "(preenchendo usuário, senha e código 2FA sem expor a senha para o prompt da IA)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "entry_id": {
                    "type": "string",
                    "description": "O ID da credencial obtido em keevault_list_logins (ou nome/domínio do site).",
                },
                "open_url_if_needed": {
                    "type": "boolean",
                    "description": "Se true (padrão), abre a URL do site no Chrome caso ainda não esteja aberta.",
                },
            },
            "required": ["entry_id"],
        },
    },
    {
        "name": "keevault_get_totp",
        "description": "Gera e retorna o código 2FA (TOTP de 6 dígitos temporário) para uma conta autorizada no KeeVault XC.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "entry_id": {
                    "type": "string",
                    "description": "O ID da credencial obtido em keevault_list_logins.",
                }
            },
            "required": ["entry_id"],
        },
    },
]


def handle_mcp_tool_call(name: str, args: dict[str, Any]) -> str:
    st = http_get_bridge_status()

    if name == "keevault_status":
        return json.dumps(
            {
                "extensionConnected": st.get("extensionConnected", False),
                "hasVault": st.get("hasVault", False),
                "unlocked": st.get("unlocked", False),
                "permanentUnlock": st.get("permanentUnlock", True),
                "mcpEnabled": st.get("mcpEnabled", True),
                "availableLoginsCount": len(st.get("entries") or []),
                "message": (
                    "🔓 Cofre destrancado e pronto para Blind Autofill!"
                    if (st.get("unlocked") and st.get("mcpEnabled"))
                    else "🔒 O cofre está trancado ou o acesso MCP está em OFF na extensão do Chrome."
                ),
            },
            ensure_ascii=False,
            indent=2,
        )

    if not st.get("unlocked"):
        return "🔒 Cofre Trancado: Peça ao usuário para abrir a extensão KeeVault XC no Chrome e desbloquear com a Senha Mestra."
    if not st.get("mcpEnabled"):
        return "⚠️ Acesso MCP Desligado: O botão 'MCP para IA (ON/OFF)' está em OFF na extensão KeeVault XC."

    entries = st.get("entries") or []

    if name == "keevault_list_logins":
        q = (args.get("search") or "").strip().lower()
        filtered = [
            e
            for e in entries
            if not q
            or q in (e.get("title") or "").lower()
            or q in (e.get("domain") or "").lower()
            or q in (e.get("url") or "").lower()
            or q in (e.get("username") or "").lower()
        ]
        return json.dumps(
            {
                "count": len(filtered),
                "note": "Zero-Knowledge Catalog: Use 'keevault_autofill_login' com o 'id' desejado para logar sem expor a senha.",
                "logins": filtered,
            },
            ensure_ascii=False,
            indent=2,
        )

    if name in ("keevault_autofill_login", "keevault_get_totp"):
        target_id = (args.get("entry_id") or "").strip()
        matched = next((e for e in entries if e.get("id") == target_id), None)
        if not matched:
            q = target_id.lower()
            matched = next(
                (
                    e
                    for e in entries
                    if q in (e.get("title") or "").lower() or q in (e.get("domain") or "").lower()
                ),
                None,
            )
        if not matched:
            return f"❌ Nenhuma credencial liberada encontrada para '{target_id}'. Chame keevault_list_logins primeiro."

        action = "autofill_login" if name == "keevault_autofill_login" else "get_totp"
        res = http_enqueue_bridge_command(
            action=action,
            entry_id=matched["id"],
            open_url=bool(args.get("open_url_if_needed", True)),
        )
        return json.dumps(res, ensure_ascii=False, indent=2)

    return f"Ferramenta desconhecida: {name}"


def run_mcp_stdio() -> None:
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    ensure_http_bridge_running()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue

        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params") or {}

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "keevault-xc-mcp", "version": "2.0.0"},
                },
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": MCP_TOOLS},
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        elif method == "tools/call":
            t_name = params.get("name", "")
            t_args = params.get("arguments") or {}
            text_out = handle_mcp_tool_call(t_name, t_args)
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": text_out}],
                },
            }
            sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
        elif req_id is not None:
            resp = {"jsonrpc": "2.0", "id": req_id, "result": {}}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    if "--bridge-daemon" in sys.argv:
        srv = ThreadingHTTPServer((BRIDGE_HOST, BRIDGE_PORT), BridgeHTTPHandler)
        srv.serve_forever()
    else:
        run_mcp_stdio()
