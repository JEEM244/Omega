#!/usr/bin/env python3
"""OMEGA AI: lightweight, offline-first symbolic agent for Termux.

This first prototype uses a small rule-based planner, a custom declarative
language, SQLite memory, and explicit per-action approval. It never invokes a
shell or executes arbitrary Python code.
"""
from __future__ import annotations

import argparse
import ast
import json
import math
import os
import platform
import shutil
import shlex
import re
import sqlite3
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = "0.3.0"
MAX_SCRIPT_BYTES = 64 * 1024
MAX_INSTRUCTIONS = 100
MAX_OMEGA_SCAN_PORTS = 100
MAX_INSPECT_PACKETS = 100
MAX_INSPECT_BYTES = 50 * 1024 * 1024
MAX_CAPTURE_SECONDS = 60
MAX_CAPTURE_PACKETS = 500
MAX_TEXT_CHARS = 4000
MAX_GOAL_CHARS = 500
MAX_MEMORIES = 500
MAX_EVENTS = 2000
MAX_PENDING = 100
MAX_APPROVAL_HISTORY = 2000
MAX_TRAINING_EXAMPLES = 1000
ALLOWED_INTENTS = {"experimento", "memoria", "diagnostico", "general"}
SAFE_FILENAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")


class OmegaError(Exception):
    """Expected user-facing error."""


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_quoted(text: str) -> str:
    try:
        value = ast.literal_eval(text.strip())
    except (ValueError, SyntaxError) as exc:
        raise OmegaError('Se esperaba una cadena entre comillas, por ejemplo "hola".') from exc
    if not isinstance(value, str):
        raise OmegaError("El valor debe ser texto entre comillas.")
    if len(value) > MAX_TEXT_CHARS:
        raise OmegaError(f"El texto supera el límite de {MAX_TEXT_CHARS} caracteres.")
    return value


def parse_language(source: str) -> list[dict[str, Any]]:
    """Compile OMEGA source into approved, data-only actions; never executes code."""
    if len(source.encode("utf-8")) > MAX_SCRIPT_BYTES:
        raise OmegaError(f"El programa supera {MAX_SCRIPT_BYTES} bytes.")
    meaningful = [
        line for line in source.splitlines()
        if line.strip() and not line.strip().startswith("#")
        and line.strip().upper() not in ("OMEGA 0.1", "OMEGA 0.2", "OMEGA 0.3")
    ]
    if len(meaningful) > MAX_INSTRUCTIONS:
        raise OmegaError(f"El programa supera el límite de {MAX_INSTRUCTIONS} instrucciones/líneas.")
    actions: list[dict[str, Any]] = []
    variables: dict[str, str | float] = {}
    var_name = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,39}$")

    def scalar(token: str) -> str | float:
        token = token.strip()
        if token.startswith("$"):
            name = token[1:]
            if name not in variables:
                raise OmegaError(f"Variable no definida: {name}")
            return variables[name]
        if token.startswith('"'):
            return parse_quoted(token)
        try:
            value = float(token)
        except ValueError as exc:
            raise OmegaError(f"Valor no válido: {token}") from exc
        if not abs(value) <= 1e12:
            raise OmegaError("Número fuera del límite permitido.")
        return value

    def expand_text(value: str) -> str:
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in variables:
                raise OmegaError(f"Variable no definida: {name}")
            return str(variables[name])
        expanded = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)", replace, value)
        if len(expanded) > MAX_TEXT_CHARS:
            raise OmegaError(f"El texto expandido supera {MAX_TEXT_CHARS} caracteres.")
        return expanded

    def compile_instruction(line: str) -> dict[str, Any]:
        upper = line.upper()
        if upper == "ESTADO":
            return {"kind": "status", "args": {}}
        if upper == "AUDITAR":
            return {"kind": "audit", "args": {}}
        if upper == "COMPACTAR":
            return {"kind": "compact", "args": {}}
        if upper.startswith("INSPECCIONAR "):
            path_text = parse_quoted(line[len("INSPECCIONAR "):])
            if not path_text.lower().endswith((".pcap", ".pcapng")):
                raise OmegaError("INSPECCIONAR requiere un archivo .pcap o .pcapng.")
            return {"kind": "capture_inspect", "args": {"path": path_text}}
        if upper.startswith("CAPTURAR "):
            match = re.fullmatch(r"CAPTURAR\s+(\d+)\s+SEGUNDOS\s+MAX\s+(\d+)\s+PAQUETES", line, re.I)
            if not match:
                raise OmegaError("Sintaxis: CAPTURAR 10 SEGUNDOS MAX 100 PAQUETES")
            seconds, max_packets = map(int, match.groups())
            if not 1 <= seconds <= MAX_CAPTURE_SECONDS:
                raise OmegaError(f"La captura debe durar entre 1 y {MAX_CAPTURE_SECONDS} segundos.")
            if not 1 <= max_packets <= MAX_CAPTURE_PACKETS:
                raise OmegaError(f"La captura admite entre 1 y {MAX_CAPTURE_PACKETS} paquetes.")
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
            output = str(Path.home() / f"omega-capture-{stamp}.pcap")
            return {"kind": "live_capture", "args": {
                "seconds": seconds, "max_packets": max_packets, "output": output
            }}
        if upper.startswith("ESCANEAR "):
            match = re.fullmatch(
                r'ESCANEAR\s+("(?:[^"\\]|\\.)*")\s+PUERTOS\s+("(?:[^"\\]|\\.)*")\s+AUTORIZADO',
                line, re.I
            )
            if not match:
                raise OmegaError('Sintaxis: ESCANEAR "192.168.1.10" PUERTOS "22,80" AUTORIZADO')
            target = parse_quoted(match.group(1))
            port_text = parse_quoted(match.group(2))
            try:
                import netmap
                target = netmap.check_target(target)
                ports = netmap.parse_ports(port_text)
            except Exception as exc:
                raise OmegaError(f"Objetivo o puertos no válidos: {exc}") from exc
            if len(ports) > MAX_OMEGA_SCAN_PORTS:
                raise OmegaError(f"OMEGA limita cada escaneo a {MAX_OMEGA_SCAN_PORTS} puertos.")
            return {"kind": "lab_scan", "args": {"target": target, "ports": ports, "authorized": True}}
        if upper.startswith("APRENDER "):
            match = re.fullmatch(
                r'APRENDER\s+("(?:[^"\\]|\\.)*")\s*=\s*(experimento|memoria|diagnostico|general)',
                line, re.I
            )
            if not match:
                raise OmegaError('Sintaxis: APRENDER "frase de ejemplo" = diagnostico')
            phrase = parse_quoted(match.group(1)).strip()
            intent = match.group(2).casefold()
            if not phrase or len(phrase) > 300:
                raise OmegaError("La frase de aprendizaje debe tener entre 1 y 300 caracteres.")
            return {"kind": "learn_example", "args": {"phrase": phrase, "intent": intent}}
        if upper.startswith("MOSTRAR "):
            raw = line[8:].strip()
            if raw.startswith("$"):
                return {"kind": "show", "args": {"text": str(scalar(raw))}}
            return {"kind": "show", "args": {"text": expand_text(parse_quoted(raw))}}
        if upper.startswith("RECORDAR "):
            match = re.fullmatch(r'RECORDAR\s+("(?:[^"\\]|\\.)*")\s*=\s*("(?:[^"\\]|\\.)*")', line, re.I)
            if not match:
                raise OmegaError('Sintaxis: RECORDAR "clave" = "valor"')
            key, value = map(parse_quoted, match.groups())
            key, value = expand_text(key), expand_text(value)
            if not key or len(key) > 120:
                raise OmegaError("La clave debe tener entre 1 y 120 caracteres.")
            return {"kind": "memory_set", "args": {"key": key, "value": value}}
        if upper.startswith("LEER_MEMORIA "):
            key = expand_text(parse_quoted(line[len("LEER_MEMORIA "):]))
            return {"kind": "memory_get", "args": {"key": key}}
        if upper.startswith("CREAR "):
            match = re.fullmatch(r'CREAR\s+("(?:[^"\\]|\\.)*")\s*=\s*("(?:[^"\\]|\\.)*")', line, re.I)
            if not match:
                raise OmegaError('Sintaxis: CREAR "archivo.txt" = "contenido"')
            filename, content = map(parse_quoted, match.groups())
            filename, content = expand_text(filename), expand_text(content)
            if not SAFE_FILENAME.fullmatch(filename) or filename in (".", ".."):
                raise OmegaError("Nombre no permitido. Usa un nombre simple sin rutas ni directorios.")
            return {"kind": "file_create", "args": {"filename": filename, "content": content}}
        if upper.startswith("SUMAR "):
            parts = line.split()
            if len(parts) != 3:
                raise OmegaError("Sintaxis: SUMAR numero numero")
            a, b = scalar(parts[1]), scalar(parts[2])
            if isinstance(a, str) or isinstance(b, str):
                raise OmegaError("SUMAR solo acepta números o variables numéricas.")
            return {"kind": "sum", "args": {"a": a, "b": b}}
        raise OmegaError("Instrucción desconocida. Usa DEFINIR, SI, MOSTRAR, SUMAR, ESTADO, AUDITAR, COMPACTAR, ESCANEAR, CAPTURAR, INSPECCIONAR, APRENDER, RECORDAR, LEER_MEMORIA o CREAR.")

    for line_number, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#") or line.upper() in ("OMEGA 0.1", "OMEGA 0.2", "OMEGA 0.3"):
            continue
        try:
            define = re.fullmatch(r'DEFINIR\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)', line, re.I)
            if define:
                name, raw_value = define.groups()
                if not var_name.fullmatch(name):
                    raise OmegaError("Nombre de variable no válido (máximo 40 caracteres).")
                if name in variables:
                    raise OmegaError(f"La variable {name} ya fue definida; no se permite redefinirla.")
                variables[name] = scalar(raw_value)
                continue

            condition = re.fullmatch(
                r'SI\s+(.+?)\s*(==|!=|>=|<=|>|<)\s*(.+?)\s+ENTONCES\s+(.+)',
                line, re.I
            )
            if condition:
                left_raw, operator, right_raw, body = condition.groups()
                left, right = scalar(left_raw), scalar(right_raw)
                if type(left) is not type(right):
                    raise OmegaError("La condición compara valores de tipos distintos.")
                if operator == "==": matched = left == right
                elif operator == "!=": matched = left != right
                elif operator == ">": matched = left > right
                elif operator == "<": matched = left < right
                elif operator == ">=": matched = left >= right
                else: matched = left <= right
                if matched:
                    if body.strip().upper().startswith(("DEFINIR ", "SI ")):
                        raise OmegaError("SI solo admite una instrucción de acción después de ENTONCES.")
                    actions.append(compile_instruction(body.strip()))
                continue

            actions.append(compile_instruction(line))
        except OmegaError as exc:
            raise OmegaError(f"Línea {line_number}: {exc}") from exc
    if not actions and not any(
        line.strip() and not line.strip().startswith("#")
        and line.strip().upper() not in ("OMEGA 0.1", "OMEGA 0.2")
        for line in source.splitlines()
    ):
        raise OmegaError("El programa no contiene instrucciones.")
    return actions

class OmegaStore:
    def __init__(self, home: str | Path):
        self.home = Path(home).expanduser().resolve()
        self.workspace = self.home / "workspace"
        self.db_path = self.home / "omega.sqlite3"
        self.home.mkdir(parents=True, exist_ok=True)
        if self.workspace.is_symlink():
            raise OmegaError("El workspace no puede ser un enlace simbólico.")
        if self.db_path.is_symlink():
            raise OmegaError("La base de datos no puede ser un enlace simbólico.")
        for suffix in ("-wal", "-shm", "-journal"):
            sidecar = Path(str(self.db_path) + suffix)
            if sidecar.is_symlink():
                raise OmegaError("Los archivos auxiliares de SQLite no pueden ser enlaces simbólicos.")
        self.workspace.mkdir(parents=True, exist_ok=True)
        if self.workspace.resolve().parent != self.home:
            raise OmegaError("La ruta real del workspace sale del directorio de OMEGA.")
        self.db = sqlite3.connect(str(self.db_path))
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS memories (
                key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL, args_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','failed')),
                created_at TEXT NOT NULL, finished_at TEXT, result TEXT
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL, event TEXT NOT NULL, detail TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS training_examples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                phrase TEXT NOT NULL, intent TEXT NOT NULL, created_at TEXT NOT NULL
            );
        """)
        self.db.commit()

    def close(self) -> None:
        self.db.close()

    def log(self, event: str, detail: str) -> None:
        self.db.execute("INSERT INTO events(created_at,event,detail) VALUES(?,?,?)",
                        (now_utc(), event, detail[:2000]))
        self.db.execute(
            "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)",
            (MAX_EVENTS,),
        )
        self.db.commit()

    def remember(self, key: str, value: str) -> str:
        if not key or len(key) > 120:
            raise OmegaError("La clave de memoria debe tener entre 1 y 120 caracteres.")
        if len(value) > MAX_TEXT_CHARS:
            raise OmegaError(f"El valor de memoria supera {MAX_TEXT_CHARS} caracteres.")
        self.db.execute("INSERT INTO memories(key,value,updated_at) VALUES(?,?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                        (key, value, now_utc()))
        self.db.execute(
            "DELETE FROM memories WHERE key NOT IN "
            "(SELECT key FROM memories ORDER BY updated_at DESC, rowid DESC LIMIT ?)",
            (MAX_MEMORIES,),
        )
        self.db.commit()
        self.log("memory_set", key)
        return f'Memoria guardada: "{key}".'

    def recall(self, key: str) -> str:
        row = self.db.execute("SELECT value,updated_at FROM memories WHERE key=?", (key,)).fetchone()
        if not row:
            return f'No existe memoria para "{key}".'
        return f'{key} = {row["value"]} (actualizada {row["updated_at"]})'

    def memories(self, limit: int = 20) -> list[dict[str, str]]:
        rows = self.db.execute("SELECT key,value,updated_at FROM memories ORDER BY updated_at DESC LIMIT ?",
                               (max(1, min(limit, 100)),)).fetchall()
        return [dict(row) for row in rows]

    def enqueue(self, kind: str, args: dict[str, Any]) -> int:
        pending_count = self.db.execute(
            "SELECT COUNT(*) FROM approvals WHERE status='pending'"
        ).fetchone()[0]
        if pending_count >= MAX_PENDING:
            raise OmegaError(f"La cola ya tiene {MAX_PENDING} operaciones pendientes; aprueba o rechaza algunas antes de continuar.")
        cursor = self.db.execute(
            "INSERT INTO approvals(kind,args_json,status,created_at) VALUES(?,?,?,?)",
            (kind, json.dumps(args, ensure_ascii=False), "pending", now_utc()),
        )
        self.db.execute(
            "DELETE FROM approvals WHERE status != 'pending' AND id NOT IN "
            "(SELECT id FROM approvals WHERE status != 'pending' ORDER BY id DESC LIMIT ?)",
            (MAX_APPROVAL_HISTORY,),
        )
        self.db.commit()
        action_id = int(cursor.lastrowid)
        self.log("proposed", f"id={action_id}; kind={kind}")
        return action_id

    def get_action(self, action_id: int) -> sqlite3.Row | None:
        return self.db.execute("SELECT * FROM approvals WHERE id=?", (action_id,)).fetchone()

    def pending(self) -> list[sqlite3.Row]:
        return self.db.execute("SELECT * FROM approvals WHERE status='pending' ORDER BY id").fetchall()

    def history(self, limit: int = 20) -> list[sqlite3.Row]:
        """Read-only history of proposals and their final status."""
        bounded = max(1, min(int(limit), 100))
        return self.db.execute(
            "SELECT id,kind,status,created_at,finished_at,result FROM approvals ORDER BY id DESC LIMIT ?",
            (bounded,),
        ).fetchall()

    def training_examples(self) -> list[dict[str, str]]:
        rows = self.db.execute(
            "SELECT phrase,intent FROM training_examples ORDER BY id DESC LIMIT ?",
            (MAX_TRAINING_EXAMPLES,),
        ).fetchall()
        return [dict(row) for row in rows]

    def learn_example(self, phrase: str, intent: str) -> str:
        phrase = phrase.strip()
        intent = intent.casefold().strip()
        if not phrase or len(phrase) > 300:
            raise OmegaError("La frase de aprendizaje debe tener entre 1 y 300 caracteres.")
        if intent not in ALLOWED_INTENTS:
            raise OmegaError("Intención no permitida. Usa: experimento, memoria, diagnostico o general.")
        self.db.execute(
            "INSERT INTO training_examples(phrase,intent,created_at) VALUES(?,?,?)",
            (phrase, intent, now_utc()),
        )
        self.db.execute(
            "DELETE FROM training_examples WHERE id NOT IN "
            "(SELECT id FROM training_examples ORDER BY id DESC LIMIT ?)",
            (MAX_TRAINING_EXAMPLES,),
        )
        self.db.commit()
        return f"Ejemplo guardado para aprendizaje local: intención {intent}."


    def finish(self, action_id: int, status: str, result: str) -> None:
        self.db.execute("UPDATE approvals SET status=?,finished_at=?,result=? WHERE id=?",
                        (status, now_utc(), result[:4000], action_id))
        self.db.commit()
        self.log(status, f"id={action_id}; {result[:500]}")

    def execute_approved(self, action_id: int, *, approved: bool = False) -> str:
        if not approved:
            raise OmegaError("Falta aprobación explícita; la operación no se ejecutó.")
        row = self.get_action(action_id)
        if row is None:
            raise OmegaError(f"No existe la operación #{action_id}.")
        if row["status"] != "pending":
            raise OmegaError(f"La operación #{action_id} ya está en estado {row['status']}.")
        # Claim the one-shot approval atomically before any side effect. If two
        # OMEGA processes race, only the process that changes pending -> approved
        # may proceed. A crash leaves finished_at NULL, which signals an
        # interrupted operation and fails closed rather than allowing replay.
        claimed = self.db.execute(
            "UPDATE approvals SET status='approved' WHERE id=? AND status='pending'",
            (action_id,),
        )
        self.db.commit()
        if claimed.rowcount != 1:
            raise OmegaError(f"La operación #{action_id} ya no está pendiente; no se ejecutó.")
        kind = row["kind"]
        try:
            args = json.loads(row["args_json"])
            if not isinstance(args, dict):
                raise OmegaError("Los argumentos de la operación están dañados.")
            if kind == "show":
                result = str(args["text"])
            elif kind == "sum":
                value = args["a"] + args["b"]
                result = str(int(value) if float(value).is_integer() else value)
            elif kind == "status":
                result = (f"OMEGA AI {VERSION} | Python {platform.python_version()} | "
                          f"plataforma {platform.system()} | memoria SQLite: {self.db_path.stat().st_size} bytes | "
                          f"espacio de trabajo: {self.workspace}")
            elif kind == "live_capture":
                seconds = args.get("seconds")
                max_packets = args.get("max_packets")
                if type(seconds) is not int or not 1 <= seconds <= MAX_CAPTURE_SECONDS:
                    raise OmegaError(f"La captura debe durar entre 1 y {MAX_CAPTURE_SECONDS} segundos.")
                if type(max_packets) is not int or not 1 <= max_packets <= MAX_CAPTURE_PACKETS:
                    raise OmegaError(f"La captura admite entre 1 y {MAX_CAPTURE_PACKETS} paquetes.")
                output = Path(str(args.get("output", ""))).expanduser()
                if output.is_symlink() or output.exists():
                    raise OmegaError("El archivo de captura ya existe o es un enlace simbólico.")
                try:
                    resolved_output = output.resolve()
                    resolved_output.parent.relative_to(Path.home().resolve())
                except (OSError, ValueError) as exc:
                    raise OmegaError("La captura debe guardarse dentro del directorio personal de Termux.") from exc
                import wirelab_live
                original_argv = list(sys.argv)
                sys.argv = [
                    "wirelab_live.py", "--port", "5123", "--output", str(resolved_output),
                    "--seconds", str(seconds), "--max-packets", str(max_packets),
                    "--launch-pcapdroid",
                ]
                try:
                    try:
                        capture_code = wirelab_live.main()
                    except SystemExit as exc:
                        capture_code = int(exc.code or 0)
                finally:
                    sys.argv = original_argv
                if capture_code != 0:
                    raise OmegaError(f"WireLab Live terminó con código {capture_code}; revisa PCAPdroid y sus permisos.")
                if resolved_output.is_file():
                    result = f"Captura guardada: {resolved_output} ({resolved_output.stat().st_size} bytes)."
                else:
                    result = "La captura terminó sin paquetes; no se creó un archivo PCAP."
            elif kind == "capture_inspect":
                raw_path = Path(str(args.get("path", ""))).expanduser()
                if raw_path.is_symlink():
                    raise OmegaError("No se inspeccionan capturas mediante enlaces simbólicos.")
                try:
                    capture_path = raw_path.resolve(strict=True)
                    capture_path.relative_to(Path.home().resolve())
                except (OSError, ValueError) as exc:
                    raise OmegaError("La captura debe existir y estar dentro del directorio personal de Termux.") from exc
                if not capture_path.is_file() or capture_path.suffix.lower() not in (".pcap", ".pcapng"):
                    raise OmegaError("La ruta debe ser un archivo PCAP/PCAPNG regular.")
                size = capture_path.stat().st_size
                if size > MAX_INSPECT_BYTES:
                    raise OmegaError(f"La captura supera el límite de {MAX_INSPECT_BYTES} bytes.")
                import pcap_inspector
                header = {"format": "unknown"}
                rows = []
                examined = 0
                for entry_kind, item in pcap_inspector.iter_capture(str(capture_path)):
                    if entry_kind == "header":
                        header = item
                        continue
                    examined += 1
                    decoded = pcap_inspector.decode_frame(item["data"], item["linktype"])
                    rows.append({
                        "number": examined, "timestamp": item["timestamp"],
                        "captured_length": item["captured_length"],
                        "original_length": item["original_length"], "decoded": decoded,
                    })
                    if examined >= MAX_INSPECT_PACKETS:
                        break
                result = pcap_inspector.render_text(rows, header, summary_only=False)
                result = f"Archivo: {capture_path} | bytes: {size} | paquetes procesados: {examined}\\n" + result
            elif kind == "lab_scan":
                if args.get("authorized") is not True:
                    raise OmegaError("El escaneo requiere confirmación explícita de autorización.")
                import netmap
                target = netmap.check_target(str(args.get("target", "")))
                raw_ports = args.get("ports")
                if not isinstance(raw_ports, list) or not raw_ports or len(raw_ports) > MAX_OMEGA_SCAN_PORTS:
                    raise OmegaError(f"El escaneo requiere entre 1 y {MAX_OMEGA_SCAN_PORTS} puertos.")
                if any(type(port) is not int or not 1 <= port <= 65535 for port in raw_ports):
                    raise OmegaError("La lista de puertos contiene valores no permitidos.")
                ports = netmap.parse_ports(",".join(str(port) for port in raw_ports))
                from concurrent.futures import ThreadPoolExecutor, as_completed
                started = time.perf_counter()
                rows = []
                with ThreadPoolExecutor(max_workers=min(8, len(ports))) as pool:
                    futures = [pool.submit(netmap.probe, target, port, 0.5) for port in ports]
                    for future in as_completed(futures):
                        rows.append(future.result())
                rows.sort(key=lambda item: item["port"])
                result = netmap.render_text(target, rows, time.perf_counter() - started, False)
            elif kind == "compact":
                before = self.db_path.stat().st_size
                free_bytes = shutil.disk_usage(self.home).free
                if free_bytes < max(1_048_576, before * 2):
                    raise OmegaError("No hay espacio libre suficiente para compactar con margen de seguridad.")
                self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self.db.execute("VACUUM")
                after = self.db_path.stat().st_size
                result = f"Base de datos compactada: {before} -> {after} bytes."
            elif kind == "audit":
                integrity = self.db.execute("PRAGMA integrity_check").fetchone()[0]
                free_bytes = shutil.disk_usage(self.home).free
                pending_count = self.db.execute(
                    "SELECT COUNT(*) FROM approvals WHERE status='pending'"
                ).fetchone()[0]
                is_root = bool(hasattr(os, "geteuid") and os.geteuid() == 0)
                result = "\n".join([
                    f"OMEGA AI {VERSION}: auditoría local",
                    f"SQLite integrity_check: {integrity}",
                    f"Workspace existe: {self.workspace.is_dir()}",
                    f"Workspace escribible: {os.access(self.workspace, os.W_OK)}",
                    f"Espacio libre en el volumen de datos: {free_bytes} bytes",
                    f"Operaciones pendientes: {pending_count}",
                    f"Proceso con privilegios root: {is_root}",
                    "Red: no consultada; auditoría completamente local.",
                ])
                if integrity != "ok":
                    raise OmegaError(f"SQLite informa un problema de integridad: {integrity}")
            elif kind == "learn_example":
                result = self.learn_example(str(args["phrase"]), str(args["intent"]))
            elif kind == "memory_set":
                result = self.remember(str(args["key"]), str(args["value"]))
            elif kind == "memory_get":
                result = self.recall(str(args["key"]))
            elif kind == "memory_list":
                rows = self.memories()
                result = "\n".join(f'{item["key"]} = {item["value"]} ({item["updated_at"]})' for item in rows)
                if not result:
                    result = "Todavía no hay recuerdos guardados."
            elif kind == "file_create":
                filename = str(args["filename"])
                if not SAFE_FILENAME.fullmatch(filename) or filename in (".", ".."):
                    raise OmegaError("Nombre de archivo no permitido.")
                target = self.workspace / filename
                if target.is_symlink() or target.exists():
                    raise OmegaError("El archivo ya existe; no se sobrescriben archivos.")
                content = str(args["content"])
                if len(content) > MAX_TEXT_CHARS:
                    raise OmegaError("Contenido demasiado largo.")
                with target.open("x", encoding="utf-8") as stream:
                    stream.write(content)
                result = f"Archivo creado: {target} ({target.stat().st_size} bytes)."
            else:
                raise OmegaError(f"Tipo de operación no permitido: {kind}")
            self.finish(action_id, "approved", result)
            return result
        except Exception as exc:
            self.finish(action_id, "failed", f"{type(exc).__name__}: {exc}")
            if isinstance(exc, OmegaError):
                raise
            raise OmegaError(f"Falló la operación: {exc}") from exc

    def reject(self, action_id: int) -> str:
        row = self.get_action(action_id)
        if row is None:
            raise OmegaError(f"No existe la operación #{action_id}.")
        if row["status"] != "pending":
            raise OmegaError(f"La operación #{action_id} ya está en estado {row['status']}.")
        # Claim rejection atomically so it cannot overwrite an approval that
        # another process already claimed and executed.
        result = "Rechazada por el usuario"
        claimed = self.db.execute(
            "UPDATE approvals SET status='rejected',finished_at=?,result=? "
            "WHERE id=? AND status='pending'",
            (now_utc(), result, action_id),
        )
        self.db.commit()
        if claimed.rowcount != 1:
            current = self.get_action(action_id)
            if current is None:
                raise OmegaError(f"No existe la operación #{action_id}.")
            raise OmegaError(f"La operación #{action_id} ya no está pendiente; no se rechazó.")
        self.log("rejected", f"id={action_id}; {result}")
        return f"Operación #{action_id} rechazada; no se ejecutó."


def describe_action(action: dict[str, Any]) -> str:
    kind, args = action["kind"], action["args"]
    if kind == "show": return f'Mostrar texto: {args["text"]!r}'
    if kind == "sum": return f'Calcular {args["a"]} + {args["b"]}'
    if kind == "status": return "Consultar estado local de OMEGA y su almacenamiento"
    if kind == "audit": return "Auditar integridad SQLite, espacio local y permisos del workspace"
    if kind == "compact": return "Compactar SQLite para recuperar espacio; requiere margen de disco"
    if kind == "lab_scan": return f'Escanear TCP en {args["target"]}, puertos {",".join(str(p) for p in args["ports"])} (solo red autorizada)'
    if kind == "capture_inspect": return f'Inspeccionar captura PCAP/PCAPNG en {args["path"]} (máximo 100 paquetes)'
    if kind == "live_capture": return f'Iniciar captura PCAPdroid durante {args["seconds"]} s, máximo {args["max_packets"]} paquetes; puede capturar tráfico del dispositivo'
    if kind == "learn_example": return f'Aprender ejemplo {args["phrase"]!r} → intención {args["intent"]}'
    if kind == "memory_set": return f'Guardar memoria {args["key"]!r} = {args["value"]!r}'
    if kind == "memory_get": return f'Consultar memoria {args["key"]!r}'
    if kind == "memory_list": return "Consultar la lista de recuerdos locales"
    if kind == "file_create": return f'Crear sin sobrescribir workspace/{args["filename"]}'
    return f"Operación {kind}"


def tokenize(text: str) -> list[str]:
    """Small offline Spanish tokenizer; no external NLP dependencies."""
    stop_words = {
        "a", "al", "algo", "como", "con", "de", "del", "el", "ella", "en",
        "es", "esa", "ese", "eso", "esta", "este", "esto", "la", "las",
        "lo", "los", "me", "mi", "mis", "para", "por", "que", "se", "su",
        "sus", "un", "una", "unas", "uno", "unos", "y", "yo", "quiero",
        "quisiera", "necesito", "puedo", "puedes", "favor",
    }
    return [
        token for token in re.findall(r"[a-z0-9áéíóúüñ]+", text.casefold())
        if token not in stop_words
    ]


def classify_intent(text: str, examples: list[dict[str, str]]) -> str | None:
    """Train a tiny multinomial Naive Bayes classifier from approved local examples."""
    usable = [
        item for item in examples
        if item.get("intent") in ALLOWED_INTENTS and isinstance(item.get("phrase"), str)
    ]
    classes = {item["intent"] for item in usable}
    query = tokenize(text)
    if len(classes) < 2 or not query:
        return None
    token_counts: dict[str, dict[str, int]] = {label: {} for label in classes}
    token_totals = {label: 0 for label in classes}
    class_counts = {label: 0 for label in classes}
    vocabulary: set[str] = set()
    for item in usable:
        label = item["intent"]
        tokens = tokenize(item["phrase"])
        class_counts[label] += 1
        for token in tokens:
            vocabulary.add(token)
            token_counts[label][token] = token_counts[label].get(token, 0) + 1
            token_totals[label] += 1
    query_vocabulary = set(query)
    if not query_vocabulary.intersection(vocabulary):
        return None
    vocabulary.update(query)
    vocab_size = max(1, len(vocabulary))
    total_examples = len(usable)
    scores: dict[str, float] = {}
    for label in classes:
        score = math.log(class_counts[label] / total_examples)
        denominator = token_totals[label] + vocab_size
        for token in query:
            probability = (token_counts[label].get(token, 0) + 1) / denominator
            score += math.log(probability)
        scores[label] = score
    return max(sorted(scores), key=lambda label: scores[label])


def make_plan(goal: str, examples: list[dict[str, str]] | None = None) -> tuple[str, list[dict[str, Any]]]:
    """Use approved local examples when available; otherwise fall back to transparent rules."""
    if not goal.strip() or len(goal) > MAX_GOAL_CHARS:
        raise OmegaError(f"El objetivo debe tener entre 1 y {MAX_GOAL_CHARS} caracteres.")
    learned_intent = classify_intent(goal, examples or [])
    normalized = goal.casefold()
    if learned_intent == "general":
        return "El clasificador local eligió la intención general. Cada operación propuesta requiere aprobación.", [
            {"kind": "show", "args": {"text": f"Objetivo registrado para diseñar después: {goal}"}},
        ]
    if learned_intent == "experimento":
        normalized = "experimento"
    elif learned_intent == "memoria":
        normalized = "memoria"
    elif learned_intent == "diagnostico":
        normalized = "diagnostico"
    if any(word in normalized for word in ("experimento", "archivo", "crear", "construir", "probar")):
        plan = [
            {"kind": "status", "args": {}},
            {"kind": "file_create", "args": {
                "filename": "primer_experimento.txt",
                "content": "OMEGA AI — experimento local\n\nEste archivo fue creado tras una aprobación explícita.\n"}},
            {"kind": "memory_set", "args": {
                "key": "ultimo_experimento", "value": f"Objetivo: {goal}"}},
        ]
        return (f"Clasificador local: {learned_intent}. " if learned_intent else "") + "Plan de experimento local: comprobar el entorno, crear un archivo de demostración y registrar el objetivo. Cada paso necesita aprobación individual.", plan
    if any(word in normalized for word in ("memoria", "recordar", "recuerdo")):
        return (f"Clasificador local: {learned_intent}. " if learned_intent else "") + "Plan de memoria: consultar el estado y listar los recuerdos guardados. Cada consulta necesita aprobación.", [
            {"kind": "status", "args": {}},
            {"kind": "memory_list", "args": {}},
        ]
    if any(word in normalized for word in ("estado", "diagnóstico", "diagnostico", "sistema")):
        return (f"Clasificador local: {learned_intent}. " if learned_intent else "") + "Plan de diagnóstico local; no contacta redes ni modifica el sistema.", [
            {"kind": "status", "args": {}},
        ]
    return ("Todavía no tengo una receta específica para ese objetivo. Preparé una operación informativa; puedes rechazarla y escribir un programa OMEGA propio.", [
        {"kind": "show", "args": {"text": f"Objetivo registrado para diseñar después: {goal}"}},
    ])


def queue_actions(store: OmegaStore, actions: list[dict[str, Any]]) -> None:
    if not actions:
        print(terminal_style("✓ Programa válido · no hay acciones que encolar.", "muted"))
        return
    pending_count = len(store.pending())
    if pending_count + len(actions) > MAX_PENDING:
        print(
            terminal_style(
                f"ERROR: no se encoló el programa; el límite es {MAX_PENDING} y ya hay {pending_count} pendientes.",
                "red",
            ),
            file=sys.stderr,
        )
        return
    print(terminal_style("◇ Acciones pendientes", "cyan"))
    for action in actions:
        action_id = store.enqueue(action["kind"], action["args"])
        print(terminal_style(f"  [{action_id}] PENDIENTE", "yellow") + f" — {describe_action(action)}")
    print(terminal_style("Nada se ejecutó.", "muted"))
    print("Revisa cada descripción; autoriza solo con aprobar <ID> y luego escribe SI.")


def help_text() -> str:
    return textwrap.dedent(f"""\
    OMEGA AI {VERSION} — laboratorio offline, sin root

    Los comandos aceptan el prefijo /; por ejemplo, /ayuda equivale a ayuda.

    Comandos del agente:
      ayuda                         Mostrar esta ayuda
      estado                        Proponer consulta del estado (requiere aprobación)
      auditar                       Proponer auditoría local (requiere aprobación)
      compactar                     Proponer compactación SQLite (requiere aprobación)
      escanear IP PUERTOS AUTORIZADO Proponer escaneo TCP privado (requiere aprobación)
      inspeccionar "archivo.pcap"    Proponer lectura de captura local (requiere aprobación)
      capturar SEGUNDOS MAX_PAQUETES  Proponer captura PCAPdroid (requiere aprobación/VPN)
      historial [N]                 Consultar las últimas N operaciones
      aprender "frase" = intención   Proponer ejemplo para aprendizaje local
      objetivo <texto>              Crear un plan transparente a partir de un objetivo
      forja [sum|max|todo|spec.json] Comparar algoritmos con pruebas locales
      forja descubrir spec.json       Sintetizar una expresión desde ejemplos y validación
      forja guardar spec.json nombre.json  Proponer guardar una capacidad validada
      forja usar nombre.json "[1, 2]"      Ejecutar una capacidad guardada de forma acotada
      pendientes                    Ver operaciones que esperan autorización
      aprobar <ID>                  Aprobar y ejecutar UNA operación pendiente
      rechazar <ID>                 Rechazar una operación pendiente
      memorias                      Proponer listar recuerdos; requiere aprobación
      recordar <clave> = <valor>    Proponer guardar una memoria; requiere aprobación
      leer <clave>                  Proponer leer una memoria; requiere aprobación
      lenguaje <archivo.omg>        Analizar programa OMEGA y encolar cada instrucción
      salir                         Salir

    Lenguaje OMEGA v0.3 (un comando por línea; comentarios con #):
      OMEGA 0.3
      DEFINIR saludo = "Hola desde OMEGA"
      DEFINIR a = 20
      DEFINIR b = 22
      MOSTRAR $saludo
      SUMAR $a $b
      SI $a < $b ENTONCES MOSTRAR "condición verdadera"
      ESTADO
      AUDITAR
      COMPACTAR
      ESCANEAR "127.0.0.1" PUERTOS "22,80" AUTORIZADO
      CAPTURAR 10 SEGUNDOS MAX 100 PAQUETES
      APRENDER "quiero revisar el sistema" = diagnostico
      RECORDAR "objetivo" = "construir OMEGA"
      LEER_MEMORIA "objetivo"
      CREAR "experimento.txt" = "Mi primer programa OMEGA"

    Las instrucciones no se ejecutan al cargarlas: cada una se pone en cola
    y requiere 'aprobar <ID>'; sustituye <ID> por el número real mostrado (por ejemplo, 'aprobar 1'). No hay ejecución de shell ni Python arbitrario.
    Workspace: solo ~/.omega_ai/workspace; no sobrescribe archivos existentes.
    """)


def parse_key_value(text: str) -> tuple[str, str]:
    match = re.fullmatch(r'\s*("(?:[^"\\]|\\.)*")\s*=\s*("(?:[^"\\]|\\.)*")\s*', text)
    if not match:
        raise OmegaError('Sintaxis: recordar "clave" = "valor"')
    key, value = map(parse_quoted, match.groups())
    if not key or len(key) > 120:
        raise OmegaError("La clave debe tener entre 1 y 120 caracteres.")
    return key, value


def terminal_color_enabled() -> bool:
    """Use ANSI styling only in interactive terminals and respect NO_COLOR."""
    return "NO_COLOR" not in os.environ and bool(
        hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    )


def terminal_style(text: str, color: str, enabled: bool | None = None) -> str:
    """Small dependency-free ANSI palette for the interactive terminal UI."""
    if enabled is None:
        enabled = terminal_color_enabled()
    palette = {
        "orange": "38;5;208",
        "muted": "90",
        "green": "32",
        "yellow": "33",
        "red": "31",
        "cyan": "36",
        "bold": "1",
    }
    code = palette.get(color)
    if not enabled or code is None:
        return text
    return f"\033[{code}m{text}\033[0m"


def print_terminal_banner(home: str | Path, enabled: bool | None = None) -> None:
    """Render a compact Claude-Code-inspired welcome screen without dependencies."""
    if enabled is None:
        enabled = terminal_color_enabled()
    print(terminal_style("✳  OMEGA AI", "orange", enabled))
    print(terminal_style(f"v{VERSION} · asistente local para Termux", "muted", enabled))
    print(terminal_style("offline  ·  sin root  ·  memoria SQLite local", "green", enabled))
    print(terminal_style(f"Directorio de datos: {Path(home)}", "muted", enabled))
    print()
    print(terminal_style("Bienvenido a OMEGA AI", "bold", enabled))
    print("Asistente local para trabajar, recordar y analizar.")
    print(terminal_style("Comandos rápidos: /ayuda · /estado · /pendientes · /salir", "muted", enabled))
    print(terminal_style("─" * min(max(shutil.get_terminal_size(fallback=(80, 24)).columns, 32), 56), "muted", enabled))


def run_repl(home: str | Path) -> int:
    store = OmegaStore(home)
    color = terminal_color_enabled()
    print_terminal_banner(store.home, color)
    print(terminal_style(f"Memoria persistente: {store.db_path}", "muted", color))
    try:
        while True:
            try:
                raw = input(terminal_style("❯ ", "orange", color)).strip()
            except EOFError:
                print()
                break
            if not raw:
                continue
            command, _, rest = raw.partition(" ")
            command = command.casefold().lstrip("/")
            try:
                if command in ("salir", "exit", "quit"):
                    break
                elif command in ("ayuda", "help", "?"):
                    print(help_text())
                elif command == "estado":
                    queue_actions(store, [{"kind": "status", "args": {}}])
                elif command == "auditar":
                    queue_actions(store, [{"kind": "audit", "args": {}}])
                elif command == "compactar":
                    queue_actions(store, [{"kind": "compact", "args": {}}])
                elif command == "capturar":
                    parts = rest.strip().split()
                    if len(parts) != 2 or not all(part.isdigit() for part in parts):
                        raise OmegaError("Uso: capturar SEGUNDOS MAX_PAQUETES")
                    seconds, max_packets = map(int, parts)
                    if not 1 <= seconds <= MAX_CAPTURE_SECONDS:
                        raise OmegaError(f"La captura debe durar entre 1 y {MAX_CAPTURE_SECONDS} segundos.")
                    if not 1 <= max_packets <= MAX_CAPTURE_PACKETS:
                        raise OmegaError(f"La captura admite entre 1 y {MAX_CAPTURE_PACKETS} paquetes.")
                    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
                    output = str(Path.home() / f"omega-capture-{stamp}.pcap")
                    queue_actions(store, [{"kind": "live_capture", "args": {
                        "seconds": seconds, "max_packets": max_packets, "output": output
                    }}])
                elif command == "inspeccionar":
                    path_text = parse_quoted(rest)
                    if not path_text.lower().endswith((".pcap", ".pcapng")):
                        raise OmegaError("Uso: inspeccionar archivo.pcap")
                    queue_actions(store, [{"kind": "capture_inspect", "args": {"path": path_text}}])
                elif command == "escanear":
                    parts = rest.strip().split()
                    if len(parts) != 3 or parts[2].upper() != "AUTORIZADO":
                        raise OmegaError("Uso: escanear IP PUERTOS AUTORIZADO")
                    target, port_text = parts[0], parts[1]
                    try:
                        import netmap
                        target = netmap.check_target(target)
                        ports = netmap.parse_ports(port_text)
                    except Exception as exc:
                        raise OmegaError(f"Objetivo o puertos no válidos: {exc}") from exc
                    if len(ports) > MAX_OMEGA_SCAN_PORTS:
                        raise OmegaError(f"OMEGA limita cada escaneo a {MAX_OMEGA_SCAN_PORTS} puertos.")
                    queue_actions(store, [{"kind": "lab_scan", "args": {"target": target, "ports": ports, "authorized": True}}])
                elif command == "aprender":
                    match = re.fullmatch(
                        r'\s*("(?:[^"\\]|\\.)*")\s*=\s*(experimento|memoria|diagnostico|general)\s*',
                        rest, re.I
                    )
                    if not match:
                        raise OmegaError('Uso: aprender "frase" = diagnostico')
                    phrase = parse_quoted(match.group(1)).strip()
                    intent = match.group(2).casefold()
                    if not phrase or len(phrase) > 300:
                        raise OmegaError("La frase debe tener entre 1 y 300 caracteres.")
                    queue_actions(store, [{"kind": "learn_example", "args": {"phrase": phrase, "intent": intent}}])
                elif command == "historial":
                    parts = rest.strip().split()
                    if len(parts) > 1 or (parts and not parts[0].isdigit()):
                        raise OmegaError("Uso: historial [N], con N entre 1 y 100.")
                    if parts and not 1 <= int(parts[0]) <= 100:
                        raise OmegaError("N debe estar entre 1 y 100.")
                    rows = store.history(int(parts[0]) if parts else 20)
                    if rows:
                        print(terminal_style("◷ Historial reciente", "cyan", color))
                    for item in rows:
                        result = (item["result"] or "").replace("\n", " | ")
                        if len(result) > 120:
                            result = result[:117] + "..."
                        state_colors = {"approved": "green", "pending": "yellow", "rejected": "muted", "failed": "red"}
                        state = terminal_style(item["status"].upper(), state_colors.get(item["status"], "muted"), color)
                        print(f'  [{item["id"]}] {item["kind"]} · {state} · {item["created_at"]}')
                        if result:
                            print(f"      {result}")
                    if not rows:
                        print(terminal_style("Todavía no hay operaciones en el historial.", "muted", color))
                elif command == "forja":
                    import omega_forge
                    raw_task = rest.strip()
                    task = raw_task.casefold() or "all"
                    try:
                        if task in ("all", "todo", "sum", "max"):
                            print(omega_forge.format_report(task))
                        elif task.startswith("guardar "):
                            parts = shlex.split(raw_task[len("guardar "):])
                            if len(parts) != 2:
                                raise OmegaError('Uso: forja guardar "spec.json" capacidad.json')
                            spec_path, filename = parts
                            if not SAFE_FILENAME.fullmatch(filename) or not filename.casefold().endswith(".json"):
                                raise OmegaError("La capacidad debe tener un nombre simple terminado en .json.")
                            report = omega_forge.synthesize_numeric(omega_forge.load_spec(spec_path))
                            if not report["validated"]:
                                raise OmegaError("No se guarda una capacidad sin validación satisfactoria.")
                            content = omega_forge.capability_document(report)
                            print(omega_forge.format_synthesis_report(report))
                            queue_actions(store, [{"kind": "file_create", "args": {
                                "filename": filename, "content": content
                            }}])
                        elif task.startswith("usar "):
                            parts = shlex.split(raw_task[len("usar "):])
                            if len(parts) != 2:
                                raise OmegaError('Uso: forja usar capacidad.json "[1, 2, 3]"')
                            filename, raw_data = parts
                            try:
                                data = json.loads(raw_data)
                            except json.JSONDecodeError as exc:
                                raise OmegaError("Los datos deben ser JSON válido; ejemplo: '[1, 2, 3]'.") from exc
                            result = omega_forge.execute_capability(store.workspace, filename, data)
                            print(f"Capacidad: {result['name']}")
                            print("Resultado:", json.dumps(result["result"], ensure_ascii=False))
                            print(f"Pasos estimados: {result['steps']}")
                            print(result["note"])
                        elif task.startswith("descubrir "):
                            spec_arg = raw_task[len("descubrir "):].strip()
                            spec_path = parse_quoted(spec_arg) if spec_arg.startswith('"') else spec_arg
                            report = omega_forge.synthesize_numeric(omega_forge.load_spec(spec_path))
                            print(omega_forge.format_synthesis_report(report))
                        else:
                            spec_path = parse_quoted(raw_task) if raw_task.startswith('"') else raw_task
                            report = omega_forge.benchmark_custom(omega_forge.load_spec(spec_path))
                            print(omega_forge.format_custom_report(report))
                    except omega_forge.ForgeError as exc:
                        raise OmegaError(str(exc)) from exc
                elif command == "objetivo":
                    if not rest.strip(): raise OmegaError("Escribe el objetivo después de 'objetivo'.")
                    summary, actions = make_plan(rest.strip(), store.training_examples())
                    print(summary)
                    queue_actions(store, actions)
                elif command == "pendientes":
                    rows = store.pending()
                    if not rows:
                        print(terminal_style("✓ No hay operaciones pendientes.", "muted", color))
                    else:
                        print(terminal_style("◇ Operaciones que requieren aprobación", "cyan", color))
                    for row in rows:
                        description = describe_action({"kind": row["kind"], "args": json.loads(row["args_json"])})
                        print(terminal_style(f'  [{row["id"]}] PENDIENTE', "yellow", color) + f" — {description}")
                elif command == "aprobar":
                    if not rest.strip().isdigit(): raise OmegaError("Sustituye ID por el número real de la operación; ejemplo: aprobar 1")
                    action_id = int(rest.strip())
                    row = store.get_action(action_id)
                    if row is None: raise OmegaError(f"No existe la operación #{action_id}.")
                    if row["status"] != "pending": raise OmegaError(f"La operación ya está en estado {row['status']}.")
                    print(terminal_style("◇ Operación solicitada", "cyan", color))
                    print("  " + describe_action({"kind": row["kind"], "args": json.loads(row["args_json"])}))
                    confirm = input(terminal_style("¿Autorizar? Escribe SI exactamente ❯ ", "orange", color)).strip()
                    if confirm != "SI":
                        print(terminal_style("No autorizada · no se ejecutó.", "muted", color))
                    else:
                        print(terminal_style("✓ RESULTADO", "green", color) + ":", store.execute_approved(action_id, approved=True))
                elif command == "rechazar":
                    if not rest.strip().isdigit(): raise OmegaError("Sustituye ID por el número real de la operación; ejemplo: rechazar 1")
                    print(terminal_style(store.reject(int(rest.strip())), "muted", color))
                elif command == "memorias":
                    queue_actions(store, [{"kind": "memory_list", "args": {}}])
                elif command == "recordar":
                    key, value = parse_key_value(rest)
                    queue_actions(store, [{"kind": "memory_set", "args": {"key": key, "value": value}}])
                elif command == "leer":
                    key = parse_quoted(rest)
                    queue_actions(store, [{"kind": "memory_get", "args": {"key": key}}])
                elif command == "lenguaje":
                    if not rest.strip(): raise OmegaError("Uso: lenguaje archivo.omg")
                    script_path = Path(rest.strip()).expanduser()
                    if script_path.stat().st_size > MAX_SCRIPT_BYTES:
                        raise OmegaError(f"El programa supera {MAX_SCRIPT_BYTES} bytes.")
                    actions = parse_language(script_path.read_text(encoding="utf-8"))
                    print(f"Programa válido: {len(actions)} instrucciones.")
                    queue_actions(store, actions)
                else:
                    print("No reconozco ese comando. Escribe 'ayuda'.")
            except (OmegaError, OSError, UnicodeError) as exc:
                print(terminal_style("ERROR", "red", color) + f": {exc}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\nSesión detenida.")
    finally:
        store.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OMEGA AI: IA simbólica local para Termux")
    parser.add_argument("--home", default=str(Path.home() / ".omega_ai"), help="Directorio de datos (para pruebas o personalización).")
    parser.add_argument("--version", action="version", version=f"OMEGA AI {VERSION}")
    args = parser.parse_args(argv)
    try:
        return run_repl(args.home)
    except (OSError, sqlite3.Error) as exc:
        print(f"No se pudo iniciar OMEGA: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
