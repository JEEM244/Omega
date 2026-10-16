#!/usr/bin/env python3
"""OMEGA FORGE: safe, bounded experiment runner for pure OMEGA algorithms.

The first version compares a small set of generated algorithm candidates. It
interprets a restricted Python-like syntax; it never calls eval(), exec(),
shell commands, imports from candidate source, or performs file/network I/O.
Its step score is an interpreter work estimate, not a wall-clock benchmark.
"""
from __future__ import annotations

import ast
import argparse
import json
import math
import operator
from dataclasses import dataclass
from typing import Any
from pathlib import Path

VERSION = "0.1.0"
MAX_SOURCE_BYTES = 8192
MAX_CASES = 100
MAX_COLLECTION_ITEMS = 256
MAX_STEPS_PER_CASE = 10000
MAX_LOOP_ITERATIONS = 256
MAX_INT_BITS = 256
MAX_ABS_NUMBER = 1e100
MAX_TEXT_LENGTH = 4096
MAX_SPEC_BYTES = 64 * 1024
MAX_CANDIDATES = 10
MAX_SYNTH_CANDIDATES = 3000
MAX_NESTING = 8


class ForgeError(ValueError):
    """Expected validation or execution error from OMEGA FORGE."""


@dataclass
class _Budget:
    steps: int = 0

    def tick(self, cost: int = 1) -> None:
        self.steps += cost
        if self.steps > MAX_STEPS_PER_CASE:
            raise ForgeError(f"Se excedió el presupuesto de {MAX_STEPS_PER_CASE} pasos.")


class _Returned(Exception):
    def __init__(self, value: Any):
        self.value = value


def _checked(value: Any, depth: int = 0) -> Any:
    if depth > MAX_NESTING:
        raise ForgeError(f"Los datos superan la profundidad máxima de {MAX_NESTING} niveles.")
    if value is None or type(value) in (bool, int, float, str):
        if type(value) is int and value.bit_length() > MAX_INT_BITS:
            raise ForgeError("Entero demasiado grande.")
        if type(value) is float and (not math.isfinite(value) or abs(value) > MAX_ABS_NUMBER):
            raise ForgeError("Número no finito o fuera de los límites.")
        if type(value) is str and len(value) > MAX_TEXT_LENGTH:
            raise ForgeError("Texto demasiado largo.")
        return value
    if type(value) in (list, tuple):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ForgeError("Colección demasiado grande.")
        return type(value)(_checked(item, depth + 1) for item in value)
    raise ForgeError(f"Tipo de dato no permitido: {type(value).__name__}.")


def _equal_typed(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if type(actual) in (list, tuple):
        return len(actual) == len(expected) and all(
            _equal_typed(a, b) for a, b in zip(actual, expected)
        )
    return actual == expected


_BINARY = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
}
_UNARY = {ast.UAdd: operator.pos, ast.USub: operator.neg, ast.Not: operator.not_}
_COMPARE = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
}


class _Interpreter:
    def __init__(self, source: str):
        if not isinstance(source, str) or len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
            raise ForgeError(f"El candidato debe ser texto de hasta {MAX_SOURCE_BYTES} bytes.")
        try:
            tree = ast.parse(source, mode="exec")
        except (SyntaxError, ValueError) as exc:
            raise ForgeError(f"Sintaxis inválida: {exc}") from exc
        if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef):
            raise ForgeError("El candidato debe contener una única función: def solve(datos):")
        function = tree.body[0]
        if (function.name != "solve" or function.decorator_list or function.returns
                or getattr(function, "type_params", []) or len(function.args.args) != 1
                or getattr(function, "type_params", []) or function.args.posonlyargs or function.args.kwonlyargs
                or function.args.vararg or function.args.kwarg or function.args.defaults
                or function.args.kw_defaults):
            raise ForgeError("Usa exactamente def solve(datos): sin decoradores ni argumentos extra.")
        self.body = function.body
        self.parameter = function.args.args[0].arg
        if self.parameter.startswith("__"):
            raise ForgeError("Nombre de parámetro no permitido.")
        self._validate_statements(self.body, loop_depth=0)

    def _validate_statements(self, statements: list[ast.stmt], loop_depth: int) -> None:
        if not statements:
            raise ForgeError("La función no puede tener un bloque vacío.")
        for node in statements:
            if isinstance(node, ast.Return):
                if node.value is not None:
                    self._validate_expr(node.value)
            elif isinstance(node, ast.Assign):
                if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                    raise ForgeError("Solo se permiten asignaciones a una variable local.")
                if node.targets[0].id.startswith("__"):
                    raise ForgeError("Nombre de variable no permitido.")
                self._validate_expr(node.value)
            elif isinstance(node, ast.If):
                self._validate_expr(node.test)
                self._validate_statements(node.body, loop_depth)
                if node.orelse:
                    self._validate_statements(node.orelse, loop_depth)
            elif isinstance(node, ast.For):
                if loop_depth >= 2:
                    raise ForgeError("Solo se permiten dos niveles de bucles.")
                if not isinstance(node.target, ast.Name) or node.target.id.startswith("__"):
                    raise ForgeError("El iterador debe ser una variable local simple.")
                if node.orelse:
                    raise ForgeError("No se admite else en un bucle.")
                self._validate_expr(node.iter)
                self._validate_statements(node.body, loop_depth + 1)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                continue
            elif isinstance(node, ast.Pass):
                continue
            else:
                raise ForgeError(f"Instrucción no permitida: {type(node).__name__}.")

    def _validate_expr(self, node: ast.expr) -> None:
        if isinstance(node, (ast.Constant, ast.Name)):
            if isinstance(node, ast.Constant):
                _checked(node.value)
            elif node.id.startswith("__"):
                raise ForgeError("Nombre reservado no permitido.")
        elif isinstance(node, ast.BinOp):
            if type(node.op) not in _BINARY and not isinstance(node.op, ast.Pow):
                raise ForgeError(f"Operador no permitido: {type(node.op).__name__}.")
            self._validate_expr(node.left)
            self._validate_expr(node.right)
        elif isinstance(node, ast.UnaryOp):
            if type(node.op) not in _UNARY:
                raise ForgeError("Operador unario no permitido.")
            self._validate_expr(node.operand)
        elif isinstance(node, ast.BoolOp):
            if not isinstance(node.op, (ast.And, ast.Or)):
                raise ForgeError("Operador booleano no permitido.")
            for value in node.values:
                self._validate_expr(value)
        elif isinstance(node, ast.Compare):
            self._validate_expr(node.left)
            for comparator in node.comparators:
                self._validate_expr(comparator)
            if any(type(op) not in _COMPARE for op in node.ops):
                raise ForgeError("Comparación no permitida.")
        elif isinstance(node, ast.IfExp):
            self._validate_expr(node.test)
            self._validate_expr(node.body)
            self._validate_expr(node.orelse)
        elif isinstance(node, (ast.List, ast.Tuple)):
            if len(node.elts) > MAX_COLLECTION_ITEMS:
                raise ForgeError("Literal de colección demasiado grande.")
            for item in node.elts:
                self._validate_expr(item)
        elif isinstance(node, ast.Subscript):
            self._validate_expr(node.value)
            if isinstance(node.slice, ast.Slice):
                for bound in (node.slice.lower, node.slice.upper, node.slice.step):
                    if bound is not None:
                        self._validate_expr(bound)
            else:
                self._validate_expr(node.slice)
        elif isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name) or node.func.id not in {
                "abs", "all", "any", "len", "max", "min", "range", "round", "sorted", "sum"
            }:
                raise ForgeError("Solo se permiten llamadas a funciones integradas autorizadas.")
            if node.keywords:
                raise ForgeError("No se permiten argumentos nombrados.")
            if len(node.args) > 3:
                raise ForgeError("Demasiados argumentos.")
            for arg in node.args:
                self._validate_expr(arg)
        else:
            raise ForgeError(f"Expresión no permitida: {type(node).__name__}.")

    def run(self, data: Any) -> tuple[Any, int]:
        data = _checked(data)
        budget = _Budget()
        env: dict[str, Any] = {self.parameter: data}
        try:
            self._exec_statements(self.body, env, budget)
        except _Returned as returned:
            return _checked(returned.value), budget.steps
        raise ForgeError("La función terminó sin devolver un resultado.")

    def _exec_statements(self, statements: list[ast.stmt], env: dict[str, Any], budget: _Budget) -> None:
        for node in statements:
            budget.tick()
            if isinstance(node, ast.Return):
                raise _Returned(None if node.value is None else self._eval(node.value, env, budget))
            if isinstance(node, ast.Assign):
                env[node.targets[0].id] = self._eval(node.value, env, budget)
            elif isinstance(node, ast.If):
                branch = node.body if self._eval(node.test, env, budget) else node.orelse
                if branch:
                    self._exec_statements(branch, env, budget)
            elif isinstance(node, ast.For):
                sequence = self._eval(node.iter, env, budget)
                if not isinstance(sequence, (list, tuple, range)):
                    raise ForgeError("El bucle solo puede recorrer una lista, tupla o range acotado.")
                if len(sequence) > MAX_LOOP_ITERATIONS:
                    raise ForgeError(f"El bucle supera {MAX_LOOP_ITERATIONS} iteraciones.")
                for item in sequence:
                    budget.tick()
                    env[node.target.id] = item
                    self._exec_statements(node.body, env, budget)
            elif isinstance(node, (ast.Pass, ast.Expr)):
                continue

    def _eval(self, node: ast.expr, env: dict[str, Any], budget: _Budget) -> Any:
        budget.tick()
        if isinstance(node, ast.Constant):
            return _checked(node.value)
        if isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]
            raise ForgeError(f"Variable no definida: {node.id}.")
        if isinstance(node, ast.List):
            return _checked([self._eval(item, env, budget) for item in node.elts])
        if isinstance(node, ast.Tuple):
            return _checked(tuple(self._eval(item, env, budget) for item in node.elts))
        if isinstance(node, ast.BinOp):
            left, right = self._eval(node.left, env, budget), self._eval(node.right, env, budget)
            if isinstance(node.op, ast.Mult):
                sequence, multiplier = (left, right) if type(right) is int else (right, left)
                if type(multiplier) is int and type(sequence) in (str, list, tuple):
                    limit = MAX_TEXT_LENGTH if type(sequence) is str else MAX_COLLECTION_ITEMS
                    if multiplier < 0 or len(sequence) * multiplier > limit:
                        raise ForgeError("La multiplicación excede el tamaño permitido.")
            if isinstance(node.op, ast.Pow):
                if type(right) not in (int, float) or abs(right) > 32:
                    raise ForgeError("El exponente debe estar entre -32 y 32.")
                try:
                    return _checked(left ** right)
                except (ArithmeticError, TypeError, ValueError) as exc:
                    raise ForgeError(f"Potencia inválida: {exc}") from exc
            try:
                return _checked(_BINARY[type(node.op)](left, right))
            except (ArithmeticError, TypeError, ValueError) as exc:
                raise ForgeError(f"Operación aritmética inválida: {exc}") from exc
        if isinstance(node, ast.UnaryOp):
            try:
                return _checked(_UNARY[type(node.op)](self._eval(node.operand, env, budget)))
            except (TypeError, ValueError) as exc:
                raise ForgeError(f"Operación unaria inválida: {exc}") from exc
        if isinstance(node, ast.BoolOp):
            if isinstance(node.op, ast.And):
                result: Any = True
                for item in node.values:
                    result = self._eval(item, env, budget)
                    if not result:
                        return result
                return result
            result = False
            for item in node.values:
                result = self._eval(item, env, budget)
                if result:
                    return result
            return result
        if isinstance(node, ast.Compare):
            left = self._eval(node.left, env, budget)
            for op_node, comp_node in zip(node.ops, node.comparators):
                right = self._eval(comp_node, env, budget)
                try:
                    matched = _COMPARE[type(op_node)](left, right)
                except (TypeError, ValueError) as exc:
                    raise ForgeError(f"Comparación inválida: {exc}") from exc
                if not matched:
                    return False
                left = right
            return True
        if isinstance(node, ast.IfExp):
            branch = node.body if self._eval(node.test, env, budget) else node.orelse
            return self._eval(branch, env, budget)
        if isinstance(node, ast.Subscript):
            sequence = self._eval(node.value, env, budget)
            try:
                if isinstance(node.slice, ast.Slice):
                    lower = None if node.slice.lower is None else self._eval(node.slice.lower, env, budget)
                    upper = None if node.slice.upper is None else self._eval(node.slice.upper, env, budget)
                    step = None if node.slice.step is None else self._eval(node.slice.step, env, budget)
                    if step == 0:
                        raise ForgeError("El paso de un corte no puede ser cero.")
                    result = sequence[slice(lower, upper, step)]
                else:
                    result = sequence[self._eval(node.slice, env, budget)]
            except (IndexError, TypeError, ValueError) as exc:
                raise ForgeError(f"Acceso a colección inválido: {exc}") from exc
            return _checked(result)
        if isinstance(node, ast.Call):
            name = node.func.id
            args = [self._eval(arg, env, budget) for arg in node.args]
            try:
                if name == "range":
                    if not 1 <= len(args) <= 3 or any(type(x) is not int for x in args):
                        raise ForgeError("range acepta de uno a tres enteros.")
                    result = range(*args)
                    try:
                        range_length = len(result)
                    except OverflowError as exc:
                        raise ForgeError(f"range supera {MAX_LOOP_ITERATIONS} elementos.") from exc
                    if range_length > MAX_LOOP_ITERATIONS:
                        raise ForgeError(f"range supera {MAX_LOOP_ITERATIONS} elementos.")
                    budget.tick(max(1, range_length // 8))
                    return result
                if len(args) != 1:
                    raise ForgeError(f"{name} requiere exactamente un argumento.")
                value = args[0]
                if name in ("all", "any", "sum", "min", "max", "sorted"):
                    if not isinstance(value, (list, tuple, range)):
                        raise ForgeError(f"{name} solo acepta listas, tuplas o range.")
                    budget.tick(len(value))
                if name == "abs":
                    return _checked(abs(value))
                if name == "len":
                    return len(value)
                if name == "sum":
                    return _checked(sum(value))
                if name == "min":
                    return _checked(min(value))
                if name == "max":
                    return _checked(max(value))
                if name == "sorted":
                    if len(value) > MAX_COLLECTION_ITEMS:
                        raise ForgeError("Colección demasiado grande para ordenar.")
                    return _checked(sorted(value))
                if name == "all":
                    return all(value)
                if name == "any":
                    return any(value)
                if name == "round":
                    return _checked(round(value))
            except ForgeError:
                raise
            except (ArithmeticError, TypeError, ValueError) as exc:
                raise ForgeError(f"Llamada inválida a {name}: {exc}") from exc
        raise ForgeError(f"Expresión no implementada: {type(node).__name__}.")


@dataclass(frozen=True)
class Candidate:
    name: str
    source: str


_TASKS: dict[str, tuple[list[Candidate], list[tuple[Any, Any]]]] = {
    "sum": (
        [
            Candidate("sum_integrado", "def solve(xs):\n    return sum(xs)\n"),
            Candidate("suma_lineal", "def solve(xs):\n    total = 0\n    for value in xs:\n        total = total + value\n    return total\n"),
            Candidate("suma_por_pares", "def solve(xs):\n    total = 0\n    for i in range(0, len(xs), 2):\n        total = total + xs[i]\n        if i + 1 < len(xs):\n            total = total + xs[i + 1]\n    return total\n"),
        ],
        [
            ([], 0),
            ([7], 7),
            ([1, 2, 3, 4, 5], 15),
            ([-10, 0, 10], 0),
            (list(range(-64, 64)), sum(range(-64, 64))),
            ([10**6, -10**6, 4, 9], 13),
        ],
    ),
    "max": (
        [
            Candidate("max_integrado", "def solve(xs):\n    return max(xs)\n"),
            Candidate("max_lineal", "def solve(xs):\n    best = xs[0]\n    for value in xs:\n        if value > best:\n            best = value\n    return best\n"),
        ],
        [
            ([1], 1),
            ([5, -3, 10, 4], 10),
            ([0, 0, 0], 0),
            ([-10, -2, -9], -2),
            (list(range(-64, 64)), 63),
            ([10**6, -10**6, 4, 9], 10**6),
        ],
    ),
}


def available_tasks() -> tuple[str, ...]:
    return tuple(sorted(_TASKS))


def _run_candidates(task: str, candidates: list[Candidate], cases: list[tuple[Any, Any]]) -> dict[str, Any]:
    if not cases or len(cases) > MAX_CASES:
        raise ForgeError(f"El conjunto de pruebas debe tener entre 1 y {MAX_CASES} casos.")
    ranked: list[dict[str, Any]] = []
    for candidate in candidates:
        interpreter = _Interpreter(candidate.source)
        passed, total_steps, failure = 0, 0, None
        for index, (data, expected) in enumerate(cases, start=1):
            try:
                actual, steps = interpreter.run(data)
                total_steps += steps
                if not _equal_typed(actual, _checked(expected)):
                    failure = f"caso {index}: resultado inesperado"
                    break
                passed += 1
            except (ForgeError, ArithmeticError, TypeError, ValueError, IndexError) as exc:
                failure = f"caso {index}: {exc}"
                break
        ranked.append({
            "name": candidate.name,
            "passed": passed,
            "total": len(cases),
            "steps": total_steps,
            "valid": passed == len(cases) and failure is None,
            "failure": failure,
            "source": candidate.source,
        })
    ranked.sort(key=lambda item: (not item["valid"], -item["passed"], item["steps"], item["name"]))
    winner = next((item for item in ranked if item["valid"]), None)
    return {
        "task": task,
        "cases": len(cases),
        "ranked": ranked,
        "winner": winner["name"] if winner else None,
        "metric": "pasos estimados del intérprete; no son milisegundos ni una medición de velocidad nativa",
    }


def benchmark(task: str) -> dict[str, Any]:
    """Run generated candidates against fixed, deterministic correctness cases."""
    name = task.casefold().strip()
    if name not in _TASKS:
        raise ForgeError(f"Tarea no disponible: {task}. Disponibles: {', '.join(available_tasks())}.")
    candidates, cases = _TASKS[name]
    return _run_candidates(name, candidates, cases)


def benchmark_custom(spec: Any) -> dict[str, Any]:
    """Compare user-supplied pure candidates against a JSON-shaped test manifest."""
    if not isinstance(spec, dict) or set(spec) != {"name", "cases", "candidates"}:
        raise ForgeError("El manifiesto requiere exactamente: name, cases y candidates.")
    name = spec["name"]
    raw_cases = spec["cases"]
    raw_candidates = spec["candidates"]
    if not isinstance(name, str) or not name.strip() or len(name) > 80:
        raise ForgeError("name debe ser texto de 1 a 80 caracteres.")
    if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= MAX_CASES:
        raise ForgeError(f"cases debe contener entre 1 y {MAX_CASES} casos.")
    if not isinstance(raw_candidates, list) or not 2 <= len(raw_candidates) <= MAX_CANDIDATES:
        raise ForgeError(f"candidates debe contener entre 2 y {MAX_CANDIDATES} candidatos.")
    cases: list[tuple[Any, Any]] = []
    for index, item in enumerate(raw_cases, start=1):
        if not isinstance(item, dict) or set(item) != {"input", "expected"}:
            raise ForgeError(f"El caso {index} requiere exactamente input y expected.")
        cases.append((_checked(item["input"]), _checked(item["expected"])))
    candidates: list[Candidate] = []
    seen_names: set[str] = set()
    for index, item in enumerate(raw_candidates, start=1):
        if not isinstance(item, dict) or set(item) != {"name", "source"}:
            raise ForgeError(f"El candidato {index} requiere exactamente name y source.")
        candidate_name, source = item["name"], item["source"]
        if (not isinstance(candidate_name, str) or not candidate_name.strip()
                or len(candidate_name) > 80 or candidate_name in seen_names):
            raise ForgeError(f"Nombre de candidato inválido o repetido en la posición {index}.")
        if not isinstance(source, str) or len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
            raise ForgeError(f"El código del candidato {index} supera el límite de {MAX_SOURCE_BYTES} bytes.")
        # Parse and policy-check all candidates before running any one candidate.
        _Interpreter(source)
        candidates.append(Candidate(candidate_name, source))
        seen_names.add(candidate_name)
    return _run_candidates(name.strip(), candidates, cases)

def format_report(task: str = "all") -> str:
    requested = available_tasks() if task.strip().casefold() in ("", "all", "todo") else (task.strip().casefold(),)
    reports = [benchmark(name) for name in requested]
    lines = [f"OMEGA FORGE {VERSION} · laboratorio de algoritmos seguros"]
    for report in reports:
        lines.append("")
        lines.append(f"Tarea: {report['task']} · casos: {report['cases']}")
        for rank, candidate in enumerate(report["ranked"], start=1):
            status = "VALIDADO" if candidate["valid"] else f"NO VALIDADO ({candidate['passed']}/{candidate['total']})"
            lines.append(f"  {rank}. {candidate['name']} — {status} — {candidate['steps']} pasos")
            if candidate["failure"]:
                lines.append(f"     Motivo: {candidate['failure']}")
        lines.append(f"  Selección: {report['winner'] or 'ninguna; todos los candidatos requieren revisión'}")
    lines.extend([
        "",
        "Nota: el motor interpreta un subconjunto seguro de Python; no ejecuta código arbitrario.",
        "La puntuación mide pasos del intérprete, no velocidad nativa ni calidad universal.",
        "La selección solo vale para estos casos de prueba; no autoriza cambios al núcleo de OMEGA.",
    ])
    return "\n".join(lines)


def load_spec(path_value: str | Path) -> Any:
    """Read one explicitly selected, size-bounded JSON manifest without following symlinks."""
    path = Path(path_value).expanduser()
    if path.is_symlink():
        raise ForgeError("El manifiesto no puede ser un enlace simbólico.")
    try:
        path = path.resolve(strict=True)
        if not path.is_file():
            raise ForgeError("El manifiesto debe ser un archivo regular.")
        if path.stat().st_size > MAX_SPEC_BYTES:
            raise ForgeError(f"El manifiesto supera {MAX_SPEC_BYTES} bytes.")
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ForgeError(f"No se pudo leer el manifiesto: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ForgeError(f"JSON inválido en el manifiesto: {exc.msg}.") from exc


def synthesize_numeric(spec: Any) -> dict[str, Any]:
    """Synthesize a small arithmetic expression from examples and a held-out validation set."""
    if not isinstance(spec, dict) or set(spec) != {"name", "examples", "validation"}:
        raise ForgeError("El manifiesto de descubrimiento requiere exactamente name, examples y validation.")
    name = spec["name"]
    if not isinstance(name, str) or not name.strip() or len(name) > 80:
        raise ForgeError("name debe ser texto de 1 a 80 caracteres.")
    raw_train, raw_valid = spec["examples"], spec["validation"]
    if not isinstance(raw_train, list) or not 3 <= len(raw_train) <= 20:
        raise ForgeError("examples debe contener entre 3 y 20 ejemplos.")
    if not isinstance(raw_valid, list) or not 1 <= len(raw_valid) <= 20:
        raise ForgeError("validation debe contener entre 1 y 20 casos reservados.")

    def read_cases(rows: list[Any], label: str) -> list[tuple[list[int | float], int | float]]:
        parsed: list[tuple[list[int | float], int | float]] = []
        for index, item in enumerate(rows, start=1):
            if not isinstance(item, dict) or set(item) != {"input", "output"}:
                raise ForgeError(f"{label} {index} requiere exactamente input y output.")
            values, expected = item["input"], item["output"]
            if not isinstance(values, list) or not 1 <= len(values) <= 3:
                raise ForgeError(f"{label} {index}: input debe ser una lista de 1 a 3 números.")
            if any(type(value) not in (int, float) for value in values):
                raise ForgeError(f"{label} {index}: los datos de entrada deben ser números.")
            if type(expected) not in (int, float):
                raise ForgeError(f"{label} {index}: output debe ser numérico.")
            checked_values = _checked(values)
            checked_output = _checked(expected)
            parsed.append((checked_values, checked_output))
        return parsed

    training = read_cases(raw_train, "Ejemplo")
    validation = read_cases(raw_valid, "Validación")
    arities = {len(values) for values, _ in training + validation}
    if len(arities) != 1:
        raise ForgeError("Todos los ejemplos y casos de validación deben tener el mismo número de entradas.")
    arity = next(iter(arities))

    variable_atoms = [f"xs[{index}]" for index in range(arity)]
    extra_atoms = [str(value) for value in (-2, -1, 0, 1, 2, 3, 10)]
    extra_atoms.append("len(xs)")
    extra_atoms.extend(f"abs(xs[{index}])" for index in range(arity))
    atoms = variable_atoms + extra_atoms

    # Prioritize expressions with up to two operators over the input variables.
    # This allows discoveries such as x0 + x1 + x2 without unbounded search.
    expressions: list[str] = []
    seen_expressions: set[str] = set()

    def add_expression(expression: str) -> None:
        if expression not in seen_expressions:
            if len(expressions) >= MAX_SYNTH_CANDIDATES:
                raise ForgeError(
                    f"La gramática supera el límite de {MAX_SYNTH_CANDIDATES} candidatos."
                )
            seen_expressions.add(expression)
            expressions.append(expression)

    for atom in atoms:
        add_expression(atom)

    symbols = ("+", "-", "*", "//", "%")
    variable_pairs: list[str] = []
    for left in variable_atoms:
        for right in variable_atoms:
            for symbol in symbols:
                expression = f"({left} {symbol} {right})"
                variable_pairs.append(expression)
                add_expression(expression)

    for inner in variable_pairs:
        for variable in variable_atoms:
            for symbol in symbols:
                add_expression(f"({inner} {symbol} {variable})")
                add_expression(f"({variable} {symbol} {inner})")

    # Fill the remaining budget with one-operation combinations that include
    # constants, absolute values, and input length.
    for left in atoms:
        for right in atoms:
            for symbol in symbols:
                expression = f"({left} {symbol} {right})"
                if expression not in seen_expressions and len(expressions) < MAX_SYNTH_CANDIDATES:
                    add_expression(expression)

    expressions = sorted(expressions, key=lambda expression: (
        sum(1 for _ in ast.walk(ast.parse(expression, mode="eval"))),
        len(expression),
        expression,
    ))

    def complexity(expression: str) -> tuple[int, int, str]:
        try:
            tree = ast.parse(expression, mode="eval")
            nodes = sum(1 for _ in ast.walk(tree))
        except SyntaxError:
            nodes = MAX_SOURCE_BYTES
        return nodes, len(expression), expression

    ordered = sorted(expressions, key=complexity)
    training_matches = 0
    valid_solutions: list[tuple[tuple[int, int, str], str, int]] = []
    attempted = 0
    for expression in ordered:
        source = f"def solve(xs):\n    return {expression}\n"
        interpreter = _Interpreter(source)
        attempted += 1
        train_ok = True
        train_steps = 0
        for values, expected in training:
            try:
                actual, steps = interpreter.run(values)
                train_steps += steps
            except (ForgeError, ArithmeticError, TypeError, ValueError, IndexError, OverflowError):
                train_ok = False
                break
            if not _equal_typed(actual, expected):
                train_ok = False
                break
        if not train_ok:
            continue
        training_matches += 1
        validation_ok = True
        validation_steps = 0
        for values, expected in validation:
            try:
                actual, steps = interpreter.run(values)
                validation_steps += steps
            except (ForgeError, ArithmeticError, TypeError, ValueError, IndexError, OverflowError):
                validation_ok = False
                break
            if not _equal_typed(actual, expected):
                validation_ok = False
                break
        if validation_ok:
            valid_solutions.append((complexity(expression), expression, train_steps + validation_steps))

    valid_solutions.sort(key=lambda item: item[0])
    winner = valid_solutions[0] if valid_solutions else None
    return {
        "name": name.strip(),
        "generated": len(ordered),
        "attempted": attempted,
        "training_matches": training_matches,
        "validation_cases": len(validation),
        "validated": winner is not None,
        "expression": winner[1] if winner else None,
        "source": f"def solve(xs):\n    return {winner[1]}\n" if winner else None,
        "steps": winner[2] if winner else None,
        "note": "La expresión solo está validada para los ejemplos entregados; no se garantiza corrección universal.",
    }


def capability_document(report: dict[str, Any]) -> str:
    """Serialize only a validated synthesized function as a reusable data-only capability."""
    if not isinstance(report, dict) or not report.get("validated") or not isinstance(report.get("source"), str):
        raise ForgeError("Solo se puede guardar una capacidad que haya superado la validación.")
    source = report["source"]
    _Interpreter(source)
    document = {
        "format": "omega-forge-capability-v1",
        "name": report.get("name"),
        "expression": report.get("expression"),
        "source": source,
        "validation_cases": report.get("validation_cases"),
        "note": "Validada solo para los casos de prueba declarados; no garantiza corrección universal.",
    }
    if not isinstance(document["name"], str) or not isinstance(document["expression"], str):
        raise ForgeError("El informe de síntesis no contiene metadatos válidos.")
    serialized = json.dumps(document, ensure_ascii=False, indent=2) + "\n"
    if len(serialized) > MAX_TEXT_LENGTH:
        raise ForgeError(f"La capacidad supera el límite de {MAX_TEXT_LENGTH} caracteres.")
    return serialized


def execute_capability(workspace: str | Path, filename: str, data: Any) -> dict[str, Any]:
    """Execute a saved capability with the restricted interpreter and bounded input."""
    import re

    if (not isinstance(filename, str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\.json", filename)
            or filename in (".json", "..json")):
        raise ForgeError("La capacidad debe ser un archivo JSON con nombre simple dentro del workspace.")
    base = Path(workspace).expanduser()
    if base.is_symlink():
        raise ForgeError("El workspace no puede ser un enlace simbólico.")
    try:
        base = base.resolve(strict=True)
        target = base / filename
        if target.is_symlink():
            raise ForgeError("La capacidad no puede ser un enlace simbólico.")
        resolved = target.resolve(strict=True)
        if resolved.parent != base or not resolved.is_file():
            raise ForgeError("La capacidad debe ser un archivo regular directamente dentro del workspace.")
        if resolved.stat().st_size > MAX_SPEC_BYTES:
            raise ForgeError(f"La capacidad supera {MAX_SPEC_BYTES} bytes.")
        raw = resolved.read_text(encoding="utf-8")
    except ForgeError:
        raise
    except (OSError, UnicodeError) as exc:
        raise ForgeError(f"No se pudo leer la capacidad: {exc}") from exc
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ForgeError(f"JSON de capacidad inválido: {exc.msg}.") from exc
    required = {"format", "name", "expression", "source", "validation_cases", "note"}
    if not isinstance(document, dict) or set(document) != required:
        raise ForgeError("El archivo no tiene el formato de capacidad OMEGA FORGE.")
    if document["format"] != "omega-forge-capability-v1":
        raise ForgeError("Versión de capacidad no compatible.")
    if not isinstance(document["name"], str) or not document["name"].strip() or len(document["name"]) > 80:
        raise ForgeError("Nombre de capacidad inválido.")
    if not isinstance(document["expression"], str) or len(document["expression"]) > MAX_SOURCE_BYTES:
        raise ForgeError("Expresión de capacidad inválida.")
    if not isinstance(document["source"], str):
        raise ForgeError("Código de capacidad inválido.")
    if type(document["validation_cases"]) is not int or not 1 <= document["validation_cases"] <= 20:
        raise ForgeError("Número de casos de validación inválido.")
    interpreter = _Interpreter(document["source"])
    result, steps = interpreter.run(_checked(data))
    return {
        "name": document["name"],
        "result": result,
        "steps": steps,
        "validation_cases": document["validation_cases"],
        "note": document["note"],
    }


def format_synthesis_report(report: dict[str, Any]) -> str:
    lines = [
        f"OMEGA FORGE {VERSION} · síntesis aritmética acotada",
        f"Experimento: {report['name']}",
        f"Candidatos generados/examinados: {report['generated']}/{report['attempted']}",
        f"Expresiones que ajustan todos los ejemplos: {report['training_matches']}",
        f"Casos de validación reservados: {report['validation_cases']}",
    ]
    if report["validated"]:
        lines.extend([
            "RESULTADO: VALIDADO EN LOS CASOS SUMINISTRADOS",
            f"Expresión seleccionada: {report['expression']}",
            "Programa generado:",
            report["source"].rstrip(),
            f"Pasos estimados del intérprete: {report['steps']}",
        ])
    else:
        lines.append("RESULTADO: sin expresión que supere ejemplos y validación")
        lines.append("Prueba con más ejemplos variados o una gramática más amplia.")
    lines.append(report["note"])
    return "\n".join(lines)


def format_custom_report(report: dict[str, Any]) -> str:
    lines = [
        f"OMEGA FORGE {VERSION} · experimento personalizado: {report['task']}",
        f"Casos de prueba: {report['cases']}",
    ]
    for rank, candidate in enumerate(report["ranked"], start=1):
        status = "VALIDADO" if candidate["valid"] else f"NO VALIDADO ({candidate['passed']}/{candidate['total']})"
        lines.append(f"  {rank}. {candidate['name']} — {status} — {candidate['steps']} pasos")
        if candidate["failure"]:
            lines.append(f"     Motivo: {candidate['failure']}")
    lines.append(f"Selección: {report['winner'] or 'ninguna'}")
    lines.extend([
        "Puntuación: pasos estimados del intérprete restringido, no milisegundos.",
        "La selección solo es válida para los casos declarados; revisa los límites del manifiesto.",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OMEGA FORGE: comparación local de algoritmos seguros")
    parser.add_argument("task", nargs="?", choices=("all", "sum", "max"), default="all")
    parser.add_argument("--spec", help="Ruta a un manifiesto JSON de experimento personalizado")
    parser.add_argument("--synthesize", help="Sintetizar una expresión aritmética desde ejemplos JSON")
    parser.add_argument("--json", action="store_true", help="Mostrar el informe en JSON")
    args = parser.parse_args(argv)
    if args.spec and args.synthesize:
        parser.error("Usa --spec o --synthesize, no ambos.")
    try:
        if args.synthesize:
            report = synthesize_numeric(load_spec(args.synthesize))
            if args.json:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                print(format_synthesis_report(report))
            return 0 if report["validated"] else 1
        if args.spec:
            spec = load_spec(args.spec)
            report = benchmark_custom(spec)
            if args.json:
                print(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                print(format_custom_report(report))
            return 0 if report["winner"] else 1
        requested = available_tasks() if args.task == "all" else (args.task,)
        reports = [benchmark(task) for task in requested]
        if args.json:
            print(json.dumps(reports, ensure_ascii=False, indent=2))
        else:
            print(format_report(args.task))
        return 0 if all(report["winner"] for report in reports) else 1
    except (ForgeError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
