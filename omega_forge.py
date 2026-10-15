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

VERSION = "0.1.0"
MAX_SOURCE_BYTES = 8192
MAX_CASES = 100
MAX_COLLECTION_ITEMS = 256
MAX_STEPS_PER_CASE = 10000
MAX_LOOP_ITERATIONS = 256
MAX_INT_BITS = 256
MAX_ABS_NUMBER = 1e100
MAX_TEXT_LENGTH = 4096


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


def _checked(value: Any) -> Any:
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
        return type(value)(_checked(item) for item in value)
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
            if isinstance(node.op, ast.Pow):
                if type(right) not in (int, float) or abs(right) > 32:
                    raise ForgeError("El exponente debe estar entre -32 y 32.")
                return _checked(left ** right)
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
                    if len(result) > MAX_LOOP_ITERATIONS:
                        raise ForgeError(f"range supera {MAX_LOOP_ITERATIONS} elementos.")
                    budget.tick(max(1, len(result) // 8))
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


def benchmark(task: str) -> dict[str, Any]:
    """Run generated candidates against fixed, deterministic correctness cases."""
    name = task.casefold().strip()
    if name not in _TASKS:
        raise ForgeError(f"Tarea no disponible: {task}. Disponibles: {', '.join(available_tasks())}.")
    candidates, cases = _TASKS[name]
    if len(cases) > MAX_CASES:
        raise ForgeError(f"El conjunto supera {MAX_CASES} casos.")
    ranked: list[dict[str, Any]] = []
    for candidate in candidates:
        interpreter = _Interpreter(candidate.source)
        passed, total_steps, failure = 0, 0, None
        for index, (data, expected) in enumerate(cases, start=1):
            try:
                actual, steps = interpreter.run(data)
                total_steps += steps
                if not _equal_typed(actual, expected):
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
        "task": name,
        "cases": len(cases),
        "ranked": ranked,
        "winner": winner["name"] if winner else None,
        "metric": "pasos estimados del intérprete; no son milisegundos ni una medición de velocidad nativa",
    }


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OMEGA FORGE: comparación local de algoritmos seguros")
    parser.add_argument("task", nargs="?", choices=("all", "sum", "max"), default="all")
    parser.add_argument("--json", action="store_true", help="Mostrar el informe en JSON")
    args = parser.parse_args(argv)
    try:
        requested = available_tasks() if args.task == "all" else (args.task,)
        reports = [benchmark(task) for task in requested]
        if args.json:
            print(json.dumps(reports, ensure_ascii=False, indent=2))
        else:
            print(format_report(args.task))
        return 0 if all(report["winner"] for report in reports) else 1
    except ForgeError as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
