import io
import json
import os
import socket
import struct
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch, Mock
from pathlib import Path

import omega_ai
import omega_forge


class OmegaLanguageTests(unittest.TestCase):
    def test_parse_all_supported_instructions(self):
        actions = omega_ai.parse_language('''OMEGA 0.1
MOSTRAR "hola"
SUMAR 20 22
ESTADO
RECORDAR "x" = "y"
LEER_MEMORIA "x"
CREAR "demo.txt" = "contenido"
''')
        self.assertEqual(
            [a["kind"] for a in actions],
            ["show", "sum", "status", "memory_set", "memory_get", "file_create"],
        )

    def test_unknown_instruction_rejected_with_line_number(self):
        with self.assertRaisesRegex(omega_ai.OmegaError, "Línea 1"):
            omega_ai.parse_language("BORRAR TODO")

    def test_reject_path_traversal(self):
        with self.assertRaisesRegex(omega_ai.OmegaError, "Nombre no permitido"):
            omega_ai.parse_language('CREAR "../important.txt" = "x"')


    def test_instruction_count_is_bounded(self):
        source = "\n".join(['MOSTRAR "x"'] * (omega_ai.MAX_INSTRUCTIONS + 1))
        with self.assertRaisesRegex(omega_ai.OmegaError, "límite de 100"):
            omega_ai.parse_language(source)


    def test_script_size_limit(self):
        with self.assertRaises(omega_ai.OmegaError):
            omega_ai.parse_language('MOSTRAR "' + ('x' * (omega_ai.MAX_SCRIPT_BYTES + 10)) + '"')


    def test_variables_expand_in_show_and_sum(self):
        source = 'OMEGA 0.2\nDEFINIR greeting = "Hola OMEGA"\nDEFINIR left = 20\nDEFINIR right = 22\nMOSTRAR $greeting\nMOSTRAR "Resultado: $left + $right"\nSUMAR $left $right'
        actions = omega_ai.parse_language(source)
        self.assertEqual(actions[0]["args"]["text"], "Hola OMEGA")
        self.assertEqual(actions[1]["args"]["text"], "Resultado: 20.0 + 22.0")
        self.assertEqual((actions[2]["args"]["a"], actions[2]["args"]["b"]), (20.0, 22.0))

    def test_true_and_false_conditions(self):
        source = 'DEFINIR a = 5\nDEFINIR b = 8\nSI $a < $b ENTONCES MOSTRAR "verdadero"\nSI $a > $b ENTONCES MOSTRAR "no debe aparecer"\nMOSTRAR "fin"'
        actions = omega_ai.parse_language(source)
        self.assertEqual([item["args"].get("text") for item in actions], ["verdadero", "fin"])

    def test_undefined_variable_rejected(self):
        with self.assertRaisesRegex(omega_ai.OmegaError, "Variable no definida"):
            omega_ai.parse_language("MOSTRAR $fantasma")

    def test_variable_redefinition_rejected(self):
        with self.assertRaisesRegex(omega_ai.OmegaError, "ya fue definida"):
            omega_ai.parse_language('DEFINIR x = 1\nDEFINIR x = 2\nMOSTRAR $x')

    def test_condition_type_mismatch_rejected(self):
        with self.assertRaisesRegex(omega_ai.OmegaError, "tipos distintos"):
            omega_ai.parse_language('DEFINIR x = 1\nSI $x == "uno" ENTONCES MOSTRAR "no"\nMOSTRAR "fin"')


    def test_false_condition_is_valid_without_actions(self):
        actions = omega_ai.parse_language('DEFINIR x = 3\nSI $x > 9 ENTONCES MOSTRAR "no"')
        self.assertEqual(actions, [])

    def test_audit_is_an_explicitly_approved_operation(self):
        temp = tempfile.TemporaryDirectory()
        store = omega_ai.OmegaStore(Path(temp.name) / "omega")
        try:
            action_id = store.enqueue("audit", {})
            with self.assertRaisesRegex(omega_ai.OmegaError, "Falta aprobación explícita"):
                store.execute_approved(action_id)
            result = store.execute_approved(action_id, approved=True)
            self.assertIn("SQLite integrity_check: ok", result)
            self.assertIn("Red: no consultada", result)
        finally:
            store.close()
            temp.cleanup()


    def test_variable_expansion_is_bounded(self):
        text = "x" * omega_ai.MAX_TEXT_CHARS
        source = 'DEFINIR long = "' + text + '"\nMOSTRAR "$long$long"'
        with self.assertRaisesRegex(omega_ai.OmegaError, "texto expandido supera"):
            omega_ai.parse_language(source)






    def test_language_capture_is_bounded(self):
        actions = omega_ai.parse_language("CAPTURAR 10 SEGUNDOS MAX 100 PAQUETES")
        self.assertEqual(actions[0]["kind"], "live_capture")
        self.assertEqual(actions[0]["args"]["seconds"], 10)
        self.assertEqual(actions[0]["args"]["max_packets"], 100)
        with self.assertRaisesRegex(omega_ai.OmegaError, "durar entre 1 y 60"):
            omega_ai.parse_language("CAPTURAR 61 SEGUNDOS MAX 100 PAQUETES")
        with self.assertRaisesRegex(omega_ai.OmegaError, "admite entre 1 y 500"):
            omega_ai.parse_language("CAPTURAR 10 SEGUNDOS MAX 501 PAQUETES")


    def test_language_can_propose_pcap_inspection(self):
        actions = omega_ai.parse_language('INSPECCIONAR "~/captura.pcapng"')
        self.assertEqual(actions[0]["kind"], "capture_inspect")
        self.assertEqual(actions[0]["args"]["path"], "~/captura.pcapng")


    def test_language_scan_requires_explicit_authorization_and_private_target(self):
        actions = omega_ai.parse_language('ESCANEAR "127.0.0.1" PUERTOS "22,80" AUTORIZADO')
        self.assertEqual(actions[0]["kind"], "lab_scan")
        self.assertTrue(actions[0]["args"]["authorized"])
        with self.assertRaisesRegex(omega_ai.OmegaError, "Sintaxis"):
            omega_ai.parse_language('ESCANEAR "127.0.0.1" PUERTOS "80"')
        with self.assertRaisesRegex(omega_ai.OmegaError, "Objetivo o puertos"):
            omega_ai.parse_language('ESCANEAR "8.8.8.8" PUERTOS "53" AUTORIZADO')

    def test_language_scan_port_limit(self):
        with self.assertRaisesRegex(omega_ai.OmegaError, "limita cada escaneo a 100"):
            omega_ai.parse_language('ESCANEAR "127.0.0.1" PUERTOS "1-101" AUTORIZADO')


    def test_language_can_propose_sqlite_compaction(self):
        actions = omega_ai.parse_language("COMPACTAR")
        self.assertEqual(actions[0]["kind"], "compact")


    def test_language_can_propose_learning_example(self):
        actions = omega_ai.parse_language('APRENDER "quiero revisar el sistema" = diagnostico')
        self.assertEqual(actions[0]["kind"], "learn_example")
        self.assertEqual(actions[0]["args"]["intent"], "diagnostico")


    def test_goal_length_is_bounded(self):
        with self.assertRaisesRegex(omega_ai.OmegaError, "objetivo debe tener"):
            omega_ai.make_plan("x" * (omega_ai.MAX_GOAL_CHARS + 1))


    def test_classifier_waits_for_two_intent_classes(self):
        examples = [{"phrase": "revisar el sistema", "intent": "diagnostico"}]
        self.assertIsNone(omega_ai.classify_intent("revisar el sistema", examples))

    def test_classifier_learns_from_local_examples(self):
        examples = [
            {"phrase": "quiero revisar el estado del sistema", "intent": "diagnostico"},
            {"phrase": "quiero guardar un recuerdo en memoria", "intent": "memoria"},
        ]
        self.assertEqual(omega_ai.classify_intent("quiero revisar el estado del sistema", examples), "diagnostico")
        summary, actions = omega_ai.make_plan("quiero revisar el estado del sistema", examples)
        self.assertIn("Clasificador local: diagnostico", summary)
        self.assertEqual([action["kind"] for action in actions], ["status"])


    def test_unmatched_query_falls_back_to_symbolic_rules(self):
        examples = [
            {"phrase": "quiero revisar el estado del sistema", "intent": "diagnostico"},
            {"phrase": "quiero guardar un recuerdo en memoria", "intent": "memoria"},
        ]
        self.assertIsNone(omega_ai.classify_intent("crear un experimento", examples))
        summary, actions = omega_ai.make_plan("crear un experimento", examples)
        self.assertIn("Plan de experimento local", summary)
        self.assertEqual([action["kind"] for action in actions], ["status", "file_create", "memory_set"])

    def test_classifier_general_intent_uses_informational_plan(self):
        examples = [
            {"phrase": "guardar memoria recuerdo", "intent": "memoria"},
            {"phrase": "mensaje general sin tarea concreta", "intent": "general"},
        ]
        summary, actions = omega_ai.make_plan("mensaje general sin tarea concreta", examples)
        self.assertIn("intención general", summary)
        self.assertEqual(actions[0]["kind"], "show")


class OmegaApprovalAndMemoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.home = Path(self.temp.name) / "omega"
        self.store = omega_ai.OmegaStore(self.home)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()


    def test_workspace_symlink_is_rejected(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        isolated_home = Path(self.temp.name) / "symlink-workspace-home"
        isolated_home.mkdir()
        (isolated_home / "workspace").symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(omega_ai.OmegaError, "workspace no puede ser un enlace simbólico"):
            omega_ai.OmegaStore(isolated_home)


    def test_sqlite_sidecar_symlink_is_rejected(self):
        outside = Path(self.temp.name) / "outside-wal"
        outside.write_bytes(b"leave alone")
        isolated_home = Path(self.temp.name) / "symlink-wal-home"
        isolated_home.mkdir()
        (isolated_home / "omega.sqlite3-wal").symlink_to(outside)
        with self.assertRaisesRegex(omega_ai.OmegaError, "auxiliares de SQLite"):
            omega_ai.OmegaStore(isolated_home)
        self.assertEqual(outside.read_bytes(), b"leave alone")

    def test_corrupt_action_json_is_marked_failed(self):
        action_id = self.store.enqueue("show", {"text": "hello"})
        self.store.db.execute("UPDATE approvals SET args_json=? WHERE id=?", ("not-json", action_id))
        self.store.db.commit()
        with self.assertRaises(omega_ai.OmegaError):
            self.store.execute_approved(action_id, approved=True)
        self.assertEqual(self.store.get_action(action_id)["status"], "failed")


    def test_database_symlink_is_rejected(self):
        outside = Path(self.temp.name) / "outside.sqlite3"
        outside.write_bytes(b"do not touch")
        isolated_home = Path(self.temp.name) / "symlink-db-home"
        isolated_home.mkdir()
        (isolated_home / "omega.sqlite3").symlink_to(outside)
        with self.assertRaisesRegex(omega_ai.OmegaError, "base de datos no puede ser un enlace simbólico"):
            omega_ai.OmegaStore(isolated_home)
        self.assertEqual(outside.read_bytes(), b"do not touch")


    def test_action_does_not_execute_until_approved(self):
        action_id = self.store.enqueue("file_create", {"filename": "demo.txt", "content": "hello"})
        self.assertFalse((self.store.workspace / "demo.txt").exists())
        with self.assertRaisesRegex(omega_ai.OmegaError, "Falta aprobación explícita"):
            self.store.execute_approved(action_id)
        self.assertFalse((self.store.workspace / "demo.txt").exists())
        result = self.store.execute_approved(action_id, approved=True)
        self.assertIn("Archivo creado", result)
        self.assertEqual((self.store.workspace / "demo.txt").read_text(), "hello")
        self.assertEqual(self.store.get_action(action_id)["status"], "approved")


    def test_repl_does_not_execute_without_exact_si(self):
        home = Path(self.temp.name) / "repl-no"
        answers = ['recordar "safe" = "value"', "aprobar 1", "yes", "salir"]
        with patch("builtins.input", side_effect=answers), redirect_stdout(io.StringIO()):
            omega_ai.run_repl(home)
        reopened = omega_ai.OmegaStore(home)
        try:
            self.assertIn("No existe memoria", reopened.recall("safe"))
            self.assertEqual(reopened.get_action(1)["status"], "pending")
        finally:
            reopened.close()

    def test_repl_explains_that_id_is_a_placeholder(self):
        home = Path(self.temp.name) / "repl-id-help"
        answers = ["auditar", "aprobar ID", "salir"]
        output = io.StringIO()
        errors = io.StringIO()
        with patch("builtins.input", side_effect=answers), redirect_stdout(output), patch("sys.stderr", errors):
            omega_ai.run_repl(home)
        self.assertIn("Sustituye ID por el número real", errors.getvalue())
        self.assertIn("aprobar 1", errors.getvalue())
        self.assertIn("autoriza solo con aprobar <ID>", output.getvalue())
        self.assertIn("luego escribe SI", output.getvalue())

    def test_repl_executes_after_exact_si(self):
        home = Path(self.temp.name) / "repl-yes"
        answers = ['recordar "safe" = "value"', "aprobar 1", "SI", "salir"]
        with patch("builtins.input", side_effect=answers), redirect_stdout(io.StringIO()):
            omega_ai.run_repl(home)
        reopened = omega_ai.OmegaStore(home)
        try:
            self.assertIn("value", reopened.recall("safe"))
            self.assertEqual(reopened.get_action(1)["status"], "approved")
        finally:
            reopened.close()


    def test_reject_never_creates_file(self):
        action_id = self.store.enqueue("file_create", {"filename": "no.txt", "content": "no"})
        self.store.reject(action_id)
        self.assertFalse((self.store.workspace / "no.txt").exists())
        self.assertEqual(self.store.get_action(action_id)["status"], "rejected")

    def test_memory_persists_after_reopen(self):
        action_id = self.store.enqueue("memory_set", {"key": "goal", "value": "build omega"})
        self.store.execute_approved(action_id, approved=True)
        self.store.close()
        reopened = omega_ai.OmegaStore(self.home)
        try:
            self.assertIn("build omega", reopened.recall("goal"))
        finally:
            reopened.close()

    def test_duplicate_approval_is_refused(self):
        action_id = self.store.enqueue("show", {"text": "hello"})
        self.store.execute_approved(action_id, approved=True)
        with self.assertRaisesRegex(omega_ai.OmegaError, "ya está en estado approved"):
            self.store.execute_approved(action_id, approved=True)

    def test_no_overwrite_existing_file(self):
        path = self.store.workspace / "same.txt"
        path.write_text("original")
        action_id = self.store.enqueue("file_create", {"filename": "same.txt", "content": "replacement"})
        with self.assertRaisesRegex(omega_ai.OmegaError, "ya existe"):
            self.store.execute_approved(action_id, approved=True)
        self.assertEqual(path.read_text(), "original")



    def test_learning_example_requires_approval_and_persists(self):
        action_id = self.store.enqueue(
            "learn_example",
            {"phrase": "quiero revisar el sistema", "intent": "diagnostico"},
        )
        with self.assertRaisesRegex(omega_ai.OmegaError, "Falta aprobación explícita"):
            self.store.execute_approved(action_id)
        self.assertEqual(self.store.training_examples(), [])
        result = self.store.execute_approved(action_id, approved=True)
        self.assertIn("aprendizaje local", result)
        self.assertEqual(self.store.training_examples()[0]["intent"], "diagnostico")



    def test_memory_size_is_bounded(self):
        with self.assertRaisesRegex(omega_ai.OmegaError, "valor de memoria supera"):
            self.store.remember("large", "x" * (omega_ai.MAX_TEXT_CHARS + 1))

    def test_memory_count_is_capped(self):
        for index in range(omega_ai.MAX_MEMORIES + 3):
            self.store.remember(f"key_{index}", "value")
        count = self.store.db.execute("SELECT COUNT(*) FROM memories").fetchone()[0]
        self.assertEqual(count, omega_ai.MAX_MEMORIES)





    def test_live_capture_requires_approval_and_uses_bounded_wirelab_args(self):
        with tempfile.TemporaryDirectory(dir=Path.home(), prefix=".omega-live-test-") as temp_dir:
            output = Path(temp_dir) / "capture.pcap"
            action_id = self.store.enqueue("live_capture", {
                "seconds": 5, "max_packets": 20, "output": str(output)
            })
            with patch("wirelab_live.main") as capture_main:
                with self.assertRaisesRegex(omega_ai.OmegaError, "Falta aprobación explícita"):
                    self.store.execute_approved(action_id)
                capture_main.assert_not_called()

                def fake_capture_main():
                    args = list(__import__("sys").argv)
                    self.assertIn("--launch-pcapdroid", args)
                    self.assertEqual(args[args.index("--seconds") + 1], "5")
                    self.assertEqual(args[args.index("--max-packets") + 1], "20")
                    output_path = Path(args[args.index("--output") + 1])
                    output_path.write_bytes(b"fake pcap for test")
                    return 0

                capture_main.side_effect = fake_capture_main
                result = self.store.execute_approved(action_id, approved=True)
                self.assertIn("Captura guardada", result)
                self.assertTrue(output.exists())


    def test_pcap_inspection_requires_approval_and_reads_local_capture(self):
        with tempfile.TemporaryDirectory(dir=Path.home(), prefix=".omega-pcap-test-") as temp_dir:
            path = Path(temp_dir) / "empty.pcap"
            path.write_bytes(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
            action_id = self.store.enqueue("capture_inspect", {"path": str(path)})
            with self.assertRaisesRegex(omega_ai.OmegaError, "Falta aprobación explícita"):
                self.store.execute_approved(action_id)
            result = self.store.execute_approved(action_id, approved=True)
            self.assertIn("Archivo:", result)
            self.assertIn("PCAP", result)
            self.assertIn("paquetes procesados: 0", result)

    def test_pcap_inspection_rejects_symlink(self):
        with tempfile.TemporaryDirectory(dir=Path.home(), prefix=".omega-pcap-link-") as temp_dir:
            target = Path(temp_dir) / "real.pcap"
            target.write_bytes(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
            link = Path(temp_dir) / "link.pcap"
            link.symlink_to(target)
            action_id = self.store.enqueue("capture_inspect", {"path": str(link)})
            with self.assertRaisesRegex(omega_ai.OmegaError, "enlaces simbólicos"):
                self.store.execute_approved(action_id, approved=True)

    def test_pcap_inspection_rejects_path_outside_home(self):
        path = Path(self.temp.name) / "outside.pcap"
        path.write_bytes(b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        action_id = self.store.enqueue("capture_inspect", {"path": str(path)})
        with self.assertRaisesRegex(omega_ai.OmegaError, "dentro del directorio personal"):
            self.store.execute_approved(action_id, approved=True)


    def test_real_loopback_scan_requires_approval_and_detects_open_port(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            action_id = self.store.enqueue(
                "lab_scan",
                {"target": "127.0.0.1", "ports": [port], "authorized": True},
            )
            with self.assertRaisesRegex(omega_ai.OmegaError, "Falta aprobación explícita"):
                self.store.execute_approved(action_id)
            result = self.store.execute_approved(action_id, approved=True)
            self.assertIn(f"{port}/tcp", result)
            self.assertIn("open", result)
        finally:
            listener.close()


    def test_sqlite_compaction_refuses_low_free_space(self):
        action_id = self.store.enqueue("compact", {})
        with patch("omega_ai.shutil.disk_usage", return_value=Mock(free=0)):
            with self.assertRaisesRegex(omega_ai.OmegaError, "No hay espacio libre suficiente"):
                self.store.execute_approved(action_id, approved=True)
        self.assertEqual(self.store.get_action(action_id)["status"], "failed")

    def test_training_examples_are_capped(self):
        for index in range(omega_ai.MAX_TRAINING_EXAMPLES + 3):
            self.store.learn_example(f"frase de ejemplo {index}", "diagnostico")
        count = self.store.db.execute("SELECT COUNT(*) FROM training_examples").fetchone()[0]
        self.assertEqual(count, omega_ai.MAX_TRAINING_EXAMPLES)


    def test_sqlite_compaction_requires_approval(self):
        action_id = self.store.enqueue("compact", {})
        with self.assertRaisesRegex(omega_ai.OmegaError, "Falta aprobación explícita"):
            self.store.execute_approved(action_id)
        result = self.store.execute_approved(action_id, approved=True)
        self.assertIn("Base de datos compactada", result)



    def test_pending_queue_is_bounded(self):
        for index in range(omega_ai.MAX_PENDING):
            self.store.enqueue("show", {"text": str(index)})
        with self.assertRaisesRegex(omega_ai.OmegaError, "cola ya tiene 100"):
            self.store.enqueue("show", {"text": "overflow"})
        self.assertEqual(len(self.store.pending()), omega_ai.MAX_PENDING)

    def test_action_batch_is_rejected_without_partial_queueing(self):
        for index in range(omega_ai.MAX_PENDING - 5):
            self.store.enqueue("show", {"text": str(index)})
        before = len(self.store.pending())
        with redirect_stdout(io.StringIO()), patch("sys.stderr", new_callable=io.StringIO):
            omega_ai.queue_actions(
                self.store,
                [{"kind": "show", "args": {"text": str(i)}} for i in range(10)],
            )
        self.assertEqual(len(self.store.pending()), before)


    def test_history_returns_newest_actions_first_and_caps_limit(self):
        first = self.store.enqueue("show", {"text": "one"})
        second = self.store.enqueue("show", {"text": "two"})
        rows = self.store.history(1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], second)
        self.assertGreater(second, first)


    def test_planner_returns_reviewable_actions(self):
        summary, actions = omega_ai.make_plan("crear un experimento")
        self.assertIn("aprobación individual", summary)
        self.assertEqual([x["kind"] for x in actions], ["status", "file_create", "memory_set"])

    def test_arbitrary_operation_is_not_executable(self):
        action_id = self.store.enqueue("shell", {"command": "rm -rf /"})
        with self.assertRaisesRegex(omega_ai.OmegaError, "no permitido"):
            self.store.execute_approved(action_id, approved=True)



class NetMapStandaloneTests(unittest.TestCase):
    def test_private_loopback_target_is_allowed(self):
        import netmap
        self.assertEqual(netmap.check_target("127.0.0.1"), "127.0.0.1")

    def test_public_target_is_rejected(self):
        import netmap
        with self.assertRaises(Exception):
            netmap.check_target("8.8.8.8")

    def test_port_parser_deduplicates_and_sorts(self):
        import netmap
        self.assertEqual(netmap.parse_ports("80,22,80,8000-8001"), [22,80,8000,8001])

    def test_port_parser_rejects_out_of_range(self):
        import netmap
        with self.assertRaises(Exception):
            netmap.parse_ports("0,80")

    def test_real_loopback_port_probe(self):
        import netmap
        import socket
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        try:
            result = netmap.probe("127.0.0.1", port, 0.5)
            self.assertEqual(result["state"], "open")
        finally:
            listener.close()


class WireLabStandaloneTests(unittest.TestCase):
    def test_decode_ethernet_ipv4_tcp(self):
        import pcap_inspector
        ethernet = bytes.fromhex("aabbccddeeff0011223344550800")
        tcp = struct.pack("!HHIIHHHH", 54321, 443, 123, 0, 0x5002, 64240, 0, 0)
        ip_len = 20 + len(tcp)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 1, 0, 64, 6, 0,
                         socket.inet_aton("192.168.1.10"), socket.inet_aton("192.168.1.1"))
        decoded = pcap_inspector.decode_frame(ethernet + ip + tcp, 1)
        self.assertEqual(decoded["protocol"], "TCP")
        self.assertEqual(decoded["dst_port"], 443)

    def test_classic_pcap_reader_roundtrip(self):
        import pcap_inspector
        packet = bytes.fromhex("aabbccddeeff0011223344550800")
        tcp = struct.pack("!HHIIHHHH", 12345, 80, 1, 0, 0x5002, 64000, 0, 0)
        ip_len = 20 + len(tcp)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 1, 0, 64, 6, 0,
                         socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"))
        frame = packet + ip + tcp
        header = bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        packet_header = struct.pack("<IIII", 1700000000, 500000, len(frame), len(frame))
        with tempfile.NamedTemporaryFile(delete=False) as output:
            path = output.name
            output.write(header + packet_header + frame)
        try:
            records = list(pcap_inspector.iter_capture(path))
            self.assertEqual(records[0][1]["format"], "PCAP")
            self.assertEqual(records[1][1]["captured_length"], len(frame))
            self.assertEqual(pcap_inspector.decode_frame(records[1][1]["data"], 1)["protocol"], "TCP")
        finally:
            os.unlink(path)

    def test_wirelab_live_rejects_short_datagram(self):
        import wirelab_live
        self.assertIsNone(wirelab_live.parse_record_datagram(b"short"))

    def test_wirelab_live_detects_raw_ip(self):
        import wirelab_live
        ipv4 = bytes.fromhex("4500002800010000400600007f0000017f000001")
        self.assertEqual(wirelab_live.detect_linktype(ipv4), 101)

    def test_pcapdroid_command_is_loopback_and_explicit(self):
        import wirelab_live
        cmd = wirelab_live.pcapdroid_command("start", 5123, "org.mozilla.firefox")
        self.assertIn("127.0.0.1", cmd)
        self.assertIn("udp_exporter", cmd)
        self.assertIn("org.mozilla.firefox", cmd)
        self.assertNotIn("shell", cmd)


class WireLabEdgeCaseTests(unittest.TestCase):
    def test_pcapng_section_header_and_interface(self):
        import pcap_inspector
        def block(block_type, body):
            total = 8 + len(body) + 4
            if total % 4:
                body += b"\\x00" * ((-total) % 4)
                total = 8 + len(body) + 4
            return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)
        shb_body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        shb = block(0x0A0D0D0A, shb_body)
        idb = block(1, struct.pack("<HHI", 1, 0, 65535))
        with tempfile.NamedTemporaryFile(delete=False) as output:
            path = output.name
            output.write(shb + idb)
        try:
            records = list(pcap_inspector.iter_capture(path))
            self.assertEqual(records[0], ("header", {"format": "PCAPNG"}))
            self.assertEqual(len(records), 1)
        finally:
            os.unlink(path)

    def test_pcapng_rejects_truncated_section_header(self):
        import pcap_inspector
        with tempfile.NamedTemporaryFile(delete=False) as output:
            path = output.name
            output.write(bytes.fromhex("0a0d0d0a1c000000"))
        try:
            with self.assertRaises((ValueError, struct.error)):
                list(pcap_inspector.iter_capture(path))
        finally:
            os.unlink(path)

    def test_pcap_inspector_rejects_unknown_magic(self):
        import pcap_inspector
        with tempfile.NamedTemporaryFile(delete=False) as output:
            path = output.name
            output.write(b"not a packet capture")
        try:
            with self.assertRaises(ValueError):
                list(pcap_inspector.iter_capture(path))
        finally:
            os.unlink(path)

    def test_live_record_parser_rejects_inconsistent_length(self):
        import wirelab_live
        data = struct.pack("<IIII", 1, 2, 20, 20) + b"short"
        self.assertIsNone(wirelab_live.parse_record_datagram(data))

    def test_safe_output_path_refuses_existing_file(self):
        import wirelab_live
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "existing.pcap")
            with open(path, "wb") as output:
                output.write(b"x")
            with self.assertRaises(OSError):
                wirelab_live.safe_output_path(path)

    def test_safe_output_path_rejects_missing_parent(self):
        import wirelab_live
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "missing", "capture.pcap")
            with self.assertRaises(OSError):
                wirelab_live.safe_output_path(path)


class OmegaFileSafetyEdgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = omega_ai.OmegaStore(Path(self.temp.name) / "omega")

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_file_create_rejects_symlink_destination(self):
        outside = Path(self.temp.name) / "outside.txt"
        outside.write_text("untouched", encoding="utf-8")
        link = self.store.workspace / "linked.txt"
        link.symlink_to(outside)
        action_id = self.store.enqueue("file_create", {"filename": "linked.txt", "content": "overwrite"})
        with self.assertRaisesRegex(omega_ai.OmegaError, "ya existe"):
            self.store.execute_approved(action_id, approved=True)
        self.assertEqual(outside.read_text(encoding="utf-8"), "untouched")

    def test_file_create_revalidates_content_limit_at_execution(self):
        action_id = self.store.enqueue("file_create", {
            "filename": "too-big.txt", "content": "x" * (omega_ai.MAX_TEXT_CHARS + 1)
        })
        with self.assertRaisesRegex(omega_ai.OmegaError, "demasiado largo"):
            self.store.execute_approved(action_id, approved=True)
        self.assertFalse((self.store.workspace / "too-big.txt").exists())

    def test_capture_inspection_rejects_non_capture_extension(self):
        path = Path.home() / "omega-test-notes.txt"
        path.write_text("not a capture", encoding="utf-8")
        action_id = self.store.enqueue("capture_inspect", {"path": str(path)})
        with self.assertRaisesRegex(omega_ai.OmegaError, "PCAP/PCAPNG"):
            self.store.execute_approved(action_id, approved=True)
        path.unlink(missing_ok=True)

    def test_capture_inspection_rejects_file_over_size_limit(self):
        path = Path(self.temp.name) / "large.pcap"
        path.write_bytes(b"x" * (omega_ai.MAX_INSPECT_BYTES + 1))
        action_id = self.store.enqueue("capture_inspect", {"path": str(path)})
        with self.assertRaisesRegex(omega_ai.OmegaError, "directorio personal|supera el límite"):
            self.store.execute_approved(action_id, approved=True)

    def test_learn_example_rejects_unknown_intent_even_if_queue_is_tampered(self):
        action_id = self.store.enqueue("learn_example", {"phrase": "hello", "intent": "execute"})
        with self.assertRaises(omega_ai.OmegaError):
            self.store.execute_approved(action_id, approved=True)
        self.assertEqual(self.store.get_action(action_id)["status"], "failed")



class PcapHardeningRegressionTests(unittest.TestCase):
    @staticmethod
    def _pcap_global_header(snaplen=65535):
        return b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, snaplen, 1)

    @staticmethod
    def _pcapng_block(block_type, body):
        total = 12 + len(body)
        return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)

    def test_classic_pcap_rejects_timestamp_fraction_out_of_range(self):
        import pcap_inspector
        with tempfile.NamedTemporaryFile() as capture:
            capture.write(self._pcap_global_header())
            capture.write(struct.pack("<IIII", 1, 1_000_000, 0, 0))
            capture.flush()
            packets = pcap_inspector.iter_capture(capture.name)
            self.assertEqual(next(packets)[1]["format"], "PCAP")
            with self.assertRaisesRegex(ValueError, "fraction out of range"):
                next(packets)

    def test_classic_pcap_rejects_captured_length_greater_than_original(self):
        import pcap_inspector
        with tempfile.NamedTemporaryFile() as capture:
            capture.write(self._pcap_global_header())
            capture.write(struct.pack("<IIII", 1, 0, 1, 0) + b"x")
            capture.flush()
            packets = pcap_inspector.iter_capture(capture.name)
            next(packets)
            with self.assertRaisesRegex(ValueError, "exceeds original length"):
                next(packets)

    def test_classic_pcap_rejects_capture_length_above_snaplen(self):
        import pcap_inspector
        with tempfile.NamedTemporaryFile() as capture:
            capture.write(self._pcap_global_header(snaplen=1))
            capture.write(struct.pack("<IIII", 1, 0, 2, 2) + b"xx")
            capture.flush()
            packets = pcap_inspector.iter_capture(capture.name)
            next(packets)
            with self.assertRaisesRegex(ValueError, "exceeds snaplen"):
                next(packets)

    def test_udp_decoder_rejects_length_smaller_than_header(self):
        import pcap_inspector
        frame = struct.pack("!HHHH", 53, 53, 4, 0)
        decoded = pcap_inspector.decode_transport(frame, 0, 17, "192.0.2.1", "192.0.2.2", len(frame))
        self.assertEqual(decoded["info"], "Invalid UDP length")

    def test_pcapng_uses_interface_timestamp_resolution(self):
        import pcap_inspector
        shb_body = b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1)
        shb = struct.pack("<II", 0x0A0D0D0A, 28) + shb_body + struct.pack("<I", 28)
        idb_body = (
            struct.pack("<HHI", 1, 0, 65535)
            + struct.pack("<HHB", 9, 1, 9) + b"\x00\x00\x00"
            + struct.pack("<HH", 0, 0)
        )
        idb = self._pcapng_block(1, idb_body)
        epb_body = struct.pack("<IIIII", 0, 0, 1_000_000_000, 4, 4) + b"test"
        epb = self._pcapng_block(6, epb_body)
        with tempfile.NamedTemporaryFile() as capture:
            capture.write(shb + idb + epb)
            capture.flush()
            items = list(pcap_inspector.iter_capture(capture.name))
        packet = next(item for kind, item in items if kind == "packet")
        self.assertEqual(packet["timestamp"], 1.0)
        self.assertEqual(packet["data"], b"test")


    def test_pcapng_rejects_packet_captured_length_greater_than_original(self):
        import pcap_inspector
        shb_body = b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1)
        shb = struct.pack("<II", 0x0A0D0D0A, 28) + shb_body + struct.pack("<I", 28)
        idb_body = struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HH", 0, 0)
        idb = self._pcapng_block(1, idb_body)
        epb_body = struct.pack("<IIIII", 0, 0, 0, 4, 3) + b"test"
        epb = self._pcapng_block(6, epb_body)
        with tempfile.NamedTemporaryFile() as capture:
            capture.write(shb + idb + epb)
            capture.flush()
            items = pcap_inspector.iter_capture(capture.name)
            next(items)
            with self.assertRaisesRegex(ValueError, "exceeds original length"):
                list(items)

    def test_pcapng_rejects_truncated_interface_timestamp_option(self):
        import pcap_inspector
        shb_body = b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1)
        shb = struct.pack("<II", 0x0A0D0D0A, 28) + shb_body + struct.pack("<I", 28)
        # Option says one byte of value but the block ends immediately after its header.
        idb_body = struct.pack("<HHI", 1, 0, 65535) + struct.pack("<HH", 9, 1)
        idb = self._pcapng_block(1, idb_body)
        with tempfile.NamedTemporaryFile() as capture:
            capture.write(shb + idb)
            capture.flush()
            items = pcap_inspector.iter_capture(capture.name)
            next(items)
            with self.assertRaisesRegex(ValueError, "option truncated"):
                next(items)


class ApprovalRaceRegressionTests(unittest.TestCase):
    def test_sqlite_journal_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            home = root / "omega-home"
            home.mkdir()
            outside = root / "outside-journal"
            outside.write_bytes(b"preserve")
            (home / "omega.sqlite3-journal").symlink_to(outside)
            with self.assertRaisesRegex(omega_ai.OmegaError, "auxiliares de SQLite"):
                omega_ai.OmegaStore(home)
            self.assertEqual(outside.read_bytes(), b"preserve")

    def test_two_process_connections_cannot_execute_one_approval_twice(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor

        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "omega-home"
            initial = omega_ai.OmegaStore(home)
            action_id = initial.enqueue("file_create", {
                "filename": "one-shot.txt", "content": "only once"
            })
            initial.close()
            barrier = threading.Barrier(2)

            def execute():
                # Create each SQLite connection inside its own worker thread.
                store = omega_ai.OmegaStore(home)
                original_get = store.get_action

                def synchronized_get(action_id):
                    row = original_get(action_id)
                    barrier.wait(timeout=5)
                    return row

                store.get_action = synchronized_get
                try:
                    try:
                        return ("ok", store.execute_approved(action_id, approved=True))
                    except omega_ai.OmegaError as exc:
                        return ("error", str(exc))
                finally:
                    store.close()

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(lambda _: execute(), range(2)))

            self.assertEqual(sum(status == "ok" for status, _ in results), 1)
            self.assertEqual(sum(status == "error" for status, _ in results), 1)
            check = omega_ai.OmegaStore(home)
            try:
                self.assertEqual((check.workspace / "one-shot.txt").read_text(), "only once")
                self.assertEqual(check.get_action(action_id)["status"], "approved")
            finally:
                check.close()


    def test_reject_and_approve_race_has_exactly_one_winner(self):
        import threading
        from concurrent.futures import ThreadPoolExecutor

        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "omega-home"
            initial = omega_ai.OmegaStore(home)
            action_id = initial.enqueue("file_create", {
                "filename": "one-shot.txt", "content": "only once"
            })
            initial.close()
            barrier = threading.Barrier(2)

            def attempt(mode):
                # Give both independent SQLite connections the same initial
                # pending snapshot, then let their conditional claims race.
                store = omega_ai.OmegaStore(home)
                original_get = store.get_action
                first_read = True

                def synchronized_get(requested_id):
                    nonlocal first_read
                    row = original_get(requested_id)
                    if first_read:
                        first_read = False
                        barrier.wait(timeout=5)
                    return row

                store.get_action = synchronized_get
                try:
                    try:
                        if mode == "approve":
                            message = store.execute_approved(action_id, approved=True)
                        else:
                            message = store.reject(action_id)
                        return (True, mode, message)
                    except omega_ai.OmegaError as exc:
                        return (False, mode, str(exc))
                finally:
                    store.close()

            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(attempt, ("approve", "reject")))

            self.assertEqual(sum(won for won, _, _ in results), 1, results)
            winner = next(mode for won, mode, _ in results if won)
            check = omega_ai.OmegaStore(home)
            try:
                self.assertEqual(check.get_action(action_id)["status"], "approved" if winner == "approve" else "rejected")
                created = (check.workspace / "one-shot.txt").exists()
                self.assertEqual(created, winner == "approve")
            finally:
                check.close()


class WireLabBoundedCaptureTests(unittest.TestCase):
    def test_live_receiver_requires_finite_capture_limits(self):
        import wirelab_live
        invalid_arguments = (
            ["--seconds", "0", "--max-packets", "0"],
            ["--seconds", "61", "--max-packets", "10"],
            ["--seconds", "10", "--max-packets", "501"],
        )
        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                with patch("sys.argv", ["wirelab_live.py", *arguments]):
                    with patch("sys.stderr", io.StringIO()):
                        with self.assertRaises(SystemExit) as raised:
                            wirelab_live.main()
                self.assertEqual(raised.exception.code, 2)


    def test_pcapdroid_stop_is_attempted_when_receiver_raises(self):
        import wirelab_live

        class BrokenSocket:
            def setsockopt(self, *args):
                pass

            def bind(self, *args):
                pass

            def settimeout(self, *args):
                pass

            def recvfrom(self, *args):
                raise OSError("simulated receiver failure")

            def close(self):
                self.closed = True

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "failed-capture.pcap"
            fake_socket = BrokenSocket()
            with patch(
                "sys.argv",
                ["wirelab_live.py", "--seconds", "1", "--max-packets", "10",
                 "--launch-pcapdroid", "--output", str(output)],
            ), patch("wirelab_live.socket.socket", return_value=fake_socket), patch(
                "wirelab_live.shutil.which", return_value="/system/bin/am"
            ), patch(
                "wirelab_live.subprocess.run", return_value=Mock(returncode=0)
            ) as run:
                with self.assertRaisesRegex(OSError, "simulated receiver failure"):
                    wirelab_live.main()

            self.assertTrue(fake_socket.closed)
            self.assertEqual(run.call_count, 2)
            stop_command = run.call_args_list[-1].args[0]
            self.assertIn("stop", stop_command)


class TerminalUiTests(unittest.TestCase):
    def test_banner_has_local_identity_and_offline_status(self):
        output = io.StringIO()
        with redirect_stdout(output):
            omega_ai.print_terminal_banner("/tmp/omega-test", enabled=False)
        rendered = output.getvalue()
        self.assertIn("✳  OMEGA AI", rendered)
        self.assertIn("offline", rendered)
        self.assertIn("sin root", rendered)
        self.assertIn("/tmp/omega-test", rendered)
        self.assertNotIn("\\033[", rendered)

    def test_terminal_style_respects_disabled_color(self):
        self.assertEqual(omega_ai.terminal_style("❯ ", "orange", enabled=False), "❯ ")

    def test_terminal_style_emits_ansi_when_enabled(self):
        styled = omega_ai.terminal_style("OMEGA", "orange", enabled=True)
        self.assertTrue(styled.startswith("\033[38;5;208m"))
        self.assertTrue(styled.endswith("\033[0m"))

    def test_slash_prefixed_help_command_works(self):
        with tempfile.TemporaryDirectory() as home:
            output = io.StringIO()
            with patch("builtins.input", side_effect=["/ayuda", "salir"]), redirect_stdout(output):
                omega_ai.run_repl(home)
            self.assertIn("Comandos del agente:", output.getvalue())

    def test_slash_prefixed_status_and_pending_are_safe(self):
        with tempfile.TemporaryDirectory() as home:
            output = io.StringIO()
            with patch("builtins.input", side_effect=["/estado", "/pendientes", "salir"]), redirect_stdout(output):
                omega_ai.run_repl(home)
            rendered = output.getvalue()
            self.assertIn("Acciones pendientes", rendered)
            self.assertIn("Operaciones que requieren aprobación", rendered)
            reopened = omega_ai.OmegaStore(home)
            try:
                self.assertEqual(len(reopened.pending()), 1)
                self.assertEqual(reopened.pending()[0]["kind"], "status")
            finally:
                reopened.close()

class OmegaForgeTests(unittest.TestCase):
    def test_sum_candidates_pass_and_forge_selects_a_winner(self):
        report = omega_forge.benchmark("sum")
        self.assertEqual(report["cases"], 6)
        self.assertEqual(report["winner"], "sum_integrado")
        self.assertTrue(all(candidate["valid"] for candidate in report["ranked"]))
        self.assertEqual(report["ranked"][0]["name"], report["winner"])
        self.assertIn("no son milisegundos", report["metric"])

    def test_max_candidates_pass_all_cases(self):
        report = omega_forge.benchmark("max")
        self.assertEqual(report["winner"], "max_integrado")
        self.assertTrue(all(candidate["passed"] == report["cases"] for candidate in report["ranked"]))

    def test_unknown_forge_task_is_rejected(self):
        with self.assertRaisesRegex(omega_forge.ForgeError, "Tarea no disponible"):
            omega_forge.benchmark("shell")

    def test_candidate_imports_are_rejected(self):
        source = "import os\ndef solve(xs):\n    return 1\n"
        with self.assertRaisesRegex(omega_forge.ForgeError, "única función"):
            omega_forge._Interpreter(source)

    def test_candidate_file_and_network_calls_are_rejected(self):
        for source in (
            "def solve(xs):\n    return open('x').read()\n",
            "def solve(xs):\n    return xs.__class__\n",
            "def solve(xs):\n    while True:\n        return 1\n",
        ):
            with self.subTest(source=source), self.assertRaises(omega_forge.ForgeError):
                omega_forge._Interpreter(source)

    def test_candidate_range_and_execution_steps_are_bounded(self):
        source = "def solve(xs):\n    total = 0\n    for i in range(999999):\n        total = total + i\n    return total\n"
        interpreter = omega_forge._Interpreter(source)
        with self.assertRaisesRegex(omega_forge.ForgeError, "range supera"):
            interpreter.run([])

    def test_candidate_never_calls_python_eval_or_exec(self):
        source = "def solve(xs):\n    return sum(xs)\n"
        interpreter = omega_forge._Interpreter(source)
        result, steps = interpreter.run([1, 2, 3])
        self.assertEqual(result, 6)
        self.assertGreater(steps, 0)

    def test_terminal_forja_command_runs_without_queuing_side_effects(self):
        with tempfile.TemporaryDirectory() as home:
            output = io.StringIO()
            with patch("builtins.input", side_effect=["/forja sum", "/salir"]), redirect_stdout(output):
                omega_ai.run_repl(home)
            rendered = output.getvalue()
            self.assertIn("OMEGA FORGE", rendered)
            self.assertIn("sum_integrado", rendered)
            store = omega_ai.OmegaStore(home)
            try:
                self.assertEqual(store.pending(), [])
                self.assertEqual(store.history(), [])
            finally:
                store.close()

    def test_custom_manifest_compares_pure_algorithms(self):
        spec = {
            "name": "suma personalizada",
            "cases": [
                {"input": [], "expected": 0},
                {"input": [1, 2, 3], "expected": 6},
                {"input": [-5, 5, 10], "expected": 10},
            ],
            "candidates": [
                {"name": "integrado", "source": "def solve(xs):\n    return sum(xs)\n"},
                {"name": "bucle", "source": "def solve(xs):\n    total = 0\n    for value in xs:\n        total = total + value\n    return total\n"},
            ],
        }
        report = omega_forge.benchmark_custom(spec)
        self.assertEqual(report["task"], "suma personalizada")
        self.assertEqual(report["cases"], 3)
        self.assertEqual(report["winner"], "integrado")
        self.assertTrue(all(candidate["valid"] for candidate in report["ranked"]))

    def test_custom_manifest_rejects_unsafe_candidate_before_running_suite(self):
        spec = {
            "name": "seguridad",
            "cases": [{"input": [], "expected": 0}],
            "candidates": [
                {"name": "seguro", "source": "def solve(xs):\n    return sum(xs)\n"},
                {"name": "no_seguro", "source": "def solve(xs):\n    return open('secret').read()\n"},
            ],
        }
        with self.assertRaisesRegex(omega_forge.ForgeError, "funciones integradas autorizadas"):
            omega_forge.benchmark_custom(spec)

    def test_custom_manifest_rejects_unexpected_fields_and_bad_cases(self):
        with self.assertRaisesRegex(omega_forge.ForgeError, "exactamente"):
            omega_forge.benchmark_custom({
                "name": "bad", "cases": [{"input": [], "expected": 0}],
                "candidates": [
                    {"name": "a", "source": "def solve(xs):\n    return 0\n"},
                    {"name": "b", "source": "def solve(xs):\n    return 0\n"},
                ],
                "execute": True,
            })
        spec = {
            "name": "bad case",
            "cases": [{"input": [], "expected": 0, "unexpected": True}],
            "candidates": [
                {"name": "a", "source": "def solve(xs):\n    return 0\n"},
                {"name": "b", "source": "def solve(xs):\n    return 0\n"},
            ],
        }
        with self.assertRaisesRegex(omega_forge.ForgeError, "requiere exactamente input y expected"):
            omega_forge.benchmark_custom(spec)

    def test_interpreter_rejects_large_collection_multiplication(self):
        interpreter = omega_forge._Interpreter("def solve(xs):\n    return xs * 1000000\n")
        with self.assertRaisesRegex(omega_forge.ForgeError, "multiplicación excede"):
            interpreter.run([1, 2])

    def test_interpreter_rejects_extreme_range_without_overflow(self):
        source = "def solve(xs):\n    for i in range(0, 999999999999999999999999):\n        return i\n    return 0\n"
        interpreter = omega_forge._Interpreter(source)
        with self.assertRaisesRegex(omega_forge.ForgeError, "range supera"):
            interpreter.run([])

    def test_custom_manifest_loader_reads_regular_json_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sum.json"
            spec = {
                "name": "carga",
                "cases": [{"input": [], "expected": 0}, {"input": [4, 2], "expected": 6}],
                "candidates": [
                    {"name": "integrado", "source": "def solve(xs):\n    return sum(xs)\n"},
                    {"name": "bucle", "source": "def solve(xs):\n    total = 0\n    for value in xs:\n        total = total + value\n    return total\n"},
                ],
            }
            path.write_text(json.dumps(spec), encoding="utf-8")
            loaded = omega_forge.load_spec(path)
            self.assertEqual(loaded["name"], "carga")
            self.assertEqual(omega_forge.benchmark_custom(loaded)["winner"], "integrado")

    def test_custom_manifest_loader_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = Path(temp_dir) / "real.json"
            target.write_text("{}", encoding="utf-8")
            link = Path(temp_dir) / "alias.json"
            link.symlink_to(target)
            with self.assertRaisesRegex(omega_forge.ForgeError, "enlace simbólico"):
                omega_forge.load_spec(link)

    def test_terminal_forja_runs_custom_manifest_read_only(self):
        with tempfile.TemporaryDirectory() as home:
            path = Path(home) / "custom.json"
            spec = {
                "name": "terminal personalizada",
                "cases": [{"input": [], "expected": 0}, {"input": [1, 2], "expected": 3}],
                "candidates": [
                    {"name": "integrado", "source": "def solve(xs):\n    return sum(xs)\n"},
                    {"name": "bucle", "source": "def solve(xs):\n    total = 0\n    for value in xs:\n        total = total + value\n    return total\n"},
                ],
            }
            path.write_text(json.dumps(spec), encoding="utf-8")
            output = io.StringIO()
            with patch("builtins.input", side_effect=[f"/forja {path}", "/salir"]), redirect_stdout(output):
                omega_ai.run_repl(home)
            rendered = output.getvalue()
            self.assertIn("experimento personalizado: terminal personalizada", rendered)
            self.assertIn("VALIDADO", rendered)
            store = omega_ai.OmegaStore(home)
            try:
                self.assertEqual(store.pending(), [])
                self.assertEqual(store.history(), [])
            finally:
                store.close()

    def test_validated_capability_can_be_saved_and_reused(self):
        spec = {
            "name": "sumar tres valores",
            "examples": [
                {"input": [1, 2, 3], "output": 6},
                {"input": [2, 4, 6], "output": 12},
                {"input": [7, -2, 5], "output": 10},
            ],
            "validation": [{"input": [10, 5, 1], "output": 16}],
        }
        report = omega_forge.synthesize_numeric(spec)
        document = omega_forge.capability_document(report)
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp) / "workspace"
            workspace.mkdir()
            (workspace / "sumar_tres.json").write_text(document, encoding="utf-8")
            result = omega_forge.execute_capability(workspace, "sumar_tres.json", [100, 20, -3])
        self.assertEqual(result["result"], 117)
        self.assertEqual(result["validation_cases"], 1)
        self.assertIn("no garantiza corrección universal", result["note"])

    def test_forge_capability_catalog_lists_only_valid_capabilities(self):
        report = omega_forge.synthesize_numeric({
            "name": "suma simple",
            "examples": [
                {"input": [1, 2], "output": 3},
                {"input": [2, 4], "output": 6},
                {"input": [7, -2], "output": 5},
            ],
            "validation": [{"input": [10, 5], "output": 15}],
        })
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp) / "workspace"
            workspace.mkdir()
            (workspace / "suma.json").write_text(
                omega_forge.capability_document(report), encoding="utf-8"
            )
            (workspace / "otro.json").write_text('{"name":"no es capacidad"}', encoding="utf-8")
            capabilities = omega_forge.list_capabilities(workspace)
        self.assertEqual([item["filename"] for item in capabilities], ["suma.json"])
        self.assertEqual(capabilities[0]["name"], "suma simple")

    def test_capability_rechecks_stored_validation_before_execution(self):
        report = omega_forge.synthesize_numeric({
            "name": "suma",
            "examples": [
                {"input": [1, 2], "output": 3},
                {"input": [2, 4], "output": 6},
                {"input": [7, -2], "output": 5},
            ],
            "validation": [{"input": [10, 5], "output": 15}],
        })
        tampered_report = dict(report, source="def solve(xs):\n    return 999\n")
        with self.assertRaisesRegex(omega_forge.ForgeError, "antes de guardarse"):
            omega_forge.capability_document(tampered_report)
        document = json.loads(omega_forge.capability_document(report))
        document["source"] = "def solve(xs):\n    return 999\n"
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp) / "workspace"
            workspace.mkdir()
            (workspace / "tampered.json").write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaisesRegex(omega_forge.ForgeError, "no supera la validación almacenada"):
                omega_forge.execute_capability(workspace, "tampered.json", [2, 3])

    def test_capability_runner_rejects_unsafe_paths_and_untrusted_syntax(self):
        with tempfile.TemporaryDirectory() as temp:
            workspace = Path(temp) / "workspace"
            workspace.mkdir()
            outside = Path(temp) / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(omega_forge.ForgeError, "nombre simple"):
                omega_forge.execute_capability(workspace, "../outside.json", [1])
            (workspace / "bad.json").write_text(json.dumps({
                "format": "omega-forge-capability-v2",
                "name": "maliciosa",
                "expression": "import os",
                "source": "import os\ndef solve(xs):\n    return 1\n",
                "validation_cases": 1,
                "validation": [{"input": [1], "output": 1}],
                "note": "test",
            }), encoding="utf-8")
            with self.assertRaises(omega_forge.ForgeError):
                omega_forge.execute_capability(workspace, "bad.json", [1])

    def test_terminal_can_save_and_reuse_a_validated_forge_capability(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "home"
            spec_path = Path(temp) / "discover.json"
            spec = {
                "name": "suma de dos valores",
                "examples": [
                    {"input": [1, 2], "output": 3},
                    {"input": [2, 4], "output": 6},
                    {"input": [7, -2], "output": 5},
                ],
                "validation": [{"input": [10, 5], "output": 15}],
            }
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            output = io.StringIO()
            with patch("builtins.input", side_effect=[
                f"/forja guardar {spec_path} suma.json",
                "/pendientes",
                "aprobar 1",
                "SI",
                "/forja lista",
                '/forja usar suma.json "[5, 6]"',
                "/salir",
            ]), redirect_stdout(output):
                omega_ai.run_repl(home)
            rendered = output.getvalue()
            self.assertIn("Archivo creado:", rendered)
            self.assertIn("suma.json — suma de dos valores", rendered)
            self.assertIn("Capacidad: suma de dos valores", rendered)
            self.assertIn("Resultado: 11", rendered)

    def test_terminal_handles_unclosed_quotes_in_forge_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            output = io.StringIO()
            with patch("builtins.input", side_effect=[
                '/forja guardar "broken.json capacidad.json',
                '/forja usar "broken.json [1]',
                '/forja usar missing.json "' + ("x" * 8193) + '"',
                "/salir",
            ]), redirect_stdout(output), redirect_stderr(output):
                omega_ai.run_repl(Path(temp) / "home")
            rendered = output.getvalue()
        self.assertIn("Sintaxis de guardado inválida", rendered)
        self.assertIn("Sintaxis de uso inválida", rendered)
        self.assertIn("superan el límite de 8192 bytes", rendered)

    def test_forge_rejects_excessive_ast_nodes_and_depth(self):
        values = ",".join(["1"] * 256)
        many_nodes = f"def solve(xs):\n    return sum([{values}]) + sum([{values}])\n"
        with self.assertRaisesRegex(omega_forge.ForgeError, "nodos de sintaxis"):
            omega_forge._Interpreter(many_nodes)

        deeply_nested = "def solve(xs):\n    return " + ("-" * 70) + "1\n"
        with self.assertRaisesRegex(omega_forge.ForgeError, "profundidad sintáctica"):
            omega_forge._Interpreter(deeply_nested)

    def test_forge_normalizes_invalid_power_operations(self):
        for source in (
            'def solve(xs):\n    return "x" ** 2\n',
            'def solve(xs):\n    return 0 ** -1\n',
        ):
            with self.subTest(source=source):
                interpreter = omega_forge._Interpreter(source)
                with self.assertRaisesRegex(omega_forge.ForgeError, "Potencia inválida"):
                    interpreter.run([1])

    def test_synthesis_discovers_expression_and_uses_held_out_validation(self):
        spec = {
            "name": "sumar dos valores",
            "examples": [
                {"input": [1, 2], "output": 3},
                {"input": [2, 4], "output": 6},
                {"input": [7, -2], "output": 5},
                {"input": [-3, 5], "output": 2},
            ],
            "validation": [
                {"input": [10, 5], "output": 15},
                {"input": [-4, -3], "output": -7},
            ],
        }
        report = omega_forge.synthesize_numeric(spec)
        self.assertTrue(report["validated"])
        self.assertGreater(report["generated"], 100)
        self.assertGreater(report["training_matches"], 0)
        interpreter = omega_forge._Interpreter(report["source"])
        result, _ = interpreter.run([20, 22])
        self.assertEqual(result, 42)

    def test_synthesis_discovers_formula_with_three_inputs_and_two_operations(self):
        spec = {
            "name": "sumar tres valores",
            "examples": [
                {"input": [1, 2, 3], "output": 6},
                {"input": [2, 4, 6], "output": 12},
                {"input": [7, -2, 5], "output": 10},
                {"input": [-3, 5, 8], "output": 10},
            ],
            "validation": [
                {"input": [10, 5, 1], "output": 16},
                {"input": [-4, -3, -2], "output": -9},
            ],
        }
        report = omega_forge.synthesize_numeric(spec)
        self.assertTrue(report["validated"])
        self.assertLessEqual(report["generated"], omega_forge.MAX_SYNTH_CANDIDATES)
        interpreter = omega_forge._Interpreter(report["source"])
        result, _ = interpreter.run([100, 20, -3])
        self.assertEqual(result, 117)

    def test_synthesis_discovers_maximum_aggregate(self):
        spec = {
            "name": "máximo de valores",
            "examples": [
                {"input": [1, 2, 3], "output": 3},
                {"input": [2, 4, 1], "output": 4},
                {"input": [-4, -3, -2], "output": -2},
                {"input": [0, 0, 0], "output": 0},
            ],
            "validation": [
                {"input": [10, 5, 1], "output": 10},
                {"input": [-10, -20, -3], "output": -3},
            ],
        }
        report = omega_forge.synthesize_numeric(spec)
        self.assertTrue(report["validated"])
        interpreter = omega_forge._Interpreter(report["source"])
        result, _ = interpreter.run([9, 1, 5])
        self.assertEqual(result, 9)

    def test_synthesis_rejects_training_fit_that_fails_held_out_validation(self):
        spec = {
            "name": "regla contradictoria",
            "examples": [
                {"input": [1], "output": 2},
                {"input": [2], "output": 4},
                {"input": [3], "output": 6},
            ],
            "validation": [{"input": [4], "output": 9}],
        }
        report = omega_forge.synthesize_numeric(spec)
        self.assertGreater(report["training_matches"], 0)
        self.assertFalse(report["validated"])
        self.assertIsNone(report["source"])

    def test_synthesis_rejects_mismatched_input_arity(self):
        spec = {
            "name": "arity",
            "examples": [
                {"input": [1], "output": 1},
                {"input": [2], "output": 2},
                {"input": [3, 4], "output": 7},
            ],
            "validation": [{"input": [5], "output": 5}],
        }
        with self.assertRaisesRegex(omega_forge.ForgeError, "mismo número de entradas"):
            omega_forge.synthesize_numeric(spec)

    def test_terminal_forja_discover_command_synthesizes_from_json(self):
        with tempfile.TemporaryDirectory() as home:
            spec_path = Path(home) / "discover.json"
            spec = {
                "name": "suma terminal",
                "examples": [
                    {"input": [1, 2], "output": 3},
                    {"input": [2, 4], "output": 6},
                    {"input": [3, 5], "output": 8},
                ],
                "validation": [{"input": [10, 5], "output": 15}],
            }
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            output = io.StringIO()
            with patch("builtins.input", side_effect=[f"/forja descubrir {spec_path}", "/salir"]), redirect_stdout(output):
                omega_ai.run_repl(home)
            rendered = output.getvalue()
            self.assertIn("síntesis aritmética acotada", rendered)
            self.assertIn("VALIDADO EN LOS CASOS SUMINISTRADOS", rendered)
            store = omega_ai.OmegaStore(home)
            try:
                self.assertEqual(store.pending(), [])
                self.assertEqual(store.history(), [])
            finally:
                store.close()

