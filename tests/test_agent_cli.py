"""Opt-in agent CLI tests. No llama-server, GPU, model file, or network."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from app.agent.cli import MAX_REQUEST_BYTES, _stdin_has_bytes, main
from app.agent.config import AgentConfig
from app.agent.contracts import AgentRequest
from app.agent.runner import AgentRunResult
from app.agent.state import RunStatus
from app.agent.tool_registry import DEFAULT_ALLOWED_DATA_ROOTS, ToolRegistry

from tests.test_docker_entrypoint import entrypoint_path

ROOT = Path(__file__).resolve().parents[1]


class _Stdin(io.BytesIO):
    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.read_sizes: list[int | None] = []

    def read(self, size: int | None = -1) -> bytes:
        self.read_sizes.append(size)
        if size is None or size < 0:
            raise AssertionError("stdin read was not bounded")
        return super().read(size)


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.workspace = self._tmp.name
        self.calls: list[dict] = []

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run(self, argv: list[str], stdin: bytes | None = None, runner=None, factory=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        old = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = stdout, stderr
        stream = _Stdin(b"" if stdin is None else stdin)
        try:
            code = main(
                argv,
                stdin=stream,
                provider_factory=factory or self._factory,
                agent_runner=runner or self._runner,
            )
        finally:
            sys.stdout, sys.stderr = old
        return code, stdout.getvalue(), stderr.getvalue(), stream

    def _factory(self, config: AgentConfig):
        self.calls.append({"config": config})
        return object()

    def _runner(self, request, *, config, provider, registry):
        self.calls.append(
            {
                "request": request,
                "config": config,
                "provider": provider,
                "registry": registry,
            }
        )
        return AgentRunResult(
            status=RunStatus.COMPLETED,
            steps_completed=1,
            message="Advisory only.",
        )

    def test_valid_arguments_build_trusted_objects(self):
        code, out, err, _ = self._run(
            [
                "--workspace-root",
                self.workspace,
                "--allowed-data-root",
                "Data",
                "--allowed-data-root",
                "out",
                "--server-url",
                "http://127.0.0.1:8081",
                "--model-alias",
                "asa-local",
                "--timeout",
                "9",
                "--max-steps",
                "3",
                "--max-output-tokens",
                "128",
                "--message",
                "What is ready?",
            ]
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(err, "")
        built = self.calls[-1]
        self.assertIsInstance(built["request"], AgentRequest)
        self.assertEqual(built["request"].message, "What is ready?")
        self.assertTrue(built["request"].request_id)
        self.assertNotEqual(built["request"].request_id, "What is ready?")
        config = built["config"]
        self.assertEqual(config.server_url, "http://127.0.0.1:8081")
        self.assertEqual(config.model_alias, "asa-local")
        self.assertEqual(config.request_timeout_seconds, 9)
        self.assertEqual(config.max_steps, 3)
        self.assertEqual(config.max_output_tokens, 128)
        self.assertIsInstance(built["registry"], ToolRegistry)
        self.assertEqual(
            built["registry"]._workspace.allowed_roots,
            (("Data",), ("out",)),
        )
        self.assertIn("status: completed", out)
        self.assertIn("steps: 1", out)
        self.assertIn("Advisory only.", out)
        self.assertNotIn("{", out)

    def test_defaults_and_message_from_stdin(self):
        code, out, err, stream = self._run(
            ["--workspace-root", self.workspace],
            stdin="Summarize local results.\n".encode(),
        )
        self.assertEqual(code, 0, err)
        config = self.calls[-1]["config"]
        self.assertEqual(config.server_url, "http://127.0.0.1:8080")
        self.assertEqual(config.model_alias, "asa-local")
        self.assertEqual(config.request_timeout_seconds, 15)
        self.assertEqual(config.max_steps, 5)
        self.assertEqual(config.max_output_tokens, 512)
        self.assertEqual(
            self.calls[-1]["registry"]._workspace.allowed_roots,
            tuple(tuple(part.split("/")) for part in DEFAULT_ALLOWED_DATA_ROOTS),
        )
        self.assertEqual(self.calls[-1]["request"].message, "Summarize local results.\n")
        self.assertEqual(stream.read_sizes, [MAX_REQUEST_BYTES + 1])
        self.assertIn("status: completed", out)

    def test_missing_workspace_root(self):
        code, _, err, _ = self._run(["--message", "hello"])
        self.assertEqual(code, 2)
        self.assertIn("workspace-root", err)
        self.assertEqual(self.calls, [])

    def test_relative_workspace_root_is_rejected(self):
        code, _, err, _ = self._run(
            ["--workspace-root", "relative", "--message", "hello"]
        )
        self.assertEqual(code, 2)
        self.assertIn("absolute", err)
        self.assertEqual(self.calls, [])

    def test_non_loopback_url_is_rejected(self):
        code, out, err, _ = self._run(
            [
                "--workspace-root",
                self.workspace,
                "--server-url",
                "http://example.com:8080",
                "--message",
                "hello",
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("loopback", err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("example.com", out)
        self.assertEqual(self.calls, [])

    def test_invalid_model_alias_steps_and_timeout(self):
        cases = [
            (["--model-alias", "bad alias"], "model_alias"),
            (["--max-steps", "0"], "max_steps"),
            (["--max-steps", "11"], "max_steps"),
            (["--timeout", "0"], "request_timeout"),
            (["--timeout", "121"], "request_timeout"),
            (["--max-output-tokens", "0"], "max_output_tokens"),
        ]
        for extra, marker in cases:
            with self.subTest(extra=extra):
                self.calls.clear()
                code, _, err, _ = self._run(
                    ["--workspace-root", self.workspace, "--message", "hello", *extra]
                )
                self.assertEqual(code, 2)
                self.assertIn(marker, err)
                self.assertEqual(self.calls, [])

    def test_invalid_allowed_data_root(self):
        code, _, err, _ = self._run(
            [
                "--workspace-root",
                self.workspace,
                "--allowed-data-root",
                "../secrets",
                "--message",
                "hello",
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("traversal", err)
        self.assertEqual(self.calls, [])

    def test_unknown_argument_and_help(self):
        code, _, err, _ = self._run(
            ["--workspace-root", self.workspace, "--shell", "id"]
        )
        self.assertEqual(code, 2)
        self.assertIn("unrecognized arguments", err)
        help_code, out, _, _ = self._run(["--help"])
        self.assertEqual(help_code, 0)
        for flag in (
            "--workspace-root",
            "--allowed-data-root",
            "--server-url",
            "--model-alias",
            "--timeout",
            "--max-steps",
            "--max-output-tokens",
            "--message",
        ):
            self.assertIn(flag, out)
        self.assertEqual(self.calls, [])

    def test_empty_invalid_and_oversized_input(self):
        code, _, err, _ = self._run(["--workspace-root", self.workspace, "--message", "   "])
        self.assertEqual(code, 2)
        self.assertIn("empty", err)

        code, _, err, stream = self._run(["--workspace-root", self.workspace], stdin=b"")
        self.assertEqual(code, 2)
        self.assertIn("empty", err)
        self.assertEqual(stream.read_sizes, [MAX_REQUEST_BYTES + 1])

        code, _, err, _ = self._run(
            ["--workspace-root", self.workspace],
            stdin=b"\xff",
        )
        self.assertEqual(code, 2)
        self.assertIn("UTF-8", err)

        code, _, err, stream = self._run(
            ["--workspace-root", self.workspace],
            stdin=b"a" * (MAX_REQUEST_BYTES + 1),
        )
        self.assertEqual(code, 2)
        self.assertIn(str(MAX_REQUEST_BYTES), err)
        self.assertEqual(stream.read_sizes, [MAX_REQUEST_BYTES + 1])
        self.assertNotIn(-1, stream.read_sizes)

    def test_message_and_stdin_together_are_rejected(self):
        code, _, err, stream = self._run(
            ["--workspace-root", self.workspace, "--message", "hello"],
            stdin=b"also stdin",
        )
        self.assertEqual(code, 2)
        self.assertIn("not both", err)
        self.assertEqual(stream.read_sizes, [])
        self.assertEqual(self.calls, [])

    def test_waiting_failed_cancelled_and_provider_failure(self):
        def waiting(request, *, config, provider, registry):
            return AgentRunResult(
                status=RunStatus.WAITING_FOR_USER,
                steps_completed=2,
                message="Which local results file?",
                needs_user_input=True,
            )

        code, out, err, _ = self._run(
            ["--workspace-root", self.workspace, "--message", "hello"],
            runner=waiting,
        )
        self.assertEqual(code, 0, err)
        self.assertIn("status: waiting_for_user", out)
        self.assertIn("needs_input: yes", out)
        self.assertIn("not saved", out)
        self.assertIn("does not continue automatically", out)
        self.assertIn("Which local results file?", out)

        def failed(request, *, config, provider, registry):
            return AgentRunResult(
                status=RunStatus.FAILED,
                steps_completed=0,
                message="The local model is unavailable.",
                error_code="provider_unavailable",
            )

        code, out, err, _ = self._run(
            ["--workspace-root", self.workspace, "--message", "hello"],
            runner=failed,
        )
        self.assertEqual(code, 1)
        self.assertIn("status: failed", out)
        self.assertIn("error_code: provider_unavailable", out)
        self.assertIn("The local model is unavailable.", out)
        self.assertNotIn("Traceback", out + err)

        def cancelled(request, *, config, provider, registry):
            return AgentRunResult(status=RunStatus.CANCELLED, steps_completed=1)

        code, out, _, _ = self._run(
            ["--workspace-root", self.workspace, "--message", "hello"],
            runner=cancelled,
        )
        self.assertEqual(code, 130)
        self.assertIn("status: cancelled", out)

    def test_unexpected_error_hides_exception_text_and_does_not_retry(self):
        secret = "SECRET_INTERNAL_PATH_/tmp/should-not-leak"

        def explode(config):
            self.calls.append("factory")
            raise RuntimeError(secret)

        code, out, err, _ = self._run(
            ["--workspace-root", self.workspace, "--message", "hello"],
            factory=explode,
        )
        self.assertEqual(code, 1)
        self.assertEqual(self.calls, ["factory"])
        self.assertNotIn(secret, out + err)
        self.assertNotIn("Traceback", out + err)
        self.assertIn("could not run", err)

    def test_keyboard_interrupt_has_no_traceback(self):
        def interrupt(request, *, config, provider, registry):
            raise KeyboardInterrupt()

        code, out, err, _ = self._run(
            ["--workspace-root", self.workspace, "--message", "hello"],
            runner=interrupt,
        )
        self.assertEqual(code, 130)
        self.assertEqual(err, "error: interrupted\n")
        self.assertNotIn("Traceback", out + err)

    def test_no_files_are_created(self):
        before = set(Path(self.workspace).rglob("*"))
        code, _, err, _ = self._run(
            ["--workspace-root", self.workspace, "--message", "hello"]
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(set(Path(self.workspace).rglob("*")), before)

    def test_existing_m2_cli_and_docker_entrypoint_remain(self):
        result = subprocess.run(
            [sys.executable, "-m", "app.cli", "--help"],
            check=False,
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--input", result.stdout)
        self.assertIn("--output", result.stdout)
        self.assertNotIn("workspace-root", result.stdout)

        entry = entrypoint_path().read_text(encoding="utf-8")
        self.assertIn("python -m app.cli", entry)
        self.assertIn("python -m app.cpe.cli", entry)
        self.assertIn("python -m app.vulnerability.cli", entry)
        self.assertNotIn("app.agent.cli", entry)
        rejected = subprocess.run(
            ["sh", str(entrypoint_path()), "agent"],
            check=False,
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("unknown ASA command", rejected.stderr)


class StdinDetectionTests(unittest.TestCase):
    def test_dev_null_is_empty_even_though_select_reports_readable(self):
        with open(os.devnull, "rb") as stream:
            self.assertFalse(_stdin_has_bytes(stream))

    def test_closed_empty_os_pipe_is_empty(self):
        read_fd, write_fd = os.pipe()
        os.close(write_fd)
        try:
            with os.fdopen(read_fd, "rb") as stream:
                self.assertFalse(_stdin_has_bytes(stream))
        finally:
            # fdopen owns and closes read_fd unless construction failed.
            try:
                os.close(read_fd)
            except OSError:
                pass

    def test_nonempty_os_pipe_is_detected_without_consuming_buffered_input(self):
        read_fd, write_fd = os.pipe()
        try:
            os.write(write_fd, b"actual piped input")
        finally:
            os.close(write_fd)
        try:
            with os.fdopen(read_fd, "rb") as stream:
                self.assertTrue(_stdin_has_bytes(stream))
                self.assertEqual(stream.read(), b"actual piped input")
        finally:
            try:
                os.close(read_fd)
            except OSError:
                pass

    def test_terminal_stdin_is_not_a_conflicting_second_source(self):
        class TerminalStream(io.BytesIO):
            def isatty(self):
                return True

        self.assertFalse(_stdin_has_bytes(TerminalStream(b"terminal input")))

    def test_nonselectable_unknown_stream_is_conservatively_rejected(self):
        class UnsupportedStream:
            def isatty(self):
                return False

            def fileno(self):
                raise io.UnsupportedOperation("no file descriptor")

        self.assertTrue(_stdin_has_bytes(UnsupportedStream()))


class CliProviderIntegrationTests(unittest.TestCase):
    def test_subprocess_cli_uses_real_loopback_provider_and_runner_with_devnull(self):
        decision = json.dumps(
            {"kind": "final_answer", "message": "integration answer", "tool_call": None},
            separators=(",", ":"),
        )

        class Handler(BaseHTTPRequestHandler):
            requests = []
            validation_errors = []

            def log_message(self, format, *args):
                pass

            def _send_json(self, payload):
                body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                self.requests.append({
                    "method": "GET",
                    "path": self.path,
                    "host": self.headers.get("Host"),
                })
                if self.path != "/health":
                    self.validation_errors.append("unexpected health path")
                    self.send_error(404)
                    return
                # Exact successful response required by LocalLlamaCppProvider.
                self._send_json({"status": "ok"})

            def do_POST(self):
                if self.path != "/v1/chat/completions":
                    self.validation_errors.append("unexpected completion path")
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                try:
                    payload = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    self.validation_errors.append("request body was not JSON")
                    self._send_json({"choices": [{
                        "message": {"role": "assistant", "content": decision},
                        "finish_reason": "stop",
                    }]})
                    return

                self.requests.append({
                    "method": "POST",
                    "path": self.path,
                    "host": self.headers.get("Host"),
                    "payload": payload,
                })
                expected_keys = {
                    "model", "messages", "max_tokens", "temperature", "stream"
                }
                if set(payload) != expected_keys:
                    self.validation_errors.append("unexpected completion fields")
                if payload.get("model") != "asa-local":
                    self.validation_errors.append("unexpected model alias")
                messages = payload.get("messages")
                if not isinstance(messages, list) or len(messages) != 2:
                    self.validation_errors.append("unexpected message count")
                else:
                    if [m.get("role") for m in messages] != ["system", "user"]:
                        self.validation_errors.append("unexpected message roles")
                    if "integration request" not in messages[1].get("content", ""):
                        self.validation_errors.append("user message missing")
                if payload.get("max_tokens") != 512:
                    self.validation_errors.append("unexpected max_tokens")
                if payload.get("temperature") != 0 or payload.get("stream") is not False:
                    self.validation_errors.append("unexpected generation settings")
                if "tools" in payload or "tool_choice" in payload:
                    self.validation_errors.append("tool schema must not be sent")
                self._send_json({"choices": [{
                    "message": {"role": "assistant", "content": decision},
                    "finish_reason": "stop",
                }]})

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        host, port = server.server_address
        self.assertEqual(host, "127.0.0.1")
        Handler.requests = []
        Handler.validation_errors = []
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        with tempfile.TemporaryDirectory() as workspace:
            before = set(Path(workspace).rglob("*"))
            command = [
                sys.executable, "-m", "app.agent.cli",
                "--workspace-root", workspace,
                "--server-url", f"http://127.0.0.1:{port}",
                "--message", "integration request",
            ]
            result = None
            try:
                result = subprocess.run(
                    command,
                    cwd=ROOT,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
            finally:
                server.shutdown()
                server_thread.join(timeout=5)
                server.server_close()

            self.assertIsNotNone(result)
            self.assertFalse(server_thread.is_alive(), "HTTP server thread did not stop")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("status: completed", result.stdout)
            self.assertIn("steps: 1", result.stdout)
            self.assertIn("integration answer", result.stdout)
            self.assertEqual(Handler.validation_errors, [])
            self.assertEqual(
                [(item["method"], item["path"]) for item in Handler.requests],
                [("GET", "/health"), ("POST", "/v1/chat/completions")],
            )
            expected_host = f"127.0.0.1:{port}"
            self.assertTrue(all(item["host"] == expected_host for item in Handler.requests))
            self.assertEqual(set(Path(workspace).rglob("*")), before)


if __name__ == "__main__":
    unittest.main()
