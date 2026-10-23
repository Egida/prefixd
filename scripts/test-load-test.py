#!/usr/bin/env python3
"""Check load-workload qualification against tiny owned loopback hey samples."""

import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/load-test.sh"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/transport":
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        self.send_response(int(self.path[1:]))
        if self.path == "/302":
            self.send_header("Location", "/200")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args):
        pass


class LoadWorkloads(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("hey"):
            raise RuntimeError("hey is required; install it before running this check")
        cls.receipts = Path(tempfile.mkdtemp(prefix="prefixd-load-selftest-"))
        print(f"Raw loopback samples retained in: {cls.receipts}", flush=True)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            cls.samples = {}
            for status in (200, 202, 302, 401, 403, 429, 500, "transport"):
                output = cls.receipts / f"hey-{status}.log"
                with output.open("w") as log:
                    try:
                        result = subprocess.run(
                            [
                                "hey",
                                "-disable-redirects",
                                "-n",
                                "100",
                                "-c",
                                "1",
                                "-t",
                                "1",
                                f"http://127.0.0.1:{server.server_port}/{status}",
                            ],
                            stdout=log,
                            stderr=subprocess.STDOUT,
                            timeout=10,
                            check=False,
                        )
                    except subprocess.TimeoutExpired:
                        output.with_suffix(".exit").write_text("timeout\n")
                        raise
                output.with_suffix(".exit").write_text(f"{result.returncode}\n")
                cls.samples[status] = output
            # Functional thresholds use explicit synthetic fast metrics; this
            # regression must not turn the loopback host speed into a benchmark.
            fast = re.sub(
                r"Requests/sec:[^\n]*", "Requests/sec: 10000", cls.samples[200].read_text()
            )
            fast = re.sub(r"Average:[^\n]*", "Average: 0.001 secs", fast)
            fast = re.sub(r"99% in [^\n]*", "99% in 0.002 secs", fast)
            cls.fast_success = cls.receipts / "control-fast-success.log"
            cls.fast_success.write_text(fast)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def shell(self, commands, *args, **kwargs):
        return subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"\n' + commands,
                "load-selftest",
                str(SCRIPT),
                *map(str, args),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
            **kwargs,
        )

    def qualify(self, path, status=0):
        return self.shell(
            'if parse_hey "$2" "$3"; then exit 0; fi\n'
            'test -z "$_hey_rps$_hey_latency_avg$_hey_latency_p99" || exit 2\nexit 1',
            path,
            status,
        )

    def test_actual_loopback_status_and_transport_controls(self):
        for status, path in self.samples.items():
            with self.subTest(status=status):
                result = self.qualify(path)
                self.assertEqual(result.returncode, 0 if status in (200, 202) else 1, result.stderr)
                self.assertEqual("Requests/sec:" in result.stdout, status in (200, 202))

    def test_empty_malformed_and_mixed_outputs_never_qualify(self):
        success = self.samples[200].read_text()
        controls = {
            "empty": "",
            "noise": "Requests/sec: 999999\n",
            "mixed": success + "  [429] 1 responses\n",
            "redirect": success.replace("[200]", "[302]"),
            "missing-status": success.split("Status code distribution:")[0],
            "missing-p99": "\n".join(line for line in success.splitlines() if "99%" not in line),
            "zero-responses": re.sub(r"(\[200\]\s+)100 responses", r"\g<1>0 responses", success),
            "bad-latency": success.replace("Average:", "Average: NaN"),
            "duplicate-summary": success + "Summary:\n",
            "request-error": success + "Error distribution:\n  [1] connection refused\n",
        }
        for label, output in controls.items():
            with self.subTest(label=label):
                path = self.receipts / f"control-{label}.log"
                path.write_text(output)
                self.assertEqual(self.qualify(path).returncode, 1, label)
        self.assertEqual(self.qualify(self.samples[200], 7).returncode, 1)

    def test_foreground_command_failure_retains_raw_output_and_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.shell(
                "RESULTS_DIR=$2; fixture=$3\n"
                'hey() { [[ "$1" == -disable-redirects ]] || return 99; cat "$fixture"; return 7; }\n'
                "if run_hey failed-command; then exit 9; fi\n"
                'test -z "$_hey_rps$_hey_latency_avg$_hey_latency_p99"',
                directory,
                self.samples[200],
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                (Path(directory) / "01-failed-command.log").read_text(),
                self.samples[200].read_text(),
            )
            self.assertEqual((Path(directory) / "01-failed-command.exit").read_text(), "7\n")

    def test_metrics_require_both_foreground_and_background_success(self):
        for foreground, background in ((200, 200), (200, 401), (429, 200)):
            with (
                self.subTest(foreground=foreground, background=background),
                tempfile.TemporaryDirectory() as directory,
            ):
                result = self.shell(
                    "RESULTS_DIR=$2; WORK_DIR=$2; foreground=$3; background=$4\n"
                    "sleep() { :; }\n"
                    'hey() { [[ "$1" == -disable-redirects ]] || return 99; if [[ "${*: -1}" == */metrics ]]; then cat "$foreground"; else cat "$background"; fi; }\n'
                    "test_metrics_under_load 4\n"
                    'test -z "$BG_PID"\nprintf "FAILURES=%s\\n" "$FAIL"',
                    directory,
                    self.fast_success if foreground == 200 else self.samples[foreground],
                    self.fast_success if background == 200 else self.samples[background],
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(
                    f"FAILURES={0 if foreground == background == 200 else 1}", result.stdout
                )
                self.assertEqual(len(list(Path(directory).glob("*.log"))), 2)
                self.assertEqual(len(list(Path(directory).glob("*.exit"))), 2)

    def test_all_probes_use_existing_auth_without_printing_token(self):
        with tempfile.TemporaryDirectory() as directory:
            token = "load-selftest-not-a-secret"
            result = self.shell(
                "fixture=$2; export TMPDIR=$3\n"
                'hey() { cat "$fixture"; }\n'
                "sleep() { :; }\n"
                "curl() {\n"
                '  [[ "$*" == *"Authorization: Bearer ${PREFIXD_API_TOKEN}"* ]] || return 17\n'
                '  if [[ "${*: -1}" == */metrics ]]; then\n'
                "    echo 'prefixd_db_pool_connections{state=\"active\"} 1'\n"
                "  else echo '{\"total_events\":1}'; fi\n"
                "}\n"
                'main quick\ntest_sustained 1 1\ntest "$FAIL" -eq 0',
                self.fast_success,
                directory,
                env={**os.environ, "PREFIXD_API_TOKEN": token},
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn(token, result.stdout + result.stderr)
            self.assertFalse(list(Path(directory).glob("prefixd-load-body-*")))

    def test_failure_cleans_body_files_and_reaps_owned_background(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            work = root / "body"
            work.mkdir()
            (work / "request.json").write_text("temporary")
            pid_file = root / "pid"
            try:
                result = self.shell(
                    "RESULTS_DIR=$2; WORK_DIR=$2/body; BG_OUTPUT=$2/background.log\n"
                    'trap cleanup EXIT\n: > "$BG_OUTPUT"\nsleep 60 > "$BG_OUTPUT" 2>&1 &\n'
                    'BG_PID=$!\nprintf "%s\\n" "$BG_PID" > "$2/pid"\nexit 1',
                    directory,
                )
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertFalse(work.exists())
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pid_file.read_text()), 0)
                self.assertTrue((root / "background.log").exists())
                self.assertNotEqual((root / "background.exit").read_text(), "0\n")
            finally:
                if pid_file.exists():
                    with suppress(ProcessLookupError):
                        os.kill(int(pid_file.read_text()), 15)

    def test_unavailable_pool_observation_is_not_reported_as_zero(self):
        for mode in ("missing", "curl-error", "malformed", "zero"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                result = self.shell(
                    "RESULTS_DIR=$2; WORK_DIR=$2; fixture=$3; mode=$4\n"
                    'hey() { cat "$fixture"; }\nsleep() { :; }\n'
                    "curl() {\n"
                    '  [[ "${*: -1}" == */metrics ]] || return 0\n'
                    '  case "$mode" in\n'
                    "    curl-error) return 22 ;;\n"
                    "    malformed) echo 'prefixd_db_pool_connections{state=\"active\"} NaN' ;;\n"
                    "    zero) echo 'prefixd_db_pool_connections{state=\"active\"} 0' ;;\n"
                    "  esac\n"
                    "}\n"
                    'test_sustained 1 1\nprintf "FAILURES=%s\\n" "$FAIL"',
                    directory,
                    self.fast_success,
                    mode,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"FAILURES={0 if mode == 'zero' else 1}", result.stdout)
                if mode != "zero":
                    self.assertNotIn("Observed DB pool active connections", result.stdout)

    def test_malformed_starting_stats_stop_before_workloads(self):
        for stats in ("{}", '{"total_events":null}', '{"total_events":"1"}', '{"total_events":-1}'):
            with self.subTest(stats=stats), tempfile.TemporaryDirectory() as directory:
                marker = Path(directory) / "hey-called"
                result = self.shell(
                    "stats=$2; export TMPDIR=$3; marker=$3/hey-called\n"
                    'hey() { touch "$marker"; }\ncurl() { echo "$stats"; }\nmain quick',
                    stats,
                    directory,
                )
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(marker.exists())
                self.assertFalse(list(Path(directory).glob("prefixd-load-body-*")))


if __name__ == "__main__":
    unittest.main()
