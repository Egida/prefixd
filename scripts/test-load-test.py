#!/usr/bin/env python3
"""Check load-workload qualification against tiny owned loopback hey samples."""

import os
import re
import select
import shutil
import signal
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
    mixed_count = 0

    def do_GET(self):
        mixed_error = False
        if self.path == "/mixed-transport":
            Handler.mixed_count += 1
            mixed_error = Handler.mixed_count % 2 == 1
        if self.path == "/transport" or mixed_error:
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        self.send_response(200 if self.path == "/mixed-transport" else int(self.path[1:]))
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
        template = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; printf "%s" "$HEY_TEMPLATE"',
                "load-selftest",
                str(SCRIPT),
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        try:
            cls.samples = {}
            for status in (200, 202, 302, 401, 403, 429, 500, "transport", "mixed-transport"):
                output = cls.receipts / f"hey-{status}.log"
                with output.open("w") as log:
                    try:
                        result = subprocess.run(
                            [
                                "hey",
                                "-disable-redirects",
                                "-o",
                                template,
                                "-n",
                                "400" if status == "mixed-transport" else "100",
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

    def qualify(self, path, status=0, expected=0):
        return self.shell(
            'if parse_hey "$2" "$3" "$4"; then exit 0; fi\n'
            'test -z "$_hey_rps$_hey_latency_avg$_hey_latency_p99" || exit 2\nexit 1',
            path,
            status,
            expected,
        )

    def test_actual_loopback_status_and_transport_controls(self):
        for status, path in self.samples.items():
            with self.subTest(status=status):
                result = self.qualify(path, expected=100)
                self.assertEqual(result.returncode, 0 if status in (200, 202) else 1, result.stderr)
                self.assertEqual("Requests/sec:" in result.stdout, status in (200, 202))

    def test_empty_malformed_and_mixed_outputs_never_qualify(self):
        success = self.samples[200].read_text()
        histogram = success.split("Response time histogram:", 1)[1].split("\n\n", 1)[0]
        controls = {
            "empty": "",
            "noise": "Requests/sec: 999999\n",
            "mixed": re.sub(
                r"(\[200\]\s+)100 responses", r"\g<1>50 responses\n  [429] 50 responses", success
            ),
            "redirect": success.replace("[200]", "[302]"),
            "missing-status": success.split("Status code distribution:")[0],
            "truncated-success-prefix": re.sub(r"(\[200\]\s+)100", r"\g<1>50", success),
            "missing-histogram": success.replace("Response time histogram:", "Missing:"),
            "duplicate-histogram": success + "Response time histogram:" + histogram + "\n\n",
            "missing-bucket": success.replace(histogram.splitlines()[1] + "\n", "", 1),
            "malformed-bucket": success.replace(histogram.splitlines()[1], "  NaN [100] |"),
            "missing-p99": "\n".join(line for line in success.splitlines() if "99%" not in line),
            "zero-responses": re.sub(r"(\[200\]\s+)100 responses", r"\g<1>0 responses", success),
            "bad-latency": success.replace("Average:", "Average: NaN"),
            "duplicate-summary": success + "Summary:\n",
            "request-error": success + "Error distribution:\n  [1] connection refused\n",
            "missing-completion": success.split("PREFIXD_HEY_COMPLETE")[0],
            "truncated-completion-count": success.replace("100 END", "1"),
            "duplicate-completion": success + "PREFIXD_HEY_COMPLETE 100 END\n",
            "after-completion": success + "unexpected tail\n",
        }
        for label, output in controls.items():
            with self.subTest(label=label):
                path = self.receipts / f"control-{label}.log"
                path.write_text(output)
                self.assertEqual(self.qualify(path).returncode, 1, label)
        self.assertEqual(self.qualify(self.samples[200], 7).returncode, 1)

    def test_timed_mixed_transport_report_requires_exact_attempts_and_completion(self):
        mixed = self.samples["mixed-transport"].read_text()
        self.assertIn("99%", mixed)
        self.assertIn("PREFIXD_HEY_COMPLETE 400 END", mixed)
        prefix = mixed.split("Error distribution:\n", 1)[0]
        for label, output in {
            "truncated-before-errors": prefix,
            "hidden-errors-with-completion": prefix + "PREFIXD_HEY_COMPLETE 400 END\n",
        }.items():
            with self.subTest(label=label):
                path = self.receipts / f"control-{label}.log"
                path.write_text(output)
                self.assertEqual(self.qualify(path).returncode, 1)

    def test_report_sampling_limit_cannot_qualify_an_unobserved_tail(self):
        success = self.fast_success.read_text()
        zero_histogram = re.sub(r"(?m)^(\s+[0-9.]+\s+)\[[0-9]+\]", r"\g<1>[0]", success)
        for count in (999999, 1000000):
            with self.subTest(count=count):
                output = zero_histogram.replace("[0]", f"[{count}]", 1)
                output = re.sub(r"(\[200\]\s+)100 responses", rf"\g<1>{count} responses", output)
                output = output.replace(
                    "PREFIXD_HEY_COMPLETE 100 END", f"PREFIXD_HEY_COMPLETE {count} END"
                )
                path = self.receipts / f"control-report-limit-{count}.log"
                path.write_text(output)
                self.assertEqual(self.qualify(path).returncode, 0 if count < 1000000 else 1)

    def test_foreground_command_failure_retains_raw_output_and_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            result = self.shell(
                "RESULTS_DIR=$2; fixture=$3\n"
                'hey() { [[ "$1" == -disable-redirects ]] || return 99; cat "$fixture"; return 7; }\n'
                "if run_hey failed-command 0; then exit 9; fi\n"
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

    def test_fixed_request_burst_requires_every_requested_response(self):
        self.assertEqual(self.qualify(self.fast_success, expected=100).returncode, 0)
        self.assertEqual(self.qualify(self.fast_success, expected=200).returncode, 1)
        for requested in (100, 200):
            with self.subTest(requested=requested), tempfile.TemporaryDirectory() as directory:
                result = self.shell(
                    "RESULTS_DIR=$2; WORK_DIR=$2; fixture=$3\n"
                    'hey() { cat "$fixture"; }\n'
                    'test_burst "$4" 1\nprintf "FAILURES=%s\\n" "$FAIL"',
                    directory,
                    self.fast_success,
                    requested,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"FAILURES={0 if requested == 100 else 1}", result.stdout)

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
        for mode in ("immediate", "ignore-term"):
            with self.subTest(mode=mode):
                self.check_failed_workload_cleanup(mode)

    def reap_owned_shell(self, process, pid_file):
        # Keep Bash alive to reap its child even when the regression fails.
        if pid_file.exists():
            pid = int(pid_file.read_text())
            with suppress(ProcessLookupError):
                if os.getpgid(pid) == process.pid:
                    os.kill(pid, signal.SIGKILL)
        if process.poll() is None:
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                with suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)

    def test_signals_preserve_foreground_status_and_reap_owned_load(self):
        for sig in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=sig.name):
                root = self.receipts / sig.name
                root.mkdir()
                ready = root / "ready"
                parent_ready = root / "parent-ready"
                os.mkfifo(ready)
                os.mkfifo(parent_ready)
                descriptor = os.open(ready, os.O_RDONLY | os.O_NONBLOCK)
                parent_descriptor = os.open(parent_ready, os.O_RDONLY | os.O_NONBLOCK)
                with (root / "parent.log").open("w") as log:
                    process = subprocess.Popen(
                        [
                            "bash",
                            "-c",
                            'source "$1"\nfixture_root=$2; export TMPDIR=$2\n'
                            "curl() { echo '{\"total_events\":1}'; }\n"
                            "hey() {\n"
                            '  trap "" TERM INT\n'
                            '  printf "%s\\n" "$BASHPID" > "$fixture_root/child.pid"\n'
                            '  printf "partial workload\\n"\n'
                            '  printf "ready\\n" > "$fixture_root/ready"\n'
                            "  exec sleep 60\n}\n"
                            "wait() {\n"
                            '  if [[ ! -f "$fixture_root/parent-wait.pid" ]]; then\n'
                            '    printf "%s\\n" "$1" > "$fixture_root/parent-wait.pid"\n'
                            '    printf "ready\\n" > "$fixture_root/parent-ready"\n'
                            '  fi\n  builtin wait "$@"\n}\nmain quick',
                            "load-selftest",
                            str(SCRIPT),
                            str(root),
                        ],
                        cwd=ROOT,
                        start_new_session=True,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                    )
                    try:
                        readable, _, _ = select.select([descriptor], [], [], 10)
                        self.assertTrue(readable, "owned foreground did not become ready")
                        self.assertEqual(os.read(descriptor, 6), b"ready\n")
                        readable, _, _ = select.select([parent_descriptor], [], [], 10)
                        self.assertTrue(readable, "parent did not wait for registered child")
                        self.assertEqual(os.read(parent_descriptor, 6), b"ready\n")
                        self.assertEqual(
                            (root / "parent-wait.pid").read_text(),
                            (root / "child.pid").read_text(),
                        )
                        os.kill(process.pid, sig)
                        self.assertEqual(process.wait(timeout=10), 128 + sig)
                    finally:
                        if process.poll() is None:
                            with suppress(ProcessLookupError):
                                os.kill(process.pid, signal.SIGTERM)
                        self.reap_owned_shell(process, root / "child.pid")
                        os.close(descriptor)
                        os.close(parent_descriptor)
                        ready.unlink()
                        parent_ready.unlink()
                        (root / "parent.exit").write_text(f"{process.returncode}\n")
                (result_dir,) = root.glob("prefixd-load-results-*")
                output = result_dir / "01-health.log"
                self.assertEqual(output.read_text(), "partial workload\n")
                self.assertEqual(output.with_suffix(".exit").read_text(), "137\n")
                self.assertEqual(self.qualify(output, 137).returncode, 1)
                self.assertFalse(list(root.glob("prefixd-load-body-*")))
                with self.assertRaises(ProcessLookupError):
                    os.kill(int((root / "child.pid").read_text()), 0)

    def test_signals_during_foreground_and_background_registration_are_deferred(self):
        for role in ("FG_PID", "BG_PID"):
            for sig in (signal.SIGTERM, signal.SIGINT):
                with self.subTest(role=role, signal=sig.name):
                    root = self.receipts / f"register-{role}-{sig.name}"
                    root.mkdir()
                    with (root / "parent.log").open("w") as log:
                        process = subprocess.Popen(
                            [
                                "bash",
                                "-c",
                                'source "$1"\nRESULTS_DIR=$2; WORK_DIR=$2/body\n'
                                'mkdir "$WORK_DIR"\nfixture_root=$2; pid_role=$3; probe_signal=$4\n'
                                "trap cleanup EXIT\ntrap 'handle_signal 143' TERM\n"
                                "trap 'handle_signal 130' INT\n"
                                'hey() { trap "" TERM INT; exec sleep 60; }\n'
                                'if [[ "$pid_role" == FG_PID ]]; then\n'
                                "  probe_receipt=$2/01-health.exit\n"
                                "else probe_receipt=$2/01-metrics-ingestion.exit; fi\n"
                                "printf() {\n"
                                '  if [[ "$1" == -v && "$2" == "$pid_role" ]]; then\n'
                                "    probe_child=$4\n"
                                '    builtin printf "%s\\n" "$probe_child" > "$fixture_root/child.pid"\n'
                                # The harness still reaps the child if deferred exit regresses.
                                '    trap \'cleanup; if [[ ! -f "$probe_receipt" ]]; then '
                                'kill -KILL "$probe_child" 2>/dev/null || true; '
                                'builtin wait "$probe_child" 2>/dev/null || true; fi\' EXIT\n'
                                '    kill -s "$probe_signal" "$BASHPID"\n'
                                '  fi\n  builtin printf "$@"\n}\n'
                                'if [[ "$pid_role" == FG_PID ]]; then test_health_throughput 4 1\n'
                                "else test_metrics_under_load 4; fi",
                                "load-selftest",
                                str(SCRIPT),
                                str(root),
                                role,
                                sig.name,
                            ],
                            cwd=ROOT,
                            start_new_session=True,
                            stdout=log,
                            stderr=subprocess.STDOUT,
                        )
                        try:
                            self.assertEqual(process.wait(timeout=10), 128 + sig)
                        finally:
                            self.reap_owned_shell(process, root / "child.pid")
                            (root / "parent.exit").write_text(f"{process.returncode}\n")
                    output = root / (
                        "01-health.log" if role == "FG_PID" else "01-metrics-ingestion.log"
                    )
                    self.assertTrue(output.exists())
                    self.assertEqual(output.with_suffix(".exit").read_text(), "137\n")
                    self.assertEqual(self.qualify(output, 137).returncode, 1)
                    self.assertFalse((root / "body").exists())
                    with self.assertRaises(ProcessLookupError):
                        os.kill(int((root / "child.pid").read_text()), 0)

    def check_failed_workload_cleanup(self, mode):
        root = self.receipts / f"cleanup-{mode}"
        root.mkdir()
        work = root / "body"
        work.mkdir()
        (work / "request.json").write_text("temporary")
        ready = root / "ready"
        if mode == "ignore-term":
            os.mkfifo(ready)
        pid_file = root / "pid"
        with (root / "parent.log").open("w") as log:
            process = subprocess.Popen(
                [
                    "bash",
                    "-c",
                    'source "$1"\n'
                    "RESULTS_DIR=$2; WORK_DIR=$2/body; BG_OUTPUT=$2/background.log\n"
                    'trap cleanup EXIT\n: > "$BG_OUTPUT"\n'
                    'if [[ "$3" == ignore-term ]]; then\n'
                    '  (trap "" TERM; printf "partial workload\\n"; '
                    'printf "ready\\n" > "$2/ready"; exec sleep 60) '
                    '> "$BG_OUTPUT" 2>&1 &\n'
                    'else sleep 60 > "$BG_OUTPUT" 2>&1 & fi\n'
                    'BG_PID=$!\nprintf "%s\\n" "$BG_PID" > "$2/pid"\n'
                    'if [[ "$3" == ignore-term ]]; then\n'
                    '  read -r ready < "$2/ready"\n'
                    '  kill -TERM "$BG_PID"\n  kill -0 "$BG_PID"\n'
                    '  printf "survived TERM\\n" > "$2/term-survived"\nfi\nexit 1',
                    "load-selftest",
                    str(SCRIPT),
                    str(root),
                    mode,
                ],
                cwd=ROOT,
                start_new_session=True,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            (root / "parent.pid").write_text(f"{process.pid}\n")
            try:
                self.assertEqual(process.wait(timeout=10), 1)
            finally:
                self.reap_owned_shell(process, pid_file)
                ready.unlink(missing_ok=True)
                (root / "parent.exit").write_text(f"{process.returncode}\n")
        self.assertFalse(work.exists())
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)
        self.assertTrue((root / "background.log").exists())
        status = int((root / "background.exit").read_text())
        self.assertEqual(status, 137)
        self.assertEqual(self.qualify(root / "background.log", status).returncode, 1)
        if mode == "ignore-term":
            self.assertEqual((root / "term-survived").read_text(), "survived TERM\n")
            self.assertEqual((root / "background.log").read_text(), "partial workload\n")

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
