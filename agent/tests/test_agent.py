import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    "workstation_agent", Path(__file__).parents[1] / "workstation_agent.py"
)
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class AgentTests(unittest.TestCase):
    def test_sessions_include_disconnected_and_choose_least_idle(self):
        result = agent.select_session(
            [{"username": "console", "idle_seconds": 1000}, {"username": "rdp", "idle_seconds": 20}]
        )
        self.assertEqual(result["username"], "rdp")
        self.assertTrue(result["logged_in"])
        self.assertEqual(
            agent.select_session([{"username": "disconnected", "idle_seconds": 3000}])["logged_in"],
            True,
        )

    def test_unknown_activity_and_failed_detection_are_conservative(self):
        result = agent.select_session(
            [
                {"username": "known", "idle_seconds": 3000},
                {"username": "unknown", "idle_seconds": None},
            ]
        )
        self.assertEqual(result["username"], "unknown")
        self.assertIsNone(result["idle_seconds"])
        self.assertFalse(agent.select_session([], False)["session_detection_ok"])
        self.assertFalse(agent.select_session([])["logged_in"])

    def test_gpu_missing_unsupported_and_multiple(self):
        self.assertIsNone(agent.parse_gpu_output("")["gpu_percent"])
        self.assertEqual(
            agent.parse_gpu_output("90, 4000, 8000\n20, 1000, 8000"),
            {"gpu_percent": 90, "gpu_memory_used_mb": 5000, "gpu_memory_total_mb": 16000},
        )
        self.assertIsNone(agent.parse_gpu_output("N/A, N/A, N/A")["gpu_percent"])
        self.assertIsNone(agent.parse_gpu_output("nan, inf, 100")["gpu_memory_used_mb"])
        with (
            patch.object(agent.shutil, "which", return_value=None),
            patch.object(agent.os, "name", "posix"),
            patch.object(agent.subprocess, "run") as run,
        ):
            self.assertEqual(
                agent.collect_gpu(),
                {"gpu_percent": None, "gpu_memory_used_mb": None, "gpu_memory_total_mb": None},
            )
            run.assert_not_called()

    def test_configuration_and_https_enforcement(self):
        config = {
            "api_url": "https://monitor.example.org",
            "api_token": "a" * 43,
            "hostname": "orc-ws-01",
        }
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "config.json"
            file.write_text(json.dumps(config), encoding="utf8")
            self.assertEqual(agent.load_config(file)["hostname"], "ORC-WS-01")
            for invalid in [
                {"api_url": "http://monitor.example.org", "allow_local_http": True},
                {"api_token": "short"},
                {"hostname": "bad/path"},
                {"heartbeat_seconds": True},
                {"api_url": "https://monitor.example.org/api/heartbeat"},
                {"collect_username": "yes"},
            ]:
                file.write_text(json.dumps({**config, **invalid}), encoding="utf8")
                with self.assertRaises(ValueError):
                    agent.load_config(file)
            file.write_text(
                json.dumps(
                    {**config, "api_url": "http://127.0.0.1:8787", "allow_local_http": True}
                ),
                encoding="utf8",
            )
            self.assertEqual(agent.load_config(file)["api_url"], "http://127.0.0.1:8787")

    def test_username_hidden_at_source_and_no_content_fields(self):
        with (
            patch.object(
                agent,
                "collect_session",
                return_value={
                    "username": "private",
                    "logged_in": True,
                    "idle_seconds": 20,
                    "session_detection_ok": True,
                },
            ),
            patch.object(agent, "collect_gpu", return_value=agent.parse_gpu_output("")),
            patch.object(agent.psutil, "cpu_percent", return_value=10),
            patch.object(agent.psutil, "boot_time", return_value=100),
            patch.object(agent, "collect_system_name", return_value="Actual-Mac"),
        ):
            payload = agent.collect_heartbeat({"hostname": "ORC-01", "collect_username": False})
        self.assertIsNone(payload["username"])
        self.assertEqual(payload["hostname"], "ORC-01")
        self.assertEqual(payload["system_name"], "Actual-Mac")
        self.assertEqual(
            set(payload),
            {
                "hostname",
                "system_name",
                "username",
                "logged_in",
                "session_detection_ok",
                "idle_seconds",
                "cpu_percent",
                "ram_percent",
                "gpu_percent",
                "gpu_memory_used_mb",
                "gpu_memory_total_mb",
                "uptime_seconds",
                "agent_version",
                "timestamp",
            },
        )

    def test_redirects_never_forward_credentials(self):
        self.assertIsNone(
            agent.NoRedirect().redirect_request(None, None, 302, "", {}, "https://attacker.example")
        )

    def test_macos_foreground_idle_and_background_occupancy(self):
        foreground = {
            "kCGSSessionUserNameKey": "console",
            "kCGSSessionUserIDKey": 501,
            "kCGSSessionOnConsoleKey": True,
            "kCGSessionLoginDoneKey": True,
        }
        background = {
            **foreground,
            "kCGSSessionUserNameKey": "switched-out",
            "kCGSSessionOnConsoleKey": False,
        }
        sessions = agent.parse_macos_sessions([foreground, background], 2000)
        result = agent.select_session(sessions)
        self.assertTrue(result["logged_in"])
        self.assertEqual(result["username"], "switched-out")
        self.assertIsNone(result["idle_seconds"])
        self.assertEqual(agent.parse_macos_sessions([foreground], 30)[0]["idle_seconds"], 30)
        self.assertIsNone(
            agent.parse_macos_sessions([{**foreground, "kCGSessionLoginDoneKey": False}], 30)[0][
                "idle_seconds"
            ]
        )
        self.assertEqual(
            agent.parse_macos_sessions(
                [{"kCGSSessionUserNameKey": "loginwindow", "kCGSSessionUserIDKey": 0}], None
            ),
            [],
        )
        with self.assertRaises(ValueError):
            agent.parse_macos_sessions([{}], 10)

    def test_macos_signed_out_ssh_and_failed_inventory(self):
        with (
            patch.object(agent, "read_macos_registry", return_value=[{"IOConsoleUsers": []}]),
            patch.object(agent.psutil, "users", return_value=[]),
        ):
            result = agent.macos_sessions()
        self.assertFalse(result["logged_in"])
        self.assertTrue(result["session_detection_ok"])
        from types import SimpleNamespace

        with (
            patch.object(agent, "read_macos_registry", return_value=[{"IOConsoleUsers": []}]),
            patch.object(
                agent.psutil,
                "users",
                return_value=[SimpleNamespace(name="ssh-user", host="remote")],
            ),
        ):
            result = agent.macos_sessions()
        self.assertTrue(result["logged_in"])
        self.assertIsNone(result["idle_seconds"])
        with (
            patch.object(agent.sys, "platform", "darwin"),
            patch.object(agent.os, "name", "posix"),
            patch.object(agent, "read_macos_registry", return_value=[{}]),
            self.assertLogs(agent.LOG, level="WARNING"),
        ):
            self.assertFalse(agent.collect_session()["session_detection_ok"])

    def test_macos_idle_nanoseconds_and_missing_idle(self):
        entry = {
            "kCGSSessionUserNameKey": "console",
            "kCGSSessionUserIDKey": 501,
            "kCGSSessionOnConsoleKey": True,
            "kCGSessionLoginDoneKey": True,
        }
        with (
            patch.object(
                agent,
                "read_macos_registry",
                side_effect=[[{"IOConsoleUsers": [entry]}], [{"HIDIdleTime": 12_500_000_000}]],
            ),
            patch.object(agent.psutil, "users", return_value=[]),
        ):
            self.assertEqual(agent.macos_sessions()["idle_seconds"], 12)
        with (
            patch.object(
                agent,
                "read_macos_registry",
                side_effect=[[{"IOConsoleUsers": [entry]}], OSError("unavailable")],
            ),
            patch.object(agent.psutil, "users", return_value=[]),
        ):
            result = agent.macos_sessions()
        self.assertTrue(result["logged_in"])
        self.assertIsNone(result["idle_seconds"])

    def test_macos_foreground_username_and_background_occupancy_are_separate(self):
        foreground = {
            "kCGSSessionUserNameKey": "current-user",
            "kCGSSessionUserIDKey": 501,
            "kCGSSessionOnConsoleKey": True,
            "kCGSessionLoginDoneKey": True,
        }
        background = {
            **foreground,
            "kCGSSessionUserNameKey": "background-user",
            "kCGSSessionOnConsoleKey": False,
        }
        with (
            patch.object(
                agent,
                "read_macos_registry",
                side_effect=[
                    [{"IOConsoleUsers": [foreground, background]}],
                    [{"HIDIdleTime": 30_000_000_000}],
                ],
            ),
            patch.object(agent.psutil, "users", return_value=[]),
        ):
            result = agent.macos_sessions()
        self.assertEqual(result["username"], "current-user")
        self.assertTrue(result["logged_in"])
        self.assertIsNone(result["idle_seconds"])

    def test_macos_system_name_and_hostname_fallback(self):
        import subprocess

        with (
            patch.object(agent.sys, "platform", "darwin"),
            patch.object(
                agent.subprocess,
                "run",
                return_value=subprocess.CompletedProcess([], 0, "Actual-Mac\n"),
            ),
        ):
            self.assertEqual(agent.collect_system_name(), "Actual-Mac")
        with (
            patch.object(agent.sys, "platform", "darwin"),
            patch.object(agent.subprocess, "run", side_effect=OSError()),
            patch.object(agent.socket, "gethostname", return_value="Fallback.local"),
        ):
            self.assertEqual(agent.collect_system_name(), "Fallback.local")

    def test_macos_localhost_console_record_does_not_erase_idle(self):
        from types import SimpleNamespace

        entry = {
            "kCGSSessionUserNameKey": "console",
            "kCGSSessionUserIDKey": 501,
            "kCGSSessionOnConsoleKey": True,
            "kCGSessionLoginDoneKey": True,
        }
        with (
            patch.object(
                agent,
                "read_macos_registry",
                side_effect=[[{"IOConsoleUsers": [entry]}], [{"HIDIdleTime": 20_000_000_000}]],
            ),
            patch.object(
                agent.psutil,
                "users",
                return_value=[
                    SimpleNamespace(name="console", terminal="console", host="localhost")
                ],
            ),
        ):
            self.assertEqual(agent.macos_sessions()["idle_seconds"], 20)

    def test_validate_only_never_collects_or_sends(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(
                json.dumps(
                    {
                        "api_url": "https://monitor.example.org",
                        "api_token": "a" * 43,
                        "hostname": "MAC-TEST",
                    }
                )
            )
            with (
                patch.object(
                    agent.sys,
                    "argv",
                    [
                        "agent",
                        "--config",
                        str(config),
                        "--validate-config",
                    ],
                ),
                patch.object(agent, "collect_heartbeat") as collect,
                patch.object(agent, "send_heartbeat") as send,
            ):
                self.assertEqual(agent.main(), 0)
                collect.assert_not_called()
                send.assert_not_called()


if __name__ == "__main__":
    unittest.main()
