"""Run Windows configuration/preflight checks without installing the agent."""

import os
import shutil
import subprocess
import unittest
from pathlib import Path

POWERSHELL = (
    os.environ.get("WORKSTATION_TEST_PWSH")
    or shutil.which("pwsh")
    or shutil.which("powershell.exe")
)
CHECKS = Path(__file__).with_suffix(".ps1")


@unittest.skipUnless(POWERSHELL, "PowerShell is required for configuration/preflight checks")
class WindowsConfigurationTests(unittest.TestCase):
    def test_key_only_installation_and_validation_before_changes(self):
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-NoLogo", "-File", str(CHECKS)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("configuration, credential handling and installer preflight assertions", result.stdout)


if __name__ == "__main__":
    unittest.main()
