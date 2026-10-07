# ORC workstation monitoring scripts

Public source for IT review of a workstation monitoring agent and its Windows installer.

A small background script sends a status update approximately once a minute to a central dashboard. It helps researchers find available shared workstations and understand CPU, RAM and GPU use before choosing a computer for a calculation.

IT can use the same source ZIP on every PC and provide only that workstation's API key. The installer detects the Windows device name and creates the protected configuration locally. The central dashboard/server is managed separately; each key must already be enrolled centrally. Downloading the source does not enrol a computer or grant access to the dashboard.

## What to review

| File | Purpose |
| --- | --- |
| [agent/workstation_agent.py](agent/workstation_agent.py) | Collect readings and send authenticated HTTPS updates. |
| [Install.cmd](Install.cmd) | Windows entry point; launches the setup script. |
| [agent/windows/setup.ps1](agent/windows/setup.ps1) | Locate the private configuration and request administrator elevation. |
| [agent/windows/install.ps1](agent/windows/install.ps1) | Install the agent in a protected folder and register the startup task. |
| [agent/windows/configuration.ps1](agent/windows/configuration.ps1) | Accept a hidden API key, detect the device name and validate settings before installation. |
| [agent/windows/service-management.ps1](agent/windows/service-management.ps1) | Inspect, start, stop or restart the task; view its logs. |
| [agent/windows/uninstall.ps1](agent/windows/uninstall.ps1) | Remove the installed task, agent, configuration and logs. |
| [config.example.json](config.example.json) | Document configuration fields using invalid placeholder credentials. |
| [SECURITY.md](SECURITY.md) | Permissions, network behaviour and handling private configuration. |

## What the agent collects

- Workstation label, actual Windows device name, update time, agent version and uptime.
- Whole-machine CPU and RAM usage through Python's `psutil` library.
- NVIDIA GPU utilisation and memory through `nvidia-smi`, when supported; unavailable readings stay empty.
- Whether an interactive user is signed in and their idle duration, through Windows session APIs. One username is included unless disabled in configuration.

The agent does not collect files, application contents, screenshots, keystrokes, browsing history or command history. Session idle time is a Windows timestamp, not a record of keyboard input. An idle signed-in user does not mean a PC is free for someone else to use.

Key-only installation reports a username by default. Add `-HideUsername` to suppress usernames in outgoing updates. The optional example configuration disables username reporting; existing provisioned configurations have their own setting, which IT should review.

## Administrator permissions

Reading CPU load locally generally does not require administrator access. The installer requires elevation to install machine-wide Python if needed, protect files under `%ProgramData%\StrathclydeWorkstationMonitor`, and register a Windows startup task.

The current task is named `StrathclydeWorkstationMonitor` and runs continuously as `SYSTEM`. It starts at boot, continues after logout and restarts after failure. The agent queries other interactive sessions using `WTSEnumerateSessionsW` and `WTSQuerySessionInformationW`; querying another session requires the appropriate session permissions. See [Microsoft's session API documentation](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw).

IT can install and manage this specific task without granting researchers permanent administrator access. A restricted task account would require a separate configuration change and verification of session visibility and reboot behaviour; it is not provided by this installer.

## Installation by IT

1. Review the scripts, then use **Code > Download ZIP** and extract the entire archive. Reuse the same source files for each PC.
2. Obtain the API key assigned to that workstation through an approved private transfer channel.
3. Open **PowerShell as Administrator** in the extracted folder and run:

```powershell
.\agent\windows\install.ps1 -ApiKey (Read-Host 'Workstation API key' -AsSecureString)
```

Paste that PC's key into the hidden prompt. This is the only required input. The script uses the built-in monitor address and the current Windows device name, installs Python if needed and the pinned dependency, writes protected configuration, and creates the startup task. A per-machine ZIP or pre-created configuration file is not required.

The API key parameter is a PowerShell `SecureString`. This command puts the prompt expression in PowerShell history, rather than the key itself. An IT credential store can also provide a `SecureString`. Do not substitute a literal key into a command, script, ticket or repository.

Alternatively, double-click `Install.cmd`, approve elevation and enter the key when prompted. The key is requested only after elevation; it is not passed through the elevation command line.

4. Wait for **Installed and reporting**. Verify that the intended PC appears in the dashboard, then verify behaviour after logout and a reboot.
5. Delete the transfer ZIP and extracted folder after a successful installation. The installed copy runs from its protected system folder.

An all-users Python 3.10+ is required. IT can provide an approved runtime instead of allowing installation through `winget`. From elevated PowerShell in the extracted folder:

```powershell
.\agent\windows\install.ps1 -ApiKey (Read-Host 'Workstation API key' -AsSecureString) -PythonPath 'C:\Program Files\Python313\python.exe' -HideUsername
```

The shared monitor origin is `https://strathclyde-workstation-monitor.furkantornaci.workers.dev`. This address is public; authentication keys are private. Use `-ApiUrl` to target a different approved HTTPS monitor. The key selects its centrally enrolled record independently of the reported device name. A device name alone cannot authenticate updates.

Previously prepared private configuration files remain supported with `-ConfigPath .\config.json`. For the `Install.cmd` path, place the private configuration beside the launcher. The example configuration is documentation and contains an invalid placeholder key. Malformed keys and invalid settings are rejected before the installer stops an existing task or changes the installation. Enrolment/revocation is verified by the server when the agent reports.

The launcher uses `-ExecutionPolicy Bypass` for its PowerShell process. It does not permanently change execution policy. IT should review this invocation and apply institutional script-signing requirements before installation.

## Network and maintenance

During normal operation the agent sends an outbound HTTPS `POST` to `/api/heartbeat` on the privately configured server. It includes that workstation's token in an Authorization header, verifies HTTPS certificates and refuses redirects. It does not listen on an inbound port or accept remote execution commands.

Installation may use `winget` to obtain Python and `pip` to obtain the dependency. IT can supply an approved Python runtime and dependency source. The runtime pins `psutil` in [agent/requirements.txt](agent/requirements.txt).

From elevated PowerShell, use `agent/windows/service-management.ps1` with `-Action status`, `stop`, `start`, `restart` or `logs`. To remove the installation, run `agent/windows/uninstall.ps1`. Shared Python remains installed. Revoke the workstation token separately in the centrally managed dashboard; the CLI mentioned by the uninstaller belongs to that separate system.

## Verification

The tests use synthetic keys and mocked sessions/network calls. Configuration and installer preflight tests run through a local PowerShell executable without installing software or creating tasks:

```powershell
python -m pip install -r .\agent\requirements.txt
python -m unittest discover -s agent/tests -v
```

The public snapshot has been checked for private credentials and syntax, and its agent and PowerShell configuration/preflight tests have been run. Actual Windows installation, sign-in detection and reboot verification must be completed on an approved test workstation.
