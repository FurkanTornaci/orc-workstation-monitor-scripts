# ORC workstation monitoring scripts

Public source for IT review of a workstation monitoring agent and its Windows installer.

A small background script sends a status update approximately once a minute to a central dashboard. It helps researchers find available shared workstations and understand CPU, RAM and GPU use before choosing a computer for a calculation.

This repository contains the agent source and installation scripts. The central dashboard/server is managed separately. The public download contains a placeholder configuration; a private configuration must be supplied before installation. Downloading the source does not enrol a computer or grant access to the dashboard.

## What to review

| File | Purpose |
| --- | --- |
| [agent/workstation_agent.py](agent/workstation_agent.py) | Collect readings and send authenticated HTTPS updates. |
| [Install.cmd](Install.cmd) | Windows entry point; launches the setup script. |
| [agent/windows/setup.ps1](agent/windows/setup.ps1) | Locate the private configuration and request administrator elevation. |
| [agent/windows/install.ps1](agent/windows/install.ps1) | Install the agent in a protected folder and register the startup task. |
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

The example configuration disables username reporting. Provisioned configurations have their own setting, which IT should review. Use `collect_username: false` or the installer's `-HideUsername` option to suppress usernames in outgoing updates.

## Administrator permissions

Reading CPU load locally generally does not require administrator access. The installer requires elevation to install machine-wide Python if needed, protect files under `%ProgramData%\StrathclydeWorkstationMonitor`, and register a Windows startup task.

The current task is named `StrathclydeWorkstationMonitor` and runs continuously as `SYSTEM`. It starts at boot, continues after logout and restarts after failure. The agent queries other interactive sessions using `WTSEnumerateSessionsW` and `WTSQuerySessionInformationW`; querying another session requires the appropriate session permissions. See [Microsoft's session API documentation](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsquerysessioninformationw).

IT can install and manage this specific task without granting researchers permanent administrator access. A restricted task account would require a separate configuration change and verification of session visibility and reboot behaviour; it is not provided by this installer.

## Installation by IT

1. Review the scripts, then use **Code > Download ZIP** and extract the entire archive.
2. Obtain a separate private `config.json` for the intended workstation through an approved private transfer channel. Put it next to `Install.cmd` at the top level of the extracted folder. Do not publish it in this repository. The example file is documentation, not a working credential.
3. Run `Install.cmd` and approve administrator elevation. The script installs Python if required, installs the pinned dependency, protects the installation folder and creates the background task.
4. Wait for **Installed and reporting**. Verify that the intended PC appears in the dashboard, then verify behaviour after logout and a reboot.
5. Delete the transfer ZIP and extracted folder after a successful installation. The installed copy runs from its protected system folder.

An all-users Python 3.10+ is required. IT can provide an approved runtime instead of allowing installation through `winget`. From elevated PowerShell in the extracted folder:

```powershell
.\agent\windows\install.ps1 -ConfigPath .\config.json -PythonPath 'C:\Program Files\Python313\python.exe' -HideUsername
```

The Windows device name is reported automatically. A per-workstation authentication token is still required to authenticate updates; it is already included in a privately prepared configuration, so IT does not need to enter it manually. A device name alone cannot prove who sent an update.

The launcher uses `-ExecutionPolicy Bypass` for its PowerShell process. It does not permanently change execution policy. IT should review this invocation and apply institutional script-signing requirements before installation.

## Network and maintenance

During normal operation the agent sends an outbound HTTPS `POST` to `/api/heartbeat` on the privately configured server. It includes that workstation's token in an Authorization header, verifies HTTPS certificates and refuses redirects. It does not listen on an inbound port or accept remote execution commands.

Installation may use `winget` to obtain Python and `pip` to obtain the dependency. IT can supply an approved Python runtime and dependency source. The runtime pins `psutil` in [agent/requirements.txt](agent/requirements.txt).

From elevated PowerShell, use `agent/windows/service-management.ps1` with `-Action status`, `stop`, `start`, `restart` or `logs`. To remove the installation, run `agent/windows/uninstall.ps1`. Shared Python remains installed. Revoke the workstation token separately in the centrally managed dashboard; the CLI mentioned by the uninstaller belongs to that separate system.

## Verification

The agent unit tests use sample configurations and mocked sessions/network calls:

```powershell
python -m pip install -r .\agent\requirements.txt
python -m unittest discover -s agent/tests -p test_agent.py -v
```

The public snapshot has been checked for private credentials and Python syntax, and its agent unit tests have been run. Actual Windows installation, sign-in detection and reboot verification must be completed on an approved test workstation.
