# Security and private configuration

## Public source boundary

This is a source-only publication with fresh Git history. It contains selected monitoring and Windows setup scripts, a synthetic example configuration and tests. It contains no real workstation configuration, enrolment tokens, workstation inventory, private setup archives, deployment configuration or operational logs. The public monitoring server origin is intentionally included so the same installer needs only an assigned API key on each PC.

Before publishing, the selected files were reviewed and checked against locally provisioned credentials. Future updates should receive the same review. `.gitignore` helps prevent accidental commits; it is not a substitute for reviewing staged files.

Do not add a real `config.json`, private setup ZIP, API token or screenshot containing credentials to GitHub. Send workstation keys through an approved private channel. The public example cannot authenticate to a server.

The `-ApiKey` parameter accepts a PowerShell `SecureString`. Supply it with `Read-Host -AsSecureString` or an IT credential store, so a literal key does not enter shell history or a process command line. In the double-click workflow, hidden input happens after administrator elevation. The installer creates the private configuration locally; no private file has to be included in the shared source ZIP. Malformed keys, JSON and unsafe configuration are rejected before changing the machine. Error messages do not include the key or private JSON fragments.

## Runtime privileges

The current Windows installer runs with administrator privileges and registers the agent as a continuous `SYSTEM` scheduled task. Installed files and configuration are restricted to `SYSTEM` and Administrators. The task command line contains the configuration path, not its token.

The selected scripts are ordinary source files, without obfuscated or encoded commands. The installer downloads dependencies, copies files and changes directory permissions. IT should inspect these actions before granting approval and use a reviewed source snapshot for deployment. The launcher requests elevation through the standard Windows administrator prompt.

The startup task executes the installed copy of the scripts. It does not download or automatically execute new versions from this public repository. The agent sends monitoring data and does not implement remote command execution, process termination or automatic job scheduling.

## Data and transport

Updates include machine identity, resource usage, uptime, signed-in state and idle duration. Username reporting is optional. Setting `collect_username: false` removes the username from outgoing updates; it does not stop local session checks needed to determine occupancy.

HTTPS is required for deployment. HTTP is supported only for explicitly enabled loopback development. The agent uses normal certificate verification and refuses HTTP redirects so a token is not forwarded to another host. Routine logs omit the payload, usernames and tokens and are limited by rotation.

Each token authenticates one centrally enrolled workstation. The reported Windows device name is metadata, not an authentication secret. Changing a label or matching a device name does not replace authentication. If a private configuration or setup package is exposed, revoke or rotate its token centrally and replace the protected local configuration.

## Review and support

Use the established private IT support channel for security concerns. Avoid posting operational details or credentials publicly. This repository provides source for review; it does not grant access to any deployed monitoring service. On-machine installation, session behaviour, dependency policy and reboot tests remain IT deployment checks.
