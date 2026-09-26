# SentinelGuard v3 — always-on Windows endpoint agent

This version adds a defensive Windows agent that sends selected telemetry to the SentinelGuard server.

## Run the server

```powershell
pip install -r requirements.txt
$env:SENTINEL_API_KEY='replace-with-a-long-random-secret'
uvicorn app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000

## Run the endpoint agent

In another PowerShell:

```powershell
pip install -r agent_requirements.txt
$env:SENTINEL_SERVER_URL='http://127.0.0.1:8000'
$env:SENTINEL_API_KEY='replace-with-the-same-secret'
python agent.py
```

The agent reports:
- heartbeat
- process-start changes (names/PIDs)
- listening TCP endpoints
- Windows Security logon event IDs 4624/4625 when pywin32 can read the log

It does not collect passwords, keystrokes, file contents, or arbitrary commands.

## Always-on Windows startup

First test `python agent.py` manually. Then run PowerShell as Administrator:

```powershell
.\install_task.ps1
```

This creates a Windows Scheduled Task that starts at boot and restarts the agent if it exits.

## Remote server

For a remote server, set `SENTINEL_SERVER_URL` to your HTTPS server URL and use a strong API key. Do not expose the dashboard or API directly to the public internet without authentication, TLS, firewall restrictions, and rate limiting.

## Production upgrades

Use a real database, persistent event IDs/checkpoints for Windows logs, HTTPS with certificate validation, secret management, RBAC, signed audit logs, and an analyst approval gate before any disruptive action.
