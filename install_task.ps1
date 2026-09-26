# Run PowerShell as Administrator after testing python agent.py manually.
$Project=(Get-Location).Path;$Python=(Get-Command python).Source
$Action=New-ScheduledTaskAction -Execute $Python -Argument "`"$Project\agent.py`"" -WorkingDirectory $Project
$Trigger=New-ScheduledTaskTrigger -AtStartup
$Principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$Settings=New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName 'SentinelGuard Endpoint Agent' -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force
Write-Host 'Always-on task installed.'