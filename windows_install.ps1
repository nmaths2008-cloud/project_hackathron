# Run PowerShell as Administrator from this directory.
$Server = 'http://127.0.0.1:8000'
$ApiKey = 'REPLACE_WITH_A_LONG_RANDOM_SECRET'
[Environment]::SetEnvironmentVariable('SENTINEL_SERVER_URL',$Server,'Machine')
[Environment]::SetEnvironmentVariable('SENTINEL_API_KEY',$ApiKey,'Machine')
[Environment]::SetEnvironmentVariable('SENTINEL_INTERVAL','15','Machine')
python -m pip install -r agent_requirements.txt
Write-Host 'Configured. Test first with: python agent.py'
