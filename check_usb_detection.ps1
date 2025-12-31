# Script PowerShell pour diagnostiquer la détection USB

Write-Host "=== Diagnostic USB Detection ===" -ForegroundColor Cyan
Write-Host ""

# 1. Vérifier si le channel DriverFrameworks est activé
Write-Host "1. Channel DriverFrameworks status:" -ForegroundColor Yellow
try {
    $log = Get-WinEvent -ListLog "Microsoft-Windows-DriverFrameworks-UserMode/Operational" -ErrorAction Stop
    Write-Host "   Enabled: $($log.IsEnabled)" -ForegroundColor $(if($log.IsEnabled){"Green"}else{"Red"})
    Write-Host "   Log Size: $($log.MaximumSizeInBytes / 1MB) MB"
    Write-Host "   Record Count: $($log.RecordCount)"
} catch {
    Write-Host "   ERROR: Channel not found or accessible" -ForegroundColor Red
}
Write-Host ""

# 2. Vérifier les événements USB récents
Write-Host "2. Recent USB events (EventID 2003, 2100, 2102):" -ForegroundColor Yellow
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
        ID = 2003,2100,2102
    } -MaxEvents 5 -ErrorAction Stop
    
    Write-Host "   Found $($events.Count) recent events" -ForegroundColor Green
    $events | ForEach-Object {
        Write-Host "   - EventID: $($_.Id) | Time: $($_.TimeCreated)" -ForegroundColor White
    }
} catch {
    Write-Host "   No events found (channel may be disabled)" -ForegroundColor Red
}
Write-Host ""

# 3. Vérifier Sysmon
Write-Host "3. Sysmon status:" -ForegroundColor Yellow
$sysmon = Get-Service -Name "Sysmon*" -ErrorAction SilentlyContinue
if ($sysmon) {
    Write-Host "   Sysmon is installed: $($sysmon.Status)" -ForegroundColor Green
} else {
    Write-Host "   Sysmon is NOT installed" -ForegroundColor Red
}
Write-Host ""

# 4. Vérifier Wazuh agent
Write-Host "4. Wazuh agent status:" -ForegroundColor Yellow
$wazuh = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($wazuh) {
    Write-Host "   Wazuh agent: $($wazuh.Status)" -ForegroundColor Green
} else {
    Write-Host "   Wazuh agent: NOT installed" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Recommendations ===" -ForegroundColor Cyan
Write-Host "To enable USB detection:"
Write-Host "1. Enable DriverFrameworks channel:"
Write-Host "   wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true"
Write-Host ""
Write-Host "2. Restart Wazuh agent to pick up new events"
Write-Host "   Restart-Service WazuhSvc"
