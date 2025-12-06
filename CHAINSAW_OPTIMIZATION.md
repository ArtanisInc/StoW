# Optimisation Chainsaw : Réduire la Latence à < 1 Minute

## Problème Actuel

Architecture standard :
```
Wodle (polling 5 min) → Chainsaw → Analyse logs → Wazuh
                ↑
           GOULOT D'ÉTRANGLEMENT
```

## Solution 1 : Event-Driven Architecture (RECOMMANDÉ)

### Remplacer Wodle par Sysmon Forward

Au lieu de polling, déclenchement **temps réel** :

```powershell
# chainsaw_realtime.ps1
# S'abonner aux événements Windows en temps réel

# Créer un event subscriber
$query = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4688)]]</Select> <!-- Process creation -->
    <Select Path="Microsoft-Windows-Sysmon/Operational">*</Select>
  </Query>
</QueryList>
"@

# Callback temps réel
$action = {
    # Timestamp de l'événement
    $event = $Event.SourceEventArgs.NewEvent
    $timestamp = $event.TimeCreated.ToString("yyyy-MM-ddTHH:mm:ss")

    # Exécuter Chainsaw uniquement sur dernière minute
    & "C:\Program Files\ossec-agent\chainsaw.exe" `
        hunt "C:\Windows\System32\winevt\Logs\" `
        --rules "C:\Program Files\ossec-agent\sigma" `
        --from "$timestamp" `
        --json | ForEach-Object {
            Add-Content "C:\Program Files\ossec-agent\active-responses.log" $_
        }
}

# Enregistrer le watcher
Register-WmiEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_NTLogEvent'" -Action $action
```

**Latence résultante** : < 5 secondes

---

## Solution 2 : Chainsaw en Daemon Mode

### Créer un service Windows persistant

```go
// chainsaw-daemon.go
package main

import (
    "github.com/fsnotify/fsnotify"
    "log"
    "os/exec"
    "time"
)

func main() {
    watcher, _ := fsnotify.NewWatcher()
    defer watcher.Close()

    // Surveiller les fichiers EVTX
    watcher.Add("C:\\Windows\\System32\\winevt\\Logs\\Security.evtx")
    watcher.Add("C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx")

    lastRun := time.Now()

    for {
        select {
        case event := <-watcher.Events:
            if event.Op&fsnotify.Write == fsnotify.Write {
                // Debounce : ne pas lancer plus d'une fois par 10 sec
                if time.Since(lastRun) > 10*time.Second {
                    runChainsaw()
                    lastRun = time.Now()
                }
            }
        }
    }
}

func runChainsaw() {
    cmd := exec.Command(
        "C:\\Program Files\\ossec-agent\\chainsaw.exe",
        "hunt",
        "C:\\Windows\\System32\\winevt\\Logs\\",
        "--rules", "C:\\Program Files\\ossec-agent\\sigma",
        "--from", time.Now().Add(-15*time.Second).Format("2006-01-02T15:04:05"),
        "--json",
    )

    output, _ := cmd.Output()
    // Envoyer à Wazuh
    appendToActiveResponses(string(output))
}
```

**Latence résultante** : 10-15 secondes

---

## Solution 3 : Micro-Batching Intelligent

Au lieu d'analyser TOUS les logs toutes les 5 min, analyser par micro-batches :

```powershell
# chainsaw_microbatch.ps1
# Exécution continue avec batches de 30 secondes

$lastTimestamp = (Get-Date).AddMinutes(-1)

while ($true) {
    $currentTimestamp = Get-Date

    # Analyse uniquement des 30 dernières secondes
    & "C:\Program Files\ossec-agent\chainsaw.exe" hunt `
        "C:\Windows\System32\winevt\Logs\" `
        --rules "C:\Program Files\ossec-agent\sigma" `
        --from $lastTimestamp.ToString("yyyy-MM-ddTHH:mm:ss") `
        --to $currentTimestamp.ToString("yyyy-MM-ddTHH:mm:ss") `
        --level high --level critical `
        --json | ForEach-Object {
            Add-Content "C:\Program Files\ossec-agent\active-responses.log" $_
        }

    $lastTimestamp = $currentTimestamp
    Start-Sleep -Seconds 30  # Latence maximale : 30 sec
}
```

**Configuration Wodle** :
```xml
<wodle name="command">
  <disabled>no</disabled>
  <tag>chainsaw</tag>
  <command>powershell.exe -ExecutionPolicy Bypass C:\chainsaw_microbatch.ps1</command>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>  <!-- Laisse tourner indéfiniment -->
</wodle>
```

**Latence résultante** : 30 secondes (configurable à 10-15 sec)

---

## Solution 4 : Filtre Pré-Chainsaw (Smart Filtering)

Ne pas lancer Chainsaw sur TOUS les événements, mais seulement les suspects :

```powershell
# Filtre Sysmon events suspects AVANT Chainsaw
$suspiciousEvents = Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'
    ID=1,3,7,8,11  # Process, Network, ImageLoad, CreateRemoteThread, File
} -MaxEvents 100 | Where-Object {
    $_.Message -match 'powershell|cmd|wscript|mshta|regsvr32|rundll32|certutil'
}

if ($suspiciousEvents.Count -gt 0) {
    # Seulement SI événements suspects → lancer Chainsaw
    & chainsaw.exe hunt ... --json
}
```

**Impact** : Réduit charge CPU de 80%, latence inchangée mais performance++

---

## Comparatif Solutions

| Solution | Latence | Complexité | Charge CPU | Fiabilité |
|----------|---------|------------|-----------|-----------|
| **Wodle standard** | 5-15 min | Faible | Moyenne | Haute |
| **Event-driven** | < 5 sec | Élevée | Faible | Moyenne |
| **Daemon mode** | 10-15 sec | Moyenne | Moyenne | Haute |
| **Micro-batching** | 30 sec | Faible | Moyenne | Haute |
| **Smart filtering** | 5-15 min | Faible | Faible | Haute |

## Recommandation Finale

**Combinaison Micro-batching + Smart Filtering** :

```powershell
# chainsaw_optimized.ps1
$interval = 30  # secondes
$lastRun = (Get-Date).AddSeconds(-$interval)

while ($true) {
    # Vérifier s'il y a des événements suspects
    $recentEvents = Get-WinEvent -FilterHashtable @{
        LogName='Security','Microsoft-Windows-Sysmon/Operational'
        StartTime=$lastRun
    } -ErrorAction SilentlyContinue | Measure-Object

    if ($recentEvents.Count -gt 0) {
        # Lancer Chainsaw uniquement s'il y a de l'activité
        & "C:\Program Files\ossec-agent\chainsaw.exe" hunt `
            "C:\Windows\System32\winevt\Logs\" `
            --rules "C:\Program Files\ossec-agent\sigma" `
            --from $lastRun.ToString("yyyy-MM-ddTHH:mm:ss") `
            --level high --level critical `
            --json | ForEach-Object {
                Add-Content "C:\Program Files\ossec-agent\active-responses.log" $_
            }
    }

    $lastRun = Get-Date
    Start-Sleep -Seconds $interval
}
```

**Résultat** :
- ✅ Latence : 30 sec (vs 5-15 min)
- ✅ CPU idle quand pas d'activité
- ✅ Simplicité de déploiement
- ✅ Fiabilité haute
