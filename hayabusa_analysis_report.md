# Analyse approfondie: sigma-to-hayabusa-converter vs StoW

## Résumé exécutif

Yamato Security's sigma-to-hayabusa-converter est un convertisseur Sigma mature (714 lignes Python) avec une excellente compréhension de Sigma. Cette analyse identifie les bonnes pratiques applicables à StoW pour Wazuh.

---

## 1. Architecture et bonnes pratiques de Hayabusa

### 1.1 Structure des mappings (YAML)

**Hayabusa utilise 3 fichiers YAML séparés:**

1. **services-mapping.yaml** (274 lignes)
   - Maps: `product + service → channel + conditions`
   - 50+ services Windows mappés
   - Gère les multi-channels (AppLocker, PowerShell, etc.)

2. **sysmon-category-mapping.yaml** (240 lignes)
   - Maps: `category → EventID + rewrite service`
   - Tous les événements Sysmon 1-29 + 255
   - file_delete map à DEUX EventIDs (23 ET 26)

3. **builtin-category-mapping.yaml** (104 lignes)
   - Maps: `category → EventID pour Security/WMI/Defender`
   - Alternative aux règles Sysmon (Event 4688 vs Event 1)
   - **INCLUT field mappings** pour transformations

**✅ Bonne pratique:** Séparation claire des responsabilités

**StoW:** Tout dans config.yaml (ProductServiceToWazuhId, CategoryToWazuhId)
- Plus simple mais moins modulaire
- Pas de field mappings

### 1.2 Services Windows mappés

**Comparaison des services:**

| Service | Hayabusa | StoW | Statut |
|---------|----------|------|--------|
| driver-framework | ✅ | ✅ | OK |
| codeintegrity-operational | ✅ | ✅ | OK |
| firewall-as | ✅ | ✅ | OK |
| bits-client | ✅ | ✅ | OK |
| dns-client | ✅ | ✅ | OK |
| ntlm | ✅ | ✅ | OK |
| taskscheduler | ✅ | ✅ | OK |
| dns-server | ✅ | ✅ | OK |
| dns-server-analytic | ✅ | ✅ | OK |
| ldap_debug | ✅ | ✅ | OK |
| lsa-server | ✅ | ✅ | OK |
| terminalservices-localsessionmanager | ✅ | ✅ | OK |
| smbclient-security | ✅ | ✅ | OK |
| smbclient-connectivity | ✅ | ✅ | OK |
| applocker | ✅ | ✅ | OK |
| security-mitigations | ✅ | ✅ | OK |
| **dhcp** | ✅ | ❌ | **MANQUANT** |
| **printservice-admin** | ✅ | ❌ | **MANQUANT** |
| **printservice-operational** | ✅ | ❌ | **MANQUANT** |
| **wmi** | ✅ | ❌ | **MANQUANT** |
| **diagnosis-scripted** | ✅ | ❌ | **MANQUANT** |
| **shell-core** | ✅ | ❌ | **MANQUANT** |
| **openssh** | ✅ | ❌ | **MANQUANT** |
| **vhdmp** | ✅ | ❌ | **MANQUANT** |
| **appxdeployment-server** | ✅ | ❌ | **MANQUANT** |
| **appxpackaging-om** | ✅ | ❌ | **MANQUANT** |
| **appmodel-runtime** | ✅ | ❌ | **MANQUANT** |
| **capi2** | ✅ | ❌ | **MANQUANT** |
| **certificateservicesclient-lifecycle-system** | ✅ | ❌ | **MANQUANT** |
| **kernel-shimengine** | ✅ | ❌ | **MANQUANT** |
| **application-experience** | ✅ | ❌ | **MANQUANT** |
| **ntfs** | ✅ | ❌ | **MANQUANT** |
| **hyper-v-worker** | ✅ | ❌ | **MANQUANT** |
| **kernel-event-tracing** | ✅ | ❌ | **MANQUANT** |

**Total:** 16 services manquants dans StoW (mais probablement peu/pas de règles Sigma pour certains)

---

## 2. Transformations de champs et valeurs

### 2.1 Field Name Transformations

**Hayabusa transforme les noms de champs Sigma → Windows natifs:**

**Exemple: process_creation avec Security (Event 4688)**
```yaml
fieldmappings_process:
    Image: NewProcessName         # Sigma → Windows Security
    ProcessId: NewProcessId
    ParentImage: ParentProcessName
    ParentProcessId: ProcessId
    LogonId: SubjectLogonId
    IntegrityLevel: MandatoryLabel
    User: SubjectUserName
```

**Exemple: registry_event avec Security (Event 4657)**
```yaml
fieldmappings_registry:
    Image: ProcessName
    User: SubjectUserName
    Details: NewValue
    EventType: OperationType
    TargetObject: ObjectName
```

**Exemple: network_connection avec Security (Event 5156)**
```yaml
fieldmappings_network:
    Image: Application
    Initiated: Direction
    SourceIp: SourceAddress
    DestinationIp: DestAddress
    DestinationPort: DestPort
```

**⚠️ StoW ne fait PAS ces transformations!**

**Pourquoi c'est important:**
- Sigma utilise des field names génériques (`Image`, `User`, etc.)
- Windows a des noms différents selon le channel (Sysmon vs Security)
- Sans transformation, les règles ne matcheront jamais!

**Impact sur StoW:**
- StoW suppose que Wazuh utilise TOUJOURS les field names Sysmon
- Cela fonctionne car StoW cible principalement Sysmon
- Mais si on veut supporter Security channel (Event 4688), il faudrait des transformations

### 2.2 Value Transformations

**Hayabusa transforme certaines valeurs pour matcher le format Windows:**

```python
# IntegrityLevel: Sigma utilise des strings, Windows utilise des SIDs
INTEGRITY_LEVEL_VALUES = {
    "LOW": "S-1-16-4096",
    "MEDIUM": "S-1-16-8192",
    "HIGH": "S-1-16-12288",
    "SYSTEM": "S-1-16-16384"
}

# OperationType: Windows utilise des message IDs
OPERATION_TYPE_VALUES = {
    "CreateKey": "%%1904",
    "SetValue": "%%1905",
    "DeleteValue": "%%1906",
    "RenameKey": "%%1905"
}

# Connection Direction
CONNECTION_INITIATED_VALUES = {
    "true": "%%14593",
    "false": "%%14592"
}

# Protocol names → numbers
CONNECTION_PROTOCOL_VALUES = {
    "tcp": "6",
    "udp": "17"
}
```

**⚠️ StoW ne fait PAS ces transformations!**

**Pourquoi c'est important:**
- Les règles Sigma utilisent des valeurs human-readable
- Windows logs contiennent les vraies valeurs (SIDs, message IDs, etc.)
- Sans transformation, les conditions ne matcheront jamais!

**Impact sur StoW:**
- Actuellement OK car Sysmon utilise des valeurs human-readable
- Mais problème si on veut supporter Security/WMI/autres channels

### 2.3 User Domain Splitting

**Hayabusa sépare automatiquement DOMAIN\Username:**

```python
if k == "SubjectUserName":
    obj[k] = re.sub(r".*\\", "", v)              # Username seulement
    obj["SubjectDomainName"] = re.sub(r"\\.*", "", v)  # Domain seulement
```

**Exemple:**
- Sigma: `User: "DOMAIN\Administrator"`
- Windows: Deux champs séparés:
  - `SubjectUserName: "Administrator"`
  - `SubjectDomainName: "DOMAIN"`

**⚠️ StoW ne fait PAS cette séparation!**

---

## 3. Gestion des événements Sysmon

### 3.1 Événements récents Sysmon

**Hayabusa supporte des événements Sysmon très récents:**

| Event ID | Category | StoW Support |
|----------|----------|--------------|
| 27 | file_block_executable | ❌ Non |
| 28 | file_block_shredding | ❌ Non |
| 29 | file_executable_detected | ❌ Non (mappé mais Event 26 désactivé) |
| 255 | sysmon_error | ❌ Non |

**Note:** Events 27-29 sont Sysmon 15.0+ (2024)

### 3.2 file_delete mapping

**Hayabusa map file_delete à DEUX EventIDs:**
```yaml
file_delete:
    category: file_delete
    conditions:
        EventID:
            - 23  # FileDelete (archives le fichier)
            - 26  # FileDeleteDetected (pas d'archivage)
```

**StoW:**
- Event 23 désactivé (problème de stockage 400GB+)
- Event 26 mappé via `file_delete_detected`
- Mais `file_delete` category ne map PAS à Event 26!

**🔧 Recommandation:** StoW devrait mapper `file_delete` → Event 26 uniquement (comme fait actuellement avec `file_delete_detected`)

---

## 4. Validation et field lists

### 4.1 Field lists pour validation

**Hayabusa définit des listes exhaustives de champs valides:**

```python
WINDOWS_SYSMON_PROCESS_CREATION_FIELDS = [
    "RuleName", "UtcTime", "ProcessGuid", "ProcessId",
    "Image", "FileVersion", "Description", "Product",
    "Company", "OriginalFileName", "CommandLine",
    "CurrentDirectory", "User", "LogonGuid", "LogonId",
    "TerminalSessionId", "IntegrityLevel", "Hashes",
    "ParentProcessGuid", "ParentProcessId", "ParentImage",
    "ParentCommandLine", "ParentUser"
]

WINDOWS_SECURITY_PROCESS_CREATION_FIELDS = [
    "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
    "SubjectLogonId", "NewProcessId", "NewProcessName",
    "TokenElevationType", "ProcessId", "CommandLine",
    "TargetUserSid", "TargetUserName", "TargetDomainName",
    "TargetLogonId", "ParentProcessName", "MandatoryLabel"
]
```

**Usage:** Valider que les règles Sigma n'utilisent que des champs existants

**⚠️ StoW n'a PAS de validation de champs!**

**🔧 Recommandation:** Ajouter une validation optionnelle avec warning pour les champs inconnus

---

## 5. Ignore list

**Hayabusa maintient une liste de règles Sigma à ignorer:**

`ignore-uuid-list.txt` - Liste d'UUIDs de règles problématiques/incompatibles

**Raisons possibles:**
- Règles utilisant des features Sigma non supportées
- Règles avec des patterns trop complexes
- Règles causant des faux positifs sur Hayabusa

**StoW:** Pas de mécanisme d'ignore list (convertit toutes les règles)

**🔧 Recommandation:** Ajouter un fichier `ignore-sigma-rules.txt` avec UUIDs à exclure

---

## 6. Différences Hayabusa vs Wazuh (limitations)

### 6.1 Architecture fondamentale

| Aspect | Hayabusa | Wazuh | Impact sur StoW |
|--------|----------|-------|-----------------|
| **Engine** | YAML detection rules | XML rules with parent dependencies | StoW doit gérer la hiérarchie parent/child |
| **Field matching** | Direct field access | Via decoders (win.eventdata.*) | StoW doit préfixer les champs |
| **Regex** | Native regex | PCRE2 | StoW doit convertir la syntaxe |
| **Conditions** | Complex boolean logic | if_sid + field matching | StoW doit simplifier/split les règles |
| **Field transforms** | Can transform field names/values | No transformations | StoW doit générer des champs "as-is" |

### 6.2 Ce que Hayabusa PEUT faire mais pas Wazuh

1. **Field name transformations à la volée**
   - Hayabusa: Peut mapper `Image` → `NewProcessName` dynamiquement
   - Wazuh: Les champs sont fixes (décodés par le decoder)
   - **Conclusion:** StoW ne PEUT PAS faire ces transformations (limitation Wazuh)

2. **Value transformations dynamiques**
   - Hayabusa: Peut convertir `"LOW"` → `"S-1-16-4096"`
   - Wazuh: Doit matcher la valeur exacte du log
   - **Conclusion:** StoW ne PEUT PAS faire ces transformations
   - **Mais:** Si Sysmon log déjà avec les bonnes valeurs, pas de problème

3. **Complex boolean logic**
   - Hayabusa: Sigma conditions directement (AND, OR, NOT, nested)
   - Wazuh: if_sid + field matching (limité)
   - **Conclusion:** StoW doit parfois créer plusieurs règles pour une règle Sigma complexe

### 6.3 Ce que StoW fait bien (mieux que Hayabusa)

1. **Parent rule hierarchy**
   - StoW génère automatiquement des parent rules multi-niveaux
   - Hayabusa n'a pas besoin (détection directe)
   - **Avantage:** Organisation claire, réutilisation

2. **CDB lists pour large value sets**
   - StoW utilise Wazuh CDB lists (O(1) lookup)
   - Hayabusa doit matcher toutes les valeurs dans la règle
   - **Avantage:** Performance pour listes de 1000+ items

3. **Integration avec l'écosystème Wazuh**
   - Active Response, GeoIP, VirusTotal, etc.
   - Hayabusa est standalone
   - **Avantage:** Enrichissement et réponse automatique

---

## 7. Recommandations pour améliorer StoW

### 7.1 PRIORITÉ HAUTE - Services manquants

**Ajouter les services Windows manquants avec règles Sigma existantes:**

Analyser combien de règles Sigma utilisent ces services:
```bash
grep -r "service: wmi" sigma/rules/windows/builtin/wmi/*.yml | wc -l
grep -r "service: openssh" sigma/rules/windows/builtin/openssh/*.yml | wc -l
# etc.
```

**Si > 5 règles:** créer parent rule + mapping dans config.yaml

**Services probablement importants:**
- `wmi` - WMI attacks (Event 5861)
- `openssh` - SSH on Windows
- `printservice-*` - Print Nightmare, etc.

### 7.2 PRIORITÉ MOYENNE - Validation des champs

**Ajouter field validation optionnelle:**

1. Créer des listes de champs valides par source:
   ```go
   var SysmonProcessCreationFields = []string{
       "Image", "CommandLine", "User", "ParentImage", ...
   }
   ```

2. Option `--validate-fields` pour warning si champ inconnu

3. **Benefit:** Détecte les erreurs dans les règles Sigma

### 7.3 PRIORITÉ BASSE - Ignore list

**Ajouter un mécanisme pour exclure certaines règles:**

1. Fichier `ignore-sigma-uuids.txt`:
   ```
   # Règle avec pattern trop complexe
   abc123-def456-...
   # Règle causant des faux positifs
   xyz789-...
   ```

2. Skip ces règles pendant la conversion

3. **Benefit:** Évite de générer des règles problématiques

### 7.4 NE PAS FAIRE - Field/Value transformations

**❌ Ne PAS implémenter les transformations comme Hayabusa:**

**Raisons:**
1. Wazuh ne peut pas transformer les champs/valeurs à la volée
2. StoW cible principalement Sysmon (qui a déjà les bonnes valeurs)
3. Complexité excessive pour un bénéfice limité
4. Si besoin de Security channel, mieux vaut créer des règles séparées

**Alternative:** Si vraiment nécessaire, créer des decoders Wazuh custom pour transformer les valeurs

---

## 8. Code Quality Comparison

### 8.1 Structure du code

**Hayabusa (Python):**
- 714 lignes, bien organisé
- Classes avec dataclasses
- Type hints partout
- Recursive transformation logic
- Unit tests (test_sigma-to-hayabusa-converter.py)

**StoW (Go):**
- ~2000+ lignes (stow.go + autres fichiers)
- Structs avec XML tags
- Type safety naturel (Go)
- Iterative logic
- Pas de tests unitaires visibles

**🔧 Recommandation:** Ajouter des tests unitaires pour StoW

### 8.2 Configuration management

**Hayabusa:**
- 3 fichiers YAML séparés (services, sysmon-cat, builtin-cat)
- Clair et modulaire
- Facile à maintenir

**StoW:**
- 1 gros fichier config.yaml
- Tout mélangé ensemble
- Plus simple mais moins maintenable

**🔧 Recommandation:** Acceptable pour StoW (plus simple), mais documenter clairement

---

## 9. Conclusions principales

### ✅ Ce que StoW fait BIEN (garder tel quel)

1. **Parent rule hierarchy** - Architecture solide adaptée à Wazuh
2. **CDB lists** - Excellente optimisation pour grandes listes
3. **Service-to-channel mappings corrects** - Alignés avec Hayabusa
4. **Simple config.yaml** - Suffit pour les besoins actuels

### 🔧 Ce que StoW devrait AMÉLIORER

1. **Ajouter services Windows manquants** (wmi, openssh, printservice, etc.)
2. **Field validation optionnelle** (warn sur champs inconnus)
3. **Ignore list** pour règles problématiques
4. **Tests unitaires**

### ❌ Ce que StoW ne devrait PAS faire

1. **Field name transformations** (incompatible avec Wazuh)
2. **Value transformations** (inutile pour Sysmon)
3. **Refactoring majeur** de l'architecture (fonctionne bien)

---

## 10. Actions recommandées (ordre de priorité)

### Immédiat (cette session)
- ✅ Vérifier que tous les services de votre liste officielle sont mappés
- ✅ Créer les parent rules manquants si nécessaire

### Court terme (prochaine version)
1. Analyser combien de règles Sigma utilisent les services manquants
2. Créer parent rules pour les services avec >5 règles
3. Ajouter un fichier `ignore-sigma-uuids.txt` (optionnel)

### Moyen terme
1. Ajouter field validation optionnelle avec warnings
2. Créer des tests unitaires basiques
3. Documentation améliorée avec exemples

### Long terme
1. Support des Sysmon events 27-29 (si adoption large)
2. Métriques de conversion (combien de règles converties/skippées)
3. Validation post-conversion (check XML syntax)

---

## Annexe A: Channels complets de Hayabusa

```yaml
# Tous les services mappés par Hayabusa (50+ services)
application: Application
security: Security
system: System
sysmon: Microsoft-Windows-Sysmon/Operational
powershell: Microsoft-Windows-PowerShell/Operational, PowerShellCore/Operational
powershell-classic: Windows PowerShell
dns-server: DNS Server
dns-server-analytic: Microsoft-Windows-DNS-Server/Analytical
driver-framework: Microsoft-Windows-DriverFrameworks-UserMode/Operational
dhcp: Microsoft-Windows-DHCP-Server/Operational
ntlm: Microsoft-Windows-NTLM/Operational
windefend: Microsoft-Windows-Windows Defender/Operational
printservice-admin: Microsoft-Windows-PrintService/Admin
printservice-operational: Microsoft-Windows-PrintService/Operational
terminalservices-localsessionmanager: Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
smbclient-security: Microsoft-Windows-SmbClient/Security
smbclient-connectivity: Microsoft-Windows-SmbClient/Connectivity
applocker: Microsoft-Windows-AppLocker/* (4 channels)
msexchange-management: MSExchange Management
microsoft-servicebus-client: Microsoft-ServiceBus-Client
ldap_debug: Microsoft-Windows-LDAP-Client/Debug
taskscheduler: Microsoft-Windows-TaskScheduler/Operational
wmi: Microsoft-Windows-WMI-Activity/Operational
codeintegrity-operational: Microsoft-Windows-CodeIntegrity/Operational
firewall-as: Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
bits-client: Microsoft-Windows-Bits-Client/Operational
diagnosis-scripted: Microsoft-Windows-Diagnosis-Scripted/Operational
shell-core: Microsoft-Windows-Shell-Core/Operational
security-mitigations: Microsoft-Windows-Security-Mitigations*
openssh: OpenSSH/Operational
vhdmp: Microsoft-Windows-VHDMP/Operational
appxdeployment-server: Microsoft-Windows-AppXDeploymentServer/Operational
lsa-server: Microsoft-Windows-LSA/Operational
appxpackaging-om: Microsoft-Windows-AppxPackaging/Operational
dns-client: Microsoft-Windows-DNS Client Events/Operational
appmodel-runtime: Microsoft-Windows-AppModel-Runtime/Admin
capi2: Microsoft-Windows-CAPI2/Operational
certificateservicesclient-lifecycle-system: Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational
kernel-shimengine: Microsoft-Windows-Kernel-ShimEngine/Operational, Microsoft-Windows-Kernel-ShimEngine/Diagnostic
application-experience: Microsoft-Windows-Application-Experience/Program-Telemetry, Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant
ntfs: Microsoft-Windows-Ntfs/Operational
hyper-v-worker: Microsoft-Windows-Hyper-V-Worker
kernel-event-tracing: Microsoft-Windows-Kernel-EventTracing
```

---

**Fin du rapport d'analyse**

**Auteur:** Claude Code (analyse du 31 décembre 2025)
**Source:** https://github.com/Yamato-Security/sigma-to-hayabusa-converter
**Version:** Commit latest (31 déc 2025)
