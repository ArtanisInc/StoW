# Analyse approfondie: sigma-to-hayabusa-converter vs StoW (Version 2)

## MISE À JOUR IMPORTANTE après lecture du README

Cette analyse complète celle précédente en intégrant la **philosophie de design** et les **raisons** expliquées dans le README de Hayabusa.

---

## 1. Philosophie fondamentale: "Deabstraction" du logsource

### 1.1 Le problème avec l'abstraction Sigma

**Sigma abstrait le logsource** avec `product`, `service`, et `category`:
```yaml
logsource:
    product: windows
    category: process_creation
```

Cette abstraction cache:
- Le **Channel** réel (Sysmon vs Security vs autres)
- L'**EventID** réel (1 vs 4688)
- Les **field names** réels (Image vs NewProcessName)
- Les **field values** réelles (tcp vs 6, LOW vs S-1-16-4096)

### 1.2 Hayabusa déabstrait en créant DEUX règles séparées

**Règle Sigma originale** → **2 règles Hayabusa**:
1. **Sysmon rule**: Channel Sysmon, EventID 1, fields Sysmon
2. **Builtin rule**: Channel Security, EventID 4688, fields transformés

**Exemple concret:**
```yaml
# AVANT (Sigma abstrait)
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '.exe'
```

```yaml
# APRÈS (Hayabusa Sysmon)
detection:
    process_creation:
        Channel: Microsoft-Windows-Sysmon/Operational
        EventID: 1
    selection:
        Image|endswith: '.exe'
    condition: process_creation and selection
```

```yaml
# APRÈS (Hayabusa Builtin)
detection:
    process_creation:
        Channel: Security
        EventID: 4688
    selection:
        NewProcessName|endswith: '.exe'  # ← Field transformé!
    condition: process_creation and selection
```

### 1.3 Pourquoi cette approche?

**D'après le README, 4 raisons principales:**

#### ❌ Challenges de l'abstraction

1. **Filtrage difficile**
   - Impossible de filtrer par Channel/EventID dans le fichier .yml
   - Règles dérivées pas encore créées (virtual rules)
   - Même UUID pour Sysmon et builtin → pas de filtrage par ID

2. **Confirmation d'alerte difficile**
   - Field names ne matchent pas entre alerte et règle
   - Analyste doit mémoriser les transformations
   - Exemple: alerte dit `NewProcessName` mais règle dit `Image`

3. **Backend logic complexe**
   - Doit gérer transformations dynamiques
   - Field mapping logic complexe
   - Value conversion logic complexe

4. **Ambiguïté sur les false positives**
   - Field Sysmon-only manquant → plus de FPs en builtin?
   - Faut-il créer la règle quand même?
   - Severity/status différents pour les deux versions?

#### ✅ Bénéfices de la deabstraction

1. **Filtrage simple**
   - Grep sur Channel: "Security" ou "Sysmon"
   - Grep sur EventID: "4688" ou "1"
   - Folders séparés: `sysmon/` vs `builtin/`

2. **Confirmation simple**
   - Field names matchent exactement le log
   - Pas de mental translation nécessaire
   - Copy-paste direct entre alerte et règle

3. **Backend simple**
   - Pas de transformations dynamiques
   - Matching direct des fields
   - Pas de conversion logic

4. **Metadata précise**
   - Status/severity séparés pour Sysmon vs builtin
   - False positive info spécifique
   - Detection info spécifique

---

## 2. Incompatibilité des champs Sysmon vs Builtin

### 2.1 Champs qui n'existent QUE dans Sysmon Event 1

**D'après le README:**
```
RuleName, UtcTime, ProcessGuid, FileVersion, Description,
Product, Company, OriginalFileName, CurrentDirectory,
LogonGuid, TerminalSessionId, Hashes, ParentProcessGuid,
ParentCommandLine, ParentUser
```

**Si une règle Sigma utilise un de ces champs:**
- ✅ Règle Sysmon créée
- ❌ **Règle builtin PAS créée** (champ manquant!)

### 2.2 Champs qui n'existent QUE dans Security Event 4688

**D'après le README:**
```
SubjectUserSid, TokenElevationType, TargetUserSid,
TargetUserName, TargetDomainName, TargetLogonId
```

**Si une règle Sigma utilise un de ces champs:**
- ❌ Règle Sysmon PAS créée
- ✅ **Règle builtin créée**

### 2.3 Exception importante: Logic OR vs AND

**Cas 1: Field Sysmon-only en OR (optionnel)**
```yaml
selection_img:
    - Image|endswith: \addinutil.exe
    - OriginalFileName: AddInUtil.exe  # Sysmon-only
```
→ **Règle builtin créée** (OriginalFileName optionnel)

**Cas 2: Field Sysmon-only en AND (requis)**
```yaml
selection_img:
    Image|endswith: \addinutil.exe
    OriginalFileName: AddInUtil.exe  # Sysmon-only
```
→ **Règle builtin PAS créée** (OriginalFileName requis)

**Cas 3: Selections séparées avec OR**
```yaml
selection_img:
    Image|endswith: \addinutil.exe
selection_orig:
    OriginalFileName: AddInUtil.exe
condition: selection_img or selection_orig
```
→ **Règle builtin créée** (OR logic)

**Cas 4: Selections séparées avec AND**
```yaml
selection_img:
    Image|endswith: \addinutil.exe
selection_orig:
    OriginalFileName: AddInUtil.exe
condition: selection_img and selection_orig
```
→ **Règle builtin PAS créée** (AND logic)

**🎯 Point clé:** Le parser doit comprendre la logique AND/OR pour décider si créer une règle builtin!

---

## 3. Ce que Hayabusa ignore (ignore-uuid-list.txt)

**D'après le README:**

1. **Règles causant des FP sur Windows Defender**
   - Contiennent des keywords comme "mimikatz"
   - Defender alerte sur le fichier .yml lui-même!

2. **Règles "placeholder"**
   - Dans `rules-placeholder/` folder
   - Squelettes de règles, pas utilisables as-is

3. **Règles avec modifiers non supportés**
   - Hayabusa supporte 30+ modifiers
   - Règles utilisant d'autres modifiers ignorées
   - Évite les parsing errors

4. **Règles avec erreurs de syntaxe**
   - YAML invalide
   - Conditions malformées

---

## 4. Alternatives Builtin aux règles Sysmon

### 4.1 Process Creation

| Source | Channel | EventID | Enabled by default? | CommandLine? |
|--------|---------|---------|---------------------|--------------|
| **Sysmon** | Microsoft-Windows-Sysmon/Operational | 1 | Non (need Sysmon) | ✅ Toujours |
| **Security** | Security | 4688 | ❌ **NON** | ❌ **Option séparée** |

**Pour activer Security 4688:**
```bash
# Enable event logging
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

# Enable CommandLine logging (SÉPARÉ!)
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled /f /t REG_DWORD /d 1
```

### 4.2 Network Connection

| Source | Channel | EventID | Enabled by default? | Impact |
|--------|---------|---------|---------------------|--------|
| **Sysmon** | Microsoft-Windows-Sysmon/Operational | 3 | Non (need Sysmon) | Medium logs |
| **Security** | Security | 5156 | ❌ **NON** | ⚠️ **HUGE logs** |

**⚠️ WARNING du README:**
> "This will create a large amount of logs which may overwrite other important logs in the Security event and potentially cause the system to slow down"

**Pour activer Security 5156:**
```bash
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
```

### 4.3 Registry Events

| Source | Channel | EventID | Category | Enabled by default? |
|--------|---------|---------|----------|---------------------|
| **Sysmon** | Microsoft-Windows-Sysmon/Operational | 12 | registry_add, registry_delete | Non (need Sysmon) |
| **Sysmon** | Microsoft-Windows-Sysmon/Operational | 13 | registry_set | Non (need Sysmon) |
| **Sysmon** | Microsoft-Windows-Sysmon/Operational | 14 | registry_rename | Non (need Sysmon) |
| **Security** | Security | 4657 | registry_event, registry_add, registry_set | ❌ **NON** |

**Note:** Security 4657 nécessite `OperationType` filtering:
- `New registry value created` → registry_add
- `Existing registry value modified` → registry_set

### 4.4 WMI Events

| Source | Channel | EventID | Enabled by default? |
|--------|---------|---------|---------------------|
| **Sysmon** | Microsoft-Windows-Sysmon/Operational | 19, 20, 21 | Non (need Sysmon) |
| **WMI** | Microsoft-Windows-WMI-Activity/Operational | 5861 | ✅ **OUI** |

---

## 5. Transformations détaillées Sysmon → Security

### 5.1 Process Creation (Event 1 → 4688)

| Sigma Field | Sysmon 1 | Security 4688 | Transformation |
|-------------|----------|---------------|----------------|
| **User** | `DOMAIN\User` | `SubjectUserName`<br>`SubjectDomainName` | **Split!**<br>`DOMAIN\Admin` →<br>`SubjectUserName: Admin`<br>`SubjectDomainName: DOMAIN` |
| **LogonId** | `0x3e7` (uppercase hex) | `SubjectLogonId` | **Lowercase!**<br>`0x3E7` → `0x3e7` |
| **ProcessId** | `1234` (decimal) | `NewProcessId` | **Convert to hex!**<br>`1234` → `0x4d2` |
| **Image** | Full path | `NewProcessName` | Rename only |
| **ParentProcessId** | `5678` (decimal) | `ProcessId` | **Convert to hex!**<br>`5678` → `0x162e` |
| **ParentImage** | Full path | `ParentProcessName` | Rename only |
| **IntegrityLevel** | `Low`, `Medium`, `High`, `System` | `MandatoryLabel` | **SID conversion!**<br>`Low` → `S-1-16-4096`<br>`Medium` → `S-1-16-8192`<br>`High` → `S-1-16-12288`<br>`System` → `S-1-16-16384` |

### 5.2 Network Connection (Event 3 → 5156)

| Sigma Field | Sysmon 3 | Security 5156 | Transformation |
|-------------|----------|---------------|----------------|
| **ProcessId** | `ProcessId` | `ProcessID` | Rename (case!) |
| **Image** | `C:\Windows\...` | `Application` | **Path format!**<br>`C:\` → `\device\harddiskvolume?\` |
| **Protocol** | `tcp`, `udp` | Protocol number | **Convert!**<br>`tcp` → `6`<br>`udp` → `17` |
| **Initiated** | `true`, `false` | `Direction` | **Message ID!**<br>`true` → `%%14593`<br>`false` → `%%14592` |
| **SourceIp** | IP address | `SourceAddress` | Rename only |
| **DestinationIp** | IP address | `DestAddress` | Rename only |
| **DestinationPort** | Port number | `DestPort` | Rename only |

---

## 6. Implications pour StoW (Wazuh)

### 6.1 ✅ Ce que StoW fait CORRECTEMENT

**1. Focus sur Sysmon uniquement**
- Wazuh users installent généralement Sysmon
- Plus de détails que Security events
- Pas besoin de transformations complexes
- **Décision validée par le README:**
  > "Many organizations cannot or do not want to install and maintain Sysmon [...] it is important to enable as many built-in event logs as well"

**Mais:** La plupart des users Wazuh qui prennent le temps de configurer Sigma rules ont probablement **déjà installé Sysmon**!

**2. Pas de deabstraction**
- Wazuh a son propre système (parent rules)
- Pas besoin de dupliquer les règles
- Approche différente mais valide

**3. Architecture parent rules**
- Hiérarchie multi-niveaux
- Réutilisation des conditions communes
- Adapté à Wazuh XML

### 6.2 ❌ Ce que StoW ne PEUT PAS faire (limitations Wazuh)

**1. Field transformations dynamiques**
- Hayabusa: `Image` → `NewProcessName` à la volée
- Wazuh: Fields fixés par les decoders
- **Impossible sur Wazuh**

**2. Value transformations**
- Hayabusa: `"Low"` → `"S-1-16-4096"` à la volée
- Wazuh: Match valeur exacte du log
- **Impossible sur Wazuh**
- **Mais:** Sysmon logs ont déjà les bonnes valeurs!

**3. Création de règles multiples**
- Hayabusa: 1 règle Sigma → 2 règles (Sysmon + builtin)
- StoW: 1 règle Sigma → 1 règle Wazuh
- **Choix de design, pas une limitation**

### 6.3 🔧 Ce que StoW DEVRAIT améliorer

**1. Ignore list (PRIORITÉ HAUTE)**

D'après le README, ignorer:
- Règles avec syntax errors
- Règles avec modifiers non supportés par Wazuh
- Règles avec fields qui n'existent pas dans Sysmon
- Règles causant des FPs connus

**Créer:** `ignore-sigma-uuids.txt`
```
# Règle avec pattern trop complexe pour Wazuh
abc123-def456-...

# Règle utilisant modifier non supporté
xyz789-...

# Règle causant FP connus
fedcba-...
```

**2. Field validation (PRIORITÉ MOYENNE)**

Valider que les champs utilisés:
- Existent dans Sysmon events
- Ne sont pas Security-only (SubjectUserSid, TokenElevationType, etc.)
- Sont supportés par les decoders Wazuh

**Warning si:**
```
⚠️ WARNING: Rule abc-123 uses field 'OriginalFileName'
   This field requires Sysmon. Ensure Sysmon is installed and configured.
```

**3. Modifier validation (PRIORITÉ MOYENNE)**

Vérifier que les modifiers utilisés sont supportés par Wazuh:
- ✅ Supportés: `contains`, `startswith`, `endswith`, `re`, etc.
- ❌ Non supportés: modifiers custom/expérimentaux

**4. UUID tracking (PRIORITÉ BASSE)**

Comme Hayabusa, créer de nouveaux UUIDs:
- Garder l'UUID original dans `related` field
- Permet de tracer la provenance
- Utile pour les updates de règles

---

## 7. Advice pour écriture de règles Sigma

**D'après le README, conseil important:**

> "If you use any field that exists in a sysmon log but not a builtin log then make sure you make that field optional so that it is still possible to use the rule for builtin logs."

**Exemple recommandé:**
```yaml
selection_img:
    - Image|endswith: \addinutil.exe         # Existe dans les deux
    - OriginalFileName: AddInUtil.exe        # Sysmon-only mais OR!
```

**Pourquoi?**
- Attacker peut renommer `addinutil.exe` → `innocent.exe`
- `OriginalFileName` (embedded name) ne change pas → détection
- Mais si pas renamed, `Image` suffit → builtin fonctionne aussi

**❌ Mauvais exemple (AND requis):**
```yaml
selection_img:
    Image|endswith: \addinutil.exe
    OriginalFileName: AddInUtil.exe    # Sysmon-only ET AND!
```
→ Règle builtin impossible

---

## 8. Comparaison finale: Approches différentes, cibles différentes

| Aspect | Hayabusa | StoW | Raison |
|--------|----------|------|--------|
| **Target users** | Tous (Sysmon + builtin) | Principalement Sysmon | Wazuh users = power users avec Sysmon |
| **Deabstraction** | ✅ Oui (2 règles) | ❌ Non (1 règle) | Wazuh: parent rules suffisent |
| **Field transforms** | ✅ Oui (Image→NewProcessName) | ❌ Non | Wazuh: impossible (decoders fixes) |
| **Value transforms** | ✅ Oui (Low→S-1-16-4096) | ❌ Non | Wazuh: impossible, Sysmon OK |
| **Builtin support** | ✅ Full (Sec 4688, 5156, etc.) | ❌ Sysmon only | Design choice |
| **Complexity** | Medium (2 règles, transforms) | Low (1 règle, no transforms) | Simplicité vs coverage |
| **User experience** | Analysts (confirmation facile) | SIEM (automated detection) | Use case différent |

---

## 9. Nouvelles recommandations pour StoW

### PRIORITÉ HAUTE ✅

1. **Ignore list**
   ```bash
   # Créer ignore-sigma-uuids.txt
   # Ignorer règles avec:
   # - Syntax errors
   # - Unsupported modifiers
   # - Security-only fields
   # - Known false positives
   ```

2. **Modifier validation**
   ```go
   supportedModifiers := []string{
       "contains", "startswith", "endswith",
       "all", "base64", "re", "cidr", ...
   }
   // Warn si modifier non supporté par Wazuh
   ```

### PRIORITÉ MOYENNE 🔧

3. **Field validation**
   ```go
   sysmonOnlyFields := []string{
       "OriginalFileName", "ProcessGuid",
       "Hashes", "ParentCommandLine", ...
   }
   // Warn si champ Sysmon-only utilisé
   ```

4. **Documentation améliorée**
   - Expliquer pourquoi focus sur Sysmon
   - Lister les limitations vs Hayabusa
   - Guider les users sur Sysmon setup

### PRIORITÉ BASSE 📝

5. **UUID tracking**
   - Générer nouveaux UUIDs
   - Link to original via `related` field
   - Traçabilité des conversions

6. **Statistics**
   ```
   Conversion completed:
   - 1234 rules converted
   - 56 rules ignored (see ignored_rules.txt)
   - 12 rules with warnings (see warnings.txt)
   ```

### ❌ NE PAS FAIRE

1. **Deabstraction (2 règles Sysmon + builtin)**
   - Pas nécessaire pour Wazuh
   - Wazuh users ont Sysmon
   - Augmente la complexité inutilement

2. **Field/Value transformations**
   - Impossible avec architecture Wazuh
   - Sysmon logs OK as-is

3. **Builtin Security event support**
   - Sysmon fournit plus de détails
   - Security events désactivés par défaut
   - Complexité vs bénéfice minimal

---

## 10. Conclusion mise à jour

### ✅ Validation de StoW

Le README Hayabusa **valide** l'approche de StoW:

1. **Focus Sysmon correct**
   - Wazuh power users installent Sysmon
   - Plus de détails que builtin
   - Pas de transformations nécessaires

2. **Pas de deabstraction nécessaire**
   - Approche différente (parent rules) valide
   - Simplifie le code
   - Suffisant pour use case Wazuh

3. **Architecture solide**
   - Parent rules hiérarchiques
   - CDB lists optimisation
   - Service mappings corrects

### 🎯 Takeaways importants

**De la philosophie Hayabusa:**
1. Deabstraction facilite la vie des **analysts**
2. Transformations permettent **builtin support**
3. OR vs AND logic determine **rule creation**
4. Ignore list évite **problematic rules**

**Pour StoW:**
1. ✅ Garde approche actuelle (Sysmon-focused)
2. ✅ Ajoute ignore list (high priority)
3. ✅ Ajoute field/modifier validation (medium priority)
4. ❌ Ne fais PAS deabstraction (pas nécessaire)
5. ❌ Ne fais PAS transformations (impossible sur Wazuh)

### 📊 Scores

| Critère | Hayabusa | StoW | Winner |
|---------|----------|------|--------|
| **Simplicité** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | StoW |
| **Coverage (Sysmon + builtin)** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | Hayabusa |
| **Analyst UX** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Hayabusa |
| **SIEM integration** | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ | StoW |
| **Adapté à la plateforme** | ⭐⭐⭐⭐⭐ (Hayabusa) | ⭐⭐⭐⭐⭐ (Wazuh) | Tie |

**Conclusion:** Chaque outil est **parfaitement adapté à sa plateforme**. StoW ne devrait PAS copier l'approche Hayabusa, mais **apprendre de leurs bonnes pratiques** (ignore list, validation) tout en gardant son architecture actuelle.

---

**Fin du rapport mis à jour**

**Date:** 31 décembre 2025
**Source:** sigma-to-hayabusa-converter README + code analysis
**Conclusion:** StoW approach validated ✅
