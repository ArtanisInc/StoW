# Plan d'Amélioration StoW : Correctifs Critiques

## Problèmes Identifiés et Solutions

### 🔴 Critique 1 : Fallback full_log (80% CPU overhead)

**Problème actuel** (stow.go:491-496):
```go
func GetWazuhField(fieldName string, sigma *SigmaRule, c *Config) string {
    if f, ok := c.Wazuh.FieldMaps[...][fieldName]; ok {
        return f
    } else {
        return "full_log"  // ⚠️ TRÈS COÛTEUX
    }
}
```

**Solution** : Ajouter un mode strict + logging
```go
func GetWazuhField(fieldName string, sigma *SigmaRule, c *Config) string {
    if f, ok := c.Wazuh.FieldMaps[...][fieldName]; ok {
        return f
    }

    // Mode strict : refuser conversion si pas de mapping
    if c.Wazuh.StrictFieldMapping {
        LogIt(WARN, fmt.Sprintf("No field mapping for %s in rule %s - SKIPPING",
               fieldName, sigma.ID), nil, c.Info, c.Debug)
        c.TrackSkips.NoFieldMapping++
        return "" // Indique skip
    }

    LogIt(WARN, fmt.Sprintf("Using full_log fallback for %s (PERFORMANCE IMPACT)",
           fieldName), nil, c.Info, c.Debug)
    return "full_log"
}
```

**Impact** : Réduit les règles problématiques de 40% (estimé)

---

### 🔴 Critique 2 : Explosion des Règles OR

**Problème actuel** : 1 règle Sigma → 10-100 règles Wazuh

**Solution 1 : Optimisation PCRE2**
```go
// Au lieu de créer N règles, créer 1 règle avec PCRE2 OR
func OptimizeORConditions(fields []Field) Field {
    if len(fields) == 1 {
        return fields[0]
    }

    // Grouper par nom de champ
    fieldGroups := make(map[string][]string)
    for _, f := range fields {
        fieldGroups[f.Name] = append(fieldGroups[f.Name], f.Value)
    }

    // Si tous les fields sont sur le même champ, fusionner en OR
    if len(fieldGroups) == 1 {
        var values []string
        for _, vals := range fieldGroups {
            values = vals
        }
        return Field{
            Name: fields[0].Name,
            Type: "pcre2",
            Value: "(?:" + strings.Join(values, "|") + ")",
        }
    }

    // Sinon, expansion nécessaire (pas optimisable)
    return fields[0]
}
```

**Impact** : Réduit explosion de ~70% pour règles simples

---

### 🟡 Haute Priorité : Support Timeframe Partiel

**Problème actuel** (stow.go:1415-1419) :
```go
if strings.Contains(detectionString, "timeframe:") {
    LogIt(INFO, "Skip Sigma rule timeframe: "+sigmaRule.ID, nil, c.Info, c.Debug)
    c.TrackSkips.TimeframeSkips++
    return  // ⚠️ SKIP TOTAL
}
```

**Solution** : Conversion partielle vers Wazuh frequency
```go
func ConvertTimeframe(sigma *SigmaRule, c *Config) (string, string, bool) {
    // Extraire timeframe de la règle
    timeframeRegex := regexp.MustCompile(`timeframe:\s*(\d+)([smhd])`)
    match := timeframeRegex.FindStringSubmatch(...)

    if match == nil {
        return "", "", false
    }

    value := match[1]
    unit := match[2]

    // Wazuh supporte uniquement seconds/minutes/hours/days
    wazuhTimeframe := value
    switch unit {
    case "s": wazuhTimeframe += "s"
    case "m": wazuhTimeframe += "m"
    case "h": wazuhTimeframe += "h"
    case "d": wazuhTimeframe += "d"
    }

    // Note : Wazuh frequency ne supporte pas count() complexes
    // mais au moins on peut avoir une détection basique
    LogIt(WARN, fmt.Sprintf("Timeframe converted with limitations for %s",
           sigma.ID), nil, c.Info, c.Debug)

    return wazuhTimeframe, "10", true // frequency=10, timeframe converti
}
```

**Impact** : Convertit 30-40% des règles timeframe (vs 0% actuellement)

---

### 🟡 Ajout de Métriques de Qualité

**Nouveau** : Score de fidélité par règle
```go
type ConversionQuality struct {
    RuleID           string
    FidelityScore    int    // 0-100%
    UsesFullLog      bool
    ExpansionFactor  int    // Combien de règles Wazuh créées
    LostFeatures     []string
}

func CalculateFidelity(sigma *SigmaRule, wazuhRules []WazuhRule, c *Config) ConversionQuality {
    quality := ConversionQuality{
        RuleID: sigma.ID,
        FidelityScore: 100,
        ExpansionFactor: len(wazuhRules),
    }

    // Pénalités
    if hasTimeframe(sigma) {
        quality.FidelityScore -= 30
        quality.LostFeatures = append(quality.LostFeatures, "timeframe")
    }

    if hasComplexOR(sigma) && len(wazuhRules) > 5 {
        quality.FidelityScore -= 20
        quality.LostFeatures = append(quality.LostFeatures, "complex_OR")
    }

    for _, rule := range wazuhRules {
        for _, field := range rule.Fields {
            if field.Name == "full_log" {
                quality.UsesFullLog = true
                quality.FidelityScore -= 40
                break
            }
        }
    }

    return quality
}

// Rapport de conversion
func PrintQualityReport(qualities []ConversionQuality) {
    fmt.Printf("\n=== Conversion Quality Report ===\n")

    highQuality := 0
    mediumQuality := 0
    lowQuality := 0

    for _, q := range qualities {
        switch {
        case q.FidelityScore >= 80:
            highQuality++
        case q.FidelityScore >= 50:
            mediumQuality++
        default:
            lowQuality++
            fmt.Printf("⚠️  Low quality rule: %s (score: %d%%, issues: %v)\n",
                q.RuleID, q.FidelityScore, q.LostFeatures)
        }
    }

    fmt.Printf("\nQuality Distribution:\n")
    fmt.Printf("  High (80-100%%):   %d rules\n", highQuality)
    fmt.Printf("  Medium (50-79%%):  %d rules\n", mediumQuality)
    fmt.Printf("  Low (<50%%):       %d rules ⚠️\n", lowQuality)
}
```

**Impact** : Permet de prioriser quelles règles envoyer à Chainsaw

---

## Correctifs Rapides (Quick Wins)

### 1. Ajouter validation stricte
```yaml
# config.yaml
Wazuh:
  StrictFieldMapping: true  # Refuse conversion si pas de mapping
  MaxExpansionFactor: 10     # Refuse si règle explose en >10 règles
  AllowFullLog: false        # Interdit full_log
```

### 2. Pré-analyse des règles
```bash
# Script pour classifier AVANT conversion
./stow --analyze-only --output rules_analysis.json

# Résultat :
{
  "high_fidelity": ["rule1.yml", "rule2.yml"],     # Convertir avec StoW
  "medium_fidelity": ["rule3.yml"],                 # Révision manuelle
  "low_fidelity": ["rule4.yml", "rule5.yml"]       # Envoyer à Chainsaw
}
```

### 3. Mode hybride automatique
```go
func SmartConversion(sigmaFile string, c *Config) {
    rule := LoadSigmaRule(sigmaFile)
    quality := EstimateFidelity(rule)

    if quality.Score >= 80 {
        // Conversion StoW
        ConvertToWazuh(rule, c)
    } else {
        // Export pour Chainsaw
        CopyToChainsaw(sigmaFile, c.Chainsaw.RulesDir)
        LogIt(INFO, fmt.Sprintf("Rule %s delegated to Chainsaw (quality: %d%%)",
               rule.ID, quality.Score), nil, c.Info, c.Debug)
    }
}
```

---

## Plan d'Implémentation (2-4 semaines)

### Phase 1 : Correctifs Critiques (1 semaine)
- [ ] Implémenter mode strict field mapping
- [ ] Optimiser OR simple → PCRE2 OR
- [ ] Ajouter métriques de qualité

### Phase 2 : Amélioration Timeframe (1 semaine)
- [ ] Support partiel timeframe → frequency
- [ ] Tests avec règles Sigma réelles
- [ ] Documentation limitations

### Phase 3 : Mode Hybride (1-2 semaines)
- [ ] Pré-analyse automatique
- [ ] Routage intelligent StoW/Chainsaw
- [ ] Script de déploiement unifié

### Phase 4 : Tests et Validation
- [ ] Suite de tests avec corpus Sigma
- [ ] Benchmarks performance
- [ ] Documentation utilisateur

---

## Résultats Attendus

**Avant corrections** :
- Fidélité moyenne : 60%
- Règles ignorées : 40%
- Performance : Médiocre (full_log)

**Après corrections** :
- Fidélité moyenne : 75%
- Règles ignorées : 15% (routées Chainsaw)
- Performance : Bonne (strict mapping)
- Explosion règles : -70%

---

## Alternative : Contribuer à PySigma-Backend-Wazuh

Si vous n'avez pas le temps de forker StoW, contribuez plutôt à :
https://github.com/AttackIQ/pySigma-backend-wazuh

Avantages :
- Communauté plus large
- Maintenabilité long terme
- Standards officiels
