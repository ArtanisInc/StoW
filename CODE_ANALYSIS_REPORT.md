# Analyse de Code StoW - Compatibilité Wazuh

**Date:** 2026-01-02
**Branche analysée:** claude/check-converter-01SLm3CrRCGqSp3uxnJLJQcm

## Résumé Exécutif

Cette analyse examine les affirmations d'un document externe concernant des problèmes de compatibilité Wazuh dans StoW. Après examen approfondi du code source actuel, voici les conclusions :

## 🔍 Problèmes Identifiés dans le Code Actuel

### ❌ PROBLÈME 1: Parser DNF Simplifié

**Fichier:** `pkg/converter/dnf.go`
**Gravité:** ⚠️ MOYENNE

**Problème:**
Le parser DNF actuel est très simplifié et ne gère PAS correctement :
- ❌ Les parenthèses imbriquées
- ❌ La négation (NOT)
- ❌ La précédence des opérateurs (NOT > AND > OR)

**Code actuel (lignes 55-83):**
```go
func Parse(tokens []Token) [][]string {
    // Simplified parser - returns DNF sets
    // In reality this would be more complex

    var result [][]string
    var current []string

    for _, token := range tokens {
        if token.Type == "LITERAL" {
            current = append(current, token.Value)
        } else if token.Type == "OR" {
            if len(current) > 0 {
                result = append(result, current)
                current = []string{}
            }
        }
    }
    // ...
}
```

**Impact:**
- Les règles Sigma avec conditions complexes (parenthèses, NOT) ne sont pas converties correctement
- Exemples : `(A AND B) OR (C AND D)`, `NOT A AND B`

**Recommandation:** ⚠️ Amélioration nécessaire pour les règles complexes

---

### ❌ PROBLÈME 2: Wildcards Sigma Non Convertis

**Fichier:** `pkg/converter/fields.go`
**Gravité:** 🔴 HAUTE

**Problème:**
La fonction `BuildFieldValue` ne convertit PAS les wildcards Sigma en regex PCRE2 :
- Sigma utilise `*` (zéro ou plusieurs caractères)
- Sigma utilise `?` (exactement un caractère)
- PCRE2 nécessite `.*` et `.` respectivement

**Code actuel (lignes 54-75):**
```go
func BuildFieldValue(v string, mods FieldModifiers, fieldName string, product string) string {
    value := v

    // Apply transformations based on modifiers
    if mods.Contains {
        value = value
    }
    if mods.StartsWith {
        value = "^" + value
    }
    if mods.EndsWith {
        value = value + "$"
    }

    // Add case-insensitive prefix if needed
    if needsCaseInsensitive(fieldName, product) && !mods.IsRegex {
        value = "(?i)" + value
    }

    return value
}
```

**Ce qui manque:**
```go
// MANQUANT: Conversion des wildcards Sigma
// * → .*
// ? → .
// Échappement des caractères spéciaux regex: . + ^ $ ( ) [ ] { } | \
```

**Impact:**
- Les règles Sigma avec wildcards (ex: `*.exe`, `C:\?emp\*`) ne matchent PAS correctement
- Les wildcards sont traités comme des caractères littéraux au lieu de patterns

**Exemple:**
- Sigma : `CommandLine: 'test*.exe'`
- Actuel : `<field type="pcre2">(?i)test*.exe</field>` ❌ (match littéral de `*`)
- Attendu : `<field type="pcre2">(?i)test.*\.exe</field>` ✅ (match pattern)

**Recommandation:** 🔴 **CORRECTION URGENTE REQUISE**

---

### ⚠️ PROBLÈME 3: Utilisation de osmatch vs pcre2

**Fichier:** `pkg/converter/builder.go`
**Gravité:** 🟡 BASSE (Optimisation)

**État actuel:**
- Le code utilise **TOUJOURS** `type="pcre2"` (ligne 136)
- `osmatch` n'est **JAMAIS** utilisé
- Le type de champ est défini vide (`""`) pour les valeurs simples (ligne 226), ce qui correspond à l'exact matching

**Code actuel:**
```go
field := types.Field{
    Name: wazuhField,
    Type: "pcre2",  // Toujours pcre2
}

// Plus tard, pour les valeurs simples:
if canUseExact && len(values) == 1 {
    field.Type = ""  // Exact matching
    field.Value = values[0]
}
```

**Documentation Wazuh:**
Selon la documentation Wazuh, les types de regex sont :
- `osregex` : Expressions régulières basiques Wazuh
- `osmatch` : String matching exact (le plus rapide)
- `pcre2` : Full PCRE2 (le plus flexible mais plus lent)

**Affirmation du document externe:**
> "osmatch ne supporte PAS (?i)"

**Vérification:** Cette affirmation est **probablement vraie** mais **NON PERTINENTE** car :
1. Le code actuel n'utilise PAS `osmatch` avec `(?i)`
2. Le code utilise `Type=""` (exact matching) pour les valeurs simples
3. Le code utilise `type="pcre2"` pour tous les patterns avec modifiers

**Impact:** AUCUN - Le code actuel ne souffre pas de ce problème

**Optimisation possible:**
- Pour Linux (case-sensitive), on pourrait utiliser `osmatch` pour les valeurs exactes simples
- Pour Windows (case-insensitive), continuer avec `pcre2 + (?i)`

**Recommandation:** 🟡 Optimisation possible mais pas critique

---

## ✅ Ce Qui Fonctionne Correctement

### 1. Case-Insensitive pour Windows ✅

**Code actuel (fields.go:83-89):**
```go
func needsCaseInsensitive(fieldName string, product string) bool {
    // Windows fields are case-insensitive
    if product == "windows" {
        return true
    }
    return false
}
```

**Résultat dans le XML:**
```xml
<field name="win.eventdata.commandLine" type="pcre2">(?i)powershell</field>
```

✅ **CORRECT** - Windows utilise bien `(?i)` avec `pcre2`

---

### 2. Field Negation ✅

**Code actuel (builder.go:140-142):**
```go
// Apply negation if this selectionKey is marked as negated
if selectionNegations[selectionKey] {
    field.Negate = "yes"
}
```

✅ **CORRECT** - La négation est supportée

---

### 3. CDB Lists ✅

**Code actuel (builder.go:341-378):**
```go
func processOversizedFields(ruleFields types.RuleFields, sigmaID string, c *types.Config) ([]types.Field, []types.ListField, error) {
    maxFieldLength := 8192
    // ... génère des CDB lists pour les champs trop longs
}
```

✅ **CORRECT** - Les CDB lists sont générées automatiquement

---

### 4. MITRE ATT&CK Tags ✅

✅ **CORRECT** - Les tags MITRE sont extraits et inclus dans le XML

---

## 📊 Synthèse des Problèmes

| Problème | Gravité | Impact | État Actuel | Action Requise |
|----------|---------|--------|-------------|----------------|
| Parser DNF simplifié | ⚠️ MOYENNE | Règles complexes mal converties | Fonctionne pour la plupart des cas | Amélioration recommandée |
| Wildcards non convertis | 🔴 HAUTE | Wildcards ne matchent pas | **CASSÉ** | **CORRECTION URGENTE** |
| osmatch avec (?i) | 🟡 BASSE | Aucun (pas utilisé) | N/A | Optimisation possible |

---

## 🔧 Corrections Nécessaires

### URGENT: Conversion des Wildcards

**Fonction à corriger:** `BuildFieldValue` dans `pkg/converter/fields.go`

**Code corrigé suggéré:**
```go
func BuildFieldValue(v string, mods FieldModifiers, fieldName string, product string) string {
    value := v

    // 1. Échapper les caractères spéciaux PCRE2 (sauf * et ? qui sont des wildcards Sigma)
    if !mods.IsRegex {
        // Échapper . + ^ $ ( ) [ ] { } | \
        value = escapePCRE2(value, false) // false = ne pas échapper * et ?

        // 2. Convertir les wildcards Sigma en regex PCRE2
        value = strings.ReplaceAll(value, "*", ".*")  // * → .*
        value = strings.ReplaceAll(value, "?", ".")   // ? → .
    }

    // 3. Apply transformations based on modifiers
    if mods.StartsWith {
        value = "^" + value
    }
    if mods.EndsWith {
        value = value + "$"
    }

    // 4. Add case-insensitive prefix if needed
    if needsCaseInsensitive(fieldName, product) && !mods.IsRegex {
        value = "(?i)" + value
    }

    return value
}

// Nouvelle fonction helper
func escapePCRE2(s string, escapeWildcards bool) string {
    // Caractères à échapper: . + ^ $ ( ) [ ] { } | \
    replacer := strings.NewReplacer(
        "\\", "\\\\",
        ".", "\\.",
        "+", "\\+",
        "^", "\\^",
        "$", "\\$",
        "(", "\\(",
        ")", "\\)",
        "[", "\\[",
        "]", "\\]",
        "{", "\\{",
        "}", "\\}",
        "|", "\\|",
    )
    s = replacer.Replace(s)

    if escapeWildcards {
        s = strings.ReplaceAll(s, "*", "\\*")
        s = strings.ReplaceAll(s, "?", "\\?")
    }

    return s
}
```

---

## 📈 Impact Estimé des Corrections

### Avant Corrections:
- ❌ Wildcards Sigma ne fonctionnent pas
- ⚠️ Règles complexes (parenthèses, NOT) mal converties
- ✅ Case-insensitive fonctionne pour Windows
- ✅ CDB lists, MITRE tags, negation OK

### Après Corrections:
- ✅ Wildcards Sigma convertis correctement en PCRE2
- ✅ Parser DNF amélioré (si corrigé)
- ✅ Meilleure compatibilité avec Sigma
- 🚀 Taux de conversion probablement > 90%

---

## 🎯 Recommandations Finales

### 1. Corrections Critiques (URGENT) 🔴
- **Implémenter la conversion des wildcards Sigma** dans `BuildFieldValue`
- Tester avec des règles Sigma contenant `*` et `?`

### 2. Améliorations Importantes ⚠️
- Améliorer le parser DNF pour gérer les parenthèses et NOT
- Ajouter des tests unitaires pour ces fonctions

### 3. Optimisations Optionnelles 🟡
- Utiliser `osmatch` pour Linux (exact matching, meilleur performance)
- Continuer avec `pcre2` pour Windows (case-insensitive requis)

---

## ✅ Compatibilité Wazuh Actuelle

Le code actuel est **compatible avec Wazuh** mais présente des **bugs critiques** :

| Feature | Compatible | Fonctionne | Notes |
|---------|------------|------------|-------|
| PCRE2 regex | ✅ Oui | ✅ Oui | Utilisé correctement |
| Case-insensitive Windows | ✅ Oui | ✅ Oui | `(?i)` ajouté |
| Field negation | ✅ Oui | ✅ Oui | `negate="yes"` |
| CDB Lists | ✅ Oui | ✅ Oui | Auto-générées |
| **Wildcards Sigma** | ✅ Oui | ❌ **NON** | **BUG CRITIQUE** |
| **Conditions complexes** | ✅ Oui | ⚠️ Partiel | Parser simplifié |

---

## 📝 Conclusion

Les affirmations du document externe sont **partiellement vraies** :

1. ✅ **Parser DNF** : Vrai - Le parser est simplifié et incomplet
2. ✅ **Wildcards** : Vrai - Ils ne sont PAS convertis (BUG CRITIQUE)
3. ❌ **osmatch + (?i)** : Vrai mais non pertinent - Le code n'utilise pas cette combinaison

**Le code actuel fonctionne** pour la majorité des règles Sigma simples, mais **échoue silencieusement** pour les règles avec wildcards.

**Action recommandée :** Implémenter la correction des wildcards en priorité.
