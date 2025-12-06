# Guide Complet : Toutes les Solutions Sigma → Wazuh

## 🎯 Résumé Exécutif

**Il n'existe PAS de solution parfaite** car Sigma et Wazuh ont des paradigmes incompatibles.

**Solution optimale pour 90% des cas** : **Architecture Hybride Multi-Backend**

---

## 📊 Les 7 Solutions Disponibles

### Solution 1 : PySigma Backend Wazuh (Officiel)
**Type** : Conversion statique
**Fidélité** : 70-75%
**Latence** : Temps réel
**Complexité** : Faible

**Installation** :
```bash
pip install pysigma pysigma-backend-wazuh
sigma convert -t wazuh -p sysmon rules/ -o wazuh_rules.xml
```

**Avantages** :
- ✅ Supporté officiellement
- ✅ Mises à jour régulières
- ✅ Documentation

**Inconvénients** :
- ❌ Mêmes limitations que StoW (timeframe, OR)
- ❌ Python (plus lent que Go pour gros volumes)

**Quand utiliser** : Production standard, besoin de stabilité

---

### Solution 2 : StoW Amélioré (Fork Custom)
**Type** : Conversion statique optimisée
**Fidélité** : 75-80% (après correctifs)
**Latence** : Temps réel
**Complexité** : Moyenne

**Correctifs prioritaires** :
1. Mode strict field mapping (éviter full_log)
2. Optimisation OR → PCRE2
3. Support partiel timeframe
4. Métriques de qualité

**Avantages** :
- ✅ Go (très rapide)
- ✅ Contrôle total du code
- ✅ Optimisable pour votre infra

**Inconvénients** :
- ❌ Maintenance à votre charge
- ❌ Nécessite compétences Go

**Quand utiliser** : Équipe DevOps, besoin de customisation

**Voir** : `/home/user/StoW/IMPROVEMENT_ROADMAP.md`

---

### Solution 3 : Chainsaw Optimisé
**Type** : Exécution native Sigma
**Fidélité** : 100%
**Latence** : 30 sec (optimisé, vs 5-15 min standard)
**Complexité** : Élevée

**Optimisations** :
- Micro-batching (30 sec au lieu de 5 min)
- Smart filtering (ne lance que si activité)
- Event-driven (< 5 sec possible)

**Avantages** :
- ✅ Fidélité parfaite
- ✅ Support timeframe/count natif
- ✅ Pas d'explosion de règles

**Inconvénients** :
- ❌ Latence minimale 30 sec (pas temps réel pur)
- ❌ Charge endpoints
- ❌ Complexité déploiement

**Quand utiliser** : Règles complexes, threat hunting

**Voir** : `/home/user/StoW/CHAINSAW_OPTIMIZATION.md`

---

### Solution 4 : Écriture Manuelle Sélective
**Type** : Conversion assistée + édition
**Fidélité** : 100%
**Latence** : Temps réel
**Complexité** : Variable

**Process** :
1. Identifier les 20 règles critiques
2. Convertir avec StoW comme base
3. Optimiser manuellement (regex, field mapping)
4. Valider avec wazuh-logtest
5. Versionner dans Git

**Estimation temps** :
- Règle simple : 15 min
- Règle complexe : 45 min
- 20 règles critiques : ~10 heures total

**Avantages** :
- ✅ Performances maximales
- ✅ Compréhension totale
- ✅ Maintenance précise

**Inconvénients** :
- ❌ Temps initial élevé
- ❌ Ne scale pas (>50 règles)

**Quand utiliser** : Règles critiques métier spécifiques

---

### Solution 5 : Architecture Hybride Multi-Backend (RECOMMANDÉ)
**Type** : Combinaison de tout ce qui précède
**Fidélité** : 85-90% (moyenne pondérée)
**Latence** : Mixte (temps réel + 30 sec)
**Complexité** : Élevée (setup) → Faible (maintenance)

**Architecture** :
```
Règles Sigma (1000 total)
    │
    ├─ 800 règles simples ──────────> PySigma/StoW ─────> Wazuh (temps réel)
    │
    ├─ 150 règles complexes ────────> Chainsaw ─────────> Wazuh (30 sec)
    │
    └─ 50 règles critiques métier ──> Manuel ───────────> Wazuh (temps réel)
```

**Classification automatique** :
```python
# sigma_classifier.py
import yaml

def classify_rule(sigma_file):
    with open(sigma_file) as f:
        rule = yaml.safe_load(f)

    score = 0

    # Critères de complexité
    if 'timeframe' in str(rule.get('detection', '')):
        score += 3
    if 'count()' in str(rule.get('detection', '')):
        score += 3
    if ' or ' in rule.get('detection', {}).get('condition', ''):
        score += rule['detection']['condition'].count(' or ')

    # Classification
    if score == 0:
        return "simple"      # → StoW/PySigma
    elif score <= 3:
        return "medium"      # → StoW + révision
    else:
        return "complex"     # → Chainsaw

# Usage
for sigma_file in Path("sigma/rules").rglob("*.yml"):
    category = classify_rule(sigma_file)

    if category == "simple":
        os.system(f"sigma convert -t wazuh {sigma_file} >> simple_rules.xml")
    elif category == "complex":
        shutil.copy(sigma_file, "chainsaw_rules/")
    else:
        print(f"REVIEW NEEDED: {sigma_file}")
```

**Déploiement unifié** :
```bash
# deploy_hybrid.sh
#!/bin/bash

echo "=== Déploiement Hybride Sigma → Wazuh ==="

# 1. Classifier les règles
python3 sigma_classifier.py

# 2. Convertir règles simples avec PySigma
sigma convert -t wazuh -p sysmon simple_rules/ -o /var/ossec/etc/rules/sigma_simple.xml

# 3. Déployer Chainsaw pour règles complexes
ansible-playbook deploy_chainsaw.yml -i inventory

# 4. Copier règles manuelles
cp manual_rules/*.xml /var/ossec/etc/rules/

# 5. Restart Wazuh
systemctl restart wazuh-manager

echo "✓ Déploiement terminé"
echo "  - $(wc -l simple_rules.xml) règles simples (temps réel)"
echo "  - $(ls chainsaw_rules/*.yml | wc -l) règles complexes (Chainsaw 30s)"
echo "  - $(ls manual_rules/*.xml | wc -l) règles manuelles (temps réel)"
```

**Avantages** :
- ✅ Meilleur compromis fidélité/performance
- ✅ Scalable (1000+ règles)
- ✅ Maintenable

**Inconvénients** :
- ❌ Setup initial complexe
- ❌ Nécessite orchestration

**Quand utiliser** : Environnement de production mature, >500 règles

---

### Solution 6 : Backends Alternatifs (Détour)
**Type** : Changer de SIEM
**Fidélité** : 100%
**Complexité** : Très élevée

**Plateformes avec support Sigma natif** :
- **Elastic Security** : Backend officiel excellent
- **Splunk** : Via TA-Sigma
- **Microsoft Sentinel** : Support partiel
- **QRadar** : Backend communautaire

**Avantages** :
- ✅ Aucune conversion nécessaire
- ✅ Fidélité totale

**Inconvénients** :
- ❌ Migration complète SIEM
- ❌ Coûts élevés
- ❌ Perte investissement Wazuh

**Quand utiliser** : Seulement si Wazuh ne répond plus aux besoins

---

### Solution 7 : Contribuer à Wazuh Core (Long Terme)
**Type** : Amélioration upstream
**Fidélité** : 100% (futur)
**Complexité** : Très élevée

**Proposition** : Intégrer un moteur Sigma natif dans Wazuh 5.x

**Faisabilité** :
- Wazuh est open source (GPLv2)
- Communauté active
- Équipe réceptive aux PR

**Roadmap** :
1. Créer une RFC sur GitHub Wazuh
2. Proposer une architecture (ex: module wazuh-sigma)
3. Implémenter un PoC
4. Soumettre PR

**Avantages** :
- ✅ Bénéfice pour toute la communauté
- ✅ Solution pérenne

**Inconvénients** :
- ❌ Temps : 6-12 mois minimum
- ❌ Compétences C++ requises
- ❌ Pas de garantie d'acceptation

**Quand utiliser** : Engagement long terme, grosse structure

---

## 🎯 Matrice de Décision

| Votre Situation | Solution Recommandée | Fidélité | Effort |
|----------------|---------------------|----------|---------|
| **PME, <100 règles simples** | PySigma | 75% | Faible |
| **PME, règles complexes** | Chainsaw optimisé | 100% | Moyen |
| **Entreprise, <500 règles** | StoW amélioré | 80% | Moyen |
| **Entreprise, >500 règles mixtes** | **Hybride Multi-Backend** | 90% | Élevé (setup) |
| **SOC mature, >1000 règles** | **Hybride + Manuel** | 95% | Élevé |
| **Budget élevé, Sigma critique** | Migration Elastic/Splunk | 100% | Très élevé |

---

## 🚀 Plan d'Action Recommandé (Approche Itérative)

### Phase 1 : Quick Win (Semaine 1)
```bash
# Tester PySigma sur 50 règles simples
pip install pysigma pysigma-backend-wazuh
sigma convert -t wazuh rules/windows/process_creation/ -o test_rules.xml

# Valider
wazuh-logtest -q -v -U 200000:200049 < sample_logs.txt

# Déployer si >80% match
```

**Objectif** : Valider la faisabilité en 1 semaine

---

### Phase 2 : Scaling (Semaines 2-4)

**Option A : Si PySigma fonctionne bien**
- Convertir l'ensemble des règles simples
- Déployer en production avec monitoring

**Option B : Si PySigma a trop de gaps**
- Fork StoW
- Implémenter les 3 correctifs critiques (roadmap)
- Reconvertir et comparer

---

### Phase 3 : Règles Complexes (Semaines 5-8)

**Choix stratégique** :

**Si latence 30 sec acceptable** :
- Déployer Chainsaw optimisé (micro-batching)
- Monitorer charge CPU endpoints
- Ajuster intervalle si nécessaire

**Si latence inacceptable** :
- Écriture manuelle des 20 règles complexes critiques
- Accepter perte des règles moins critiques
- Prioriser selon MITRE ATT&CK

---

### Phase 4 : Architecture Hybride (Semaines 9-12)

**Finaliser le pipeline** :
```
Classification auto → Routing → Déploiement → Monitoring
```

**Métriques de succès** :
- [ ] >90% des règles Sigma déployées (d'une manière ou d'une autre)
- [ ] <5% CPU overhead sur manager Wazuh
- [ ] Latence moyenne <1 min pour 95% des détections
- [ ] Taux de faux positifs <10%

---

## 📈 Comparatif Final des Solutions

| Solution | Fidélité | Latence | Complexité | Maintenance | Coût |
|----------|---------|---------|-----------|-------------|------|
| **PySigma** | 70% | 0s | ⭐ | ⭐⭐ | Gratuit |
| **StoW vanilla** | 60% | 0s | ⭐ | ⭐⭐ | Gratuit |
| **StoW amélioré** | 80% | 0s | ⭐⭐⭐ | ⭐⭐⭐ | Temps dev |
| **Chainsaw standard** | 100% | 300s | ⭐⭐⭐ | ⭐⭐ | Gratuit |
| **Chainsaw optimisé** | 100% | 30s | ⭐⭐⭐⭐ | ⭐⭐⭐ | Temps dev |
| **Manuel sélectif** | 100% | 0s | ⭐⭐ | ⭐⭐⭐⭐ | Temps (10h) |
| **Hybride** | 90% | 15s | ⭐⭐⭐⭐ | ⭐⭐⭐ | Setup ++ |
| **Migration SIEM** | 100% | 0s | ⭐⭐⭐⭐⭐ | ⭐ | €€€€€ |

---

## 💡 Recommandation Finale Personnalisée

**Pour vous** (basé sur votre question) :

### Si vous avez < 200 règles :
→ **PySigma + 20 règles manuelles** (effort : 2 semaines)

### Si vous avez 200-500 règles :
→ **StoW amélioré + Chainsaw optimisé** (effort : 1 mois)

### Si vous avez > 500 règles :
→ **Architecture Hybride complète** (effort : 2-3 mois)

---

## 🔧 Scripts d'Aide

### Analyser votre corpus Sigma
```bash
# sigma_analyze.sh
#!/bin/bash

echo "=== Analyse Corpus Sigma ==="

total=$(find sigma/rules -name "*.yml" | wc -l)
timeframe=$(grep -r "timeframe:" sigma/rules | wc -l)
count_agg=$(grep -r "count()" sigma/rules | wc -l)
complex_or=$(grep -r "condition:.*or.*or" sigma/rules | wc -l)

echo "Total règles: $total"
echo "Avec timeframe: $timeframe ($(($timeframe * 100 / $total))%)"
echo "Avec count(): $count_agg ($(($count_agg * 100 / $total))%)"
echo "OR complexes: $complex_or ($(($complex_or * 100 / $total))%)"

complexity_score=$(($timeframe + $count_agg + $complex_or))
complexity_pct=$(($complexity_score * 100 / $total))

echo ""
echo "Score complexité: $complexity_pct%"

if [ $complexity_pct -lt 15 ]; then
    echo "→ RECOMMANDATION: PySigma seul suffit"
elif [ $complexity_pct -lt 30 ]; then
    echo "→ RECOMMANDATION: StoW amélioré + Chainsaw pour exceptions"
else
    echo "→ RECOMMANDATION: Architecture Hybride complète"
fi
```

### Tester la fidélité de conversion
```bash
# test_fidelity.sh
#!/bin/bash

echo "=== Test Fidélité Conversion ==="

# Convertir avec PySigma
sigma convert -t wazuh rules/test_set/ -o pysigma_output.xml

# Convertir avec StoW
./stow --config test_config.yaml

# Comparer
diff <(xmllint --format pysigma_output.xml | grep -v "<!--") \
     <(xmllint --format sigma_windows.xml | grep -v "<!--") \
     > conversion_diff.txt

lines_diff=$(wc -l < conversion_diff.txt)
echo "Différences: $lines_diff lignes"

if [ $lines_diff -lt 100 ]; then
    echo "✓ Conversions similaires"
else
    echo "⚠ Conversions divergent significativement"
fi
```

---

## 📚 Ressources

- **PySigma** : https://github.com/SigmaHQ/pySigma
- **PySigma-Backend-Wazuh** : https://github.com/AttackIQ/pySigma-backend-wazuh
- **Chainsaw** : https://github.com/WithSecureLabs/chainsaw
- **StoW** : https://github.com/theflakes/StoW (référence originale)
- **Wazuh Ruleset Docs** : https://documentation.wazuh.com/current/user-manual/ruleset/

---

## ❓ FAQ

**Q: Puis-je combiner StoW et PySigma ?**
A: Oui ! Utilisez PySigma pour la baseline, StoW pour les règles spécifiques nécessitant ses optimisations Go.

**Q: Chainsaw fonctionne-t-il sur Linux ?**
A: Principalement Windows (EVTX). Pour Linux, utilisez conversions statiques.

**Q: Quelle solution a le meilleur ROI ?**
A: **PySigma** pour démarrage rapide, **Hybride** pour long terme.

**Q: Combien de règles puis-je raisonnablement gérer ?**
A: Wazuh peut gérer 10,000+ règles, mais >2000 règles complexes impactent la performance. Optimisez via CDB lists et regex efficaces.
