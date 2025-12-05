# 📘 Tutoriel StoW - Sigma to Wazuh Converter

Guide complet pour utiliser le convertisseur de règles Sigma vers Wazuh.

---

## 📋 Table des Matières

1. [Prérequis](#prérequis)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Utilisation Basique](#utilisation-basique)
5. [Utilisation Avancée](#utilisation-avancée)
6. [Fichiers de Sortie](#fichiers-de-sortie)
7. [Intégration avec Wazuh](#intégration-avec-wazuh)
8. [Dépannage](#dépannage)

---

## 🔧 Prérequis

### Logiciels Requis

- **Go** 1.19 ou supérieur
- **Git**
- Connexion Internet (pour télécharger les règles Sigma)

### Vérifier les installations

```bash
go version      # Go 1.19+ requis
git --version   # Git 2.x+ requis
```

---

## 📥 Installation

### 1. Cloner le repository

```bash
git clone https://github.com/[votre-repo]/StoW.git
cd StoW
```

### 2. Télécharger les règles Sigma

Le converter a besoin des règles Sigma. Vous avez deux options:

#### Option A: Core Rules uniquement (Recommandé pour débuter)

```bash
cd ..
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git
cd sigma
git sparse-checkout set rules
cd ../StoW
```

**Résultat:** ~3,076 règles (5.9 MB)

#### Option B: Toutes les règles (Core + Emerging Threats + Threat Hunting)

```bash
cd ..
git clone https://github.com/SigmaHQ/sigma.git
cd ../StoW
```

**Résultat:** ~8,000+ règles (20+ MB)

### 3. Compiler le converter

```bash
go build -ldflags="-s -w"
```

Cela crée l'exécutable `StoW` (ou `stow` sur certains systèmes).

### 4. Vérifier l'installation

```bash
./StoW --help     # Devrait afficher l'aide (si implémenté)
# OU
ls -lh StoW      # Vérifier que l'exécutable existe
```

---

## ⚙️ Configuration

### Fichier de Configuration Principal: `config.yaml`

#### 1. Choisir les Produits à Convertir

Éditez `config.yaml` section `ConvertProducts`:

```yaml
Sigma:
  ConvertProducts:
    - windows           # Règles Windows (Sysmon, Event Logs)
    - windows_defender  # Windows Defender
    - linux             # Linux auditd
    - azure             # Microsoft Azure
    - m365              # Microsoft 365
    - aws               # Amazon Web Services (optionnel)
```

**Conseils:**
- Commencez avec uniquement les produits que vous utilisez
- Plus de produits = plus de règles générées

#### 2. Configurer les Field Mappings

Les field mappings traduisent les champs Sigma vers les champs Wazuh.

**Exemple pour Linux (déjà configuré):**

```yaml
Wazuh:
  FieldMappings:
    Linux:
      CommandLine: audit.command
      Image: audit.exe
      a0: audit.execve.a0
      a1: audit.execve.a1
      # ... etc
```

**Exemple pour Windows (déjà configuré):**

```yaml
    Windows:
      CommandLine: win.eventdata.commandLine
      Image: win.eventdata.image
      User: win.eventdata.user
      # ... etc
```

⚠️ **Important:** Ne modifiez ces mappings que si vous savez comment Wazuh structure ses données!

#### 3. Niveaux de Sévérité

Configurez la correspondance entre niveaux Sigma et Wazuh:

```yaml
Sigma:
  LevelMap:
    informational: 3
    low: 5
    medium: 7
    high: 10
    critical: 13
```

---

## 🚀 Utilisation Basique

### Conversion Simple

```bash
./StoW
```

C'est tout! Le converter va:
1. ✅ Lire les règles Sigma depuis `../sigma/rules/`
2. ✅ Convertir selon `config.yaml`
3. ✅ Générer les fichiers XML par produit

### Résultat Attendu

```
Created sigma_windows.xml with 4106 rules
Created sigma_linux.xml with 300 rules
Created sigma_azure.xml with 134 rules
Created sigma_m365.xml with 18 rules

***************************************************************************
 Number of Sigma rules converted: 2709 / 3076
 Sigma rules converted %: 88.07
***************************************************************************
```

### Fichiers Générés

```
StoW/
├── sigma_windows.xml    # Règles Windows (le plus gros fichier)
├── sigma_linux.xml      # Règles Linux
├── sigma_azure.xml      # Règles Azure
├── sigma_m365.xml       # Règles Microsoft 365
└── rule_ids.json        # Mapping Sigma ID → Wazuh Rule ID
```

---

## 🎯 Utilisation Avancée

### 1. Convertir Uniquement Certaines Catégories

Éditez `config.yaml`:

```yaml
Sigma:
  ConvertCategories:
    - process_creation
    - network_connection
    - file_event
```

### 2. Exclure des Règles Spécifiques

Si une règle cause des problèmes, vous pouvez l'exclure:

```yaml
Sigma:
  SkipIds:
    - a7af2487-9c2f-42e4-9bb9-ff961f0561d5  # Sigma Rule ID à ignorer
    - 977ef627-4539-4875-adf4-ed8f780c4922
```

### 3. Mapper des Règles à des if_sid Spécifiques

Pour faire dépendre certaines règles de règles parent Wazuh:

```yaml
Wazuh:
  SigmaIdToWazuhId:
    # Faire dépendre toutes les règles Sysmon de la règle 18100
    windows:
      if_sid: "18100"

    # Règle spécifique
    a7af2487-9c2f-42e4-9bb9-ff961f0561d5:
      if_sid: "200110"
```

### 4. Règles avec Alertes Email

Activer les alertes email pour certaines règles:

```yaml
Wazuh:
  SigmaIdEmail:
    - a7af2487-9c2f-42e4-9bb9-ff961f0561d5  # Envoie email si détecté
```

---

## 📤 Fichiers de Sortie

### Structure d'une Règle Wazuh Générée

```xml
<rule id="900152" level="7">
  <info type="link">https://github.com/SigmaHQ/sigma/...</info>
  <!--     Author: John Doe-->
  <!--Description: Detects suspicious activity-->
  <!--    Created: 2021-09-04-->
  <!--   Sigma ID: a7af2487-9c2f-42e4-9bb9-ff961f0561d5-->

  <mitre>
    <id>attack.collection</id>
    <id>attack.t1123</id>
  </mitre>

  <description>Audio Capture</description>
  <options>no_full_log</options>
  <group>linux,auditd,</group>

  <!-- Champs de détection -->
  <field name="audit.type" type="pcre2">(?i)EXECVE</field>
  <field name="audit.execve.a0" type="pcre2">(?i)arecord</field>

  <!-- Support CIDR pour IPs -->
  <srcip negate="yes">10.0.0.0/8</srcip>
  <srcip negate="yes">192.168.0.0/16</srcip>
</rule>
```

### Comprendre les Règles Générées

| Élément | Description |
|---------|-------------|
| `id` | ID unique Wazuh (900000-999999) |
| `level` | Sévérité (3=info, 5=low, 7=medium, 10=high, 13=critical) |
| `<info>` | Lien vers la règle Sigma source |
| `<mitre>` | Tags MITRE ATT&CK |
| `<field>` | Conditions de détection (regex PCRE2) |
| `<srcip>/<dstip>` | Filtres IP avec support CIDR |
| `<options>` | Options Wazuh (no_full_log, alert_by_email, etc.) |
| `<if_sid>` | Dépendance vers règles parent |

---

## 🔗 Intégration avec Wazuh

### 1. Copier les Règles sur le Serveur Wazuh

```bash
# Sur votre machine locale
scp sigma_*.xml root@wazuh-server:/tmp/

# Sur le serveur Wazuh
ssh root@wazuh-server
cd /var/ossec/etc/rules/
cp /tmp/sigma_*.xml .
chown wazuh:wazuh sigma_*.xml
chmod 660 sigma_*.xml
```

### 2. Activer les Règles dans ossec.conf

Éditez `/var/ossec/etc/ossec.conf`:

```xml
<ossec_config>
  <rules>
    <include>sigma_windows.xml</include>
    <include>sigma_linux.xml</include>
    <include>sigma_azure.xml</include>
    <include>sigma_m365.xml</include>
  </rules>
</ossec_config>
```

### 3. Tester la Configuration

```bash
# Vérifier la syntaxe des règles
/var/ossec/bin/wazuh-logtest

# Redémarrer Wazuh
systemctl restart wazuh-manager
```

### 4. Vérifier que les Règles sont Chargées

```bash
# Compter les règles chargées
grep -r "rule id=\"90" /var/ossec/etc/rules/sigma_*.xml | wc -l

# Tester une règle spécifique
/var/ossec/bin/wazuh-logtest -U 900152
```

### 5. Exemple de Test avec wazuh-logtest

```bash
echo '{"audit":{"type":"EXECVE","execve":{"a0":"arecord","a1":"-vv"}}}' | /var/ossec/bin/wazuh-logtest
```

**Résultat attendu:**

```
**Phase 1: Completed pre-decoding.
**Phase 2: Completed decoding.
**Phase 3: Completed filtering (rules).
       Rule: 900152 (level 7) -> 'Audio Capture'
```

---

## 🎨 Personnalisation des Règles

### Modifier les Niveaux de Sévérité

Si vous trouvez qu'une règle a un niveau trop élevé/faible:

```yaml
# Dans config.yaml
Wazuh:
  LevelMap:
    high: 12      # Au lieu de 10
    critical: 15  # Au lieu de 13
```

### Ajouter des if_sid pour Réduire les Faux Positifs

```yaml
Wazuh:
  SigmaIdToWazuhId:
    windows:
      if_sid: "18100, 60000, 60001"  # Requiert un event Windows d'abord
    linux:
      if_sid: "200110"                # Requiert un event auditd d'abord
```

### Exclure des Règles Bruyantes

Après avoir testé en production, vous pouvez exclure les règles qui génèrent trop de faux positifs:

```yaml
Sigma:
  SkipIds:
    - a7af2487-9c2f-42e4-9bb9-ff961f0561d5  # Trop de faux positifs
```

Puis relancez la conversion:

```bash
./StoW
```

---

## 🐛 Dépannage

### Problème: "No rules converted"

**Cause:** Les règles Sigma ne sont pas trouvées.

**Solution:**

```bash
# Vérifier que ../sigma/rules existe
ls -la ../sigma/rules/

# Vérifier le chemin dans config.yaml
grep "RulesRoot" config.yaml
# Devrait afficher: RulesRoot: ../sigma/rules
```

### Problème: "Conversion rate only 50%"

**Cause:** Produits non configurés dans `ConvertProducts`.

**Solution:**

```yaml
Sigma:
  ConvertProducts:
    - windows          # Ajouter tous les produits que vous voulez
    - linux
    - azure
    - m365
```

### Problème: Les règles Wazuh ne se déclenchent pas

**Causes possibles:**

1. **Règles mal activées dans ossec.conf**

   ```bash
   # Vérifier ossec.conf
   grep "sigma_" /var/ossec/etc/ossec.conf
   ```

2. **Mauvais field mappings**

   ```bash
   # Vérifier qu'un événement contient les champs attendus
   tail -f /var/ossec/logs/archives/archives.json | grep audit
   ```

3. **if_sid incorrect**

   ```xml
   <!-- Si la règle a un if_sid, vérifier qu'il existe -->
   <if_sid>18100</if_sid>

   <!-- Vérifier que la règle 18100 existe -->
   grep "id=\"18100\"" /var/ossec/etc/rules/*.xml
   ```

### Problème: "CIDR rules skipped"

**Obsolète:** Ce problème est résolu dans la version actuelle. Les règles CIDR sont maintenant supportées.

### Problème: Fichiers XML trop gros

**Solution:** Diviser par catégorie ou niveau de sévérité.

1. Modifier le code pour filtrer par niveau:

   ```yaml
   Sigma:
     RuleStatus:
       - stable
       - test
     # Ne pas inclure 'experimental'
   ```

2. Ou utiliser uniquement certaines catégories Windows:

   ```yaml
   Sigma:
     ConvertCategories:
       - process_creation
       - network_connection
   ```

---

## 📊 Statistiques et Monitoring

### Voir le Mapping des IDs

```bash
# Ouvrir rule_ids.json
cat rule_ids.json | jq '.'

# Chercher un Sigma ID spécifique
cat rule_ids.json | jq '."a7af2487-9c2f-42e4-9bb9-ff961f0561d5"'
```

**Résultat:**

```json
{
  "a7af2487-9c2f-42e4-9bb9-ff961f0561d5": "900152"
}
```

### Statistiques de Conversion

Le converter affiche automatiquement:

```
Total Sigma rules: 3076
Total Sigma rules converted: 2709
Sigma rules converted %: 88.07
Rules skipped: 367
```

**Raisons de skip:**

- Produits non configurés (ex: MacOS, Zeek)
- Règles expérimentales
- Règles avec timeframe (non supporté)
- Règles avec NEAR operator (non supporté)

---

## 📚 Exemples d'Usage Complets

### Exemple 1: Environnement Windows uniquement

**But:** Convertir uniquement les règles Windows Sysmon.

```yaml
# config.yaml
Sigma:
  ConvertProducts:
    - windows
  ConvertCategories:
    - process_creation
    - network_connection
    - image_load
```

```bash
./StoW
# Résultat: sigma_windows.xml avec ~2000 règles
```

### Exemple 2: Environnement Cloud (Azure + M365)

```yaml
Sigma:
  ConvertProducts:
    - azure
    - m365
```

```bash
./StoW
# Résultat: sigma_azure.xml + sigma_m365.xml
```

### Exemple 3: Règles Linux auditd uniquement

```yaml
Sigma:
  ConvertProducts:
    - linux
```

```bash
./StoW
# Résultat: sigma_linux.xml avec ~300 règles
```

### Exemple 4: Tout Convertir

```yaml
Sigma:
  ConvertProducts:
    - windows
    - windows_defender
    - linux
    - azure
    - m365
    - aws
    - gcp
```

```bash
./StoW
# Résultat: 6+ fichiers XML avec 4000+ règles
```

---

## 🔄 Mise à Jour des Règles Sigma

Pour obtenir les dernières règles Sigma:

```bash
cd ../sigma
git pull origin master
cd ../StoW
./StoW  # Reconvertir
```

**Fréquence recommandée:** Mensuelle (ou à chaque release Sigma)

---

## 🎯 Bonnes Pratiques

### 1. Commencez Petit

- ✅ Convertissez d'abord uniquement Windows ou Linux
- ✅ Testez sur un environnement de dev
- ✅ Ajustez les if_sid et niveaux
- ✅ Puis déployez en production

### 2. Monitoring

- 📊 Surveillez le taux d'alertes par règle
- 📊 Identifiez les règles bruyantes
- 📊 Ajustez ou excluez via `SkipIds`

### 3. Documentation

- 📝 Gardez un changelog des modifications config.yaml
- 📝 Documentez les règles exclues et pourquoi
- 📝 Partagez les mappings customisés avec votre équipe

### 4. Version Control

```bash
git add config.yaml
git commit -m "Updated field mappings for Linux"
git push
```

---

## 🆘 Support et Ressources

### Documentation Officielle

- **Sigma:** https://github.com/SigmaHQ/sigma
- **Wazuh Rules:** https://documentation.wazuh.com/current/user-manual/ruleset/
- **PCRE2 Regex:** https://www.pcre.org/current/doc/html/

### Exemple de Règles Wazuh

- https://github.com/socfortress/Wazuh-Rules/

### Communauté

- Sigma Discord
- Wazuh Community Forums
- GitHub Issues

---

## 🎓 Conclusion

Vous savez maintenant:

✅ Installer et configurer StoW
✅ Convertir des règles Sigma → Wazuh
✅ Personnaliser les field mappings
✅ Intégrer les règles dans Wazuh
✅ Dépanner les problèmes courants

**Prochaines étapes:**

1. Convertir vos premières règles
2. Les tester avec wazuh-logtest
3. Les déployer en production
4. Monitorer et ajuster

Bonne détection! 🛡️
