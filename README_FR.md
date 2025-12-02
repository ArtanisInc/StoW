# 🔄 StoW - Sigma to Wazuh Converter

<div align="center">

![Version](https://img.shields.io/badge/version-2.0-blue)
![Go](https://img.shields.io/badge/Go-1.19+-00ADD8?logo=go)
![License](https://img.shields.io/badge/license-MIT-green)

**Convertisseur automatique de règles Sigma vers Wazuh XML**

[🇬🇧 English](./README.md) | [🇫🇷 Français](./README_FR.md)

</div>

---

## 📖 Description

**StoW** (Sigma to Wazuh) est un outil en Go qui convertit automatiquement les règles de détection Sigma en règles XML Wazuh prêtes à l'emploi.

### ✨ Fonctionnalités

- ✅ **Conversion automatique** de 3000+ règles Sigma → Wazuh
- ✅ **Support multi-plateformes**: Windows, Linux, Azure, M365, AWS, GCP
- ✅ **Support CIDR** pour les adresses IP (srcip/dstip)
- ✅ **Field mappings configurables** par produit
- ✅ **Génération par produit** (fichiers XML séparés)
- ✅ **Tags MITRE ATT&CK** préservés
- ✅ **Traçabilité** complète (liens vers règles Sigma sources)

### 📊 Statistiques de Conversion

| Métrique | Valeur |
|----------|--------|
| **Règles Sigma (Core)** | 3,076 |
| **Taux de conversion** | 88.07% |
| **Règles Wazuh générées** | 4,558 |
| **Plateformes supportées** | 6+ |

---

## 🚀 Démarrage Rapide

### Installation (5 minutes)

```bash
# 1. Cloner le repo
git clone https://github.com/[votre-org]/StoW.git
cd StoW

# 2. Télécharger les règles Sigma
cd .. && git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git
cd sigma && git sparse-checkout set rules && cd ../StoW

# 3. Compiler
go build -ldflags="-s -w"

# 4. Convertir
./StoW
```

### Résultat

```
Created sigma_windows.xml with 4106 rules
Created sigma_linux.xml with 300 rules
Created sigma_azure.xml with 134 rules
Created sigma_m365.xml with 18 rules

Sigma rules converted: 2709 / 3076 (88.07%)
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [🚀 Quick Start](./QUICK_START.md) | Démarrage en 5 minutes |
| [📘 Tutorial](./TUTORIAL.md) | Guide complet et détaillé |
| [⚙️ Configuration](./config.yaml) | Fichier de configuration |

---

## 🎯 Cas d'Usage

### 1. Environnement Windows (Sysmon)

```yaml
# config.yaml
ConvertProducts:
  - windows
```

**Résultat:** 4,106 règles Windows prêtes pour Wazuh

### 2. Serveurs Linux (auditd)

```yaml
ConvertProducts:
  - linux
```

**Résultat:** 300 règles Linux auditd

### 3. Cloud (Azure + M365)

```yaml
ConvertProducts:
  - azure
  - m365
```

**Résultat:** 134 règles Azure + 18 règles M365

---

## 🔧 Configuration

### Fichier `config.yaml`

```yaml
Sigma:
  # Produits à convertir
  ConvertProducts:
    - windows
    - linux
    - azure
    - m365

  # Chemin des règles Sigma
  RulesRoot: ../sigma/rules

Wazuh:
  # Mappings Sigma → Wazuh par produit
  FieldMappings:
    Linux:
      CommandLine: audit.command
      Image: audit.exe
      a0: audit.execve.a0
      # ... etc

    Windows:
      CommandLine: win.eventdata.commandLine
      Image: win.eventdata.image
      # ... etc

  # Niveaux de sévérité
  LevelMap:
    informational: 3
    low: 5
    medium: 7
    high: 10
    critical: 13
```

---

## 📤 Intégration Wazuh

### 1. Copier les Règles

```bash
scp sigma_*.xml root@wazuh-server:/var/ossec/etc/rules/
```

### 2. Activer dans ossec.conf

```xml
<ossec_config>
  <rules>
    <include>sigma_windows.xml</include>
    <include>sigma_linux.xml</include>
  </rules>
</ossec_config>
```

### 3. Redémarrer

```bash
systemctl restart wazuh-manager
```

### 4. Tester

```bash
/var/ossec/bin/wazuh-logtest
```

---

## 🆕 Nouveautés v2.0

### Support CIDR (IP Filtering)

Les règles Sigma avec modificateur `|cidr` sont maintenant converties:

**Sigma:**
```yaml
selection:
  SourceIp|cidr:
    - 10.0.0.0/8
    - 192.168.0.0/16
```

**Wazuh généré:**
```xml
<srcip negate="yes">10.0.0.0/8</srcip>
<srcip negate="yes">192.168.0.0/16</srcip>
```

### Field Mappings Linux Corrigés

Les champs Linux utilisent maintenant le format Wazuh correct:

| Avant (❌) | Après (✅) |
|-----------|-----------|
| `linux.auditd.a0` | `audit.execve.a0` |
| `linux.auditd.exe` | `audit.exe` |
| `linux.auditd.name` | `audit.directory.name` |

### Génération Multi-Fichiers

Un fichier XML par produit pour une meilleure organisation:

```
sigma_windows.xml    (4,106 règles)
sigma_linux.xml      (300 règles)
sigma_azure.xml      (134 règles)
sigma_m365.xml       (18 règles)
```

---

## 🏗️ Architecture

```
StoW/
├── stow.go              # Code principal
├── config.yaml          # Configuration
├── TUTORIAL.md          # Documentation complète
├── QUICK_START.md       # Guide rapide
├── README_FR.md         # Ce fichier
│
├── sigma_*.xml          # Fichiers générés (sortie)
├── rule_ids.json        # Mapping Sigma ID → Wazuh ID
│
└── ../sigma/rules/      # Règles Sigma sources
    ├── windows/
    ├── linux/
    ├── cloud/
    └── ...
```

---

## 🔍 Exemples de Règles Générées

### Exemple 1: Linux Audio Capture

```xml
<rule id="900152" level="7">
  <info type="link">https://github.com/SigmaHQ/sigma/...</info>
  <!--     Author: Pawel Mazur-->
  <!--Description: Detects audio recording attempts-->
  <!--   Sigma ID: a7af2487-9c2f-42e4-9bb9-ff961f0561d5-->

  <mitre>
    <id>attack.collection</id>
    <id>attack.t1123</id>
  </mitre>

  <description>Audio Capture</description>
  <group>linux,auditd,</group>

  <field name="audit.type" type="pcre2">(?i)EXECVE</field>
  <field name="audit.execve.a0" type="pcre2">(?i)arecord</field>
  <field name="audit.execve.a1" type="pcre2">(?i)-vv</field>
</rule>
```

### Exemple 2: Windows Process Creation

```xml
<rule id="900500" level="10">
  <description>Suspicious PowerShell Execution</description>
  <group>windows,sysmon,</group>

  <field name="win.eventdata.commandLine" type="pcre2">(?i)powershell.*-enc</field>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
</rule>
```

### Exemple 3: Azure avec CIDR

```xml
<rule id="901200" level="13">
  <description>External RDP Logon from Public IP</description>
  <group>windows,security,</group>

  <srcip negate="yes">10.0.0.0/8</srcip>
  <srcip negate="yes">192.168.0.0/16</srcip>
  <field name="win.eventdata.logonType" type="pcre2">(?i)10</field>
</rule>
```

---

## 🛠️ Développement

### Prérequis

- Go 1.19+
- Git

### Build

```bash
# Standard
go build

# Optimisé (taille réduite)
go build -ldflags="-s -w"

# Cross-compilation
GOOS=linux GOARCH=amd64 go build
```

### Tests

```bash
go test ./...
```

---

## 🤝 Contribution

Les contributions sont les bienvenues!

1. Fork le projet
2. Créer une branche (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

---

## 📊 Statistiques Détaillées

### Règles Sigma par Plateforme (Core)

| Plateforme | Nombre | % |
|------------|--------|---|
| Windows | 2,356 | 76.6% |
| Cloud (Azure, AWS, GCP, M365) | 226 | 7.3% |
| Linux | 205 | 6.7% |
| Applications | 150 | 4.9% |
| Network | 100 | 3.3% |
| Web | 39 | 1.3% |
| **TOTAL** | **3,076** | **100%** |

### Règles Wazuh Générées

| Produit | Règles Wazuh |
|---------|--------------|
| Windows | 4,106 |
| Linux | 300 |
| Azure | 134 |
| M365 | 18 |
| **TOTAL** | **4,558** |

---

## 🐛 Problèmes Connus

| Problème | Status | Workaround |
|----------|--------|------------|
| ~~CIDR modifier non supporté~~ | ✅ Résolu v2.0 | N/A |
| ~~Field mappings Linux incorrects~~ | ✅ Résolu v2.0 | N/A |
| Timeframe operator | ⚠️ Non supporté | Exclure ces règles |
| NEAR operator | ⚠️ Non supporté | Exclure ces règles |

---

## 📜 Changelog

### v2.0.0 (2025-12-01)

- ✅ Ajout support CIDR (srcip/dstip)
- ✅ Correction field mappings Linux (audit.* au lieu de linux.auditd.*)
- ✅ Ajout arguments a4-a7 pour Linux
- ✅ Génération multi-fichiers par produit
- ✅ Documentation complète (FR/EN)

### v1.0.0

- ✅ Conversion basique Sigma → Wazuh
- ✅ Support Windows, Linux, Azure, M365

---

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

---

## 🙏 Remerciements

- [Sigma HQ](https://github.com/SigmaHQ/sigma) - Règles de détection Sigma
- [Wazuh](https://wazuh.com/) - Plateforme SIEM open-source
- [SocFortress](https://github.com/socfortress/Wazuh-Rules) - Exemples de règles Wazuh

---

## 📞 Support

- 📧 Email: [support@example.com]
- 💬 Discord: [Lien Discord]
- 🐛 Issues: [GitHub Issues](https://github.com/[votre-org]/StoW/issues)
- 📖 Docs: [TUTORIAL.md](./TUTORIAL.md)

---

<div align="center">

**Fait avec ❤️ pour la communauté SOC**

⭐ **Si ce projet vous aide, n'hésitez pas à lui donner une étoile!** ⭐

</div>
