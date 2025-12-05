# 🚀 Guide de Démarrage Rapide - StoW

Guide ultra-rapide pour commencer en 5 minutes.

---

## ⚡ Installation Express (5 minutes)

```bash
# 1. Télécharger les règles Sigma
cd ..
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git
cd sigma && git sparse-checkout set rules && cd ../StoW

# 2. Compiler
go build -ldflags="-s -w"

# 3. Convertir
./StoW
```

**C'est tout!** Vous avez maintenant vos fichiers XML.

---

## 📝 Configuration Minimale

Éditez `config.yaml` pour choisir vos produits:

```yaml
Sigma:
  ConvertProducts:
    - windows           # ✅ Activé
    - linux             # ✅ Activé
    - azure             # ❌ Désactivé si non utilisé
    - m365              # ❌ Désactivé si non utilisé
```

---

## 📤 Déploiement sur Wazuh (2 minutes)

```bash
# Copier les règles
scp sigma_*.xml root@wazuh-server:/var/ossec/etc/rules/

# Sur le serveur Wazuh
ssh root@wazuh-server
chown wazuh:wazuh /var/ossec/etc/rules/sigma_*.xml
```

Ajouter dans `/var/ossec/etc/ossec.conf`:

```xml
<rules>
  <include>sigma_windows.xml</include>
  <include>sigma_linux.xml</include>
</rules>
```

Redémarrer:

```bash
systemctl restart wazuh-manager
```

---

## ✅ Test Rapide

```bash
# Tester une règle
echo '{"audit":{"type":"EXECVE","execve":{"a0":"nc"}}}' | /var/ossec/bin/wazuh-logtest
```

---

## 📊 Résultats Attendus

```
✓ sigma_windows.xml    (~4,106 règles)
✓ sigma_linux.xml      (~300 règles)
✓ sigma_azure.xml      (~134 règles)
✓ sigma_m365.xml       (~18 règles)
```

---

## 🔥 Commandes Utiles

```bash
# Reconvertir après modification config
./StoW

# Vérifier une règle dans Wazuh
grep "id=\"900152\"" sigma_linux.xml

# Compter les règles générées
wc -l sigma_*.xml

# Mettre à jour Sigma et reconvertir
cd ../sigma && git pull && cd ../StoW && ./StoW
```

---

## 🆘 Problèmes Courants

| Problème | Solution |
|----------|----------|
| "No rules found" | Vérifier `../sigma/rules/` existe |
| Conversion rate 50% | Activer plus de produits dans config.yaml |
| Règles ne se déclenchent pas | Vérifier les field mappings et if_sid |

---

## 📚 Documentation Complète

Pour plus de détails, voir [TUTORIAL.md](./TUTORIAL.md)

---

**En 5 minutes, vous avez converti 3000+ règles Sigma! 🎉**
