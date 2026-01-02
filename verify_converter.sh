#!/bin/bash
# Comprehensive Converter Verification Script
# Checks XML validity, rule structure, and conversion statistics

echo "======================================"
echo "StoW Converter Verification"
echo "======================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ERRORS=0
WARNINGS=0

# 1. Check if all expected files exist
echo "[1] Checking Expected Files..."
EXPECTED_FILES=(
    "100000-sysmon_new_events.xml"
    "109970-windows_builtin_channels_parent.xml"
    "200000-windows_powershell_parent.xml"
    "200100-windows_eventid_parent.xml"
    "210000-linux_auditd_parent.xml"
    "200400-sigma_windows_part1.xml"
    "200400-sigma_windows_part2.xml"
    "200400-sigma_windows_part3.xml"
    "200400-sigma_windows_part4.xml"
    "200400-sigma_windows_part5.xml"
    "200400-sigma_windows_part6.xml"
    "200400-sigma_windows_part7.xml"
    "210007-sigma_linux.xml"
)

for file in "${EXPECTED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} Found: $file"
    else
        echo -e "${RED}✗${NC} Missing: $file"
        ((ERRORS++))
    fi
done
echo ""

# 2. Validate XML syntax
echo "[2] Validating XML Syntax..."
for file in *.xml; do
    if xmllint --noout "$file" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Valid XML: $file"
    else
        echo -e "${RED}✗${NC} Invalid XML: $file"
        xmllint --noout "$file" 2>&1 | head -5
        ((ERRORS++))
    fi
done
echo ""

# 3. Check for required XML elements in rules
echo "[3] Checking Rule Structure..."
for file in 200400-sigma_windows_part*.xml 210007-sigma_linux.xml; do
    if [ ! -f "$file" ]; then
        continue
    fi

    # Check for rule tags
    rule_count=$(grep -c '<rule id=' "$file" 2>/dev/null || echo 0)
    if_sid_count=$(grep -c '<if_sid>' "$file" 2>/dev/null || echo 0)
    description_count=$(grep -c '<description>' "$file" 2>/dev/null || echo 0)

    echo "File: $file"
    echo "  Rules: $rule_count"
    echo "  Parent refs (if_sid): $if_sid_count"
    echo "  Descriptions: $description_count"

    if [ "$rule_count" -eq 0 ]; then
        echo -e "${RED}✗${NC} No rules found in $file"
        ((ERRORS++))
    elif [ "$if_sid_count" -lt "$rule_count" ]; then
        echo -e "${YELLOW}⚠${NC} Some rules may not have parent rule references"
        ((WARNINGS++))
    fi
done
echo ""

# 4. Check parent rules
echo "[4] Checking Parent Rules..."
PARENT_FILES=(
    "100000-sysmon_new_events.xml"
    "109970-windows_builtin_channels_parent.xml"
    "200000-windows_powershell_parent.xml"
    "200100-windows_eventid_parent.xml"
    "210000-linux_auditd_parent.xml"
)

for file in "${PARENT_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}✗${NC} Missing parent file: $file"
        ((ERRORS++))
        continue
    fi

    parent_count=$(grep -c '<rule id=' "$file" 2>/dev/null || echo 0)
    if [ "$parent_count" -eq 0 ]; then
        echo -e "${RED}✗${NC} No parent rules in: $file"
        ((ERRORS++))
    else
        echo -e "${GREEN}✓${NC} $file has $parent_count parent rules"
    fi
done
echo ""

# 5. Check for Wazuh compliance
echo "[5] Checking Wazuh Compliance..."
for file in 200400-sigma_windows_part*.xml 210007-sigma_linux.xml; do
    if [ ! -f "$file" ]; then
        continue
    fi

    # Check for no_full_log option (best practice)
    no_full_log_count=$(grep -c '<options>no_full_log</options>' "$file" 2>/dev/null || echo 0)
    rule_count=$(grep -c '<rule id=' "$file" 2>/dev/null || echo 0)

    if [ "$no_full_log_count" -gt 0 ]; then
        echo -e "${GREEN}✓${NC} $file: $no_full_log_count/$rule_count rules use no_full_log"
    else
        echo -e "${YELLOW}⚠${NC} $file: No rules use no_full_log option"
        ((WARNINGS++))
    fi
done
echo ""

# 6. Check CDB lists
echo "[6] Checking CDB Lists..."
if [ -d "lists" ]; then
    cdb_count=$(ls -1 lists/sigma_* 2>/dev/null | wc -l)
    if [ "$cdb_count" -gt 0 ]; then
        echo -e "${GREEN}✓${NC} Found $cdb_count CDB list files"
        ls -lh lists/sigma_* | awk '{print "  " $9 " (" $5 ")"}'
    else
        echo -e "${YELLOW}⚠${NC} No CDB list files found"
        ((WARNINGS++))
    fi
else
    echo -e "${YELLOW}⚠${NC} No lists directory found"
    ((WARNINGS++))
fi
echo ""

# 7. Check rule_ids.json
echo "[7] Checking Rule ID Tracking..."
if [ -f "rule_ids.json" ]; then
    echo -e "${GREEN}✓${NC} rule_ids.json exists"
    file_size=$(du -h rule_ids.json | cut -f1)
    echo "  Size: $file_size"
    rule_mapping_count=$(grep -c '"' rule_ids.json 2>/dev/null || echo 0)
    echo "  Approximate mappings: $rule_mapping_count"
else
    echo -e "${YELLOW}⚠${NC} rule_ids.json not found"
    ((WARNINGS++))
fi
echo ""

# 8. Summary
echo "======================================"
echo "Verification Summary"
echo "======================================"
if [ $ERRORS -eq 0 ] && [ $WARNINGS -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    exit 0
elif [ $ERRORS -eq 0 ]; then
    echo -e "${YELLOW}⚠ Passed with $WARNINGS warnings${NC}"
    exit 0
else
    echo -e "${RED}✗ Failed with $ERRORS errors and $WARNINGS warnings${NC}"
    exit 1
fi
