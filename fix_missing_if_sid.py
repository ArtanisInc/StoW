#!/usr/bin/env python3
"""
Fix all Wazuh rules missing if_sid references.

This script:
1. Identifies rules without if_sid
2. Maps them to correct parent rules based on groups/EventIDs
3. Patches the XML files to add if_sid tags
"""

import re
import glob
from pathlib import Path

# Mapping of group names to parent IDs
GROUP_TO_PARENT = {
    # Windows built-in channels
    'driver-framework': '109999',
    'driverframeworks': '109999',

    # Windows Defender - needs manual checking (might use EventID)
    'windefend': None,  # Will be determined from EventID/Channel

    # Sysmon events (from official Wazuh + extended events)
    'sysmon_error': '61600',  # Base Sysmon parent
    'file_access': '61617',   # Sysmon Event 15
    'file_delete': '109212',  # Sysmon Event 26
    'file_rename': '61604',   # Sysmon Event 2
    'file_executable_detected': None,  # Need to check EventID

    # PowerShell
    'powershell-classic': None,  # Determined by EventID (200002-200004)
    'ps_classic': None,

    # Linux - various
    'clamav': None,  # No parent
    'cron': None,    # No parent
    'guacamole': None,  # No parent
    'sshd': None,    # No parent
    'syslog': None,  # No parent
    'vsftpd': None,  # No parent
}

def find_parent_for_rule(rule_id, rule_content, groups):
    """Determine the correct parent ID for a rule based on groups and content."""

    # DriverFrameworks (USB detection, etc.)
    if 'driver-framework' in groups or 'driverframeworks' in groups:
        return '109999'

    # Sysmon Events
    if 'sysmon_error' in groups:
        return '61600'  # Base Sysmon parent from Wazuh official rules

    if 'file_access' in groups:
        return '61617'  # Sysmon Event 15 (File Stream Creation)

    if 'file_delete' in groups:
        return '109212'  # Sysmon Event 26 (FileDeleteDetected)

    if 'file_rename' in groups:
        return '61604'  # Sysmon Event 2 (File Rename)

    if 'file_executable_detected' in groups:
        # Event 29 - no parent exists yet
        return None

    # PowerShell Classic - determine by EventID
    if 'powershell-classic' in groups or 'ps_classic' in groups:
        if 'eventID">400<' in rule_content or 'eventID">^400$<' in rule_content:
            return '200002'
        elif 'eventID">403<' in rule_content or 'eventID">^403$<' in rule_content:
            return '200003'
        elif 'eventID">600<' in rule_content or 'eventID">^600$<' in rule_content:
            return '200004'
        # If EventID not found, check pcre2 patterns
        if re.search(r'eventID.*400', rule_content, re.IGNORECASE):
            return '200002'
        if re.search(r'eventID.*403', rule_content, re.IGNORECASE):
            return '200003'
        if re.search(r'eventID.*600', rule_content, re.IGNORECASE):
            return '200004'
        return None

    # Windows Defender - no parent exists (rules work without parent)
    if 'windefend' in groups:
        return None

    # Generic Windows rule (e.g., Mimikatz detection) - no parent needed
    if rule_id == '200772':
        return None

    # Linux rules - most don't need parents
    # These are product-level rules without specific service/category
    linux_no_parent_groups = [
        'clamav', 'cron', 'guacamole', 'sshd', 'syslog', 'vsftpd',
        'linux,',  # Generic Linux with no specific category
    ]

    for group in linux_no_parent_groups:
        if group in groups:
            return None

    # Default: no parent
    return None

def patch_rule_with_if_sid(rule_block, parent_id):
    """Add if_sid tag to a rule block."""

    # Find the position after <rule id="...">
    match = re.search(r'(<rule id="[^"]+"[^>]*>\n)', rule_block)
    if not match:
        return rule_block

    # Check if if_sid already exists
    if '<if_sid>' in rule_block:
        return rule_block

    # Insert if_sid after the rule opening tag
    insertion_point = match.end()
    if_sid_tag = f'    <if_sid>{parent_id}</if_sid>\n'

    patched = rule_block[:insertion_point] + if_sid_tag + rule_block[insertion_point:]
    return patched

def main():
    xml_files = (
        glob.glob('200400-sigma_windows_part*.xml') +
        glob.glob('210007-sigma_linux.xml')
    )

    total_patched = 0
    total_skipped = 0

    for xml_file in sorted(xml_files):
        if not Path(xml_file).exists():
            continue

        print(f"\nProcessing {xml_file}...")

        with open(xml_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Find all rule blocks
        rule_pattern = r'(<rule id="(\d+)"[^>]*>.*?</rule>)'
        rules = list(re.finditer(rule_pattern, content, re.DOTALL))

        file_modified = False
        new_content = content
        offset = 0  # Track position changes as we patch

        for match in rules:
            rule_block = match.group(1)
            rule_id = match.group(2)

            # Skip rules that already have if_sid
            if '<if_sid>' in rule_block:
                continue

            # Extract groups
            group_match = re.search(r'<group>(.*?)</group>', rule_block)
            groups = group_match.group(1).lower() if group_match else ''

            # Determine parent
            parent_id = find_parent_for_rule(rule_id, rule_block, groups)

            if parent_id:
                # Truncate groups for display
                groups_display = groups[:60] + '...' if len(groups) > 60 else groups
                print(f"  Rule {rule_id}: Adding if_sid={parent_id} (groups: {groups_display})")

                # Patch the rule block
                patched_block = patch_rule_with_if_sid(rule_block, parent_id)

                # Replace in content (accounting for offset)
                start_pos = match.start() + offset
                end_pos = match.end() + offset
                new_content = new_content[:start_pos] + patched_block + new_content[end_pos:]

                # Update offset
                offset += len(patched_block) - len(rule_block)
                file_modified = True
                total_patched += 1
            else:
                total_skipped += 1

        # Write back if modified
        if file_modified:
            with open(xml_file, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"  ✓ Patched {xml_file}")

    print(f"\n{'='*70}")
    print(f"Total rules patched: {total_patched}")
    print(f"Total rules skipped (no parent needed): {total_skipped}")
    print(f"{'='*70}")

if __name__ == '__main__':
    main()
