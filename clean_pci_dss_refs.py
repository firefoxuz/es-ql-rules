#!/usr/bin/env python3
"""
Script to remove "Requirement " prefix from PCI-DSS compliance references.
Example:
  - pci_dss: ["Requirement 10.5"] → pci_dss: ["10.5"]
"""

import os
import re
from pathlib import Path


def transform_pci_dss_line(line: str) -> str:
    """
    Remove "Requirement " prefix from PCI-DSS references in a YAML line.
    
    Args:
        line: A line from a YAML file
        
    Returns:
        The transformed line
    """
    # Pattern to match pci_dss field with "Requirement "
    # Match both array format: pci_dss: ["Requirement X"] 
    # And string format: pci_dss: "Requirement X"
    
    # For array format
    pattern_array = r'(pci_dss:\s*\[)([^\]]+)(\])'
    
    def replace_in_array(match):
        prefix = match.group(1)
        content = match.group(2)
        suffix = match.group(3)
        
        # Remove "Requirement " from content
        content = content.replace('"Requirement ', '"').replace("'Requirement ", "'")
        
        return prefix + content + suffix
    
    line = re.sub(pattern_array, replace_in_array, line)
    
    # For string format (not in array)
    pattern_string = r'(pci_dss:\s*)"Requirement\s+([^"]+)"'
    line = re.sub(pattern_string, r'\1"\2"', line)
    
    pattern_string_single = r"(pci_dss:\s*)'Requirement\s+([^']+)'"
    line = re.sub(pattern_string_single, r"\1'\2'", line)
    
    return line


def process_yaml_file(filepath: Path) -> tuple[bool, int]:
    """
    Process a single YAML file and remove "Requirement " prefix from PCI-DSS references.
    
    Args:
        filepath: Path to the YAML file
        
    Returns:
        Tuple of (was_modified, num_changes)
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        modified = False
        num_changes = 0
        new_lines = []
        
        for line in lines:
            new_line = transform_pci_dss_line(line)
            if new_line != line:
                modified = True
                num_changes += 1
            new_lines.append(new_line)
        
        if modified:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)
        
        return modified, num_changes
    
    except Exception as e:
        print(f"Error processing {filepath}: {e}")
        return False, 0


def main():
    """Main function to process all YAML files in specified directories."""
    
    # Get the script directory
    script_dir = Path(__file__).parent
    
    # Directories to process (focusing on nist-800-53 but checking all)
    directories = [
        script_dir / 'nist-800-53',
        script_dir / 'gdpr-all',
        script_dir / 'hipaa',
        script_dir / 'pci-dss-all',
    ]
    
    total_files = 0
    total_modified = 0
    total_changes = 0
    
    for directory in directories:
        if not directory.exists():
            print(f"Directory not found: {directory}")
            continue
        
        print(f"\nProcessing directory: {directory.name}")
        print("=" * 60)
        
        yaml_files = list(directory.glob('*.yml'))
        dir_modified = 0
        dir_changes = 0
        
        for yaml_file in yaml_files:
            was_modified, num_changes = process_yaml_file(yaml_file)
            total_files += 1
            
            if was_modified:
                dir_modified += 1
                total_modified += 1
                dir_changes += num_changes
                total_changes += num_changes
                print(f"✓ {yaml_file.name}: {num_changes} line(s) modified")
        
        if dir_modified > 0:
            print(f"\nDirectory summary: {dir_modified}/{len(yaml_files)} files modified, {dir_changes} total changes")
        else:
            print(f"No changes needed in this directory")
    
    print("\n" + "=" * 60)
    print(f"TOTAL: {total_modified}/{total_files} files modified")
    print(f"TOTAL CHANGES: {total_changes} lines")
    print("=" * 60)


if __name__ == '__main__':
    main()
