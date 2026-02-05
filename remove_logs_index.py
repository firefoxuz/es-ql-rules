#!/usr/bin/env python3
"""
Script to remove 'logs-*' index pattern from YAML files.
Removes from both:
1. index: arrays
2. FROM clauses in queries
"""

import os
import re
from pathlib import Path


def remove_logs_index(line: str) -> str:
    """
    Remove 'logs-*' from index arrays and FROM clauses.
    
    Args:
        line: A line from a YAML file
        
    Returns:
        The cleaned line
    """
    # Skip if line doesn't contain 'logs-*'
    if 'logs-*' not in line:
        return line
    
    # Handle index array format: "  - logs-*"
    if re.match(r'^\s*-\s+logs-\*\s*$', line):
        return ''  # Remove the entire line
    
    # Handle FROM clause - remove logs-* and clean up commas
    if 'FROM' in line:
        # Remove 'logs-*,' or ', logs-*' patterns
        line = re.sub(r',\s*logs-\*', '', line)
        line = re.sub(r'logs-\*\s*,\s*', '', line)
        # Remove standalone 'logs-*' if it's the only index left
        line = re.sub(r'FROM\s+logs-\*\s*$', 'FROM ', line)
    
    return line


def process_yaml_file(filepath: Path) -> tuple[bool, int]:
    """
    Process a single YAML file and remove logs-* references.
    
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
            new_line = remove_logs_index(line)
            
            # Skip empty lines that were index entries
            if new_line == '' and line.strip() != '':
                modified = True
                num_changes += 1
                continue
                
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
    
    # Directories to process
    directories = [
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
                print(f"✓ {yaml_file.name}: {num_changes} change(s)")
        
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
