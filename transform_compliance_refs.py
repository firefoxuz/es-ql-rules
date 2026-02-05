#!/usr/bin/env python3
"""
Script to transform compliance references from bracket notation to dot notation.
Examples:
  - §164.312(b) → 164.312.b
  - §164.406, §164.408 → 164.406, 164.408
  - §164.310(d)(1) → 164.310.d.1
  - Article 5(1)(c) → Article 5.1.c
"""

import os
import re
from pathlib import Path


def transform_reference(ref: str) -> str:
    """
    Transform a single reference from bracket notation to dot notation.
    
    Args:
        ref: The reference string to transform
        
    Returns:
        The transformed reference string
    """
    # Remove § symbol
    ref = ref.replace('§', '')
    
    # Replace parentheses with dots
    # Pattern: (X) -> .X
    ref = re.sub(r'\(([^)]+)\)', r'.\1', ref)
    
    return ref


def transform_yaml_line(line: str) -> str:
    """
    Transform compliance references in a YAML line.
    
    Args:
        line: A line from a YAML file
        
    Returns:
        The transformed line
    """
    # Match patterns like: hipaa: ["§164.312(b)"] or gdpr: ["Article 5(1)(c)"]
    # We need to find the array content and transform it
    
    # Pattern to match the compliance field arrays
    pattern = r'((?:hipaa|gdpr|pci_dss|nist):\s*\[)([^\]]+)(\])'
    
    def replace_array_content(match):
        prefix = match.group(1)  # Field name and opening bracket
        content = match.group(2)  # Array content
        suffix = match.group(3)  # Closing bracket
        
        # Split by comma to handle multiple references
        items = [item.strip() for item in content.split(',')]
        
        # Transform each item
        transformed_items = []
        for item in items:
            # Remove quotes to work with the content
            if item.startswith('"') and item.endswith('"'):
                inner = item[1:-1]
                transformed = transform_reference(inner)
                transformed_items.append(f'"{transformed}"')
            elif item.startswith("'") and item.endswith("'"):
                inner = item[1:-1]
                transformed = transform_reference(inner)
                transformed_items.append(f"'{transformed}'")
            else:
                # No quotes, just transform
                transformed_items.append(transform_reference(item))
        
        # Reconstruct the line
        return prefix + ', '.join(transformed_items) + suffix
    
    # Apply the transformation
    return re.sub(pattern, replace_array_content, line)


def process_yaml_file(filepath: Path) -> tuple[bool, int]:
    """
    Process a single YAML file and transform compliance references.
    
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
            new_line = transform_yaml_line(line)
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
        script_dir / 'nist-800-53',
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
        
        print(f"\nDirectory summary: {dir_modified}/{len(yaml_files)} files modified, {dir_changes} total changes")
    
    print("\n" + "=" * 60)
    print(f"TOTAL: {total_modified}/{total_files} files modified")
    print(f"TOTAL CHANGES: {total_changes} lines")
    print("=" * 60)


if __name__ == '__main__':
    main()
