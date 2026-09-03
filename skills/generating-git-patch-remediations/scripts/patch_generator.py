#!/usr/bin/env python3
"""
patch_generator.py - Generates unified diffs (.patch) from original and remediated code snippets
"""
import sys, json, difflib

def create_patch(filename, original_text, fixed_text):
    orig_lines = original_text.splitlines(keepends=True)
    fixed_lines = fixed_text.splitlines(keepends=True)
    
    diff = list(difflib.unified_diff(
        orig_lines,
        fixed_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
        lineterm=""
    ))
    
    patch_str = "".join(diff)
    return {
        "file": filename,
        "patch": patch_str,
        "changed_lines": len(diff)
    }

def main():
    if len(sys.argv) < 4:
        print(json.dumps({"error": "Usage: python patch_generator.py <filename> <orig_file> <fixed_file>"}))
        sys.exit(1)
    
    filename = sys.argv[1]
    with open(sys.argv[2], "r", errors="ignore") as f:
        orig = f.read()
    with open(sys.argv[3], "r", errors="ignore") as f:
        fixed = f.read()

    print(json.dumps(create_patch(filename, orig, fixed), indent=2))

if __name__ == "__main__":
    main()
