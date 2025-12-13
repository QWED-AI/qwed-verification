"""Fix code_verifier.py - Add os.system and subprocess CRITICAL checks"""

# Read the file
with open('src/qwed_new/core/code_verifier.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Find and fix os.system check (insert after line 202, before line 203)
new_lines = []
for i, line in enumerate(lines):
    new_lines.append(line)
    
    # After the CRITICAL_FUNCTIONS block, add os.system check
    if i < len(lines) - 1 and '})' in line and 'elif func_name in self.WARNING_FUNCTIONS:' in lines[i+1]:
        # Insert os.system check here
        new_lines.append('                # Special case: os.system is always CRITICAL\n')
        new_lines.append('                elif func_name == "os.system":\n')
        new_lines.append('                    issues.append(SecurityIssue(\n')
        new_lines.append('                        Severity.CRITICAL,\n')
        new_lines.append('                        "Shell command execution via os.system() - command injection risk",\n')
        new_lines.append('                        line=line_no,\n')
        new_lines.append('                        remediation="Use subprocess with argument list instead"\n')
        new_lines.append('                    ))\n')

# Now fix subprocess block - replace complex logic with simple CRITICAL
final_lines = []
skip_until = -1
for i, line in enumerate(final_lines if len(final_lines) > 0 else new_lines):
    if skip_until > 0 and i < skip_until:
        continue
    
    # Find subprocess block start
    if '# Context-aware check for subprocess' in line:
        # Replace entire block until the "else:" after it
        final_lines.append('                    # Subprocess: always CRITICAL\n')
        final_lines.append('                    elif func_name.startswith("subprocess."):\n')
        final_lines.append('                        issues.append(SecurityIssue(\n')
        final_lines.append('                            Severity.CRITICAL,\n')
        final_lines.append('                            f"Subprocess usage: {func_name} - command injection risk",\n')
        final_lines.append('                            line=line_no,\n')
        final_lines.append('                            remediation="Validate and sanitize all subprocess arguments"\n')
        final_lines.append('                        ))\n')
        final_lines.append('                    \n')
        
        # Skip to the "else:" line
        j = i + 1
        while j < len(new_lines):
            if new_lines[j].strip().startswith('else:') and 'issues.append(SecurityIssue(' in new_lines[j+1]:
                skip_until = j
                break
            j += 1
    else:
        final_lines.append(line)

# Write back
with open('src/qwed_new/core/code_verifier.py', 'w', encoding='utf-8') as f:
    f.writelines(final_lines if len(final_lines) > 0 else new_lines)

print("Fixed code_verifier.py")
