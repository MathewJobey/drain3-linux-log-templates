import re
import json
import os
import pandas as pd
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from drain3.masking import MaskingInstruction

# ==========================================
# 1. SETUP
# ==========================================
config = TemplateMinerConfig()
config.profiling_enabled = False
config.drain_depth = 7 
config.drain_sim_th = 0.75 
config.mask_prefix = "" 
config.mask_suffix = ""

config.masking_instructions = [
    # 1. SPECIFIC FIXES (High Priority)
    MaskingInstruction(r"\(Address already in use \(errno = \d+\)\)", "(Address already in use (errno=<NUM>))"),
    MaskingInstruction(r"FAILED LOGIN\s+\d+", "FAILED LOGIN <NUM>"),
    MaskingInstruction(r"fd\s+\d+", "fd <NUM>"),
    MaskingInstruction(r"\b\d+\s+seconds", "<NUM> seconds"),
    MaskingInstruction(r"\b\d+\s*([<>=!]+)\s*\d+", r"<NUM> \1 <NUM>"),
    MaskingInstruction(r"bad username\s*\[.*?\]", "bad username [<USERNAME>]"),
    MaskingInstruction(r"password changed for\s+\S+", "password changed for <USERNAME>"),
    MaskingInstruction(r"FOR\s+.*?,", "FOR <USERNAME>,"),
    MaskingInstruction(r"([cC]onnect(?:ion)? from)\s+\S+", r"\1 <RHOST>"),
    MaskingInstruction(r"\b(startup|shutdown)\b(?!:)", "<STATE>"),
    
    # FTP Rule
    MaskingInstruction(r"ANONYMOUS FTP LOGIN FROM .+", "ANONYMOUS FTP LOGIN FROM <RHOST>"),

    # 2. GENERIC VARIABLES (Low Priority)
    MaskingInstruction(r"\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}", "<TIMESTAMP>"),
    MaskingInstruction(r"\[\d+\]", "[<PID>]"),
    # FIX: Capture the prefix word (e.g., LOGIN, sshd) and keep it in the template
    MaskingInstruction(r"\b(\w+)\(uid=\d+\)", r"\1(uid=<UID>)"),
    MaskingInstruction(r"\buid=\d+", "uid=<UID>"),
    MaskingInstruction(r"user=\S+", "user=<USERNAME>"),
    MaskingInstruction(r"user\s+\S+", "user <USERNAME>"),
    # FIX: added '|ftpd' to the negative lookahead list so (ftpd) is NOT masked as <RHOST>
    MaskingInstruction(r"(?<=\s)\((?!uid=|Address|errno|ftpd)[^)]*\)", "(<RHOST>)"),
# 1. Handle explicit rhost=... (matches "rhost=1.2.3.4" -> "rhost=<RHOST>")
    MaskingInstruction(r"rhost=\S+", "rhost=<RHOST>"),
    
    # 2. Handle naked IPs (matches "1.2.3.4" -> "<RHOST>")
    MaskingInstruction(r"((?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)(?::\d+)?)", "<RHOST>"),
]

template_miner = TemplateMiner(config=config)

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
def remove_trailing_timestamp(text):
    """
    Removes the redundant 'at Sat Jun 18...' timestamp from the end of the line.
    """
    # Regex for: " at Sat Jun 18 02:08:12 2005" (at the end of string)
    trailing_regex = r"\s+at\s+\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}$"
    return re.sub(trailing_regex, "", text)

def preprocess_log(log_line):
    # 1. Remove the redundant trailing timestamp first
    log_line = remove_trailing_timestamp(log_line)
    
    log_line = normalize_ftpd_rhost(log_line)
    
    # 2. Standardize the Header
    header_regex = r'^([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+(\S+)'
    log_line = re.sub(header_regex, '<TIMESTAMP> <HOSTNAME>', log_line)
    
    return log_line.strip()

def normalize_ftpd_rhost(line):
    pattern = re.compile(
        r"(connection from)\s+(\d{1,3}(?:\.\d{1,3}){3})\s*\(([^)]*)\)"
    )

    def replacer(match):
        prefix = match.group(1)
        outer_ip = match.group(2)
        inner = match.group(3).strip()

        # Always preserve structure
        if inner:
            return f"{prefix} {outer_ip} ({inner})"
        else:
            return f"{prefix} {outer_ip}"

    return pattern.sub(replacer, line)


def extract_named_parameters(clean_raw_line, template):
    """
    Extracts values using the Cleaned Raw Line (no trailing timestamp).
    """
    params = {}
    regex_pattern = re.escape(template)

    # --- FIX START: Allow flexible whitespace ---
    # Replace literal spaces (escaped or not) with \s+ to match 1 or more spaces
    regex_pattern = regex_pattern.replace(r"\ ", r"\s+")
    regex_pattern = regex_pattern.replace(" ", r"\s+")
    # --- FIX END ---

    # Special tags
    special_tags = {
        "<TIMESTAMP>": r"([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})",
        "<HOSTNAME>": r"(\S+)"
    }
    
    # ... rest of the function remains the same ...

    # Replace special tags first
    for tag, pattern in special_tags.items():
        if tag in template:
            regex_pattern = regex_pattern.replace(re.escape(tag), pattern)

    # Replace remaining tags generically
    remaining_tags = re.findall(r"<[A-Z]+>", template)
    for tag in set(remaining_tags):
        if tag not in special_tags:
            regex_pattern = regex_pattern.replace(re.escape(tag), r"(.*?)")

    regex_pattern = f"^{regex_pattern}$"

    try:
        match = re.match(regex_pattern, clean_raw_line)
        if not match:
            return json.dumps({})

        extracted_values = list(match.groups())
        ordered_tags = re.findall(r"<[A-Z]+>", template)

        for tag, value in zip(ordered_tags, extracted_values):
            key = tag.strip("<>")
            value = value.strip()

            if not value:
                continue

            if key in params:
                # merge only if different
                if value not in params[key]:
                    params[key] = f"{params[key]}, {value}"
            else:
                params[key] = value

    except Exception:
        pass

    return json.dumps(params)

# ==========================================
# 3. EXECUTION
# ==========================================
print("="*40)
user_input = input("Enter log filename to scan (default: Linux_2k_clean.log): ").strip()

if not user_input:
    target_file = 'Linux_2k_clean.log'
else:
    target_file = user_input

base_name, _ = os.path.splitext(target_file)
output_excel = f"{base_name}_analysis.xlsx"

print(f"Reading from: {target_file}")
print(f"Writing to:   {output_excel}")
print("="*40)

rows = []

try:
    with open(target_file, 'r') as f:
        print("Processing logs... (This may take a moment)")
        for line in f:
            raw_line = line.strip()
            if not raw_line: continue
            
            # 1. Preprocess & Mine
            # (Removes trailing timestamp internally so Drain doesn't see it)
            content = preprocess_log(raw_line)
            result = template_miner.add_log_message(content)
            
            template = result['template_mined']
            cluster_id = result['cluster_id']
            
            # 2. Extract Variables
            # CRITICAL: We must also remove the trailing timestamp from the raw line
            # used for extraction, otherwise the regex won't match the shortened template.
            clean_raw_line = remove_trailing_timestamp(raw_line)
            
            # --- FIX START: Normalize the line for extraction too ---
            clean_raw_line = normalize_ftpd_rhost(clean_raw_line)
            # --- FIX END ---
            
            params_json = extract_named_parameters(clean_raw_line, template)
            
            rows.append({
                "Raw Log": raw_line,          # We keep the ORIGINAL full log here
                "Drained Named Log": template,
                "Template ID": cluster_id,
                "Parameters": params_json
            })

    if rows:
        print(f"Generating Excel file with {len(rows)} rows...")
        df = pd.DataFrame(rows)
        df = df.sort_values(by="Template ID")
        df = df[["Raw Log", "Drained Named Log", "Template ID", "Parameters"]]
        df.to_excel(output_excel, index=False)
        
        print("="*40)
        print("SUCCESS!")
        print(f"File saved: {output_excel}")
        print("="*40)
    else:
        print("Warning: No logs found in the file.")

except FileNotFoundError:
    print(f"Error: '{target_file}' not found.")
    print("Please check the filename and try again.")
except Exception as e:
    print(f"An error occurred: {e}")