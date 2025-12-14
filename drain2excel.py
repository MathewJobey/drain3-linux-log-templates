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
    MaskingInstruction(r"\b\w+\(uid=\d+\)", "(uid=<UID>)"),
    MaskingInstruction(r"\buid=\d+", "uid=<UID>"),
    MaskingInstruction(r"user=\S+", "user=<USERNAME>"),
    MaskingInstruction(r"user\s+\S+", "user <USERNAME>"),
    MaskingInstruction(r"(?<=\s)\((?!uid=|Address|errno)[^)]*\)", "(<RHOST>)"),
    MaskingInstruction(r"(rhost=\S+)|((?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)(?::\d+)?)", "rhost=<RHOST>"),
]

template_miner = TemplateMiner(config=config)

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
def preprocess_log(log_line):
    # This prepares the log for Drain training (learning the patterns)
    header_regex = r'^([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+(\S+)'
    log_line = re.sub(header_regex, '<TIMESTAMP> <HOSTNAME>', log_line)
    return log_line.strip()

def extract_named_parameters(raw_line, template):
    """
    Extracts values from the RAW line using the pattern found in the TEMPLATE.
    Now specifically handles timestamps containing spaces.
    """
    params = {}
    
    # 1. Prepare the Template Regex
    regex_pattern = re.escape(template)
    
    # 2. Define specific regex patterns for special tags
    # This ensures TIMESTAMP grabs "Jun 09 10:00:00" instead of just "Jun"
    special_tags = {
        "<TIMESTAMP>": r"([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})",
        "<HOSTNAME>": r"(\S+)"  # Hostname is usually one word (no spaces)
    }

    # 3. Replace special tags first
    for tag, pattern in special_tags.items():
        if tag in template:
            # We un-escape the tag because re.escape() turned '<' into '\<'
            escaped_tag = re.escape(tag) 
            regex_pattern = regex_pattern.replace(escaped_tag, pattern)

    # 4. Replace remaining generic tags (like <PID>, <RHOST>) with (.*?)
    remaining_tags = re.findall(r"<[A-Z]+>", template)
    for tag in set(remaining_tags):
        if tag not in special_tags:
            escaped_tag = re.escape(tag)
            regex_pattern = regex_pattern.replace(escaped_tag, r"(.*?)")
    
    regex_pattern = f"^{regex_pattern}$"
    
    try:
        match = re.match(regex_pattern, raw_line)
        if match:
            extracted_values = list(match.groups())
            
            # We need to map values back to tags. 
            # We must follow the order they appear in the template.
            ordered_tags = re.findall(r"<[A-Z]+>", template)
            
            current_val_index = 0
            for tag in ordered_tags:
                if current_val_index < len(extracted_values):
                    key = tag.strip("<>")
                    params[key] = extracted_values[current_val_index].strip()
                    current_val_index += 1

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
            
            # 1. Preprocess & Train
            # We use the MODIFIED line to teach Drain the pattern.
            content = preprocess_log(raw_line)
            result = template_miner.add_log_message(content)
            
            template = result['template_mined']
            cluster_id = result['cluster_id']
            
            # 2. Extract Parameters
            # FIX: We now use 'raw_line' here, so we capture "Jun 9..." instead of "<TIMESTAMP>"
            params_json = extract_named_parameters(raw_line, template)
            
            rows.append({
                "Raw Log": raw_line,
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