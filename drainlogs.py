import re
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from drain3.masking import MaskingInstruction

# ==========================================
# 1. SETUP
# ==========================================
config = TemplateMinerConfig()
config.profiling_enabled = False

config.mask_prefix = ""
config.mask_suffix = ""

config.masking_instructions = [
    # Rule A: Suffix Timestamp (e.g. "Fri Jun 17...")
    MaskingInstruction(
        r"\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}", 
        "<TIMESTAMP>"
    ),

    # Rule B: PID -> [<PID>]
    MaskingInstruction(r"\[\d+\]", "[<PID>]"),

    # Rule C: UID -> (uid=<UID>) (Critical: Do this before generic parentheses!)
    MaskingInstruction(r"\(uid=\d+\)", "(uid=<UID>)"),

    # Rule D: USER -> user=<USER>
    MaskingInstruction(r"user=\S+", "user=<USER>"),

    # Rule E: Smart Parentheses -> (<RHOST>)
    # Catches (adelphia.net) but IGNORES (uid=...)
    MaskingInstruction(r"(?<=\s)\((?!uid=)[^)]*\)", "(<RHOST>)"),

    # Rule F: Combined IP / RHOST -> <RHOST>
    MaskingInstruction(
        r"(rhost=\S+)|((?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d))", 
        "rhost=<RHOST>"
    )
]

template_miner = TemplateMiner(config=config)

# ==========================================
# 2. PRE-PROCESSOR 
# ==========================================
def preprocess_log(log_line):
    # 1. Standard Header Replacement
    # Finds "Jul 27 14:41:57 combo" and replaces with tags
    header_regex = r'^([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+(\S+)'
    log_line = re.sub(header_regex, '<TIMESTAMP> <HOSTNAME>', log_line)
    return log_line.strip()
# ==========================================
# 3. EXECUTION
# ==========================================
line_count = 0

print("Scanning logs...")
try:
    with open('Linux_2k_clean.log', 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            
            content = preprocess_log(line)
            template_miner.add_log_message(content)
            line_count += 1

    print(f"Done! Scanned {line_count} lines.")
    print("\n" + "="*50)
    print(f"ALL CLUSTERS (Total: {len(template_miner.drain.clusters)})")
    print("="*50)
    
    # Sort by frequency
    sorted_clusters = sorted(template_miner.drain.clusters, key=lambda x: x.size, reverse=True)

    # LOOP THROUGH ALL CLUSTERS (No limit)
    for i, cluster in enumerate(sorted_clusters, 1):
        print(f"[{i}]Count: {cluster.size}\t| {cluster.get_template()}")

except FileNotFoundError:
    print("Error: 'Linux_2k.log' not found.")