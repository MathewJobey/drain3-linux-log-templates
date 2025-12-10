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
    # Rule A: Suffix TIMESTAMP
    MaskingInstruction(
        r"\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}", 
        "<TIMESTAMP>"
    ),

    # Rule B: PID
    MaskingInstruction(r"\[\d+\]", "[<PID>]"),

    # Rule C: USER
    MaskingInstruction(r"user=\S+", "user=<USER>"),

    # Rule D: Parentheses (Remote Domains/IPs)
    # Replaces "(adelphia.net)" or "()" with "(<rHOST>)"
    # This correctly labels it as the REMOTE host, not your local HOSTNAME.
    MaskingInstruction(r"(?<=\s)\([^)]*\)", "(<rHOST>)"),

    # Rule E: Combined IP / rhost= Rule
    # Replaces "rhost=1.2.3.4" or just "1.2.3.4" with "<rHOST>"
    MaskingInstruction(
        r"(rhost=\S+)|((?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d))", 
        "<rHOST>"
    )
]

template_miner = TemplateMiner(config=config)

# ==========================================
# 2. PRE-PROCESSOR
# ==========================================
def preprocess_log(log_line):
    # 1. Replace Date at start
    log_line = re.sub(r'^[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2}', '<TIMESTAMP>', log_line)
    
    # 2. Replace HOSTNAME (The local machine "combo")
    # We deliberately call this <HOSTNAME> to distinguish it from <rHOST>
    log_line = re.sub(r'(?<=<TIMESTAMP>)\s+(\S+)', ' <HOSTNAME>', log_line)
    
    return log_line.strip()

# ==========================================
# 3. EXECUTION
# ==========================================
line_count = 0

print("Scanning logs with rHOST correction...")
try:
    with open('Linux_2k.log', 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            
            content = preprocess_log(line)
            template_miner.add_log_message(content)
            line_count += 1

    print(f"Done! Scanned {line_count} lines.")
    print("\n--- Your Final Templates ---")
    
    sorted_clusters = sorted(template_miner.drain.clusters, key=lambda x: x.size, reverse=True)

    for cluster in sorted_clusters[:15]:
        print(f"[{cluster.size}] {cluster.get_template()}")

except FileNotFoundError:
    print("Error: 'Linux_2k.log' not found.")