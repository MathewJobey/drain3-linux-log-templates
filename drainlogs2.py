import re
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from drain3.masking import MaskingInstruction

# ==========================================
# 1. CONFIGURATION
# ==========================================
config = TemplateMinerConfig()
config.profiling_enabled = False
config.mask_prefix = ""
config.mask_suffix = ""

config.masking_instructions = [
    # Rule A: The "Lookbehind" Fix for RHOST
    # "Find characters after 'rhost=' and replace them with <HOST>"
    # Input:  rhost=218.188.2.4
    # Output: rhost=<HOST>
    #MaskingInstruction(r"rhost=\S+", "rhost=<rHOST>"),
    MaskingInstruction(r"((?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d))|rhost=\S+", "<rHOST>"),

    # Rule B: The "Lookbehind" Fix for USER
    # Input:  user=root
    # Output: user=<USER>
    MaskingInstruction(r"(?<=user=)\S+", "<USER>"),

    # Rule C: PID Masking (sshd[12345] -> sshd[<PID>])
    MaskingInstruction(r"\[(\d+)\]", "[<PID>]"),

    # Rule D: Generic IP Masking (Fallback for IPs not in rhost=)
    #MaskingInstruction(r"((?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d))", "<IP>")
]

template_miner = TemplateMiner(config=config)

# ==========================================
# 2. HEADER PRE-PROCESSOR
# ==========================================
def preprocess_log(log_line):
    """
    Handles only the standard Syslog header at the START of the line.
    Input:  'Jun 14 15:16:01 combo sshd...'
    Output: '<timestamp> <hostname> sshd...'
    """
    # 1. Match the Timestamp at the start
    # Format: Jun 14 15:16:01
    log_line = re.sub(
        r'^[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2}', 
        '<TIMESTAMP>', 
        log_line
    )
    # 2. Match the Hostname (the first word after the timestamp)
    # Format: <timestamp> combo ...
    # We look for <timestamp> followed by space and then any text
    log_line = re.sub(
        r'(?<=<TIMESTAMP>)\s+(\S+)', 
        ' <HOSTNAME>', 
        log_line
    )
    return log_line.strip()
# ==========================================
# 3. EXECUTION
# ==========================================
line_count = 0

print("Scanning logs with Lookbehind Rules...")
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
    
    # Sort by frequency
    sorted_clusters = sorted(template_miner.drain.clusters, key=lambda x: x.size, reverse=True)

    for cluster in sorted_clusters[:15]:
        print(f"[{cluster.size}] {cluster.get_template()}")

except FileNotFoundError:
    print("Error: 'Linux_2k.log' not found.")