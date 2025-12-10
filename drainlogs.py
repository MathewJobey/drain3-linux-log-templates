import re
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from drain3.masking import MaskingInstruction

# ==========================================
# 1. SETUP: Smarter Rules (Fixed)
# ==========================================
config = TemplateMinerConfig()
config.profiling_enabled = False

config.masking_instructions = [
    # Rule A: Mask PIDs specifically (e.g., sshd[12345] -> sshd[<PID>])
    # We do this instead of masking ALL numbers, so 'uid=0' stays '0'.
    MaskingInstruction(r"\[(\d+)\]", "[<PID>]"),

    # Rule B: Force 'rhost=...' to always look the same
    # Whether it is "rhost=1.2.3.4" or "rhost=example.com", it becomes "rhost=<HOST>"
    MaskingInstruction(r"rhost=(\S+)", "rhost=<HOST>"),

    # Rule C: Force 'user=...' to always look the same
    # "user=root" or "user=admin" becomes "user=<USER>"
    MaskingInstruction(r"user=(\S+)", "user=<USER>"),

    # Rule D: Mask standard IPs (just in case they appear elsewhere)
    MaskingInstruction(r"((?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d))", "<IP>")
]

template_miner = TemplateMiner(config=config)

# ==========================================
# 2. HELPER: Strip the Header
# ==========================================
def get_log_content(log_line):
    # Matches: Jun 14 15:16:01 combo
    header_pattern = r'^[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2}\s+\S+\s+'
    cleaned_line = re.sub(header_pattern, '', log_line)
    return cleaned_line.strip()

# ==========================================
# 3. RUN IT
# ==========================================
line_count = 0

print("Scanning logs with V2 rules...")
try:
    with open('Linux_2k.log', 'r') as f:
        for line in f:
            line = line.strip()
            if not line: continue
            
            # Step A: Clean
            content = get_log_content(line)
            
            # Step B: Feed to Drain
            template_miner.add_log_message(content)
            line_count += 1

    # 4. Print Results
    print(f"Done! Scanned {line_count} lines.")
    print(f"Found {len(template_miner.drain.clusters)} unique patterns.")
    print("\n--- Your Perfect Templates ---")
    
    sorted_clusters = sorted(template_miner.drain.clusters, key=lambda x: x.size, reverse=True)

    for cluster in sorted_clusters[:15]:
        print(f"[{cluster.size}] {cluster.get_template()}")

except FileNotFoundError:
    print("Error: 'Linux_2k.log' not found.")