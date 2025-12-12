import re
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from drain3.masking import MaskingInstruction

# ==========================================
# 1. SETUP (Optimized)
# ==========================================
config = TemplateMinerConfig()
config.profiling_enabled = False
config.drain_depth=7 # More depth for Linux logs
config.drain_sim_th = 0.75 # Default is usually 0.5. Increasing this makes it stricter.
config.mask_prefix = "" 
config.mask_suffix = ""

config.masking_instructions = [
    # =========================================================
    # 1. SPECIFIC FIXES (High Priority)
    # =========================================================
    
    # Rule: Fixes "bind failed (Address ... (errno = 98))"
    MaskingInstruction(r"\(Address already in use \(errno = \d+\)\)", "(Address already in use (errno=<NUM>))"),

    # Rule: Fixes "FAILED LOGIN 1" -> "FAILED LOGIN <NUM>"
    MaskingInstruction(r"FAILED LOGIN\s+\d+", "FAILED LOGIN <NUM>"),

    # Rule: Fixes "fd 12" -> "fd <NUM>"
    MaskingInstruction(r"fd\s+\d+", "fd <NUM>"),

    # Rule: Fixes ANY duration -> "<NUM> seconds"
    MaskingInstruction(r"\b\d+\s+seconds", "<NUM> seconds"),

    # Rule: Numeric Comparison (e.g. "7 > 3", "uid=0", "val = 5")
    MaskingInstruction(r"\b\d+\s*([<>=!]+)\s*\d+", r"<NUM> \1 <NUM>"),
    
    # Rule: Handles "bad username []"
    MaskingInstruction(r"bad username\s*\[.*?\]", "bad username [<USERNAME>]"),

    # Rule: Handles "password changed for test"
    MaskingInstruction(r"password changed for\s+\S+", "password changed for <USERNAME>"),

    # Rule: Fixes "FAILED LOGIN ... FOR , Authentication" -> "FOR <USERNAME>,"
    MaskingInstruction(r"FOR\s+.*?,", "FOR <USERNAME>,"),

    # Rule: Fixes "connect from"
    MaskingInstruction(r"([cC]onnect(?:ion)? from)\s+\S+", r"\1 <RHOST>"),

    # Rule: Normalize service states ("startup succeeded" -> "<STATE> succeeded")
    MaskingInstruction(r"\b(startup|shutdown)\b(?!:)", "<STATE>"),

    # --- UPDATED FTP RULE ---
    # Now uses (?:,.*)? to match OPTIONAL comma + anything after it.
    # Matches:
    #   "LOGIN FROM 1.2.3.4"
    #   "LOGIN FROM 1.2.3.4, dns.name"
    #   "LOGIN FROM 1.2.3.4,   (anonymous)"
    MaskingInstruction(r"ANONYMOUS FTP LOGIN FROM .+", "ANONYMOUS FTP LOGIN FROM <RHOST>"),

    # =========================================================
    # 2. GENERIC VARIABLES (Low Priority)
    # =========================================================

    # Rule A: Suffix Timestamp
    MaskingInstruction(r"\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}", "<TIMESTAMP>"),

    # Rule B: PID
    MaskingInstruction(r"\[\d+\]", "[<PID>]"),

    # Rule C: UID
    MaskingInstruction(r"\b\w+\(uid=\d+\)", "(uid=<UID>)"),
    MaskingInstruction(r"\buid=\d+", "uid=<UID>"),

    # Rule D: USER (General Catch-all)
    MaskingInstruction(r"user=\S+", "user=<USERNAME>"),
    MaskingInstruction(r"user\s+\S+", "user <USERNAME>"),

    # Rule E: Smart Parentheses
    MaskingInstruction(r"(?<=\s)\((?!uid=|Address|errno)[^)]*\)", "(<RHOST>)"),

    # Rule F: IPs
    MaskingInstruction(r"(rhost=\S+)|((?<!\d)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?!\d)(?::\d+)?)", "rhost=<RHOST>"),
]

template_miner = TemplateMiner(config=config)

# ==========================================
# 2. PRE-PROCESSOR (Simplified)
# ==========================================
def preprocess_log(log_line):
    # Since we used 'drain_extra_delimiters', we only need to fix the header!
    header_regex = r'^([A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+(\S+)'
    log_line = re.sub(header_regex, '<TIMESTAMP> <HOSTNAME>', log_line)
    return log_line.strip()

# ==========================================
# 3. EXECUTION
# ==========================================
line_count = 0

print("Scanning logs with Pro Config...")
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
    
    sorted_clusters = sorted(template_miner.drain.clusters, key=lambda x: x.size, reverse=True)

    for i, cluster in enumerate(sorted_clusters, 1):
        print(f"[{i}] Count: {cluster.size}\t| {cluster.get_template()}")

except FileNotFoundError:
    print("Error: 'Linux_2k_clean.log' not found.")