# ==========================================
# SURGICAL LOG CLEANER
# Checks ONLY the Process Name (Token #5)
# ==========================================

input_filename = 'Linux_2k.log'
output_filename = 'Linux_2k_clean.log'

# The Blocklist
# Just the pure process names. No colons, no brackets.
# We will check if the log's process section STARTS with these.
BLACKLIST = [
    # 1. Hardware & Boot
    "kernel",       # Matches "kernel:"
    "rc",           # Matches "rc:"
    "irqbalance",
    "sysctl",
    "network",      # Matches "network:"
    "random",       # Matches "random:" (rngd)
    "udev",        # Matches "udevd" or "udev:"
    "apmd",         # Power management/Battery
    "smartd",       # SMART disk monitoring
    "init",
    
    # 2. Peripherals
    "bluetooth", 
    "sdpd",  
    "hcid",         # Bluetooth daemon
    "cups",         # Printing system
    "gpm",          # General Purpose Mouse

    # 3. System Housekeeping
    "logrotate",
    "syslog",       # Matches "syslogd", "syslog"
    "klogd",
    "crond",
    "anacron",
    "atd",
    "readahead",
    "messagebus",
    "ntpd",
    "dd",
    

    # 4. Network Plumbing (NFS/RPC)
    "rpc.statd",
    "rpcidmapd",
    "portmap",
    "nfslock",
    "automount",
    "ifup",         # Interface startup
    "netfs",        # Network file system mounter
    "autofs",       # Auto filesystem mounter
    
    # 5. PROXIES & SERVERS
    "privoxy", 
    "squid",
    "sendmail",     # Mail server startup
    "spamassassin",
    "httpd",        
    "xfs",          
    "IIim",         
    "htt",          
    "htt_server",   
    "canna",
    "named",
    "rsyncd",
    "mysqld",
    "FreeWnn",
]

removed_count = 0
kept_count = 0

print(f"Reading from: {input_filename}")
print(f"Targeting process names after hostname...")

try:
    with open(input_filename, 'r') as infile, open(output_filename, 'w') as outfile:
        for line in infile:
            stripped_line = line.strip()
            if not stripped_line:
                continue

            # Split the line into tokens
            # Format: Date Time Hostname ProcessName ...
            # Index:   0    1      2        3          4
            tokens = stripped_line.split()

            # Safety check: Ensure line has enough parts
            if len(tokens) < 5:
                # If line is too short (weird junk), keep it or log warning. 
                # Usually safe to keep as it might be a weird raw message.
                outfile.write(line)
                kept_count += 1
                continue

            # "combo" is at index 3. The Process is at index 4.
            process_token = tokens[4] 

            # Check if the process token starts with anything in our blacklist
            # e.g., "kernel:" starts with "kernel" -> DELETE
            # e.g., "sshd[123]:" starts with "kernel"? -> KEEP
            is_noise = False
            for bad_process in BLACKLIST:
                if process_token.startswith(bad_process):
                    is_noise = True
                    break
            
            if is_noise:
                removed_count += 1
            else:
                outfile.write(line)
                kept_count += 1

    print("\n" + "="*40)
    print("CLEANING COMPLETE")
    print("="*40)
    print(f"Removed: {removed_count} lines")
    print(f"Kept:    {kept_count} lines")
    print(f"Saved to: {output_filename}")

except FileNotFoundError:
    print(f"Error: Could not find '{input_filename}'.")