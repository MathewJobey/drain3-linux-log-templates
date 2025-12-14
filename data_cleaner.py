import os

# ==========================================
# SURGICAL LOG CLEANER (DEBUG MODE)
# Saves removed lines to 'trash.log' so you can check them.
# ==========================================

print("="*40)
user_input = input("Enter log filename to clean (default: Linux_2k.log): ").strip()

if not user_input:
    input_filename = 'Linux_2k.log'
else:
    input_filename = user_input

# Output filenames
base_name, extension = os.path.splitext(input_filename)
output_filename = f"{base_name}_clean{extension}"
trash_filename = f"{base_name}_trash{extension}"

print(f"Target Input:  {input_filename}")
print(f"Clean Output:  {output_filename}")
print(f"Trash Output:  {trash_filename} (Check this to see what was removed!)")
print("="*40)

BLACKLIST = [
    # 1. Hardware & Boot
    "kernel", "rc", "irqbalance", "sysctl", "network", "random", "udev", 
    "apmd", "smartd", "init",
    # 2. Peripherals
    "bluetooth", "sdpd", "hcid", "cups", "gpm",
    # 3. System Housekeeping
    "logrotate", "syslog", "klogd", "crond", "anacron", "atd", "readahead", 
    "messagebus", "ntpd", "dd",
    # 4. Network Plumbing
    "rpc.statd", "rpcidmapd", "portmap", "nfslock", "automount", "ifup", 
    "netfs", "autofs",
    # 5. PROXIES & SERVERS
    "privoxy", "squid", "sendmail", "spamassassin", "httpd", "xfs", 
    "IIim", "htt", "htt_server", "canna", "named", "rsyncd", "mysqld", "FreeWnn"
]

removed_count = 0
kept_count = 0

try:
    with open(input_filename, 'r') as infile, \
         open(output_filename, 'w') as outfile, \
         open(trash_filename, 'w') as trashfile:
        
        for line in infile:
            stripped_line = line.strip()
            if not stripped_line: continue

            tokens = stripped_line.split()

            # Safety check for short lines
            if len(tokens) < 5:
                outfile.write(line)
                kept_count += 1
                continue

            # Token 4 is the process name (e.g., "sshd[123]:")
            process_token = tokens[4] 

            matched_keyword = None
            for bad_process in BLACKLIST:
                if process_token.startswith(bad_process):
                    matched_keyword = bad_process
                    break
            
            if matched_keyword:
                # Write to TRASH with the reason
                trashfile.write(f"[MATCHED: {matched_keyword}] {line}")
                removed_count += 1
            else:
                outfile.write(line)
                kept_count += 1

    print("\n" + "="*40)
    print("DEBUG RUN COMPLETE")
    print("="*40)
    print(f"Kept:    {kept_count} lines")
    print(f"Removed: {removed_count} lines")
    print(f"Details: See '{trash_filename}' to verify removals.")

except FileNotFoundError:
    print(f"\nError: Could not find '{input_filename}'.")