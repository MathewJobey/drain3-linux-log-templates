import re
import json
import pandas as pd
from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig
from drain3.file_persistence import FilePersistence


# ---------------------------------------------------------
# LINUX FIELD VOCABULARY (Patterns)
# ---------------------------------------------------------
LINUX_FIELD_PATTERNS = {
    "pid": re.compile(r"\[(\d+)\]"),
    "rhost": re.compile(r"rhost=([^\s]+)"),
    "user": re.compile(r"user=([A-Za-z0-9_\-]*)"),
    "ip": re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
}


def extract_linux_fields(msg: str):
    """
    Extracts named fields from Linux logs and replaces them
    with <pid>, <user>, <rhost>, <ip>
    """
    params = {}
    template = msg

    for key, pattern in LINUX_FIELD_PATTERNS.items():
        matches = pattern.findall(msg)
        if matches:
            params[key] = matches[0]
            template = pattern.sub(f"<{key}>", template)

    return template, params


# ---------------------------------------------------------
# Drain3 Initialization (tuned for Linux)
# ---------------------------------------------------------
persistence = FilePersistence("./drain_state_linux.bin")

config = TemplateMinerConfig()
config.drain_sim_threshold = 0.4
config.drain_depth = 4
config.drain_extra_delimiters = ""
config.drain_max_children = 100
config.drain_max_clusters = 20000
config.profiling_enabled = False

template_miner = TemplateMiner(persistence, config)


# ---------------------------------------------------------
# Align Drain <*> with Named Template <pid>/<user> etc.
# ---------------------------------------------------------
def align_templates(drain_t, named_t):
    if not drain_t:
        return named_t

    dp = list(re.finditer(r"<\*>", drain_t))
    np = list(re.finditer(r"<[^>]+>", named_t))

    if len(dp) != len(np):
        return named_t

    result = ""
    last = 0
    for d, n in zip(dp, np):
        result += drain_t[last:d.start()]
        result += named_t[n.start():n.end()]
        last = d.end()

    result += drain_t[last:]
    return result


# ---------------------------------------------------------
# Process a single Linux message
# ---------------------------------------------------------
def process_linux_message(msg):
    # Drain template
    try:
        out = template_miner.add_log_message(msg)
        drain_t = out.get("template_mined")
    except:
        drain_t = ""

    # Named template + parameters
    named_t, params = extract_linux_fields(msg)

    # Align named placeholders with Drain <*> spots
    final_named = align_templates(drain_t, named_t)

    return drain_t, final_named, params


# ---------------------------------------------------------
# Run on CSV
# ---------------------------------------------------------
def run_on_csv(input_csv, output_csv):
    df = pd.read_csv(input_csv, dtype=str).fillna("")

    drain_templates = []
    named_templates = []
    parameters = []

    for i, row in df.iterrows():
        msg = row["Log_Content"]  # ensure column name is correct

        drain_t, named_t, params = process_linux_message(msg)

        drain_templates.append(drain_t)
        named_templates.append(named_t)
        parameters.append(json.dumps(params))

        if (i + 1) % 200 == 0:
            print(f"Processed {i+1} rows...")

    df["drain_template"] = drain_templates
    df["named_template"] = named_templates
    df["parameters"] = parameters

    df.to_csv(output_csv, index=False)
    print("✔ Completed and saved to:", output_csv)

    return df


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------
if __name__ == "__main__":
    INPUT = "Linux_20k_parsed.csv"
    OUTPUT = "Linux_20k_with_templates.csv"

    run_on_csv(INPUT, OUTPUT)
