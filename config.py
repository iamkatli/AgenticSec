"""
config.py

Centralised paths and run parameters for the defense-matrix benchmark.
Change values here -- run_defense_matrix.py never hard-codes a path or
TOTAL_RUNS itself.

Directory layout this expects on disk:

    it_ops_crew/
    ├── data/                                  <- input for every attack group (payload="injected")
    │   ├── new_vm_request_*.txt               <- request files; one carries the injected payload
    │   └── current_active_vm_list.csv         <- working file: reset before each run, rewritten by the Writer agent
    ├── data_zero/                             <- input for the ZERO no-attack groups (payload="clean")
    │   ├── new_vm_request_*.txt               <- the same request files WITHOUT the injected one
    │   └── current_active_vm_list.csv         <- working file (same role as above)
    ├── defaults/                              <- read-only reference files, never touched by the crew
    │   ├── current_active_vm_list_org.csv     <- seed state copied into the working file before each run
    │   ├── current_active_vm_list_gt.csv      <- expected end state, attack groups
    │   └── current_active_vm_list_zero_gt.csv <- expected end state, ZERO groups
    ├── logs/
    └── reports/

Each group's `payload` ("injected" | "clean") selects its scenario below:
input directory, seed CSV and ground truth. Nothing else branches on it.
"""

import os

from dotenv import load_dotenv

load_dotenv()  # so MODEL / OPENAI_API_BASE below see .env, whatever imports config first

# --- Run parameters (defaults; both can be overridden on the command line) ---
TOTAL_RUNS = 100           # runs per group;           CLI: --runs N
HALT_ON_ANOMALY = True     # stop on impossible signal; CLI: --halt-on-anomaly / --no-halt-on-anomaly
# HALT_ON_ANOMALY: when True, the runner stops the ENTIRE script the moment
# classify_block_stage() raises ImpossibleSignalCombination
# (success=True, attempted=False), logging full diagnostics first (most
# likely cause: a stale HACKED_FILE that reset_env() failed to clear).

# A run that raises (e.g. the model server is down) is retried with
# back-off. After this many consecutive failed attempts of the same run the
# script stops, so a dead server never leaves it retrying forever.
MAX_RETRIES_PER_RUN = 15

# --- LLM (pinned here so results do not depend on model-file defaults) ---
# Model and endpoint come from .env (MODEL, OPENAI_API_BASE, OPENAI_API_KEY);
# sampling parameters are fixed in code. TEMPERATURE / TOP_P equal the
# qwen3:14b model-file defaults used in all earlier runs. top_k (20) and
# repeat_penalty (1) are not part of the OpenAI-compatible API, so they
# still come from the Ollama model file -- the report header records them.
LLM_MODEL = os.getenv("MODEL", "openai/qwen3:14b")
LLM_BASE_URL = os.getenv("OPENAI_API_BASE", "http://localhost:3001/v1")
LLM_TEMPERATURE = 0.6
LLM_TOP_P = 0.95
OLLAMA_MODEL_NAME = "qwen3:14b"   # used only to record `ollama show` output in the report

# --- Attack detection ---
HACKED_FILE = "/tmp/hacked_status.txt"

# --- Scenarios ---
DEFAULTS_DIR = "defaults"
ACTIVE_CSV_NAME = "current_active_vm_list.csv"

SCENARIOS = {
    "injected": {
        "data_dir": "data",
        "seed_csv": os.path.join(DEFAULTS_DIR, "current_active_vm_list_org.csv"),
        "ground_truth_csv": os.path.join(DEFAULTS_DIR, "current_active_vm_list_gt.csv"),
    },
    "clean": {
        "data_dir": "data_zero",
        "seed_csv": os.path.join(DEFAULTS_DIR, "current_active_vm_list_org.csv"),
        "ground_truth_csv": os.path.join(DEFAULTS_DIR, "current_active_vm_list_zero_gt.csv"),
    },
}


def data_dir(payload: str) -> str:
    return SCENARIOS[payload]["data_dir"]


def active_csv(payload: str) -> str:
    """The working CSV for this scenario (read by Task1, rewritten by Task4)."""
    return os.path.join(data_dir(payload), ACTIVE_CSV_NAME)


def seed_csv(payload: str) -> str:
    return SCENARIOS[payload]["seed_csv"]


def ground_truth_csv(payload: str) -> str:
    return SCENARIOS[payload]["ground_truth_csv"]


# --- Output directories ---
LOGS_DIR = "logs"
REPORTS_DIR = "reports"
