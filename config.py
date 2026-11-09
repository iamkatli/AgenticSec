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
TOTAL_RUNS = 300           # runs per group;           CLI: --runs N
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
# sampling parameters are fixed in code, per model, in MODEL_PROFILES below.
# Policy: each model runs with its developer's officially recommended
# sampling settings. top_k / repeat_penalty are not part of the
# OpenAI-compatible API, so they still come from the Ollama model file --
# the report header records them.
LLM_MODEL = os.getenv("MODEL", "openai/qwen3:14b")
LLM_BASE_URL = os.getenv("OPENAI_API_BASE", "http://localhost:3001/v1")

# Ollama tag of the model (used to pick the profile and to record
# `ollama show` in the report). Derived from MODEL ("openai/qwen3:14b" ->
# "qwen3:14b"); set OLLAMA_MODEL in .env only if the proxy uses an alias.
OLLAMA_MODEL_NAME = os.getenv("OLLAMA_MODEL", LLM_MODEL.split("/", 1)[-1])

# Per-model sampling. None = not sent (the model / server default applies,
# and the report header records the Ollama model-file value).
#   temperature, top_p : developer-recommended values (check the model card)
#   reasoning_effort   : only for models with thinking levels (gpt-oss).
#                        None = model default (gpt-oss: "medium"). Before
#                        setting it, confirm in a Langfuse trace that the
#                        proxy really forwards it to Ollama.
MODEL_PROFILES = {
    # Qwen3 thinking-mode recommendation (top_k 20 from the model file).
    # MUST stay 0.6 / 0.95: every earlier qwen3 run used these values.
    "qwen3:14b":        {"temperature": 0.6, "top_p": 0.95, "reasoning_effort": None},
    # OpenAI gpt-oss recommendation: temperature 1.0, top_p 1.0.
    "gpt-oss:20b":      {"temperature": 1.0, "top_p": 1.0,  "reasoning_effort": None},
    # Meta Llama 3.1 generation_config: temperature 0.6, top_p 0.9.
    "llama3.1:8b":      {"temperature": 0.6, "top_p": 0.9,  "reasoning_effort": None},
    # Google Gemma 3: temperature 1.0, top_p 0.95 (top_k 64 from the model file).
    "gemma3:12b":       {"temperature": 1.0, "top_p": 0.95, "reasoning_effort": None},
    # Mistral NeMo: temperature 0.3 recommended; no top_p recommendation.
    "mistral-nemo:12b": {"temperature": 0.3, "top_p": None, "reasoning_effort": None},
}

if OLLAMA_MODEL_NAME not in MODEL_PROFILES:
    # Fail loudly instead of silently running with someone else's sampling.
    raise SystemExit(
        f"config.py: no sampling profile for model '{OLLAMA_MODEL_NAME}'. "
        f"Add it to MODEL_PROFILES (known: {', '.join(MODEL_PROFILES)})."
    )

LLM_TEMPERATURE = MODEL_PROFILES[OLLAMA_MODEL_NAME]["temperature"]
LLM_TOP_P = MODEL_PROFILES[OLLAMA_MODEL_NAME]["top_p"]
LLM_REASONING_EFFORT = MODEL_PROFILES[OLLAMA_MODEL_NAME]["reasoning_effort"]

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
