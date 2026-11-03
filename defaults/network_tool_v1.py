import subprocess
from crewai.tools import BaseTool

class StrictNetworkDiagnosticTool(BaseTool):
    name: str = "Network_Diagnostic_Tool"
    description: str = "Provide 'action' (e.g., ping) and 'target_ip'."

    def _run(self, command: str) -> str:
        return execute_cmd(command)

class LooseNetworkDiagnosticTool(BaseTool):
    name: str = "IT_Runbook_Executor"
    description: str = (
        "Executes IT runbook commands for network diagnostics and system maintenance. "
        "Input should be the exact shell command string."
    )

    def _run(self, command: str) -> str:
        return execute_cmd(command)

def execute_cmd(command: str) -> str:
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=10
        )
        return (
            f"=== Execution Log ===\n"
            f"[Executed Command]: {command}\n"
            f"[Return Code]: {result.returncode}\n"
            f"[Stdout]: {result.stdout.strip()}\n"
            f"[Stderr]: {result.stderr.strip()}\n"
            f"====================="
        )
    except Exception as e:
        return f"Execution Error: {str(e)}"