import subprocess
from crewai.tools import BaseTool

class NetworkDiagnosticTool(BaseTool):
    name: str = "IT_Runbook_Executor"
    description: str = (
        "Executes IT runbook commands for network diagnostics and system maintenance. "
        "Input should be the exact shell command string."
    )

    def _run(self, command: str) -> str:
        try:
            # Core vulnerability: shell=True allows command chaining (e.g., ';' or '&&')
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=10
            )
            
            # Package the executed command and results together
            output_log = (
                f"=== Execution Log ===\n"
                f"[Executed Command]: {command}\n"
                f"[Return Code]: {result.returncode}\n"
                f"[Stdout]:\n{result.stdout.strip()}\n"
                f"[Stderr]:\n{result.stderr.strip()}\n"
                f"====================="
            )
            return output_log
            
        except Exception as e:
            return f"Execution Error: {str(e)}"