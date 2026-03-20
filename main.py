import subprocess
import shutil
from typing import Optional

def objdump_disassemble(path: str, extra_args: Optional[list[str]] = None) -> str:
    if not shutil.which("objdump"):
        raise RuntimeError("objdump not found in PATH")
    
    cmd = ["objdump", "-d", path]
    if extra_args:
        cmd.extend(extra_args)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"objdump failed (exit code {e.returncode}): {e.stderr}") from e
    except FileNotFoundError:
        raise RuntimeError(f"File not found: {path}") from None

if __name__ == "__main__":
    print(objdump_disassemble("/bin/ls"))
