import subprocess
import shutil
import tempfile
import os
from typing import Optional, Iterator, Union
from pathlib import Path
from enum import Enum

class DisassemblyFormat(Enum):
    INTEL = "intel"
    ATT = "att"

class ObjdumpDisassembler:
    def __init__(self, objdump_path: str = "objdump"):
        self.objdump_path = objdump_path
        self._check_objdump()
    
    def _check_objdump(self) -> None:
        if not shutil.which(self.objdump_path):
            raise RuntimeError(f"{self.objdump_path} not found in PATH")
    
    def disassemble(self, path: Union[str, Path], extra_args: Optional[list[str]] = None) -> str:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        cmd = [self.objdump_path, "-d", str(path)]
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
    
    def disassemble_section(self, path: Union[str, Path], section: str) -> str:
        return self.disassemble(path, extra_args=[f"--section={section}"])
    
    def disassemble_with_source(self, path: Union[str, Path]) -> str:
        return self.disassemble(path, extra_args=["-S"])
    
    def disassemble_all_headers(self, path: Union[str, Path]) -> str:
        return self.disassemble(path, extra_args=["-D"])
    
    def disassemble_with_format(self, path: Union[str, Path], format: DisassemblyFormat) -> str:
        if format == DisassemblyFormat.INTEL:
            return self.disassemble(path, extra_args=["-M", "intel"])
        elif format == DisassemblyFormat.ATT:
            return self.disassemble(path, extra_args=["-M", "att"])
        return self.disassemble(path)
    
    def disassemble_stream(self, path: Union[str, Path], extra_args: Optional[list[str]] = None) -> Iterator[str]:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        cmd = [self.objdump_path, "-d", str(path)]
        if extra_args:
            cmd.extend(extra_args)
        
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        ) as proc:
            for line in proc.stdout:
                yield line.rstrip()
            
            if proc.returncode and proc.returncode != 0:
                stderr = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(f"objdump failed (exit code {proc.returncode}): {stderr}")
    
    def get_symbols(self, path: Union[str, Path]) -> dict[str, str]:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        symbols = {}
        try:
            result = subprocess.run(
                [self.objdump_path, "-t", str(path)],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.splitlines():
                if line and not line.startswith("SYMBOL TABLE"):
                    parts = line.split()
                    if len(parts) >= 4:
                        address = parts[0]
                        symbol_name = parts[-1]
                        symbols[symbol_name] = address
            return symbols
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to get symbols: {e.stderr}") from e
    
    def compare_disassembly(self, path1: Union[str, Path], path2: Union[str, Path]) -> dict[str, list[str]]:
        disasm1 = self.disassemble(path1).splitlines()
        disasm2 = self.disassemble(path2).splitlines()
        
        differences = {
            "only_in_first": [],
            "only_in_second": [],
            "different_lines": []
        }
        
        max_len = max(len(disasm1), len(disasm2))
        
        for i in range(max_len):
            line1 = disasm1[i] if i < len(disasm1) else None
            line2 = disasm2[i] if i < len(disasm2) else None
            
            if line1 is None and line2 is not None:
                differences["only_in_second"].append(f"Line {i}: {line2}")
            elif line2 is None and line1 is not None:
                differences["only_in_first"].append(f"Line {i}: {line1}")
            elif line1 != line2:
                differences["different_lines"].append(f"Line {i}:\n  {line1}\n  {line2}")
        
        return differences
    
    def disassemble_to_file(self, path: Union[str, Path], output_path: Union[str, Path]) -> None:
        disassembly = self.disassemble(path)
        output_path = Path(output_path)
        output_path.write_text(disassembly)
    
    def disassemble_multiple(self, paths: list[Union[str, Path]]) -> dict[str, str]:
        results = {}
        for path in paths:
            try:
                results[str(path)] = self.disassemble(path)
            except Exception as e:
                results[str(path)] = f"ERROR: {e}"
        return results

def disassemble_bytes(code_bytes: bytes, architecture: str = "i386") -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
        tmp.write(code_bytes)
        tmp_path = tmp.name
    
    try:
        result = subprocess.run(
            ["objdump", "-D", "-b", "binary", "-m", architecture, tmp_path],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    finally:
        os.unlink(tmp_path)

def analyze_binary_security(path: Union[str, Path]) -> dict[str, bool]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    security_features = {
        "nx_bit": False,
        "pie": False,
        "relro": False,
        "canary": False
    }
    
    try:
        result = subprocess.run(
            ["readelf", "-l", str(path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        if "GNU_STACK" in result.stdout and "RWE" not in result.stdout:
            security_features["nx_bit"] = True
        
        result = subprocess.run(
            ["readelf", "-h", str(path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        if "Type: DYN" in result.stdout:
            security_features["pie"] = True
        
        result = subprocess.run(
            ["readelf", "-d", str(path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        if "BIND_NOW" in result.stdout:
            security_features["relro"] = True
        
        result = subprocess.run(
            ["objdump", "-d", str(path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        if "__stack_chk_fail" in result.stdout:
            security_features["canary"] = True
            
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Security analysis failed: {e.stderr}") from e
    except FileNotFoundError as e:
        raise RuntimeError("readelf not found. Install binutils package.") from e
    
    return security_features

if __name__ == "__main__":
    disassembler = ObjdumpDisassembler()
    
    print("Basic disassembly (first 500 chars):")
    output = disassembler.disassemble("/bin/ls")[:500]
    print(output)
    
    print("\n" + "="*50)
    print("Intel syntax disassembly (first 500 chars):")
    intel_output = disassembler.disassemble_with_format("/bin/ls", DisassemblyFormat.INTEL)[:500]
    print(intel_output)
    
    print("\n" + "="*50)
    print("Symbol table (first 10 symbols):")
    symbols = disassembler.get_symbols("/bin/ls")
    for i, (name, addr) in enumerate(list(symbols.items())[:10]):
        print(f"  {addr}: {name}")
    
    print("\n" + "="*50)
    print("Security features:")
    security = analyze_binary_security("/bin/ls")
    for feature, enabled in security.items():
        print(f"  {feature}: {enabled}")
