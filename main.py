import subprocess
import shutil
import tempfile
import os
from typing import Optional, Iterator, Union, Dict, List
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
        
        cmd = [self.objdump_path, "-d"]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(str(path))
        
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
        
        cmd = [self.objdump_path, "-d"]
        if extra_args:
            cmd.extend(extra_args)
        cmd.append(str(path))
        
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1
        ) as proc:
            for line in proc.stdout:
                yield line.rstrip()
            
            return_code = proc.wait()
            if return_code != 0:
                stderr = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(f"objdump failed (exit code {return_code}): {stderr}")
    
    def get_symbols(self, path: Union[str, Path]) -> Dict[str, str]:
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
                if not line or line.startswith("SYMBOL TABLE") or line.startswith("00000000") and "FILE" in line:
                    continue
                
                parts = line.split()
                if len(parts) >= 4:
                    candidate_address = parts[0]
                    candidate_symbol = parts[-1]
                    
                    if candidate_address.replace("0", "").replace("x", "").replace("a", "").replace("b", "").replace("c", "").replace("d", "").replace("e", "").replace("f", "").isdigit() or candidate_address == "00000000":
                        symbols[candidate_symbol] = candidate_address
                    
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to get symbols: {e.stderr}") from e
        
        return symbols
    
    def get_dynamic_symbols(self, path: Union[str, Path]) -> Dict[str, str]:
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")
        
        symbols = {}
        try:
            result = subprocess.run(
                [self.objdump_path, "-T", str(path)],
                capture_output=True,
                text=True,
                check=True
            )
            
            for line in result.stdout.splitlines():
                if not line or "no symbols" in line.lower():
                    continue
                
                parts = line.split()
                if len(parts) >= 5 and "DF" in line:
                    symbol_name = parts[-1]
                    address = parts[0] if parts[0].startswith("0x") else "0x0"
                    symbols[symbol_name] = address
                    
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to get dynamic symbols: {e.stderr}") from e
        
        return symbols
    
    def compare_disassembly(self, path1: Union[str, Path], path2: Union[str, Path]) -> Dict[str, List[str]]:
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
    
    def disassemble_multiple(self, paths: List[Union[str, Path]]) -> Dict[str, str]:
        results = {}
        for path in paths:
            try:
                results[str(path)] = self.disassemble(path)
            except Exception as e:
                results[str(path)] = f"ERROR: {e}"
        return results

def disassemble_bytes(code_bytes: bytes, architecture: str = "i386:x86-64") -> str:
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
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"objdump failed on byte disassembly: {e.stderr}") from e
    finally:
        os.unlink(tmp_path)

def analyze_binary_security(path: Union[str, Path]) -> Dict[str, bool]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    security_features = {
        "nx_bit": False,
        "pie": False,
        "full_relro": False,
        "canary": False
    }
    
    try:
        if not shutil.which("readelf"):
            raise RuntimeError("readelf not found. Install binutils package.")
        
        result = subprocess.run(
            ["readelf", "-l", str(path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        if "GNU_STACK" in result.stdout:
            for line in result.stdout.splitlines():
                if "GNU_STACK" in line and "RWE" not in line and "RW" in line:
                    security_features["nx_bit"] = True
                    break
        
        result = subprocess.run(
            ["readelf", "-h", str(path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        for line in result.stdout.splitlines():
            if "Type:" in line and "DYN" in line:
                security_features["pie"] = True
                break
        
        result = subprocess.run(
            ["readelf", "-l", str(path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        has_gnu_relro = False
        for line in result.stdout.splitlines():
            if "GNU_RELRO" in line:
                has_gnu_relro = True
                break
        
        result = subprocess.run(
            ["readelf", "-d", str(path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        has_bind_now = "BIND_NOW" in result.stdout
        
        security_features["full_relro"] = has_gnu_relro and has_bind_now
        
        try:
            symbols = subprocess.run(
                ["objdump", "-t", str(path)],
                capture_output=True,
                text=True,
                check=True
            )
            if "__stack_chk_fail" in symbols.stdout:
                security_features["canary"] = True
            else:
                dyn_symbols = subprocess.run(
                    ["objdump", "-T", str(path)],
                    capture_output=True,
                    text=True,
                    check=True
                )
                if "__stack_chk_fail" in dyn_symbols.stdout:
                    security_features["canary"] = True
        except subprocess.CalledProcessError:
            pass
            
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Security analysis failed: {e.stderr}") from e
    
    return security_features

def get_program_headers(path: Union[str, Path]) -> List[Dict[str, str]]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    
    headers = []
    try:
        result = subprocess.run(
            ["readelf", "-l", str(path)],
            capture_output=True,
            text=True,
            check=True
        )
        
        current_header = {}
        for line in result.stdout.splitlines():
            if line.startswith("Program Headers:"):
                continue
            if line.startswith("Type") and "Offset" in line:
                continue
            if line.strip() and not line.startswith("Section to Segment"):
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ["PHDR", "INTERP", "LOAD", "DYNAMIC", "NOTE", "GNU_STACK", "GNU_RELRO", "GNU_PROPERTY"]:
                    if current_header:
                        headers.append(current_header)
                    current_header = {"type": parts[0]}
                    for i, part in enumerate(parts[1:]):
                        if i == 0:
                            current_header["offset"] = part
                        elif i == 1:
                            current_header["vaddr"] = part
                        elif i == 2:
                            current_header["paddr"] = part
                        elif i == 3:
                            current_header["filesz"] = part
                        elif i == 4:
                            current_header["memsz"] = part
                        elif i == 5:
                            current_header["flags"] = part
                        elif i == 6:
                            current_header["align"] = part
        if current_header:
            headers.append(current_header)
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Failed to get program headers: {e.stderr}") from e
    
    return headers

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
    
    print("\n" + "="*50)
    print("Program headers:")
    headers = get_program_headers("/bin/ls")
    for header in headers[:5]:
        print(f"  {header}")
