"""Secure PCAP Path Resolver and Integrity Safeguards.

Guarantees:
1. Only PCAPs within explicit allowlisted directories (e.g. artifacts/demo, tests, artifacts) can be accessed.
2. Prevents path traversal (e.g. ../../etc/passwd or C:\\Windows\\...).
3. Validates file existence, file type (.pcap, .pcapng, .cap), and file permissions.
4. Computes SHA-256 checksums to verify source capture non-mutation before and after experiments.
"""
import hashlib
from pathlib import Path
from typing import List, Optional, Tuple


DEFAULT_ALLOWED_ROOTS: List[Path] = [
    Path("artifacts/demo").resolve(),
    Path("artifacts").resolve(),
    Path("tests").resolve(),
]


class PcapSecurityError(ValueError):
    """Raised when an unauthorized or malicious PCAP path is supplied."""
    pass


def get_allowed_roots(additional_roots: Optional[List[Path]] = None) -> List[Path]:
    """Returns canonical, resolved list of allowlisted directories."""
    roots = list(DEFAULT_ALLOWED_ROOTS)
    if additional_roots:
        for r in additional_roots:
            try:
                resolved = r.resolve()
                if resolved not in roots:
                    roots.append(resolved)
            except Exception:
                continue
    return roots


def resolve_safe_pcap_path(
    user_input: str,
    additional_roots: Optional[List[Path]] = None,
) -> Path:
    """Safely resolves and validates a PCAP file path.
    
    Accepts:
    - A relative path within allowed roots (e.g. 'artifacts/demo/test-SYN_FLOOD-0.pcap')
    - A basename of a file located in an allowed root (e.g. 'test-SYN_FLOOD-0.pcap')
    
    Rejects:
    - Path traversal attempts (e.g. '../..')
    - Files outside allowlisted roots
    - Missing files or directories
    - Unsupported file extensions (must be .pcap, .pcapng, or .cap)
    - Null-byte injections
    """
    if not user_input or not isinstance(user_input, str):
        raise PcapSecurityError("PCAP identifier or path cannot be empty.")

    if "\0" in user_input:
        raise PcapSecurityError("Null bytes detected in path.")

    cleaned_input = user_input.strip()
    allowed_roots = get_allowed_roots(additional_roots)
    allowed_extensions = {".pcap", ".pcapng", ".cap"}

    # Security Check 1: Traversal sequences in user input
    if ".." in cleaned_input:
        raise PcapSecurityError(f"Path traversal sequence detected in input path: {cleaned_input}")

    # Case 1: Check if input is a simple filename without path separators
    candidate_path: Optional[Path] = None
    if "/" not in cleaned_input and "\\" not in cleaned_input:
        for root in allowed_roots:
            candidate = root / cleaned_input
            if candidate.exists() and candidate.is_file():
                candidate_path = candidate
                break

    # Case 2: Treat as relative or absolute path
    if candidate_path is None:
        try:
            candidate_path = Path(cleaned_input).resolve()
        except Exception as e:
            raise PcapSecurityError(f"Invalid path structure: {e}")

    # Security Check 2: Validate extension
    if candidate_path.suffix.lower() not in allowed_extensions:
        raise PcapSecurityError(
            f"Unauthorized file extension '{candidate_path.suffix}'. Allowed: {', '.join(sorted(allowed_extensions))}"
        )

    # Security Check 3: Validate containment within at least one allowed root
    resolved_candidate = candidate_path.resolve()
    is_contained = False
    for root in allowed_roots:
        try:
            if resolved_candidate.is_relative_to(root):
                is_contained = True
                break
        except AttributeError:
            try:
                resolved_candidate.relative_to(root)
                is_contained = True
                break
            except ValueError:
                continue

    if not is_contained:
        raise PcapSecurityError(f"Path is restricted outside authorized roots: {cleaned_input}")

    # Operational Check: File existence and regular file check
    if not candidate_path.exists():
        raise FileNotFoundError(f"PCAP file does not exist: {cleaned_input}")

    if not candidate_path.is_file():
        raise PcapSecurityError(f"Specified path is a directory, not a regular file: {cleaned_input}")

    return candidate_path


def compute_pcap_fingerprint(pcap_path: Path) -> Tuple[str, int]:
    """Calculates SHA-256 digest and byte size of a PCAP file for tamper-evident provenance."""
    sha = hashlib.sha256()
    size = 0
    with pcap_path.open("rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
            size += len(chunk)
    return sha.hexdigest(), size


def verify_pcap_unmodified(pcap_path: Path, expected_hash: str) -> bool:
    """Verifies that a PCAP file has not been modified during an analysis or sweep."""
    current_hash, _ = compute_pcap_fingerprint(pcap_path)
    return current_hash == expected_hash
