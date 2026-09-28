"""Bounded local binary-input fuzzing and opt-in HTTP payload mutation."""

from __future__ import annotations

import hashlib
import json
import math
import os
import random
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from secagents.core.aura_memory import AuraMemoryManager


def sha256_file(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def byte_changes(before: bytes, after: bytes, limit: int = 32) -> dict:
    """Describe positional byte and bit differences without storing entire outputs."""
    changes: list[dict] = []
    count = 0
    for offset in range(max(len(before), len(after))):
        old = before[offset] if offset < len(before) else None
        new = after[offset] if offset < len(after) else None
        if old == new:
            continue
        count += 1
        if len(changes) < limit:
            xor = old ^ new if old is not None and new is not None else None
            changes.append(
                {
                    "byte_offset": offset,
                    "before_hex": f"{old:02x}" if old is not None else None,
                    "after_hex": f"{new:02x}" if new is not None else None,
                    "xor_hex": f"{xor:02x}" if xor is not None else None,
                    "changed_bit_offsets": (
                        [offset * 8 + bit for bit in range(8) if xor & (1 << bit)]
                        if xor is not None
                        else []
                    ),
                }
            )
    return {
        "before_bytes": len(before),
        "after_bytes": len(after),
        "changed_positions": count,
        "changes_truncated": count > limit,
        "alignment": "positional; insertions and deletions shift subsequent offsets",
        "changes": changes,
    }


def available_binary_operators(seed: bytes, max_input_bytes: int) -> list[str]:
    if not seed:
        return ["insert"]
    operators = ["bit_flip", "boundary_byte", "arithmetic", "zero_region"]
    if len(seed) < max_input_bytes:
        operators.extend(["insert", "duplicate"])
    if len(seed) > 1:
        operators.append("delete")
    return operators


def mutate_binary(
    seed: bytes,
    attempt: int,
    rng: random.Random,
    max_input_bytes: int,
    preferred_operator: str | None = None,
) -> tuple[bytes, dict]:
    """Apply one reproducible mutation with a bounded output size."""
    if not seed:
        return bytes([rng.randrange(256)]), {"operator": "insert", "offset": 0, "length": 1}
    operators = available_binary_operators(seed, max_input_bytes)
    operator = (
        preferred_operator
        if preferred_operator in operators
        else operators[attempt % len(operators)]
    )
    offset = rng.randrange(len(seed))
    data = bytearray(seed)
    detail: dict = {"operator": operator, "offset": offset}
    if operator == "bit_flip":
        bit = rng.randrange(8)
        data[offset] ^= 1 << bit
        detail["bit_offset"] = offset * 8 + bit
    elif operator == "boundary_byte":
        chosen = (0, 1, 0x7F, 0x80, 0xFE, 0xFF)[rng.randrange(6)]
        data[offset] = chosen if chosen != data[offset] else chosen ^ 1
    elif operator == "arithmetic":
        data[offset] = (data[offset] + (1 if rng.randrange(2) else -1)) & 0xFF
    elif operator == "zero_region":
        length = min(len(seed) - offset, rng.randint(1, 4))
        data[offset : offset + length] = bytes(length)
        detail["length"] = length
    elif operator == "insert":
        data.insert(offset, rng.randrange(256))
        detail["length"] = 1
    elif operator == "duplicate":
        length = min(len(seed) - offset, max_input_bytes - len(seed), rng.randint(1, 4))
        data[offset:offset] = seed[offset : offset + length]
        detail["length"] = length
    elif operator == "delete":
        del data[offset]
        detail["length"] = 1
    return bytes(data), detail


def payload_variants(check_key: str, payload: dict, max_variants: int = 6) -> list[dict]:
    """Return bounded single and pairwise mutations; proof policies decide findings."""
    if max_variants < 0 or max_variants > 32:
        raise ValueError("max_variants must be between 0 and 32")
    if max_variants == 0:
        return []
    if payload.get("method") != "GET" or not isinstance(payload.get("value"), str):
        return []
    value = payload["value"]
    if not value or len(value) > 512:
        return []
    transforms = []
    if check_key == "sqli":
        transforms.extend(
            [
                ("sql_comment_space", lambda text: text.replace(" ", "/**/")),
                ("sql_tab_space", lambda text: text.replace(" ", "\t")),
                (
                    "sql_keyword_case",
                    lambda text: text.replace(" OR ", " oR ").replace("SELECT", "SeLeCt"),
                ),
            ]
        )
    elif check_key == "xss":
        transforms.extend(
            [
                (
                    "html_tag_case",
                    lambda text: text.replace("script", "ScRiPt").replace("img", "ImG"),
                ),
                (
                    "html_numeric_entity",
                    lambda text: text.replace("<", "&#x3c;").replace(">", "&#x3e;"),
                ),
            ]
        )
    elif check_key == "ssti":
        transforms.append(("template_whitespace", lambda text: text.replace("*", " * ")))
    elif check_key == "lfi":
        transforms.extend(
            [
                ("path_redundant_slash", lambda text: text.replace("/", "//")),
                ("path_percent_dot", lambda text: text.replace("..", "%2e%2e")),
            ]
        )
    else:
        return []
    transforms.extend(
        [
            ("percent_encode", lambda text: quote(text, safe="")),
            ("double_percent_encode", lambda text: quote(quote(text, safe=""), safe="")),
        ]
    )
    candidates = [(name, transform(value)) for name, transform in transforms]
    for first_name, first_transform in transforms:
        first_value = first_transform(value)
        if first_value == value:
            continue
        for second_name, second_transform in transforms:
            if first_name == second_name:
                continue
            candidates.append((f"{first_name}+{second_name}", second_transform(first_value)))
    seen = {value}
    variants = []
    for name, candidate in candidates:
        if candidate in seen or len(candidate) > 2048:
            continue
        seen.add(candidate)
        variants.append({**payload, "value": candidate, "mutation_name": name})
        if len(variants) >= max_variants:
            break
    return variants


@dataclass(frozen=True)
class BinaryFuzzConfig:
    seed_path: Path
    results_dir: Path
    program: Path | None = None
    program_args: tuple[str, ...] = ()
    allow_host_execution: bool = False
    runs: int = 128
    timeout_seconds: float = 2.0
    max_duration_seconds: float = 300.0
    max_input_bytes: int = 1_048_576
    max_output_bytes: int = 65_536
    max_saved_cases: int = 20
    mutation_seed: int = 0
    retry_after_seconds: float = 86400.0

    def __post_init__(self) -> None:
        if not 1 <= self.runs <= 5000:
            raise ValueError("runs must be between 1 and 5000")
        if not 0 < self.timeout_seconds <= 60 or not 0 < self.max_duration_seconds <= 86400:
            raise ValueError("timeouts must be positive and within configured limits")
        if not 1 <= self.max_input_bytes <= 4_194_304:
            raise ValueError("max_input_bytes must be between 1 and 4194304")
        if not 1 <= self.max_output_bytes <= 1_048_576:
            raise ValueError("max_output_bytes must be between 1 and 1048576")
        if not 0 <= self.max_saved_cases <= 100:
            raise ValueError("max_saved_cases must be between 0 and 100")
        if self.retry_after_seconds < 0:
            raise ValueError("retry_after_seconds must be non-negative")
        if self.program is not None and not self.allow_host_execution:
            raise ValueError("Running a local program requires --allow-host-execution")


def _read_limited(stream, max_bytes: int, result: dict) -> None:
    digest = hashlib.sha256()
    kept = bytearray()
    total = 0
    try:
        while chunk := stream.read(65536):
            total += len(chunk)
            digest.update(chunk)
            if len(kept) < max_bytes:
                kept.extend(chunk[: max_bytes - len(kept)])
    except OSError:
        pass
    finally:
        stream.close()
    result.update(
        prefix=bytes(kept), size=total, sha256=digest.hexdigest(), truncated=total > max_bytes
    )


def _run_program(
    config: BinaryFuzzConfig, input_path: Path, scratch: Path, timeout_seconds: float
) -> dict:
    assert config.program is not None
    args = [arg.replace("{input}", str(input_path)) for arg in config.program_args]
    if not any("{input}" in arg for arg in config.program_args):
        args.append(str(input_path))
    safe_env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "PATHEXT", "TEMP", "TMP", "LANG"}
    }
    started = time.monotonic()
    process = subprocess.Popen(
        [str(config.program), *args],
        cwd=scratch,
        env=safe_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        shell=False,
        start_new_session=os.name != "nt",
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
    )
    stdout: dict = {}
    stderr: dict = {}
    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(
            target=_read_limited,
            args=(process.stdout, config.max_output_bytes, stdout),
            daemon=True,
        ),
        threading.Thread(
            target=_read_limited,
            args=(process.stderr, config.max_output_bytes, stderr),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        process.wait()
    for reader in readers:
        reader.join(timeout=2)
    capture_incomplete = any(reader.is_alive() for reader in readers)
    empty_digest = hashlib.sha256(b"").hexdigest()
    stdout.setdefault("prefix", b"")
    stdout.setdefault("size", 0)
    stdout.setdefault("sha256", empty_digest)
    stdout.setdefault("truncated", False)
    stderr.setdefault("prefix", b"")
    stderr.setdefault("size", 0)
    stderr.setdefault("sha256", empty_digest)
    stderr.setdefault("truncated", False)
    return {
        "exit_code": process.returncode,
        "timed_out": timed_out,
        "duration_seconds": round(time.monotonic() - started, 4),
        "capture_incomplete": capture_incomplete,
        "stdout": stdout,
        "stderr": stderr,
    }


def _public_outcome(outcome: dict | None) -> dict | None:
    if outcome is None:
        return None
    return {
        "exit_code": outcome["exit_code"],
        "timed_out": outcome["timed_out"],
        "duration_seconds": outcome["duration_seconds"],
        "capture_incomplete": outcome["capture_incomplete"],
        "stdout": {key: val for key, val in outcome["stdout"].items() if key != "prefix"},
        "stderr": {key: val for key, val in outcome["stderr"].items() if key != "prefix"},
    }


def run_binary_fuzz(config: BinaryFuzzConfig, memory: AuraMemoryManager) -> dict:
    """Mutate a file seed and optionally observe a local program's bounded outcomes."""
    seed_path = config.seed_path.resolve(strict=True)
    if not seed_path.is_file() or seed_path.stat().st_size > config.max_input_bytes:
        raise ValueError("Seed must be a regular file within max_input_bytes")
    seed = seed_path.read_bytes()
    if len(seed) > config.max_input_bytes:
        raise ValueError("Seed exceeds max_input_bytes")
    program = config.program.resolve(strict=True) if config.program else None
    if program is not None and not program.is_file():
        raise ValueError("Program must be a regular file")
    seed_digest = hashlib.sha256(seed).hexdigest()
    program_digest = sha256_file(program) if program else "mutation-only"
    key_material = json.dumps([seed_digest, program_digest, config.program_args]).encode()
    target_key = hashlib.sha256(key_material).hexdigest()
    rng = random.Random(int(seed_digest[:16], 16) ^ config.mutation_seed)
    started = time.monotonic()
    cases: list[dict] = []
    skipped_repeat = 0
    saved = 0
    baseline = None
    seen_outcomes: set[tuple] = set()
    feedback = memory.recall_fuzz_feedback(target_key, "binary") if program else {}
    operators = available_binary_operators(seed, config.max_input_bytes)
    termination_reason = "run_limit_reached"
    config.results_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="secagent-fuzz-") as temp:
        scratch = Path(temp)
        input_path = scratch / "input.bin"
        if program:
            input_path.write_bytes(seed)
            baseline = _run_program(
                config,
                input_path,
                scratch,
                min(config.timeout_seconds, max(0.01, config.max_duration_seconds)),
            )
            seen_outcomes.add(
                (
                    baseline["exit_code"],
                    baseline["timed_out"],
                    baseline["stdout"]["sha256"],
                    baseline["stderr"]["sha256"],
                )
            )
        for attempt in range(config.runs * 20):
            if len(cases) >= config.runs:
                break
            if time.monotonic() - started >= config.max_duration_seconds:
                termination_reason = "deadline_exceeded"
                break
            preferred = None
            if program and attempt >= len(operators) * 2 and attempt % 4 != 0:
                total = sum(count for count, _ in feedback.values())
                weights = []
                for operator in operators:
                    count, interesting_count = feedback.get(operator, (0, 0))
                    weights.append(
                        (interesting_count + 1) / (count + 2)
                        + math.sqrt(2 * math.log(total + 2) / (count + 1))
                    )
                preferred = rng.choices(operators, weights=weights, k=1)[0]
            mutated, mutation = mutate_binary(
                seed, attempt, rng, config.max_input_bytes, preferred_operator=preferred
            )
            if mutated == seed:
                continue
            fingerprint = hashlib.sha256(mutated).hexdigest()
            if not memory.claim_fuzz_attempt(
                target_key,
                "binary",
                fingerprint,
                retry_after_seconds=config.retry_after_seconds,
            ):
                skipped_repeat += 1
                continue
            input_path.write_bytes(mutated)
            try:
                remaining = config.max_duration_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    memory.release_fuzz_attempt(target_key, "binary", fingerprint)
                    termination_reason = "deadline_exceeded"
                    break
                observed = (
                    _run_program(
                        config, input_path, scratch, min(config.timeout_seconds, remaining)
                    )
                    if program
                    else None
                )
            except OSError:
                memory.release_fuzz_attempt(target_key, "binary", fingerprint)
                raise
            changed_outcome = bool(
                observed
                and baseline
                and (
                    observed["exit_code"] != baseline["exit_code"]
                    or observed["timed_out"] != baseline["timed_out"]
                    or (
                        not observed["capture_incomplete"]
                        and not baseline["capture_incomplete"]
                        and (
                            observed["stdout"]["sha256"] != baseline["stdout"]["sha256"]
                            or observed["stderr"]["sha256"] != baseline["stderr"]["sha256"]
                        )
                    )
                )
            )
            outcome_signature = (
                (
                    observed["exit_code"],
                    observed["timed_out"],
                    observed["stdout"]["sha256"],
                    observed["stderr"]["sha256"],
                )
                if observed
                else None
            )
            novel_outcome = bool(
                outcome_signature
                and not observed["capture_incomplete"]
                and outcome_signature not in seen_outcomes
            )
            if outcome_signature:
                seen_outcomes.add(outcome_signature)
                operator = mutation["operator"]
                memory.record_fuzz_feedback(target_key, "binary", operator, novel_outcome)
                count, interesting_count = feedback.get(operator, (0, 0))
                feedback[operator] = (count + 1, interesting_count + int(novel_outcome))
            interesting = novel_outcome or program is None
            memory.record_fuzz_outcome(
                target_key, "binary", fingerprint, "interesting" if interesting else "unchanged"
            )
            case = {
                "index": len(cases) + 1,
                "input_sha256": fingerprint,
                "mutation": mutation,
                "input_bit_diff": byte_changes(seed, mutated),
                "outcome": _public_outcome(observed),
                "outcome_changed": changed_outcome,
                "novel_outcome": novel_outcome,
                "new_nonzero_exit": bool(
                    observed
                    and baseline
                    and observed["exit_code"] != 0
                    and baseline["exit_code"] == 0
                ),
                "stdout_bit_diff": (
                    byte_changes(baseline["stdout"]["prefix"], observed["stdout"]["prefix"])
                    if observed and baseline
                    else None
                ),
                "stderr_bit_diff": (
                    byte_changes(baseline["stderr"]["prefix"], observed["stderr"]["prefix"])
                    if observed and baseline
                    else None
                ),
            }
            if interesting and saved < config.max_saved_cases:
                corpus = config.results_dir / "cases"
                corpus.mkdir(exist_ok=True)
                saved_path = corpus / f"{fingerprint[:24]}.bin"
                saved_path.write_bytes(mutated)
                case["saved_input"] = str(saved_path)
                saved += 1
            cases.append(case)
        else:
            termination_reason = "mutation_space_exhausted"
    summary = {
        "cases_executed": len(cases),
        "skipped_repeated_inputs": skipped_repeat,
        "outcomes_changed": sum(case["outcome_changed"] for case in cases),
        "novel_outcomes": sum(case["novel_outcome"] for case in cases),
        "new_nonzero_exits": sum(case["new_nonzero_exit"] for case in cases),
        "timeouts": sum(bool(case["outcome"] and case["outcome"]["timed_out"]) for case in cases),
        "saved_cases": saved,
        "termination_reason": termination_reason,
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    report = {
        "schema_version": "1.0",
        "seed_sha256": seed_digest,
        "program_sha256": program_digest,
        "host_execution": program is not None,
        "baseline": _public_outcome(baseline),
        "summary": summary,
        "cases": cases,
    }
    report_path = config.results_dir / f"binary-fuzz-{seed_digest[:12]}-{time.time_ns()}.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["report_path"] = str(report_path)
    return report
