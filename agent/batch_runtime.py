"""Durable bounded batch execution and offline replay for evidence stages."""

from __future__ import annotations

import asyncio
import json
import random
import time
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Awaitable, Callable

from agent.evidence_contract import (
    BATCH_STATES, RULESET_VERSION, content_hash, validate_coverage,
)


class SplitBatch(Exception):
    """Only a context overflow or truncated output may split a batch."""


class DependencyCircuit:
    def __init__(self, threshold: int = 3):
        self.threshold = threshold
        self.failures: dict[str, int] = {}
        self.gates = {"deps_dev": asyncio.Semaphore(8), "osv_api": asyncio.Semaphore(2)}

    def check(self, dependency: str) -> None:
        if self.failures.get(dependency, 0) >= self.threshold:
            raise RuntimeError(f"dependency_circuit_open:{dependency}")

    def record(self, dependency: str, success: bool) -> None:
        self.failures[dependency] = 0 if success else self.failures.get(dependency, 0) + 1


def _write_json(path: Path, value: dict) -> None:
    if "batches" in value:
        value["plan_hash"] = content_hash([
            (item["batch_id"], item.get("parent_id"), item["owned_components"],
             item["input_hash"])
            for item in value["batches"]
        ])
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(path)


@lru_cache(maxsize=4096)
def _estimate_tokens(serialized: str) -> int:
    try:
        import tiktoken
        return len(tiktoken.get_encoding("cl100k_base").encode(serialized))
    except Exception:
        return max(1, len(serialized) // 3)


def estimate_record_tokens(record: dict) -> int:
    return max(32, _estimate_tokens(json.dumps(record, ensure_ascii=False, sort_keys=True)))


def make_manifest(stage: str, components: list[dict], token_budget: int = 3000,
                  max_items: int = 16, groups: list[list[str]] | None = None) -> dict:
    """Stable budget-driven packing; a group is indivisible for evidence affinity."""
    by_id = {item["component_id"]: item for item in components}
    if len(by_id) != len(components):
        raise ValueError("批次输入含重复组件 ID")
    units = groups or [[item["component_id"]] for item in components]
    flattened = [cid for group in units for cid in group]
    if len(flattened) != len(set(flattened)) or set(flattened) != set(by_id):
        raise ValueError("批次规划单元不是 S1 组件集合的精确划分")
    batches = []
    owned: list[str] = []
    weight = 0
    for unit in units:
        unit_weight = sum(estimate_record_tokens(by_id[cid]) for cid in unit)
        if owned and (weight + unit_weight > token_budget or len(owned) + len(unit) > max_items):
            batches.append(owned)
            owned, weight = [], 0
        owned.extend(unit)
        weight += unit_weight
    if owned:
        batches.append(owned)
    manifest = {
        "plan_version": 1, "ruleset_version": RULESET_VERSION, "stage": stage,
        "input_set_hash": content_hash(sorted(by_id)),
        "input_content_hash": content_hash(components),
        "group_hash": content_hash(units),
        "token_budget": token_budget, "max_items": max_items,
        "batches": [],
    }
    for index, ids in enumerate(batches, 1):
        manifest["batches"].append({
            "batch_id": f"{stage.lower()}-{index:04d}", "parent_id": None,
            "owned_components": ids, "context_components": [],
            "input_hash": content_hash([by_id[cid] for cid in ids]),
            "status": "pending", "attempts": 0, "feedback_used": False,
        })
    manifest["plan_hash"] = content_hash([
        (item["batch_id"], item["parent_id"], item["owned_components"], item["input_hash"])
        for item in manifest["batches"]
    ])
    return manifest


def _leaves(manifest: dict) -> list[dict]:
    parents = {item["parent_id"] for item in manifest["batches"] if item.get("parent_id")}
    return [item for item in manifest["batches"] if item["batch_id"] not in parents]


def validate_manifest(manifest: dict, components: list[dict]) -> list[str]:
    errors = []
    if manifest.get("ruleset_version") != RULESET_VERSION:
        errors.append("批次规则版本不匹配")
    if manifest.get("input_content_hash") != content_hash(components):
        errors.append("批次输入内容哈希不匹配")
    layout_hash = content_hash([
        (item["batch_id"], item.get("parent_id"), item["owned_components"], item["input_hash"])
        for item in manifest["batches"]
    ])
    if manifest.get("plan_hash") != layout_hash:
        errors.append("批次清单布局哈希不匹配")
    ids = [cid for item in _leaves(manifest) for cid in item["owned_components"]]
    expected = {item["component_id"] for item in components}
    if set(ids) != expected or len(ids) != len(expected):
        errors.append("活动叶批次 owned_components 与 S1 组件集合不一致")
    for item in manifest["batches"]:
        if item["status"] not in BATCH_STATES:
            errors.append(f"批次状态非法: {item['batch_id']}")
    return errors


def _split(manifest: dict, batch: dict, by_id: dict[str, dict]) -> None:
    ids = batch["owned_components"]
    if len(ids) < 2:
        batch["status"] = "incomplete"
        return
    middle = len(ids) // 2
    batch["status"] = "split"
    for index, shard in enumerate((ids[:middle], ids[middle:]), 1):
        manifest["batches"].append({
            "batch_id": f"{batch['batch_id']}/{index}",
            "parent_id": batch["batch_id"], "owned_components": shard,
            "context_components": [],
            "input_hash": content_hash([by_id[cid] for cid in shard]),
            "status": "pending", "attempts": 0, "feedback_used": False,
        })


async def run_stage(
    session_dir: Path, stage: str, components: list[dict],
    worker: Callable[[list[dict], DependencyCircuit], Awaitable[dict]],
    *, token_budget: int = 3000, max_items: int = 16,
    groups: list[list[str]] | None = None, concurrency: int = 3,
) -> dict:
    """Run bounded leaf batches, persist every output, then verify exact coverage."""
    path = session_dir / f"batch_plan_{stage.lower()}.json"
    proposal = make_manifest(stage, components, token_budget, max_items, groups)
    if path.exists():
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if (manifest.get("input_content_hash") != proposal["input_content_hash"]
                or manifest.get("group_hash") != proposal["group_hash"]
                or manifest.get("ruleset_version") != RULESET_VERSION):
            manifest = proposal
    else:
        manifest = proposal
    errors = validate_manifest(manifest, components)
    if errors:
        raise ValueError("；".join(errors))
    _write_json(path, manifest)
    by_id = {item["component_id"]: item for item in components}
    circuit = DependencyCircuit()
    gate = asyncio.Semaphore(concurrency)
    output_dir = session_dir / "batch_outputs" / stage.lower()

    async def execute(batch: dict) -> None:
        output_path = output_dir / (batch["batch_id"].replace("/", "_") + ".json")
        if batch["status"] == "succeeded" and output_path.exists():
            return
        async with gate:
            for attempt in range(3):
                batch["status"] = "running"
                batch["attempts"] += 1
                _write_json(path, manifest)
                started = time.perf_counter()
                try:
                    payload = await worker([by_id[cid] for cid in batch["owned_components"]], circuit)
                    outcomes = payload.get("outcomes") or []
                    errors = validate_coverage(set(batch["owned_components"]), outcomes, stage)
                    if errors:
                        raise ValueError("；".join(errors))
                    result = {
                        "stage": stage, "batch_id": batch["batch_id"],
                        "idempotency_key": content_hash([
                            stage, batch["batch_id"], batch["input_hash"], RULESET_VERSION,
                            manifest["plan_hash"], "deterministic-worker-v1",
                            payload.get("datasource_snapshot_id"),
                        ]),
                        "input_hash": batch["input_hash"],
                        "input_id_set_hash": content_hash(sorted(batch["owned_components"])),
                        "output_id_set_hash": content_hash(sorted(item["component_id"] for item in outcomes)),
                        "source_snapshot_id": payload.get("datasource_snapshot_id"),
                        "fetched_at": datetime.now(timezone.utc).isoformat(),
                        "outcomes": outcomes, "records": payload.get("records") or [],
                        "metadata": payload.get("metadata") or {},
                        "metrics": {"duration_ms": round((time.perf_counter()-started)*1000),
                                    "attempts": batch["attempts"],
                                    "estimated_input_tokens": sum(estimate_record_tokens(by_id[cid])
                                                                  for cid in batch["owned_components"]),
                                    "reserved_output_tokens": 0,
                                    "actual_model_tokens": 0},
                    }
                    result["output_content_hash"] = content_hash({k: v for k, v in result.items()
                                                                   if k != "output_content_hash"})
                    _write_json(output_path, result)
                    batch["status"] = "succeeded"
                    batch["output_file"] = output_path.relative_to(session_dir).as_posix()
                    batch["output_hash"] = result["output_content_hash"]
                    _write_json(path, manifest)
                    return
                except SplitBatch as exc:
                    batch["last_error"] = str(exc)
                    _split(manifest, batch, by_id)
                    _write_json(path, manifest)
                    return
                except ValueError as exc:
                    batch["last_error"] = str(exc)
                    # These workers are deterministic; a schema contradiction is
                    # not cured by repeating the same request unchanged.
                    break
                except Exception as exc:
                    batch["last_error"] = str(exc)
                    if "context" in str(exc).lower() or "truncat" in str(exc).lower():
                        _split(manifest, batch, by_id)
                        _write_json(path, manifest)
                        return
                    if attempt < 2:
                        await asyncio.sleep(min(2 ** attempt + random.random(), 5))
            batch["status"] = "incomplete"
            _write_json(path, manifest)

    while True:
        pending = [batch for batch in _leaves(manifest) if batch["status"] != "succeeded"
                   and batch["status"] not in {"incomplete", "failed"}]
        if not pending:
            break
        await asyncio.gather(*(execute(batch) for batch in pending))
    return replay_stage(session_dir, stage, components)


def replay_stage(session_dir: Path, stage: str, components: list[dict]) -> dict:
    """Offline merge: reads only the plan and persisted leaf artifacts."""
    manifest = json.loads((session_dir / f"batch_plan_{stage.lower()}.json").read_text(encoding="utf-8"))
    errors = validate_manifest(manifest, components)
    outcomes, records, metrics = [], [], []
    failed_batches: dict[str, dict] = {}
    for batch in _leaves(manifest):
        if batch["status"] != "succeeded":
            errors.append(f"批次未完成: {batch['batch_id']} ({batch['status']})")
            failed_batches.update({cid: batch for cid in batch["owned_components"]})
            continue
        try:
            result = json.loads((session_dir / batch["output_file"]).read_text(encoding="utf-8"))
        except (OSError, KeyError, ValueError) as exc:
            errors.append(f"批次产物无法读取: {batch['batch_id']}: {exc}")
            continue
        digest = content_hash({k: v for k, v in result.items() if k != "output_content_hash"})
        if digest != result.get("output_content_hash") or digest != batch.get("output_hash"):
            errors.append(f"批次内容哈希不匹配: {batch['batch_id']}")
        if result.get("input_hash") != batch["input_hash"]:
            errors.append(f"批次输入哈希不匹配: {batch['batch_id']}")
        if result.get("input_id_set_hash") != content_hash(sorted(batch["owned_components"])):
            errors.append(f"批次输入集合哈希不匹配: {batch['batch_id']}")
        if result.get("output_id_set_hash") != content_hash(sorted(
                item.get("component_id") for item in result.get("outcomes", []))):
            errors.append(f"批次输出集合哈希不匹配: {batch['batch_id']}")
        errors.extend(validate_coverage(set(batch["owned_components"]),
                                        result.get("outcomes", []), stage))
        outcomes.extend(result.get("outcomes", []))
        records.extend(result.get("records", []))
        metrics.append(result.get("metrics", {}))
    errors.extend(validate_coverage({item["component_id"] for item in components}, outcomes, stage))
    uncovered = [item for item in outcomes if item.get("status") not in {"complete", "no_finding"}]
    missing = {item["component_id"] for item in components} - {
        item.get("component_id") for item in outcomes
    }
    for cid in sorted(missing):
        batch = failed_batches.get(cid) or {}
        cause = str(batch.get("last_error") or "")
        uncovered.append({"component_id": cid,
                          "status": "over_budget" if "context" in cause.lower() else "source_failed",
                          "reason_code": "batch_incomplete",
                          "batch_id": batch.get("batch_id"), "detail": cause[:160]})
    return {
        "stage": stage, "ok": not errors, "errors": errors, "outcomes": outcomes,
        "records": records, "metrics": metrics,
        "uncovered": uncovered,
        "plan_file": f"batch_plan_{stage.lower()}.json",
    }
