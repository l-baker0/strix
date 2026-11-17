"""Decide, at sandbox start, which mounted source trees are graph-backed.

The decision belongs to Strix, not the agent: after the sandbox is up the runner calls
:func:`prepare_code_graphs`, which runs the image's ``strix-codegraph build`` for each
mounted source tree (policy ``auto``, ``on`` or ``off``) and returns a small context dict.
Agents are only told about a graph when one is ready; ``off`` (black-box runs), URL-only
scans, skipped trees, and failed builds all look the same to the agent: no graph, no skill.
A build problem never stops the scan.
"""

import json
import logging
from typing import Any

from strix.config import load_settings


logger = logging.getLogger(__name__)

GRAPH_ROOT = "/workspace/.strix-codegraph"
_WORKSPACE_ROOT = "/workspace"
_BUILD_TIMEOUT_MARGIN_S = 120


def graph_dir_name(source: dict[str, Any]) -> str:
    return str(source.get("workspace_subdir") or "").strip("/") or "root"


def _source_path(source: dict[str, Any]) -> str:
    sub = str(source.get("workspace_subdir") or "").strip("/")
    return f"{_WORKSPACE_ROOT}/{sub}" if sub else _WORKSPACE_ROOT


def _last_json_line(stdout: str) -> dict[str, Any] | None:
    for raw in reversed(stdout.strip().splitlines()):
        line = raw.strip()
        if line.startswith("{"):
            try:
                parsed = json.loads(line)
            except ValueError:
                return None
            return parsed if isinstance(parsed, dict) else None
    return None


def summarize(source: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    """Reduce a strix-codegraph status.json to what the prompt and logs need."""
    entry = {
        "source": _source_path(source),
        "state": status.get("state", "failed"),
        "reason": status.get("reason"),
    }
    if entry["state"] == "ready":
        entry.update(
            db=status.get("db"),
            status_file=f"{GRAPH_ROOT}/{graph_dir_name(source)}/status.json",
            functions=status.get("functions"),
            calls=status.get("calls"),
            flows=status.get("flows"),
            derived=status.get("derived") or {},
            warnings=list(status.get("warnings") or []),
        )
    return entry


async def prepare_code_graphs(
    session: Any,
    local_sources: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    """Build graphs for mounted sources per ``STRIX_CODE_GRAPH`` and describe the outcome.

    Returns ``{"mode", "ready", "graphs", "skipped"}``. ``ready`` is true only if at least
    one source has a usable graph; it is what loads the query skill into agent prompts.
    """
    cfg = load_settings().code_graph
    result: dict[str, Any] = {"mode": cfg.mode, "ready": False, "graphs": [], "skipped": []}
    if cfg.mode == "off" or not local_sources:
        return result

    for source in local_sources:
        out = f"{GRAPH_ROOT}/{graph_dir_name(source)}"
        cmd = [
            "strix-codegraph",
            "build",
            "--source",
            _source_path(source),
            "--out",
            out,
            "--policy",
            cfg.mode,
            "--timeout",
            str(cfg.timeout_s),
            "--min-files",
            str(cfg.min_files),
            "--min-loc",
            str(cfg.min_loc),
            "--reuse",
        ]
        try:
            run = await session.exec(*cmd, timeout=cfg.timeout_s + _BUILD_TIMEOUT_MARGIN_S)
        except Exception as exc:  # noqa: BLE001 - timeout or backend error; scan continues
            logger.warning("code graph build did not complete for %s: %s", source, exc)
            result["skipped"].append(
                summarize(source, {"state": "failed", "reason": str(exc)[:200]})
            )
            continue
        stdout = run.stdout.decode("utf-8", errors="replace") if run.stdout else ""
        status = _last_json_line(stdout)
        if status is None:
            # Older image without strix-codegraph, or a crash before it could report.
            reason = "strix-codegraph unavailable" if run.exit_code == 127 else "no build status"
            status = {"state": "failed", "reason": reason}
        summary = summarize(source, status)
        if summary["state"] == "ready":
            result["graphs"].append(summary)
        else:
            result["skipped"].append(summary)
        logger.info(
            "code graph for %s: %s%s",
            summary["source"],
            summary["state"],
            f" ({summary['reason']})" if summary.get("reason") else "",
        )

    result["ready"] = bool(result["graphs"])
    return result
