#!/usr/bin/env python3
"""AD Rules Elasticsearch Dashboard — Kibana-style Flask app."""

import os
import re
import copy
import json
import time
import hashlib
from datetime import datetime
from pathlib import Path

import yaml
import requests
from flask import Flask, render_template, jsonify, Response, request

# ── Configuration ────────────────────────────────────────────────────────────
ES_URL = os.environ.get("ES_URL", "http://10.10.10.60:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS", "elasticpassword")
RULES_DIR = os.environ.get(
    "RULES_DIR",
    str(Path(__file__).resolve().parent.parent / "AD rules"),
)
QUERY_TIMEOUT = 120  # seconds per query

app = Flask(__name__)

# ── Helpers ──────────────────────────────────────────────────────────────────

def _es(method, path, **kwargs):
    """Low-level Elasticsearch request."""
    url = f"{ES_URL}{path}"
    kwargs.setdefault("auth", (ES_USER, ES_PASS))
    kwargs.setdefault("timeout", QUERY_TIMEOUT)
    return getattr(requests, method)(url, **kwargs)


def _rule_id(name: str) -> str:
    return hashlib.md5(name.encode()).hexdigest()[:12]


# ── Rule Loader ──────────────────────────────────────────────────────────────

_rules_cache: list | None = None


def load_rules(force=False) -> list:
    global _rules_cache
    if _rules_cache is not None and not force:
        return _rules_cache

    rules = []
    rules_path = Path(RULES_DIR)
    if not rules_path.is_dir():
        return rules

    for fp in sorted(rules_path.iterdir()):
        if fp.suffix not in (".yml", ".yaml"):
            continue
        try:
            with open(fp, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if not data or "query" not in data:
                continue

            rule = {
                "id": _rule_id(data.get("name", fp.stem)),
                "file": fp.name,
                "name": data.get("name", fp.stem),
                "description": (data.get("description") or "").strip(),
                "type": data.get("type", "esql"),
                "query": data.get("query", ""),
                "index": data.get("index", []),
                "severity": data.get("severity", "medium"),
                "risk_score": data.get("risk_score", 50),
                "tags": data.get("tags", []),
                "enabled": data.get("enabled", False),
                "schedule_interval": data.get("schedule_interval", "10m"),
                "mitre_attack": data.get("mitre_attack", {}),
                "nist": data.get("nist", []),
                "pci_dss": data.get("pci_dss", []),
                "gdpr": data.get("gdpr", []),
                "references": data.get("references", []),
            }
            rules.append(rule)
        except Exception as exc:
            app.logger.warning("Failed to load %s: %s", fp.name, exc)

    _rules_cache = rules
    return rules


# ── Elasticsearch helpers ────────────────────────────────────────────────────

def get_es_status():
    """Return basic cluster info."""
    try:
        r = _es("get", "/")
        r.raise_for_status()
        info = r.json()
        return {
            "connected": True,
            "cluster_name": info.get("cluster_name", ""),
            "version": info.get("version", {}).get("number", ""),
        }
    except Exception as exc:
        return {"connected": False, "error": str(exc)}


def get_indexes():
    """List indices matching winlogbeat-*."""
    try:
        r = _es("get", "/_cat/indices/winlogbeat*", params={"format": "json", "h": "index,docs.count,store.size,status"})
        r.raise_for_status()
        return r.json()
    except Exception:
        # fallback: try data streams
        try:
            r = _es("get", "/_cat/indices/*winlogbeat*", params={"format": "json", "h": "index,docs.count,store.size,status"})
            r.raise_for_status()
            return r.json()
        except Exception:
            return []


# Time-range rewrite patterns
_TIME_RE = re.compile(
    r"@timestamp\s*>=\s*NOW\(\)\s*-\s*\d+\s*(?:minutes?|hours?|days?|[mhd])",
    re.IGNORECASE,
)
TIME_RANGES = {
    "15m": "15 minutes",
    "1h": "1 hour",
    "6h": "6 hours",
    "24h": "24 hours",
    "7d": "7 days",
    "30d": "30 days",
    "all": None,  # remove filter entirely
}


def _rewrite_time(query: str, time_range: str) -> str:
    """Replace the time window in an ES|QL query."""
    if time_range not in TIME_RANGES or time_range == "15m":
        return query  # keep original
    replacement = TIME_RANGES[time_range]
    if replacement is None:
        # Remove the entire WHERE clause containing the timestamp filter
        query = re.sub(
            r"\|\s*WHERE\s+@timestamp\s*>=\s*NOW\(\)\s*-\s*\d+\s*(?:minutes?|hours?|days?|[mhd])\s*",
            "",
            query,
            flags=re.IGNORECASE,
        )
    else:
        query = _TIME_RE.sub(f"@timestamp >= NOW() - {replacement}", query)
    return query


def execute_esql(query: str, time_range: str = "15m"):
    """Execute an ES|QL query and return (columns, values, took_ms, error)."""
    query = _rewrite_time(query, time_range)
    try:
        r = _es(
            "post",
            "/_query",
            headers={"Content-Type": "application/json"},
            json={"query": query},
        )
        body = r.json()
        if r.status_code != 200:
            error_msg = body.get("error", {})
            if isinstance(error_msg, dict):
                error_msg = error_msg.get("reason", json.dumps(error_msg))
            return [], [], 0, str(error_msg)
        cols = [c["name"] for c in body.get("columns", [])]
        vals = body.get("values", [])
        took = body.get("took", 0)
        return cols, vals, took, None
    except requests.exceptions.Timeout:
        return [], [], 0, "Query timed out"
    except Exception as exc:
        return [], [], 0, str(exc)


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    return jsonify(get_es_status())


@app.route("/api/indexes")
def api_indexes():
    return jsonify(get_indexes())


@app.route("/api/rules")
def api_rules():
    rules = load_rules()
    return jsonify(rules)


@app.route("/api/execute/<rule_id>")
def api_execute_rule(rule_id):
    rules = load_rules()
    rule = next((r for r in rules if r["id"] == rule_id), None)
    if not rule:
        return jsonify({"error": "Rule not found"}), 404

    time_range = request.args.get("time_range", "15m")
    query = rule["query"].strip()
    cols, vals, took, error = execute_esql(query, time_range)
    return jsonify({
        "rule_id": rule_id,
        "rule_name": rule["name"],
        "columns": cols,
        "values": vals,
        "hit_count": len(vals),
        "took_ms": took,
        "error": error,
        "executed_at": datetime.utcnow().isoformat() + "Z",
    })


@app.route("/api/execute_all")
def api_execute_all():
    """SSE endpoint — streams execution results for every rule."""
    rules = load_rules()

    def generate():
        total = len(rules)
        summary = {
            "total": total,
            "executed": 0,
            "alerts": 0,
            "errors": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        }
        results = []

        time_range = request.args.get("time_range", "15m")
        for idx, rule in enumerate(rules):
            query = rule["query"].strip()
            cols, vals, took, error = execute_esql(query, time_range)
            hit_count = len(vals)
            summary["executed"] += 1

            result = {
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "risk_score": rule["risk_score"],
                "hit_count": hit_count,
                "took_ms": took,
                "error": error,
                "columns": cols,
                "values": vals,
                "tags": rule["tags"],
                "mitre_attack": rule["mitre_attack"],
                "nist": rule["nist"],
                "pci_dss": rule["pci_dss"],
                "gdpr": rule["gdpr"],
            }

            if error:
                summary["errors"] += 1
            if hit_count > 0:
                summary["alerts"] += hit_count
                sev = rule["severity"].lower()
                if sev in summary["by_severity"]:
                    summary["by_severity"][sev] += hit_count

            results.append(result)

            event_data = json.dumps({
                "progress": idx + 1,
                "total": total,
                "result": result,
                "summary": summary,
            })
            yield f"data: {event_data}\n\n"

        # Final summary
        yield f"data: {json.dumps({'done': True, 'summary': summary, 'results': results})}\n\n"

    return Response(generate(), mimetype="text/event-stream")


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
