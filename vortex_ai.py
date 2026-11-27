"""Optional local AI review of aggregate configuration-audit counts."""
import argparse
import json
from pathlib import Path
import urllib.request
import urllib.error

ENDPOINT = "http://127.0.0.1:11434/api/chat"
LEVELS = ("medium", "low", "review", "info")
MODELS = ("qwen3:1.7b", "qwen3:4b", "qwen3:8b", "qwen3:14b")


def summarize(report):
    counts = dict.fromkeys(LEVELS, 0)
    for result in report["results"]:
        for finding in result["findings"]:
            severity = finding["severity"]
            if severity not in counts:
                raise ValueError("Unknown severity")
            counts[severity] += 1
    return counts


def coverage(report):
    """Deterministic coverage, never infer absence of vulnerabilities."""
    results = report["results"]
    return {"targets": len(results),
            "completed": sum(r.get("outcome") == "completed" for r in results),
            "errors": sum(r.get("outcome") == "error" for r in results),
            "demo": report.get("demo") is True,
            "limitations": "Configuration observations only; unassessed risks remain unknown."}


def review(report, model="qwen3:4b"):
    if model not in MODELS:
        raise ValueError("Choose a supported local model")
    counts = summarize(report)
    audit_coverage = coverage(report)
    payload = {"model": model, "stream": False, "think": False, "format": {"type": "object", "properties": {"summary": {"type": "string"}},
                          "required": ["summary"], "additionalProperties": False},
               "options": {"temperature": 0.1, "num_predict": 1024},
               "messages": [
                   {"role": "system", "content": "Explain aggregate configuration audit counts for a defensive report. Do not invent vulnerabilities or claim any severity is absent beyond the supplied counts. These are observations, not confirmed vulnerabilities. Never imply that untested risks are absent. Return exactly one JSON object matching {\"summary\": \"brief advisory text\"}; no other keys. Recommend manual verification and remediation planning only."},
                   {"role": "user", "content": json.dumps({"counts": counts, "coverage": audit_coverage})}]}
    request = urllib.request.Request(ENDPOINT, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=120) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("Response too large")
    envelope = json.loads(raw)
    content = envelope["message"]["content"]
    if not isinstance(content, str) or not content.strip():
        raise ValueError("Ollama returned empty content; check model generation settings.")
    try:
        answer = json.loads(content)
    except json.JSONDecodeError:
        raise ValueError("Ollama returned invalid JSON content.") from None
    if not isinstance(answer, dict) or set(answer) != {"summary"} or not isinstance(answer["summary"], str) or not 0 < len(answer["summary"].strip()) <= 4000:
        raise ValueError("AI response must contain exactly one nonempty summary string.")
    return {"model": model, "advisory_only": True, "counts": counts, "coverage": audit_coverage, "summary": answer["summary"]}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--model", choices=MODELS, default="qwen3:4b")
    args = parser.parse_args()
    try:
        with args.report.open("rb") as source:
            raw = source.read(2000001)
        if len(raw) > 2000000:
            raise ValueError("Report too large")
        print(json.dumps(review(json.loads(raw), args.model), indent=2))
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        parser.exit(1, "Local AI review failed; check report format and Ollama availability.\n")


if __name__ == "__main__":
    main()
