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


def review(report, model="qwen3:4b"):
    if model not in MODELS:
        raise ValueError("Choose a supported local model")
    counts = summarize(report)
    payload = {"model": model, "stream": False, "format": "json",
               "options": {"temperature": 0.1, "num_predict": 512},
               "messages": [
                   {"role": "system", "content": "Explain aggregate configuration audit counts for a defensive report. Do not invent vulnerabilities. Return JSON with one string key summary. Recommend manual verification and remediation planning only."},
                   {"role": "user", "content": json.dumps(counts)}]}
    request = urllib.request.Request(ENDPOINT, data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=120) as response:
        raw = response.read(65537)
    if len(raw) > 65536:
        raise ValueError("Response too large")
    answer = json.loads(json.loads(raw)["message"]["content"])
    if not isinstance(answer, dict) or set(answer) != {"summary"} or not isinstance(answer["summary"], str) or not 0 < len(answer["summary"]) <= 4000:
        raise ValueError("Unexpected AI response")
    return {"model": model, "advisory_only": True, "counts": counts, "summary": answer["summary"]}


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
        parser.exit(1, "Local AI review failed; check report format and Ollama availability.\\n")


if __name__ == "__main__":
    main()
