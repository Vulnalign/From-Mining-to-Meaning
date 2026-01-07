import json
import sys
from pathlib import Path

GENERIC_KERNEL = {"name": "python3", "display_name": "Python 3"}

for fp in sys.argv[1:]:
    p = Path(fp)
    nb = json.loads(p.read_text(encoding="utf-8"))

    # generic notebook metadata
    nb.setdefault("metadata", {})
    nb["metadata"]["kernelspec"] = GENERIC_KERNEL

    for cell in nb.get("cells", []):
        if "execution_count" in cell:
            cell["execution_count"] = None
        if "outputs" in cell:
            cell["outputs"] = []
        # wipe cell metadata (often holds editor fingerprints)
        cell["metadata"] = {}

    p.write_text(json.dumps(nb, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Sanitized: {p}")
