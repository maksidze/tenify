"""Single-writer status publication; transient Windows sharing errors are bounded."""
import json
import os
import time
from pathlib import Path


def write_json(path, value, timeout_seconds=0.250):
    path = Path(path)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')
    deadline = time.monotonic() + timeout_seconds
    retries = 0
    while True:
        try:
            os.replace(temporary, path)
            return retries
        except OSError as error:
            remaining = deadline - time.monotonic()
            if getattr(error, 'winerror', None) not in (5, 32, 33, 303) or remaining <= 0:
                raise
            retries += 1
            time.sleep(min(0.010, remaining))
