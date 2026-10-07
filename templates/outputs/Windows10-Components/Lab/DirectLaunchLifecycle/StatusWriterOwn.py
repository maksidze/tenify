"""Non-UI fixture for the actual production AtomicStatus writer."""
import json
import sys
import time
from pathlib import Path
from AtomicStatus import write_json

directory = Path(sys.argv[1])
mode = sys.argv[2]
(directory/'ready').write_text('ready')
deadline = time.monotonic()+10
while not (directory/'go').exists():
    if time.monotonic() >= deadline:
        raise TimeoutError('Own writer fixture gate')
    time.sleep(.002)
start = time.monotonic()
try:
    count = 400 if mode == 'concurrent' else 1
    retries = 0
    for sequence in range(1, count+1):
        retries += write_json(directory/'status.json', {'sequence': sequence, 'payload': 'x'*8000})
        if count > 1:
            time.sleep(.001)
    result = {'Passed': mode != 'refuse', 'Replacements': count, 'Retries': retries}
except OSError as error:
    result = {'Passed': mode == 'refuse' and error.winerror in (5,32,33,303), 'WinError': error.winerror}
result['ElapsedMs'] = (time.monotonic()-start)*1000
(directory/'result.json').write_text(json.dumps(result))
sys.exit(0 if result['Passed'] else 1)
