"""Own non-shell controller used only to verify packaged lifetime/argv."""
import argparse
import json
from pathlib import Path
import time

parser = argparse.ArgumentParser()
parser.add_argument('--run-directory', required=True)
parser.add_argument('--sample', required=True)
args = parser.parse_args()
Path(args.run_directory, 'dummy-controller.json').write_text(json.dumps(vars(args)), encoding='utf-8')
time.sleep(4)
