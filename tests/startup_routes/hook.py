import subprocess
import sys
from pathlib import Path
mode, prefix, router = sys.argv[1:]
with Path('/artifacts/hooks.log').open('a') as output:
    output.write(mode + ' ' + prefix + '\n')
subprocess.run(['ip', '-6', 'route', 'replace' if mode == 'up' else 'del', prefix,
                'via', router, 'dev', 'lan0'], check=True)
