"""Diagnostic observer only: execute whole server.py, without replacing functions."""
import json
import os
from pathlib import Path
import runpy
import sys
import threading

webui, output = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(webui))
def observe(frame, event, arg):
    if frame.f_code.co_filename == str(webui / 'api/post_restart_continuation.py'):
        if event == 'return' and frame.f_code.co_name == 'consume':
            with output.open('a') as f:
                f.write(json.dumps({'pid': os.getpid(), 'result': arg}) + '\n')
        elif event == 'exception':
            with output.open('a') as f:
                f.write(json.dumps({'pid': os.getpid(), 'function': frame.f_code.co_name, 'exception': str(arg[1])}) + '\n')
    return observe
threading.settrace(observe)
sys.settrace(observe)
sys.argv = [str(webui / 'server.py')]
runpy.run_path(sys.argv[0], run_name='__main__')
