from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import tempfile

from flask import Flask, jsonify, request

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(name)s] %(levelname)s: %(message)s'
)
logger = logging.getLogger('worker-app')

app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/apply", methods=["POST"])
def apply_update():
    payload = request.get_json(force=True)
    module_source = payload.get("module_source")
    manifest = payload.get("manifest", {})
    if not module_source:
        return jsonify({"status": "error", "message": "module_source missing"}), 400

    with tempfile.TemporaryDirectory() as td:
        module_path = os.path.join(td, "update_module.py")
        with open(module_path, "w", encoding="utf-8") as fh:
            fh.write(module_source)

        # Runner code executed in subprocess to allow resource limits
        manifest_json = json.dumps(manifest)
        runner_code = f"""
import json
import logging
import resource
import sys
try:
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_AS, (200 * 1024 * 1024, 200 * 1024 * 1024))
except Exception:
    pass
logger = logging.getLogger('worker-sandbox')
def record_event(*args, **kwargs):
    return None
ns = {{}}
with open({json.dumps(module_path)!r}, 'r', encoding='utf-8') as f:
    code = f.read()
exec(code, ns)
if 'apply_update' in ns:
    try:
        result = ns['apply_update']({{'logger': logger, 'record_event': record_event, 'manifest': {manifest_json}, 'runtime_dir': '/artifacts', 'leak_file': '/artifacts/simulated_leak.txt'}})
        print(json.dumps({{'status': 'ok', 'result': result}}))
    except Exception as e:
        print(json.dumps({{'status': 'error', 'message': str(e)}}))
else:
    print(json.dumps({{'status': 'error', 'message': 'no apply_update found'}}))
"""

        try:
            proc = subprocess.run([sys.executable, "-c", runner_code], capture_output=True, text=True, timeout=15)
            out = proc.stdout.strip()
            try:
                resp = json.loads(out.splitlines()[-1])
            except Exception:
                resp = {"status": "error", "stdout": proc.stdout, "stderr": proc.stderr}
            return jsonify(resp)
        except subprocess.TimeoutExpired:
            return jsonify({"status": "error", "message": "worker timeout"}), 500
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/test", methods=["POST"])
def test_artifact():
    payload = request.get_json(force=True)
    artifact_dir = payload.get("artifact_dir")
    manifest = payload.get("manifest", {})
    
    logger.info(f"[/test] artifact_dir={artifact_dir}")
    logger.info(f"[/test] manifest={manifest}")
    
    if not artifact_dir:
        logger.error("[/test] artifact_dir missing in payload")
        return jsonify({"status": "error", "message": "artifact_dir missing"}), 400

    module_path = os.path.join("/artifacts", artifact_dir, "module.py")
    logger.info(f"[/test] checking module at: {module_path}")
    logger.info(f"[/test] /artifacts exists: {os.path.exists('/artifacts')}")
    logger.info(f"[/test] artifact_dir exists: {os.path.exists(os.path.join('/artifacts', artifact_dir)) if artifact_dir else 'N/A'}")
    
    if not os.path.exists(module_path):
        logger.error(f"[/test] module.py NOT found at {module_path}")
        logger.info(f"[/test] listing /artifacts: {os.listdir('/artifacts') if os.path.exists('/artifacts') else 'N/A'}")
        if os.path.exists(os.path.join("/artifacts", artifact_dir)):
            logger.info(f"[/test] listing {module_path.rsplit('/', 1)[0]}: {os.listdir(module_path.rsplit('/', 1)[0])}")
        return jsonify({"status": "error", "message": "module not found"}), 404
    
    logger.info(f"[/test] module.py found, size={os.path.getsize(module_path)} bytes")

    # Execute module in isolated subprocess with limits
    manifest_json = json.dumps(manifest)
    runner_code = f"""
import json
import logging
import os
import resource
import sys
import time as _time

print('[runner] START', flush=True)
print('[runner] module_path={module_path!r}', flush=True)

try:
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_AS, (200 * 1024 * 1024, 200 * 1024 * 1024))
    print('[runner] resource limits set', flush=True)
except Exception as e:
    print(f'[runner] resource limits error: {{e}}', flush=True)

def _blocked_sleep(*args, **kwargs):
    raise RuntimeError('time.sleep is blocked in sandbox tests')

_time.sleep = _blocked_sleep
logger = logging.getLogger('worker-sandbox')
logging.basicConfig(level=logging.DEBUG, format='[sandbox] %(message)s')

def record_event(*args, **kwargs):
    print(f'[runner] record_event called: args={{args}}, kwargs={{kwargs}}', flush=True)
    return None

print('[runner] loading module...', flush=True)
ns = {{}}
try:
    with open({module_path!r}, 'r', encoding='utf-8') as f:
        code = f.read()
    print(f'[runner] code loaded, length={{len(code)}}', flush=True)
    exec(code, ns)
    print(f'[runner] code executed, namespace keys={{list(ns.keys())}}', flush=True)
except Exception as e:
    print(f'[runner] ERROR loading/executing code: {{type(e).__name__}}: {{e}}', flush=True)
    import traceback
    traceback.print_exc()

if 'apply_update' in ns:
    print('[runner] found apply_update, calling it...', flush=True)
    try:
        # Provide the same shape of context that application code expects
        ctx = {{'logger': logger, 'record_event': record_event, 'manifest': {manifest_json}, 'runtime_dir': '/artifacts', 'leak_file': '/artifacts/simulated_leak.txt', 'module_path': {module_path!r}}}
        print(f'[runner] context keys={{list(ctx.keys())}}', flush=True)
        result = ns['apply_update'](ctx)
        print(f'[runner] apply_update returned: {{result}}', flush=True)
        print(json.dumps({{'status':'pass'}}))
    except Exception as e:
        print(f'[runner] ERROR in apply_update: {{type(e).__name__}}: {{e}}', flush=True)
        import traceback
        traceback.print_exc()
        print(json.dumps({{'status':'fail','message': str(e)}}))
else:
    print(f'[runner] apply_update NOT found in namespace, available: {{list(ns.keys())}}', flush=True)
    print(json.dumps({{'status':'fail','message':'no apply_update found'}}))
"""

    logger.info(f"[/test] executing subprocess runner...")
    try:
        proc = subprocess.run([sys.executable, "-c", runner_code], capture_output=True, text=True, timeout=20)
        logger.info(f"[/test] subprocess completed, return code={proc.returncode}")
        logger.debug(f"[/test] stdout:\n{proc.stdout}")
        if proc.stderr:
            logger.debug(f"[/test] stderr:\n{proc.stderr}")
        
        out = proc.stdout.strip()
        
        # Find the JSON response (last line that looks like JSON)
        json_line = None
        for line in reversed(out.split('\n')):
            if line.strip().startswith('{'):
                json_line = line
                break
        
        try:
            if json_line:
                resp = json.loads(json_line)
                logger.info(f"[/test] parsed response: {resp}")
            else:
                logger.warning(f"[/test] no JSON line found in output")
                resp = {"status": "fail", "all_stdout": proc.stdout, "all_stderr": proc.stderr}
        except Exception as e:
            logger.error(f"[/test] JSON parse error: {e}")
            resp = {"status": "fail", "parse_error": str(e), "all_stdout": proc.stdout, "all_stderr": proc.stderr}
        
        return jsonify(resp)
    except subprocess.TimeoutExpired:
        logger.error("[/test] subprocess timeout")
        return jsonify({"status": "fail", "message": "timeout"}), 500
    except Exception as e:
        logger.error(f"[/test] exception: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("WORKER_PORT", "8003")))
