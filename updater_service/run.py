#!/usr/bin/env python3
import os
import subprocess
import sys

mtls_enabled = os.getenv("UPDATER_MTLS_ENABLED") == "1"
cert_file = os.getenv("UPDATER_TLS_CERT_FILE", "")
key_file = os.getenv("UPDATER_TLS_KEY_FILE", "")

cmd = ["gunicorn", "--bind", "0.0.0.0:8001", "app:app"]

if mtls_enabled and os.path.isfile(cert_file) and os.path.isfile(key_file):
    print("Starting updater-service with mTLS enabled")
    cmd.extend(["--certfile", cert_file, "--keyfile", key_file, "--ssl-version=TLSv1_2"])
else:
    print("Starting updater-service with plain HTTP")

os.execvp(cmd[0], cmd)
