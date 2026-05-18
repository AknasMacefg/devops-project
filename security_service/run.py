#!/usr/bin/env python3
import os
import subprocess
import sys

mtls_enabled = os.getenv("SECURITY_MTLS_ENABLED") == "1"
cert_file = os.getenv("SECURITY_TLS_CLIENT_CERT_FILE", "")
key_file = os.getenv("SECURITY_TLS_CLIENT_KEY_FILE", "")

cmd = ["gunicorn", "--bind", "0.0.0.0:8002", "app:app"]

if mtls_enabled and os.path.isfile(cert_file) and os.path.isfile(key_file):
    print("Starting security-service with mTLS enabled (client mode)")
else:
    print("Starting security-service with plain HTTP")

os.execvp(cmd[0], cmd)
