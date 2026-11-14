import os
import subprocess

# Tainted: user input flows into eval (code injection).
cmd = input("command: ")
result = eval(cmd)

# Tainted across an assignment chain: env -> name -> shell command.
name = os.environ["TARGET"]
target = name
subprocess.run(target, shell=True)

# Not tainted: constant argument.
subprocess.run("ls -la", shell=False)
