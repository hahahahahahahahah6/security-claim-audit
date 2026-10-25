import subprocess
import pickle

def parse(user_input, name, data, code):
    eval(user_input)
    subprocess.run(["ls", name])
    pickle.loads(data)
    exec(code)
