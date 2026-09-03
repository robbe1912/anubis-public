import os
path = os.path.join("a", "b", "c.txt")
if os.path.exists(path):
    with open(path) as f:
        text = f.read()
