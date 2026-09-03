from pathlib import Path
path = Path("a") / "b" / "c.txt"
if path.exists():
    text = path.read_text()
