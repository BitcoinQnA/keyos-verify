"""Generate a plain-text SHA-256 QR for the public demo artifact."""
import hashlib
from pathlib import Path
import qrcode

root = Path(__file__).resolve().parents[1]
demo = root / "dist/verify-demo"
digest = hashlib.sha256((demo / "demo-release.txt").read_bytes()).hexdigest()
qrcode.make(digest, box_size=10, border=4).save(demo / "demo-sha256-qr.png")
print(digest)
