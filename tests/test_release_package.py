import copy
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pack_beta3", ROOT / "scripts/pack-beta3.py")
pack = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pack)


class ArchiveStructureTests(unittest.TestCase):
    def assert_bad_archive(self, entries):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "invalid.app"
            with tarfile.open(path, "w:gz") as archive:
                for name, kind in entries:
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    entry.size = 1 if kind == tarfile.REGTYPE else 0
                    archive.addfile(entry, io.BytesIO(b"x") if entry.size else None)
            with self.assertRaises(ValueError):
                pack.read_bundle(path)

    def test_manifest_must_be_first(self):
        self.assert_bad_archive([("app.elf", tarfile.REGTYPE)])

    def test_duplicates_are_rejected(self):
        self.assert_bad_archive([("manifest.json", tarfile.REGTYPE)] * 2)

    def test_symlinks_are_rejected(self):
        self.assert_bad_archive([("manifest.json", tarfile.REGTYPE), ("app.elf", tarfile.SYMTYPE)])

    def test_parent_traversal_is_rejected(self):
        self.assert_bad_archive([("manifest.json", tarfile.REGTYPE), ("../app.elf", tarfile.REGTYPE)])

    def test_absolute_path_is_rejected(self):
        self.assert_bad_archive([("manifest.json", tarfile.REGTYPE), ("/app.elf", tarfile.REGTYPE)])


@unittest.skipUnless(os.environ.get("VERIFY_PACKAGE"), "set VERIFY_PACKAGE to the built .app")
class SignedReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = pack.read_bundle(Path(os.environ["VERIFY_PACKAGE"]))
        cls.config = pack.read_config(ROOT)

    def check_signature(self, data, valid):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "signed.bin"
            path.write_bytes(data)
            result = subprocess.run(["cosign2", "dump", "--input", str(path)], capture_output=True)
            self.assertEqual(result.returncode == 0, valid, result.stderr.decode())

    def test_real_manifest_and_elf_signatures(self):
        pack.validate(self.files, self.config)
        for name in ["manifest.json", "app.elf"]:
            self.check_signature(self.files[name], True)

    def test_modified_signed_payloads_fail(self):
        for name in ["manifest.json", "app.elf"]:
            data = bytearray(self.files[name])
            data[-1] ^= 1
            self.check_signature(data, False)

    def test_modified_ecdsa_signature_fails(self):
        data = bytearray(self.files["manifest.json"])
        data[180] ^= 1
        self.check_signature(data, False)

    def test_icon_tampering_fails(self):
        files = copy.deepcopy(self.files)
        files["icon.bin"] += b"tampered"
        with self.assertRaisesRegex(ValueError, "Hash mismatch"):
            pack.validate(files, self.config)


if __name__ == "__main__":
    unittest.main()
