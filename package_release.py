"""Rebuild the two distributable bundles from the current working tree.

    python package_release.py

Produces, next to this script:

    HybridIDS-.exe-Share/     + HybridIDS-.exe-Share.zip  (end users)
      Windows/HybridIDS.exe       prebuilt, copied from APP/dist/
      macOS-Linux/                source bundle + build_unix.sh
      README-FIRST.md, SHA256SUMS.txt

    HybridIDS-Code-Share/     + HybridIDS-Code-Share.zip  (teammates)
      the source tree only, no binary

Why an explicit allow-list instead of "copy the folder and exclude junk"
----------------------------------------------------------------------
README-FIRST.md makes hard privacy claims about these bundles: no alert
database, no packet captures, no credentials, no retrain_state.json, no
absolute paths carrying the builder's username. An exclusion-based copy makes
those claims only as good as the exclusion list -- one new .db or .pcap
dropped into a contributor folder and it ships silently. Listing what goes IN
means a file nobody named can never leak, and a genuinely new source file
shows up as a loud "missing" warning instead.

Adding a file to a bundle is therefore a deliberate edit to _SHARE_FILES /
_CODE_SHARE_FILES below, not a side effect of leaving it in a folder.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sys
import zipfile
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))

# Bundle folder names, defined once. The end-user bundle was renamed from
# "HybridIDS-Share" to "HybridIDS-.exe-Share" (it is the one carrying the
# prebuilt .exe); the zip takes the same name so the folder and the archive
# cannot drift apart again. _STALE_BUNDLES are previous names, removed on
# each run so a rename never leaves a stale copy shipping old code.
EXE_BUNDLE = "HybridIDS-.exe-Share"
CODE_BUNDLE = "HybridIDS-Code-Share"
_STALE_BUNDLES = ["HybridIDS-Share"]

# ── Files common to both bundles ─────────────────────────────────────────────
# Paths are relative to ROOT and are used verbatim as the path inside the
# bundle, except where _SHARE_EXTRA / _CODE_SHARE_EXTRA remap them.
_COMMON = [
    # Aalok — dashboard, detection engine, trained models
    "Aalok/Dashboard/.streamlit/config.toml",
    "Aalok/Dashboard/advanced_data_scaler.pkl",
    "Aalok/Dashboard/advanced_kmeans_model.pkl",
    "Aalok/Dashboard/advanced_parser.py",
    "Aalok/Dashboard/app.py",
    "Aalok/Dashboard/baseline.txt.example",
    "Aalok/Dashboard/favicon.png",
    "Aalok/Dashboard/feature_engineer.py",
    "Aalok/Dashboard/live_backend.py",
    "Aalok/Dashboard/lstm_model.pt",
    "Aalok/Dashboard/notifier.py",
    "Aalok/Dashboard/notifier_config.json.example",
    "Aalok/Dashboard/rf_model.pkl",
    "Aalok/Dashboard/rf_scaler.pkl",
    "Aalok/Dashboard/start_system.bat",
    "Aalok/Dashboard/threat_intel.txt",
    "Aalok/Dashboard/trainai_rf.py",
    # Runtime, not a dev script: app.py imports this at module scope for the
    # Detection Benchmark tab. Omitting it does not crash the app (the import
    # is guarded) but the tab reports itself broken, so it belongs in every
    # bundle that ships app.py -- including the runtime-only Code-Share.
    "Aalok/Dashboard/evaluate_benchmark.py",
    # Aaron — MITRE ATT&CK mapping
    "Aaron/app.py",
    "Aaron/live_backend.py",
    "Aaron/mitre_mapping.py",
    # Megan — LSTM sequence model, SHAP, retraining
    "Megan/lstm_model.py",
    "Megan/retrain_pipeline.py",
    "Megan/shap_explainer.py",
    # Rui Yang — PCAP engine, rules, scoring, reports
    "Rui Yang/START.bat",
    "Rui Yang/STOP.bat",
    "Rui Yang/app/pcap_engine.py",
    "Rui Yang/app/upload_app.py",
    "Rui Yang/models/ids_model_live.pkl",
    "Rui Yang/models/live_features.pkl",
    "Rui Yang/models/scaler_live.pkl",
    "Rui Yang/scripts/docx_report.py",
    "Rui Yang/scripts/management_report.py",
    "Rui Yang/scripts/offender_history.py",
    "Rui Yang/scripts/report.py",
    "Rui Yang/scripts/rules.py",
    "Rui Yang/scripts/scoring.py",
    # rules.py loads this at import time; without it every threshold silently
    # falls back to the older hand-picked defaults, so it has to ship. It is a
    # .json rather than a .py, but it is runtime input, not documentation.
    "Rui Yang/scripts/thresholds.json",
]

# ── HybridIDS-Share/macOS-Linux (end-user source bundle) ─────────────────────
# Everything in _COMMON goes under macOS-Linux/, plus these extras. The
# launcher, spec and build script live at the top of that folder.
_SHARE_ONLY = [
    "Aalok/Dashboard/debug_flags.py",
    "Aalok/Dashboard/test_notifier.py",
    "Aalok/Dashboard/trainai.py",
    "Aaron/mitre_backfill.py",
    "Megan/test_v2_features.py",
    "Rui Yang/generate_pcap.py",
    "Rui Yang/make_443ddos_test.py",
    "Rui Yang/requirements.txt",
    "Rui Yang/scripts/clean.py",
    "Rui Yang/scripts/eda.py",
    "Rui Yang/scripts/train2.py",
    # Test suite + bootstrap, the script that derived thresholds.json, and the
    # two methodology write-ups. These belong here and NOT in Code-Share:
    # Code-Share is deliberately runtime code only (its README-FIRST.md says
    # so), whereas this bundle already carries test_notifier.py,
    # test_v2_features.py and the offline training scripts, and its README
    # points recipients at `python -m pytest` so the detection claims can be
    # checked rather than taken on trust. Neither ships inside the frozen exe
    # -- HybridIDS.spec skips tests/ outright.
    "Rui Yang/conftest.py",
    "Rui Yang/pytest.ini",
    "Rui Yang/tests/test_offender_history.py",
    "Rui Yang/tests/test_report.py",
    "Rui Yang/tests/test_rules.py",
    "Rui Yang/tests/test_scoring.py",
    "Rui Yang/scripts/derive_thresholds.py",
    "Rui Yang/ML_METHODOLOGY.md",
    "Rui Yang/SCORING_METHODOLOGY.md",
]
# (source in the working tree, destination inside macOS-Linux/)
_SHARE_REMAP = [
    ("APP/run_hybrid_ids.py", "run_hybrid_ids.py"),
    ("APP/build_unix.sh", "build_unix.sh"),
    ("APP/HybridIDS_unix.spec", "HybridIDS_unix.spec"),
]

# ── HybridIDS-Code-Share (teammate bundle) ───────────────────────────────────
# Same source, no binary, and it keeps the Windows batch launchers because
# teammates run it on Windows.
_CODE_SHARE_REMAP = [
    ("APP/run_hybrid_ids.py", "run_hybrid_ids.py"),
    ("START.bat", "START.bat"),
    ("STOP.bat", "STOP.bat"),
    # Per-contributor feature status: what each person built and whether it was
    # observed working. Teammate-facing, so it ships in this bundle only — the
    # end-user bundle has no use for a "what is still PARTIAL" list.
    ("FEATURE-TEST-REPORT.md", "FEATURE-TEST-REPORT.md"),
]

# ── Files that must NEVER ship, whatever a list says ──────────────────────────
# A second, independent guard: even if one of the lists above gains a bad entry
# by a careless edit, these patterns stop the bundle being written.
_FORBIDDEN_EXT = {".db", ".pcap", ".pcapng", ".cap", ".log", ".pyc", ".pyo"}
_FORBIDDEN_NAMES = {
    "ids_logs.db", "offender_history.db", "retrain_state.json",
    "notifier_config.json", "ai_ready_advanced_flows.csv",
    "master_advanced_dataset.csv", "master_behavioral_dataset.csv",
    "temp_live.pcap", "temp_raw.csv",
}


def _check_safe(rel_path: str) -> None:
    name = os.path.basename(rel_path)
    ext = os.path.splitext(name)[1].lower()
    if name in _FORBIDDEN_NAMES or ext in _FORBIDDEN_EXT or ".bak" in name:
        raise SystemExit(
            f"REFUSING to package {rel_path!r}: it matches the never-ship list "
            f"(runtime databases, captures, credentials, backups). Remove it "
            f"from the manifest in package_release.py."
        )


def _copy_set(pairs, dest_root: str) -> list[str]:
    """Copy (src_rel, dest_rel) pairs into dest_root. Returns dest_rel list."""
    written, missing = [], []
    for src_rel, dest_rel in pairs:
        _check_safe(dest_rel)
        src = os.path.join(ROOT, src_rel.replace("/", os.sep))
        if not os.path.isfile(src):
            missing.append(src_rel)
            continue
        dest = os.path.join(dest_root, dest_rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(src, dest)
        written.append(dest_rel)
    if missing:
        print("  !! MISSING from working tree (not packaged):")
        for m in missing:
            print(f"       {m}")
    return written


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_checksums(bundle_dir: str, star_prefix: bool) -> None:
    """Write SHA256SUMS.txt covering every file in the bundle except itself."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [
        "# Hybrid IDS - SHA-256 checksums",
        f"# Generated {stamp} for the {os.path.basename(bundle_dir)} release.",
        "#",
        "# Verify on Linux:   sha256sum -c SHA256SUMS.txt",
        "# Verify on macOS:   shasum -a 256 <file>",
        "# Verify on Windows: Get-FileHash <file> -Algorithm SHA256",
        "#",
        "# A match proves the file is byte-for-byte what was published.",
        "# See README-FIRST.md for what this does and does not guarantee.",
    ]
    entries = []
    for dirpath, dirnames, filenames in os.walk(bundle_dir):
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for fn in sorted(filenames):
            if fn == "SHA256SUMS.txt":
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, bundle_dir).replace(os.sep, "/")
            entries.append((rel, _sha256(full)))
    for rel, digest in sorted(entries):
        sep = " *" if star_prefix else "  "
        lines.append(f"{digest}{sep}{rel}")
    out = os.path.join(bundle_dir, "SHA256SUMS.txt")
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"  SHA256SUMS.txt: {len(entries)} file(s)")


def _zip_bundle(bundle_dir: str) -> str:
    """Zip bundle_dir so the archive contains one top-level folder."""
    zip_path = bundle_dir + ".zip"
    if os.path.exists(zip_path):
        os.remove(zip_path)
    top = os.path.basename(bundle_dir)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        for dirpath, dirnames, filenames in os.walk(bundle_dir):
            dirnames[:] = [d for d in dirnames if d != "__pycache__"]
            for fn in sorted(filenames):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, bundle_dir).replace(os.sep, "/")
                zf.write(full, f"{top}/{rel}")
    mb = os.path.getsize(zip_path) / (1024 * 1024)
    print(f"  {os.path.basename(zip_path)}: {mb:.1f} MB")
    return zip_path


def _stash(bundle: str, rel_paths) -> dict:
    """Read bundle-owned files so they survive the rmtree + rebuild.

    README-FIRST.md and the bundle's own requirements.txt are written FOR the
    bundle, not copied from the working tree. macOS-Linux/requirements.txt in
    particular is deliberately different from `Rui Yang/requirements.txt`: it
    uses version FLOORS (a Linux recipient on Python 3.10 cannot necessarily
    get pandas==3.0.2) and it lists psutil, which the pinned Windows file does
    not. Regenerating it from the working tree would silently downgrade the
    macOS/Linux install instructions, so it is preserved instead.
    """
    kept = {}
    for rel in rel_paths:
        full = os.path.join(bundle, rel.replace("/", os.sep))
        if os.path.isfile(full):
            with open(full, "rb") as fh:
                kept[rel] = fh.read()
        else:
            print(f"  !! bundle-owned file missing, will not be restored: {rel}")
    return kept


def _restore(bundle: str, kept: dict) -> None:
    for rel, blob in kept.items():
        full = os.path.join(bundle, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as fh:
            fh.write(blob)


def build_share_bundle() -> None:
    print(f"[*] {EXE_BUNDLE} (Windows exe + macOS/Linux source)")
    bundle = os.path.join(ROOT, EXE_BUNDLE)
    kept = _stash(bundle, ["README-FIRST.md", "macOS-Linux/requirements.txt"])
    if os.path.isdir(bundle):
        shutil.rmtree(bundle)

    pairs = [(p, f"macOS-Linux/{p}") for p in _COMMON + _SHARE_ONLY]
    pairs += [(s, f"macOS-Linux/{d}") for s, d in _SHARE_REMAP]
    written = _copy_set(pairs, bundle)
    print(f"  macOS-Linux/: {len(written)} file(s)")

    # Windows: the prebuilt exe from APP/dist.
    exe_src = os.path.join(ROOT, "APP", "dist", "HybridIDS.exe")
    if os.path.isfile(exe_src):
        exe_dest = os.path.join(bundle, "Windows", "HybridIDS.exe")
        os.makedirs(os.path.dirname(exe_dest), exist_ok=True)
        shutil.copy2(exe_src, exe_dest)
        mb = os.path.getsize(exe_dest) / (1024 * 1024)
        print(f"  Windows/HybridIDS.exe: {mb:.1f} MB")
    else:
        print("  !! APP/dist/HybridIDS.exe not found — run APP/build.ps1 first.")

    _restore(bundle, kept)
    _write_checksums(bundle, star_prefix=False)
    _zip_bundle(bundle)


def build_code_share_bundle() -> None:
    print(f"[*] {CODE_BUNDLE} (source only, for teammates)")
    bundle = os.path.join(ROOT, CODE_BUNDLE)
    kept = _stash(bundle, ["README-FIRST.md", "requirements.txt"])
    if os.path.isdir(bundle):
        shutil.rmtree(bundle)

    pairs = [(p, p) for p in _COMMON]
    pairs += list(_CODE_SHARE_REMAP)
    written = _copy_set(pairs, bundle)
    print(f"  source: {len(written)} file(s)")

    _restore(bundle, kept)
    _write_checksums(bundle, star_prefix=True)
    _zip_bundle(bundle)


def build_app_zip() -> None:
    """Refresh APP/HybridIDS-App.zip — the Windows-only, exe-plus-instructions
    download (no source, no macOS/Linux path). Superseded by HybridIDS-Share
    for anyone who wants all three platforms, but kept current so it cannot
    hand someone a stale binary.
    """
    print("[*] APP/HybridIDS-App.zip (Windows exe only)")
    exe_src = os.path.join(ROOT, "APP", "dist", "HybridIDS.exe")
    readme_src = os.path.join(ROOT, "APP", "Read-Me-First.txt")
    if not os.path.isfile(exe_src):
        print("  !! APP/dist/HybridIDS.exe not found — skipped.")
        return
    zip_path = os.path.join(ROOT, "APP", "HybridIDS-App.zip")
    if os.path.exists(zip_path):
        os.remove(zip_path)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
        zf.write(exe_src, "HybridIDS.exe")
        if os.path.isfile(readme_src):
            zf.write(readme_src, "Read-Me-First.txt")
    mb = os.path.getsize(zip_path) / (1024 * 1024)
    print(f"  HybridIDS-App.zip: {mb:.1f} MB")


def purge_stale_bundles() -> None:
    """Delete bundles/zips left behind by an earlier name.

    A renamed bundle is worse than a missing one: the old folder keeps its old
    SHA256SUMS.txt and looks perfectly valid while shipping superseded code.
    """
    for name in _STALE_BUNDLES:
        folder = os.path.join(ROOT, name)
        archive = folder + ".zip"
        if os.path.isdir(folder):
            shutil.rmtree(folder)
            print(f"  removed stale folder: {name}/")
        if os.path.isfile(archive):
            os.remove(archive)
            print(f"  removed stale archive: {name}.zip")


def main() -> int:
    print(f"Packaging from: {ROOT}\n")
    print("[*] Clearing superseded bundle names")
    purge_stale_bundles()
    print()
    build_share_bundle()
    print()
    build_code_share_bundle()
    print()
    build_app_zip()
    print("\n[+] Done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
