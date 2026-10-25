# Offline replay

Use Python3.12 and Node22.15.0 (the exact originally executed versions are in `DEPENDENCIES.json` and recorded logs). Verification dependencies and their licenses are included; no installation or network call is needed.

From the package root:

```powershell
python -B replay/offline_replay.py --out ../deils-offline-public
python -B -O replay/offline_replay.py --out ../deils-offline-public-optimized
```

Public default checks two NIP01/BIP340 signed records, active manifest/row bindings,19official verification vectors,13local record controls, Python JCS/event IDs and saved-observation consistency. It reports the three unavailable content controls as **NOT_REPLAYED**.

If separately authorized to possess the original local inputs, supply a directory containing exactly the three raw files and digests identified in `evidence/PRIVATE_INPUT_REQUIREMENTS.json`:

```powershell
python -B replay/offline_replay.py --out ../deils-offline-private --private-input-dir <authorized-private-input-directory>
```

This copies the inputs into a disposable directory, executes the unchanged original Python/Node verifiers normally/repeatedly/with Python-O, compares saved semantic results, and destroys the temporary copy. It does not export the content or canonical preimage. The source input directory is read-only. The public package deliberately cannot supply these private files.

All output directories must be outside the pack. The scripts contain no networking and do not issue GET/reveal/prove/verify-proof calls. Live-request replay clients were deliberately excluded. Runtime logs record exits, stdout/stderr and hashes; current packaging replay is in `evidence/offline/`.

`SHA256SUMS` hashes every published file except itself. `INVENTORY.txt` also lists the manifest. `verify_integrity.py` verifies this exact inventory. The archive uses sorted paths, fixed ZIP timestamps, fixed permissions and stored compression for reproducibility. Archive digests are recorded outside the archive to avoid a circular hash.

Verification-only BIP340 CSV removes original secret-key/auxiliary-randomness columns' values; public keys, messages, signatures and expected booleans are unchanged. Thirteen public controls are mechanically extracted from the saved original checker; three private-content controls are not replaced with synthetic claims.
