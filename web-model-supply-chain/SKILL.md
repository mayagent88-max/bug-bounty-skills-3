---
name: web-model-supply-chain
description: "Model supply-chain / serialized-model-file testing for a pentest-team engagement — malicious pickle __reduce__ payloads, unsafe deserialization across PyTorch/joblib/Keras-H5/GGUF/SavedModel, Lambda-layer and custom-code injection, and artifact provenance, with modelaudit and fickling. Load it when the appsec-triage model-artifact sweep turns up a serialized-model-file (pickle/PyTorch/Keras/GGUF) lead on a claimed target."
---

# Model supply chain — under the engagement protocol

Deep methodology for the **serialized-model-file** class. You reach here from the `appsec-triage` model-artifact sweep with a lead on a surface you already own on the board — a `.pkl`/`.pt`/`.bin`/`.h5`/`.gguf` artifact the app loads, a model pulled from a registry or hub, an uploaded checkpoint. The underlying bug is almost always unsafe deserialization, so cross-link `web-deserialization` for the class (pickle is the sink); cross-link `web-agentic`/`web-llm` when the model is loaded by an agent or LLM app.

## Under the engagement protocol

- **Claimed and in-scope only.** Analyze model artifacts that belong to a target you own on the board and that is on the `ROE.md` allowlist — the app's model files, its registry/hub namespace, an upload sink you were pointed at. A model one hop away (a public hub mirror, another tenant's bucket) is out of scope.
- **Model files are untrusted; analyze statically first.** A loaded malicious model *executes code* — treat every artifact as hostile. Never open a suspect file with the framework's default loader on your box or a shared host. Scan and disassemble statically; load only in a throwaway sandbox with the human's go.
- **Prove with a marker, not a payload.** `fickling --inject` builds a **BENIGN proof-of-concept ONLY** — the injected code is a harmless marker (writes a canary file, prints a token, DNS/HTTP callback to your in-scope listener), **never** a real payload, shell, or data touch. The primitive existing *is* the finding.
- **Read before write; loading is gated.** Actually loading a model to demonstrate execution is a destructive/outward-facing action (arbitrary code runs) — mark the surface blocked and route through the lead to the anchor for the human's explicit go, and do it only in an isolated sandbox with no secrets, no network egress beyond the in-scope callback, and a clean teardown.
- **Least-invasive proof, no DoS.** Static scans are cheap; don't upload giant crafted checkpoints or spin loads that exhaust the target's model-loading workers. Coordinate load on the board.
- **Proof-capsule discipline.** A `modelaudit`/`fickling` static hit is a **`candidate`**. It promotes to **`confirmed`** only when a **benign injected marker executes on load** *and* a **negative control** — a clean model of the same format that does **not** fire the marker — is shown alongside it. The control rules out coincidence and proves the payload, not the loader, ran.
- **Log and file** per PROTOCOL §Evidence and §Findings — findings in the `appsec-reporting` format, with the exact tool versions, the disassembled opcode/hit, and a re-runnable reproduction.

## Quick workflow

1. Inventory model artifacts and formats — every file the app loads or accepts (path, format, magic bytes, where it came from).
2. Static scan the widest net with `modelaudit`, SARIF out.
3. Triage the SARIF — rank by "executes on load" (pickle/Lambda/custom-op) over "metadata-only".
4. Deep-pickle analysis with `fickling` — trace the opcode stream / `__reduce__` on the ranked hits.
5. Prove with a **benign injected marker** loaded in a sandbox, alongside a **clean negative control**.
6. File the finding with the static hit, the marker proof, and the control.

## Inventory & format recognition

| Format | Ext | Signature | Executes on load? |
|---|---|---|---|
| Raw pickle | `.pkl` `.pickle` `.bin` | `\x80\x04\x95` / `\x80\x02` / `(dp0` | **Yes** — `__reduce__`/`GLOBAL`+`REDUCE` |
| PyTorch | `.pt` `.pth` `.bin` `.ckpt` | ZIP (`PK\x03\x04`) with `data.pkl`, or raw pickle | **Yes** — inner pickle, unless `weights_only=True` |
| joblib / sklearn | `.joblib` `.pkl` | pickle, sometimes zlib/lz4-framed | **Yes** — pickle under the frame |
| Keras / HDF5 | `.h5` `.keras` `.hdf5` | `\x89HDF\r\n` / `.keras` = ZIP | **Yes** — `Lambda` layers, custom objects |
| TF SavedModel | `saved_model.pb` dir | protobuf | **Conditional** — custom ops / `tf.io`+py_func |
| GGUF / GGML | `.gguf` `.ggml` | `GGUF` magic | Metadata mostly; abuse via loader/template fields |
| safetensors | `.safetensors` | JSON header + tensor blob | **No code path** (the safe target) |
| NumPy | `.npy` `.npz` | `\x93NUMPY` | **Yes** if `allow_pickle=True` |

`file`, `xxd | head`, and `unzip -l` fingerprint fast. A `.bin`/`.ckpt` is ambiguous — check the magic, not the extension.

## Static scan — modelaudit (widest formats, SARIF)

```bash
# Recurse a model dir / repo; SARIF for triage and the finding
modelaudit scan ./models/ --format sarif --output modelaudit.sarif

# Single artifact, human-readable while triaging
modelaudit scan suspect.pt

# CI/registry gate shape — non-zero exit on a hit
modelaudit scan ./artifact --strict
```

`modelaudit` flags dangerous pickle opcodes/globals, Keras `Lambda`/custom layers, suspicious GGUF metadata, and blacklisted imports across the format table above — the widest first pass. Triage the SARIF: rank "executes on load" (pickle `REDUCE`, `os`/`subprocess`/`builtins.eval`/`exec` globals, Lambda layers) above metadata-only notes.

## Deep-pickle analysis — fickling

```bash
# Disassemble the pickle opcode stream WITHOUT executing it
fickling suspect.pkl                       # decompiled, human-readable
fickling --check-safety suspect.pkl        # verdict: safe / unsafe
fickling --trace suspect.pkl               # opcode-by-opcode trace

# PyTorch: reach the inner data.pkl in the zip
unzip -o model.pt -d /tmp/model && fickling /tmp/model/*/data.pkl
```

Read the disassembly for the tell: a `GLOBAL` importing `os`/`posix`/`subprocess`/`builtins` (`eval`,`exec`,`__import__`) followed by `REDUCE` — that is a `__reduce__` payload firing on `pickle.load`. What a malicious `__reduce__` looks like (illustrative, benign marker only):

```python
# BENIGN PoC — marker only, never a real payload
class Marker:
    def __reduce__(self):
        # canary file, not a shell — the primitive is what we prove
        return (__import__('os').system, ('id > /tmp/modfile_canary',))
```

## Building the benign PoC (gated, sandbox only)

```bash
# Inject a HARMLESS marker into a copy of a clean model — proves the load-time exec path
fickling --inject 'open("/tmp/modfile_canary","w").write("modfile")' clean.pkl > poc.pkl

# Prove in an isolated sandbox with human go; keep a clean negative control
#   poc.pkl   -> marker fires (canary written)      => confirmed
#   clean.pkl -> no canary                            => negative control
```

`--inject` payload is **always** a benign marker (canary file / stdout token / in-scope callback), never a shell or data touch. Load `poc.pkl` and `clean.pkl` in the same throwaway sandbox: canary-from-poc + no-canary-from-clean is the confirmed capsule.

## Per-format execution vectors

- **Raw pickle / joblib / NumPy** — `__reduce__` payload in any `pickle.load`/`joblib.load`/`np.load(allow_pickle=True)` sink. The canonical case; see `web-deserialization` for the Python-pickle class.
- **PyTorch** — `torch.load` runs the inner `data.pkl` unless `weights_only=True`. Legacy checkpoints and `.bin` LoRA/adapter files are common carriers. Check whether the app pins `weights_only`.
- **Keras / H5** — a `Lambda` layer serializes an arbitrary Python function (marshalled bytecode) that runs on `load_model`; custom `objects`/`get_config` are a second path. Disassemble the `Lambda` config.
- **TF SavedModel** — custom ops and `tf.py_function`/`py_func` graph nodes can execute native/Python code when the graph runs; audit the op set and any `custom_objects`.
- **GGUF / GGML** — no pickle, but abuse the loader: crafted metadata, an embedded chat/prompt **template** field, or a tokenizer path the runtime `eval`s — check what the loader trusts from the header.

## Provenance & supply chain

- **Unsigned / unpinned artifacts** — model pulled by mutable tag or a bare hub name with no hash pin or signature lets a compromised registry swap the file. Confirm whether the app verifies a digest/signature (Sigstore, HF safetensors hash, model card checksum) before load.
- **Typosquatted / namespace-confused repos** — a hub/registry name one character off the intended org, or an internal name shadowed by a public one (dependency-confusion for models). Enumerate what the app actually resolves.
- **Conversion trust** — a "convert to safetensors" or fine-tune pipeline that first `pickle.load`s the source still executes the source's payload. The safe *format* doesn't help if an unsafe *load* happens upstream.

## Remediation (for the finding)

1. **Fix** — prefer **safetensors** (no code path) for weights; where a framework loader is unavoidable, force the safe mode (`torch.load(..., weights_only=True)`, `np.load(..., allow_pickle=False)`, Keras `safe_mode=True` / no `Lambda`); require **signed + pinned** artifacts (digest/signature verified before load), never a mutable tag.
2. **Defense in depth** — load untrusted/third-party models only in a sandbox (seccomp/gVisor/container, no secrets, no egress); gate the model registry behind provenance checks (Sigstore/model signing, checksum pinning, allowlisted namespaces); run `modelaudit` as a CI/registry admission gate.
3. **Detection** — scan artifacts at ingest and in CI for dangerous pickle opcodes/globals and Lambda layers; alert on model-runtime processes spawning shells or making unexpected network/DNS egress; log and diff model digests against the pinned manifest.

Write it up in the `appsec-reporting` finding format, **MITRE ATLAS (ML Supply Chain Compromise) / CWE-502 — Deserialization of Untrusted Data**, with the static hit, the benign-marker proof, and the clean negative control in the reproduction.
