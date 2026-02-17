<!-- Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Migration note: removing legacy Python

You requested that the original Python implementation be removed/evicted from GitHub.
This repository is **Rust-only**.

If your existing GitHub repo currently contains Python sources:

1. Unpack this zip into a **new empty folder** (recommended), or into the existing repo.
2. If using the existing repo, remove legacy Python directories and artifacts:

```bash
# Example (adjust paths to match your repo)
git rm -r --cached python/ src_py/ notebooks/ || true
find . -name "*.py" -o -name "requirements.txt" -o -name "Pipfile" -o -name "poetry.lock" \
  | xargs -I{} git rm --cached "{}" || true
```

3. Commit the deletion and the new Rust workspace:

```bash
git add -A
git commit -m "Replace legacy Python kernel with Rust EvidenceOS"
```

4. Push to GitHub.

> Safety note: the DiscOS repo includes a small Python gRPC example under
> `DiscOS/examples/python_ipc/` purely to demonstrate IPC interoperability.
