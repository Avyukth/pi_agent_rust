# Native security review

`security_scan` retains its existing local source operations: `plan`, `run`,
`disposition`, and `compare`. The source-rule engine is now in
`src/security_scan/source.rs`; its implementation and tests are retained intact.

## Inspect locked dependencies without a network request

```json
{"op":"dependency_plan"}
{"op":"dependency_plan","paths":["Cargo.lock","web/package-lock.json"]}
```

Empty dependency paths inspect **root `Cargo.lock` and `package-lock.json` only**.
Nested workspaces must supply explicit lockfile paths. A dependency path is a
lockfile, not a directory. No manifest resolver, package manager, installation,
source execution, or vulnerability-service request runs during this operation.

The result contains exact public-registry package/version pairs, all their
lockfile locations, lockfile SHA-256 digests, and explicit exclusions. Identical
queries are deduplicated across files and nested npm installations without
losing their locations. Multiple locked versions remain distinct. Development
and optional packages present in a supported lockfile are included.

Supported inputs are Cargo lockfile versions 1–4 (including older files without
an explicit version) and npm `package-lock.json`/`npm-shrinkwrap.json` versions
2–3. npm v1 and unknown versions fail rather than yielding an empty inventory.
The root npm project entry is not treated as its own dependency. npm aliases
use their recorded package name; scoped and nested packages retain identity.

Only recorded public crates.io sources and credential-free HTTPS
`registry.npmjs.org` tarball origins qualify. Local/workspace, linked, git,
private-registry, missing-origin, and unresolved-version entries are exclusions,
not inferred public package names. Exclusions do not include source URLs or
credentials. **An inventory is not a security verdict or an installed-code or
reachability analysis.** A missing lockfile or parse failure is an error.

Reads are bounded to 32 lockfiles, 4 MiB per file, 16 MiB combined, 20,000 entries,
and 10,000 unique public package/version pairs. Descriptor-relative reads reject
symlinks and parent traversal; the currently implemented filesystem backend
requires supported Unix descriptor APIs. Other platforms fail explicitly rather
than quietly weakening that confinement. Filesystem calls are not preemptible
hard real-time operations. This is not a sandbox for other security tool ops.

## Validation

The implementation adds pure parser/identity/limit tests and real temporary-file
confinement tests. Existing source scanner tests are retained unchanged. The
required quality entry point is `dsr quality --tool pi_agent_rust`; no direct
Cargo or GitHub Actions lane substitutes for it. No Rust test or compile pass
is claimed until that gate has run.
