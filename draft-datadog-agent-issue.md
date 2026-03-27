<!--
  Published: https://github.com/DataDog/datadog-agent/issues/48510
  (Labels at create time: kind/bug, pending, team/agent-security)
-->

## Title (copy into GitHub)

[BUG] CWS event_monitor fails on Talos Linux: `attach_recursive_mnt` kprobe — kernel symbol only present as `attach_recursive_mnt.isra.0`

---

### Agent version

7.77.1 (system-probe / security-agent as shipped in chart `datadog` Helm 3.196.0). Likely affects other 7.x builds using the same CWS mount probes without `MatchFuncName`.

### Bug Report

On **Talos Linux v1.12.5** (kernel **6.18.15**), **Cloud Workload Security (CWS) runtime** does not start: the **event_monitor** module fails during probe activation because the kprobe target **`attach_recursive_mnt`** is not found. The kernel exports the function as **`attach_recursive_mnt.isra.0`** (GCC IPA-SRA), while the agent resolves the hook to an **exact** symbol name `attach_recursive_mnt` via `/sys/kernel/debug/tracing/available_filter_functions` (no `MatchFuncName` regex on this probe).

Because **event_monitor** never loads, **`/var/run/sysprobe/runtime-security.sock`** is never created and **security-agent** loops on:

`error while connecting to the runtime security module ... dial unix /var/run/sysprobe/runtime-security.sock: connect: no such file or directory`

**Expected:** CWS runtime loads on Talos the same as on kernels that retain the unsuffixed `attach_recursive_mnt` symbol.

**Actual:** Probe validation fails; full log line from system-probe:

```text
error registering HTTP endpoints for module event_monitor: failed to init probe:
probes activation validation failed: AllOf requirement failed, the following probes
are not running [{UID:security EBPFFuncName:hook_attach_recursive_mnt}:
symbol 'attach_recursive_mnt' not found: invalid argument]
```

**Root cause (concise):** `hook_attach_recursive_mnt` is registered in `pkg/security/ebpf/probes/mount.go` without `MatchFuncName`, while `pkg/security/ebpf/probes/event_types.go` places it in an **`AllOf`** group — one failed attach aborts the whole module. Same class of issue as existing network tracer handling for suffixed symbols, e.g. `MatchFuncName: "^ctnetlink_fill_info(\\.constprop\\.0)?$"` in `pkg/network/tracer/ebpf_conntracker.go`.

**Suggested fix (for discussion):** Add `MatchFuncName` for the mount kprobe so both `attach_recursive_mnt` and `attach_recursive_mnt.isra.0` resolve, mirroring the conntracker literal-`.0` style:

```go
MatchFuncName: "^attach_recursive_mnt(\\.isra\\.0)?$",
```

### Reproduction Steps

1. Boot a Talos **v1.12.5** cluster (or use a kernel where `attach_recursive_mnt` appears only as `attach_recursive_mnt.isra.N` in kallsyms / `available_filter_functions`).
2. Install the Datadog Agent with **`datadog.securityAgent.runtime.enabled: true`** (and system-probe privileged as required).
3. Inspect **system-probe** logs: confirm `symbol 'attach_recursive_mnt' not found` and **security-agent** errors on missing `runtime-security.sock`.

**Public minimal repro (CI + scripts):** [ChipWolf/datadog-cws-talos-repro](https://github.com/ChipWolf/datadog-cws-talos-repro) — GitHub Action `live-repro.yml` boots Talos in QEMU, installs the agent, and asserts the failure; utility scripts under `scripts/` extract Talos `vmlinuz` kallsyms and compare to expected CWS probe names.

### Agent configuration

Relevant Helm values excerpt (repro):

```yaml
datadog:
  securityAgent:
    runtime:
      enabled: true
    compliance:
      enabled: false  # optional; runtime is the failing piece
```

Also set explicit hostname / `DD_HOSTNAME` if the node has no resolvable hostname, so system-probe reaches probe init (optional; unrelated to symbol suffix but needed in minimal QEMU CI).

**Mitigation (not a fix):** `datadog.securityAgent.runtime.enabled: false` avoids loading **event_monitor**; CWS runtime features remain off until probe matching is fixed.

### Operating System

Talos Linux **v1.12.5**, Linux **6.18.15** (amd64). Example symbol table lines from published Talos `vmlinuz` (kallsyms extraction):

```text
ffffffff8192c7f0 t attach_recursive_mnt.isra.0
```

### Other environment details

- **CNI / Kubernetes:** Any; repro uses single-node Talos with QEMU.
- **Links:** CWS mount hook definition — [`pkg/security/ebpf/c/include/hooks/mount.h`](https://github.com/DataDog/datadog-agent/blob/main/pkg/security/ebpf/c/include/hooks/mount.h) (`HOOK_ENTRY("attach_recursive_mnt")`); Go probes — [`pkg/security/ebpf/probes/mount.go`](https://github.com/DataDog/datadog-agent/blob/main/pkg/security/ebpf/probes/mount.go); selector — [`pkg/security/ebpf/probes/event_types.go`](https://github.com/DataDog/datadog-agent/blob/main/pkg/security/ebpf/probes/event_types.go) (mount `AllOf` block).
- **GCC:** IPA-SRA `.isra.N` suffix — see [GCC IPA-SRA documentation](https://gcc.gnu.org/onlinedocs/gccint/IPA-SRA.html).
