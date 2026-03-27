# datadog-cws-talos-repro

Datadog Agent CWS runtime cannot start on Talos Linux because GCC renames a
kernel symbol the eBPF kprobe attaches to by exact name.

## Affected Versions

| Component        | Version   |
|------------------|-----------|
| Talos Linux      | v1.12.5   |
| Linux Kernel     | 6.18.15   |
| Datadog Agent    | 7.77.1    |
| Datadog Helm     | 3.196.0   |

## Symptoms

**security-agent** logs this error continuously (~every 60 seconds):

```
error while connecting to the runtime security module: rpc error: code = Unavailable
desc = connection error: desc = "transport: Error while dialing: dial unix
/var/run/sysprobe/runtime-security.sock: connect: no such file or directory"
```

**system-probe** logs the actual failure at startup:

```
error registering HTTP endpoints for module event_monitor: failed to init probe:
probes activation validation failed: AllOf requirement failed, the following probes
are not running [{UID:security EBPFFuncName:hook_attach_recursive_mnt}:
symbol 'attach_recursive_mnt' not found: invalid argument]
```

## Root Cause

Talos v1.12.5 compiles kernel 6.18.15 with GCC IPA-SRA, which renames
`attach_recursive_mnt` to `attach_recursive_mnt.isra.0`. Datadog's system-probe
does an exact kprobe lookup, fails, and the `event_monitor` module never loads.
Because the module never loads, `runtime-security.sock` is never created, and
`security-agent` retries connecting to it forever.

### Static Proof from Talos Kernel Binary

Extracting kallsyms from the published Talos v1.12.5 vmlinuz confirms the symbol
only exists with the `.isra.0` suffix:

```
$ ./scripts/extract-symbols.sh v1.12.5
$ grep attach_recursive_mnt /tmp/talos-kernel/symbols.txt
ffffffff8192c7e0 t __pfx_attach_recursive_mnt.isra.0
ffffffff8192c7f0 t attach_recursive_mnt.isra.0
```

Running the mismatch checker:

```
$ ./scripts/check-mismatch.sh /tmp/talos-kernel/symbols.txt

FUNCTION                       SELECTOR   STATUS     DETAIL
--------                       --------   ------     ------
attach_recursive_mnt           AllOf      MISMATCH   attach_recursive_mnt.isra.0
propagate_mnt                  AllOf      OK
security_sb_umount             AllOf      OK
clone_mnt                      AllOf      OK
mnt_change_mountpoint          AllOf      OK
cleanup_mnt                    AllOf      OK
alloc_vfsmnt                   BestEffort OK
attach_mnt                     OneOf      MISSING
__attach_mnt                   OneOf      MISSING
make_visible                   OneOf      OK
mnt_set_mountpoint             OneOf      OK
mnt_want_write                 AllOf      OK
```

`attach_recursive_mnt` is in an `AllOf` selector, so this single mismatch kills
the entire `event_monitor` module.

(`attach_mnt`/`__attach_mnt` MISSING is fine -- they're in a `OneOf` group where
`make_visible` and `mnt_set_mountpoint` both succeed.)

## Source Code Analysis

Three files in the Datadog agent form the bug chain:

### 1. eBPF C Hook: Exact Symbol Target

[`pkg/security/ebpf/c/include/hooks/mount.h`](https://github.com/DataDog/datadog-agent/blob/main/pkg/security/ebpf/c/include/hooks/mount.h#L476-L501)

```c
HOOK_ENTRY("attach_recursive_mnt")       // expands to SEC("kprobe/attach_recursive_mnt")
int hook_attach_recursive_mnt(ctx_t *ctx) {
    // ... mount tracking logic ...
}
```

`HOOK_ENTRY` expands via
[`fentry_macro.h`](https://github.com/DataDog/datadog-agent/blob/main/pkg/security/ebpf/c/include/constants/fentry_macro.h#L63)
to `SEC("kprobe/attach_recursive_mnt")` -- an exact symbol name with no pattern
matching.

### 2. Go Probe Registration: No `MatchFuncName`

[`pkg/security/ebpf/probes/mount.go`](https://github.com/DataDog/datadog-agent/blob/main/pkg/security/ebpf/probes/mount.go#L14-L19)

```go
var mountProbes = []*manager.Probe{
    {
        ProbeIdentificationPair: manager.ProbeIdentificationPair{
            UID:          SecurityAgentUID,
            EBPFFuncName: "hook_attach_recursive_mnt",
        },
        // NOTE: No MatchFuncName field -- exact symbol lookup only
    },
```

The ebpf-manager strips the `hook_` prefix to derive the kernel function name
`attach_recursive_mnt`, then does an exact lookup in
`/sys/kernel/debug/tracing/available_filter_functions`.

### 3. AllOf Selector: One Failure Kills Everything

[`pkg/security/ebpf/probes/event_types.go`](https://github.com/DataDog/datadog-agent/blob/main/pkg/security/ebpf/probes/event_types.go#L250-L258)

```go
// Mount probes
&manager.AllOf{Selectors: []manager.ProbesSelector{
    hookFunc("hook_attach_recursive_mnt"),   // <-- this one fails
    hookFunc("hook_propagate_mnt"),
    hookFunc("hook_security_sb_umount"),
    hookFunc("hook_clone_mnt"),
    hookFunc("rethook_clone_mnt"),
    hookFunc("hook_mnt_change_mountpoint"),
    hookFunc("hook_cleanup_mnt"),
}},
```

`manager.AllOf` means **every** probe in the group must successfully attach.
When `attach_recursive_mnt` fails, the entire `event_monitor` module is aborted.

## Existing Precedent in the Codebase

The Datadog agent already handles this exact class of GCC optimization suffix in
the **network tracer**:

[`pkg/network/tracer/ebpf_conntracker.go`](https://github.com/DataDog/datadog-agent/blob/main/pkg/network/tracer/ebpf_conntracker.go#L429-L433)

```go
{
    ProbeIdentificationPair: manager.ProbeIdentificationPair{
        EBPFFuncName: probes.ConntrackFillInfo,
        UID:          "conntracker",
    },
    MatchFuncName: "^ctnetlink_fill_info(\\.constprop\\.0)?$",
},
```

The `MatchFuncName` field tells the ebpf-manager to search
`available_filter_functions` using a regex pattern instead of requiring an exact
match. This handles `ctnetlink_fill_info.constprop.0` on kernels where GCC
applies constant propagation.

The CWS security team has not applied this same pattern to `attach_recursive_mnt`.

## Proposed Fix

Add `MatchFuncName` to the probe definition in `mount.go`:

```diff
--- a/pkg/security/ebpf/probes/mount.go
+++ b/pkg/security/ebpf/probes/mount.go
@@ -15,6 +15,7 @@ func getMountProbes(fentry bool) []*manager.Probe {
 		{
 			ProbeIdentificationPair: manager.ProbeIdentificationPair{
 				UID:          SecurityAgentUID,
 				EBPFFuncName: "hook_attach_recursive_mnt",
 			},
+			MatchFuncName: "^attach_recursive_mnt(\\.isra\\.[0-9]+)?$",
 		},
```

This regex matches both `attach_recursive_mnt` (standard kernels) and
`attach_recursive_mnt.isra.0` (Talos 1.12.5 / kernel 6.18.15), following the
same pattern already established by the network team for `.constprop.0`.

## Workaround

Disable CWS runtime in Datadog Helm values (CSPM/compliance still works):

```yaml
datadog:
  securityAgent:
    runtime:
      enabled: false
```

## Reproduction

### CI: Live QEMU Reproduction

The workflow boots a real Talos QEMU cluster, deploys the Datadog agent with CWS
enabled, and captures the failure logs:

```bash
gh workflow run live-repro.yml
```

Requires KVM on the runner. GitHub Actions `ubuntu-latest` has intermittent KVM
support so the job is `continue-on-error: true`.

### Local: Static Symbol Analysis

Utility scripts to extract the Talos kernel symbol table from the published
`vmlinuz` and compare against Datadog's expected kprobe targets.

Prerequisites: `python3`, `zstandard` pip package, `vmlinux-to-elf` (`uv tool install vmlinux-to-elf`).

```bash
./scripts/extract-symbols.sh          # downloads vmlinuz, extracts kallsyms
./scripts/check-mismatch.sh           # compares against expected probes
```

## Related Links

- [DataDog/datadog-agent](https://github.com/DataDog/datadog-agent) -- agent source
- [DataDog/ebpf-manager](https://github.com/DataDog/ebpf-manager) -- `MatchFuncName` implementation
- [siderolabs/talos v1.12.5](https://github.com/siderolabs/talos/releases/tag/v1.12.5) -- kernel 6.18.15
- [GCC IPA-SRA docs](https://gcc.gnu.org/onlinedocs/gccint/IPA-SRA.html) -- `.isra` suffix origin
