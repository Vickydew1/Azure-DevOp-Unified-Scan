# AccuKnox Unified Scan

Unified AccuKnox ASPM scanner for Azure DevOps. Run any combination of **SAST, SCA, Secret, IaC, ML Static Scan and SBOM** scans in a **single task** and upload the findings to the **AccuKnox Console** for centralized visibility, risk tracking and remediation.

Instead of adding a separate task for every scanner, configure one task, pick the scans you need via **Scan Types**, and shift security left across your entire codebase.

## Features

- **6 scanners, one task** – SAST (optional AI-SAST), SCA, Secret, IaC, ML Static Scan and SBOM (image + filesystem).
- **Run any combination** – Select one or many scans from the multi-select **Scan Types** input.
- **Per-scan command text** – Every scanner exposes a `*Command` input mapped directly to the CLI's `--command`.
- **IaC with frameworks** – Restrict IaC scans to one or more frameworks (e.g. `Kubernetes,Terraform`).
- **SBOM for image & filesystem** – Generate a CycloneDX SBOM from a container image or your source tree.
- **Quality gates** – Let AccuKnox policies pass or fail the build (`qualityGate`).
- **Soft fail** – Optionally keep the pipeline green even when findings are detected.

## Prerequisites

- Any **Linux or Windows** Azure DevOps agent, hosted or self-hosted — SAST, SCA, Secret and SBOM run natively, with no Docker requirement.
- The scanner binary and scan tools are **cached after the first run** on an agent (self-hosted agents keep them between runs; Microsoft-hosted agents start clean each job).
- **AI-SAST** needs a **Linux** agent. Enable with `enableAiSast` or `ACCUKNOX_ENABLE_AI_SAST=TRUE`. Map `ACCUKNOX_AI_API_KEY` on the task with `env:`, and set `codeassure.json` `api_key` to `$ACCUKNOX_AI_API_KEY`.
- **Docker** is needed if you select **IaC** or **ML Static Scan** (they always run in their containers) or set `containerMode: true` to run every scanner in a container.
- An **AccuKnox Console** tenant, an **API token**, and a **label** to tag the uploaded results.

## Inputs

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `scanType` | Scans to run: `sast`, `sca`, `secret`, `iac`, `ml`, `sbom` | Yes | — |
| `accuknoxEndpoint` | AccuKnox Console URL to push results to | Yes | — |
| `accuknoxToken` | AccuKnox API token | Yes | — |
| `accuknoxLabel` | Label for associating scan results | Yes | — |
| `scannerVersion` | Git tag of the `accuknox-aspm-scanner` binary | No | `v0.17.0` |
| `softFail` | Do not fail the task on findings | No | `true` |
| `containerMode` | Run every scanner in a container (`--container-mode`) instead of natively. Needs Docker on the agent. IaC and ML use their containers even when this is `false` | No | `false` |
| `qualityGate` | Wait for the AccuKnox policy verdict and fail the task when a policy blocks the build | No | `false` |
| `accuknoxGateToken` | User token for the quality-gate API | No | `""` |
| `gateTimeout` | Seconds to wait for the policy verdict | No | `300` |
| `gateOnTimeout` | `fail` or `pass` when no verdict arrives in time | No | `fail` |

Each scan also exposes its own optional inputs (see the README for the full table).

## Examples

All examples assume the credentials are defined as pipeline variables: `ACCUKNOX_ENDPOINT`, `ACCUKNOX_TOKEN`, `ACCUKNOX_LABEL`.

### 1. SAST

```yaml
- task: AccuKnox-Unified-Scan@1
  inputs:
    scanType: 'sast'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    softFail: true
```

### 1b. SAST with AI analysis

```yaml
- task: AccuKnox-Unified-Scan@1
  env:
    ACCUKNOX_ENABLE_AI_SAST: 'TRUE'
    ACCUKNOX_AI_API_KEY: $(ACCUKNOX_AI_API_KEY)
  inputs:
    scanType: 'sast'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    enableAiSast: true
    sastAiScanSeverity: 'HIGH,CRITICAL'
    softFail: true
```

### 2. SCA

```yaml
- task: AccuKnox-Unified-Scan@1
  inputs:
    scanType: 'sca'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    softFail: true
```

### 3. Secret

```yaml
- task: AccuKnox-Unified-Scan@1
  inputs:
    scanType: 'secret'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    softFail: true
```

### 4. IaC

```yaml
- task: AccuKnox-Unified-Scan@1
  inputs:
    scanType: 'iac'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    softFail: true
```

### 5. ML Static Scan

```yaml
- task: AccuKnox-Unified-Scan@1
  inputs:
    scanType: 'ml'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    softFail: true
```

### 6. SBOM

> **Prerequisite — Create a Project** in the AccuKnox Console first (**SBOM → Projects → New Project**). Use the **Container** classifier for an image SBOM or **Application** for a filesystem SBOM, and pass the project name as `sbomProjectName`.

Filesystem SBOM:

```yaml
- task: AccuKnox-Unified-Scan@1
  inputs:
    scanType: 'sbom'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    sbomScanType: 'filesystem'
    sbomScanPath: '.'
    sbomProjectName: 'my-project'   # required for SBOM
    softFail: true
```

Image SBOM (build/pull the image earlier in the same job):

```yaml
- task: AccuKnox-Unified-Scan@1
  inputs:
    scanType: 'sbom'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    sbomScanType: 'image'
    sbomImageRef: 'myapp:latest'
    sbomProjectName: 'my-project'
    softFail: true
```

### 7. Unified — multiple scans in one task

```yaml
- task: AccuKnox-Unified-Scan@1
  inputs:
    scanType: 'sast, sca, secret, iac, sbom'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    softFail: true
    sbomScanType: 'filesystem'
    sbomScanPath: '.'
    sbomProjectName: 'my-project'
```

### 8. Quality Gate

Let the policies in the AccuKnox Console decide the build. With `qualityGate: true` the task waits for the policy verdict after the upload. Without it (the default) the scans are uploaded and no verdict is awaited.

```yaml
- task: AccuKnox-Unified-Scan@1
  inputs:
    scanType: 'sast, sca, secret, iac'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    qualityGate: true
    accuknoxGateToken: $(ACCUKNOX_GATE_TOKEN)   # user token for the gate API
    softFail: false
```

| Outcome | Task result |
|---------|-------------|
| Gate passed (or passed with warnings) | Succeeded |
| A policy blocked the build | Failed (Succeeded when `softFail: true`) |
| A scan could not run, an upload failed, or no verdict arrived in time | Failed, even with `softFail: true` |

> `ml` is not covered by the gate and runs as a separate scan.

Review findings in the AccuKnox Console under **Dashboard → Issues → Findings**, filtered by scan type.
