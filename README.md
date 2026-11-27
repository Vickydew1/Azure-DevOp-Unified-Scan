# 🛡️ AccuKnox Unified Scan — Azure DevOps Extension

The **AccuKnox Unified Scan** extension is a single, unified Azure DevOps task that runs any combination of AccuKnox ASPM code-analysis scans — **SAST, SCA, Secret, IaC, ML Static Scan and SBOM** — and uploads the results to the **AccuKnox Console** for centralized visibility, risk tracking and remediation.

Instead of wiring up a separate task for every scanner, configure **one task**, pick the scans you need via `scanType`, and shift security left across your entire codebase — **before it reaches production**.

---

## 🎯 Key Features

- ✅ **6 Scanners, One Task** – SAST (optional AI-SAST), SCA, Secret, IaC, ML Static Scan and SBOM (image + filesystem).
- 🧩 **Run Any Combination** – Select one or many scans with a single comma/space separated `scanType` input.
- 🤖 **AI-SAST** – After OpenGrep SAST, optionally run CodeAssure AI analysis (`enableAiSast`) to triage findings.
- ⌨️ **Command Text Per Scan** – Every scanner exposes a `*Command` input mapped directly to the CLI's `--command`.
- 🏗️ **IaC with Frameworks** – Restrict IaC scans to one or more frameworks (e.g. `Kubernetes,Terraform`).
- 📦 **SBOM for Image & Filesystem** – Generate a CycloneDX SBOM from a container image or your source tree.
- 🔒 **Shift Left Security** – Integrate all checks directly into your Azure Pipelines.
- 🚦 **Quality Gates** – Let AccuKnox policies pass or fail the build (`qualityGate`).
- 📥 **Seamless AccuKnox Console Integration** – Findings flow automatically to the AccuKnox dashboard.

---

## ⚠️ Prerequisites

- 🖥️ **Any Linux or Windows agent** – SAST, SCA, Secret and SBOM run the scanner natively, so Microsoft-hosted agents work; no Docker required for those.
- ⚡ **Cached after the first run** – The scanner binary and the scan tools are downloaded once and reused by later runs on the same agent. See [Caching](#-caching).
- 🤖 **AI-SAST** – Native CodeAssure install is Linux-only. Enable with `enableAiSast` or `ACCUKNOX_ENABLE_AI_SAST=TRUE`. Put the LLM key in `ACCUKNOX_AI_API_KEY` (provider-agnostic) and map it on the task with `env:`. In `codeassure.json` set `"api_key": "$ACCUKNOX_AI_API_KEY"`. Optionally pass the config path as `sastCodeassureConfig`.
- 🐳 **Docker (for IaC, ML Static Scan or `containerMode: true`)** – The IaC and ML scans always run in their containers, and `containerMode` runs every scanner in one, so each of these requires an agent with Docker available and network access to pull scanner images.
- 🔐 **AccuKnox Console Access** – Sign in to your AccuKnox tenant.
- 🗝️ **API Token** – Retrieve this from the AccuKnox Console (**Settings → Tokens**).
- 🏷️ **Label Created in Console** – For tagging the uploaded scan reports.
- 🔑 **Pipeline Variables / Secrets** – Store the credentials securely as pipeline variables.

---

## 📌 Installation & Usage

### Step 1: Retrieve AccuKnox Credentials

1. Log in to your AccuKnox Console.
2. Navigate to **Settings → Tokens**, click **Create Token**, and save the value.
3. Create a label under **Dashboard → Labels** to tag scan results.

### Step 2: Add Pipeline Variables

Define the following as pipeline variables (mark the token as secret):

| Variable | Description |
|----------|-------------|
| `ACCUKNOX_TOKEN` | Your AccuKnox API token |
| `ACCUKNOX_ENDPOINT` | The AccuKnox Console URL (e.g. `cspm.demo.accuknox.com`) |
| `ACCUKNOX_LABEL` | Label used to tag and group scan results |
| `ACCUKNOX_GATE_TOKEN` (optional) | User token for the quality-gate API. Mark as secret and pass it as `accuknoxGateToken` |
| `ACCUKNOX_ENABLE_AI_SAST` (optional) | Set to `TRUE` to enable AI-SAST (same as `enableAiSast`) |
| `ACCUKNOX_AI_API_KEY` (optional) | Provider-agnostic LLM API key for AI-SAST. Mark as secret and map it on the task with `env:`. `codeassure.json` must use `"api_key": "$ACCUKNOX_AI_API_KEY"` |

### Step 3: Add the Task to Your Pipeline

```yaml
trigger:
- main

pool:
  name: selfhosted

steps:
- task: AccuKnox-Unified-Scan@1
  inputs:
    # Pick any combination of scans
    scanType: 'sast, sca, secret, iac'

    # AccuKnox credentials
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)

    # Common options
    softFail: true
```

> 💡 Only the inputs for the scans listed in `scanType` are used — everything else is ignored, so you can keep your pipeline minimal.

---

## 📝 Examples

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

Enable with `enableAiSast: true` or `ACCUKNOX_ENABLE_AI_SAST=TRUE`. Store the LLM key in `ACCUKNOX_AI_API_KEY` (any provider). Use a Linux agent.

```yaml
- task: AccuKnox-Unified-Scan@1
  env:
    ACCUKNOX_ENABLE_AI_SAST: 'TRUE'   # optional if enableAiSast is true
    ACCUKNOX_AI_API_KEY: $(ACCUKNOX_AI_API_KEY)
  inputs:
    scanType: 'sast'
    accuknoxEndpoint: $(ACCUKNOX_ENDPOINT)
    accuknoxToken: $(ACCUKNOX_TOKEN)
    accuknoxLabel: $(ACCUKNOX_LABEL)
    enableAiSast: true
    sastAiScanSeverity: 'HIGH,CRITICAL'
    # sastCodeassureConfig: 'codeassure.json'   # optional
    softFail: true
```

Example `codeassure.json` — the key name is AccuKnox-generic; `provider` / `api_base` pick the actual LLM:

```json
{
  "model": {
    "provider": "openai-compatible",
    "name": "your-model-name",
    "api_base": "https://your-llm-endpoint",
    "api_key": "$ACCUKNOX_AI_API_KEY",
    "tool_calling": true
  }
}
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

> **Prerequisite — Create a Project.** To associate SBOM data with the correct entity, create a **Project** in the AccuKnox Console first (**SBOM → Projects → New Project**). Use **Container** classifier for an image SBOM or **Application** for a filesystem SBOM, and pass the project name as `sbomProjectName`.

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

> For an **image** SBOM, set `sbomScanType: 'image'` and `sbomImageRef: 'myapp:latest'` (build/pull the image earlier in the same job).

### 7. Unified — Multiple Scans in One Task

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

> Add `ml` to `scanType` to include the ML scan — it runs in a container, so the agent needs Docker.

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

---

## ⚙️ Configuration Options (Inputs)

### Common

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scanType` | Scans to run (comma/space separated): `sast`, `sca`, `secret`, `iac`, `ml`, `sbom` | Yes | — |
| `accuknoxEndpoint` | URL of the AccuKnox Console to push results | Yes | — |
| `accuknoxToken` | API token for authenticating with AccuKnox SaaS | Yes | — |
| `accuknoxLabel` | Label used in AccuKnox SaaS to organise results | Yes | — |
| `scannerVersion` | Git tag of the `accuknox-aspm-scanner` binary (`v0.17.0` or later) | No | `v0.17.0` |
| `softFail` | Prevent the task from failing on findings (all scans) | No | `true` |
| `containerMode` | Run every scanner in a container (`--container-mode`) instead of natively. Needs Docker on the agent. IaC and ML use their containers even when this is `false` | No | `false` |

### Quality Gate

| Input | Description | Default |
|-------|-------------|---------|
| `qualityGate` | Wait for the AccuKnox policy verdict and fail the task when a policy blocks the build. The gate runs only when this is `true` | `false` |
| `accuknoxGateToken` | User token for the quality-gate API. Falls back to the `ACCUKNOX_GATE_TOKEN` environment variable, then `accuknoxToken` | `""` |
| `gateTimeout` | Seconds to wait for the policy verdict. Raise it if the first run for a scan type times out | `300` |
| `gateOnTimeout` | `fail` or `pass` when no verdict arrives in time | `fail` |

### SAST (`sast`)

| Input | Description | Default |
|-------|-------------|---------|
| `sastCommand` | Command text passed to `--command` (target to scan) | `.` |
| `enableAiSast` | After OpenGrep SAST, run CodeAssure AI analysis (`--ai-analysis`). Same as `ACCUKNOX_ENABLE_AI_SAST=TRUE` | `false` |
| `sastAiScanSeverity` | OpenGrep impacts sent to CodeAssure (`--aiscan-severity`). Shown when AI-SAST is on | `HIGH,CRITICAL` |
| `sastCodeassureConfig` | Optional path to `codeassure.json` (`--codeassure-config`). Use `"api_key": "$ACCUKNOX_AI_API_KEY"` | `""` |

### SCA (`sca`)

| Input | Description | Default |
|-------|-------------|---------|
| `scaCommand` | Command text passed to `--command` (e.g. `fs .`) | `fs .` |

### Secret (`secret`)

| Input | Description | Default |
|-------|-------------|---------|
| `secretCommand` | Command text passed to `--command` (e.g. `git file://.` or `filesystem .`) | `git file://.` |
| `secretAdditionalArguments` | Extra arguments appended to the command | `""` |

### IaC (`iac`)

| Input | Description | Default |
|-------|-------------|---------|
| `iacCommand` | Raw command text passed to `--command`. Overrides the structured inputs below | `""` |
| `iacDirectory` | Directory with infrastructure code to scan | `.` |
| `iacFile` | Specific file to scan; cannot be used with `iacDirectory` | `""` |
| `iacFramework` | One or more frameworks (comma-separated), e.g. `Kubernetes,Terraform` | `""` (all) |
| `iacCompact` | Do not display code blocks in output | `true` |
| `iacQuiet` | Display only failed checks | `true` |

### ML Static Scan (`ml`)

| Input | Description | Default |
|-------|-------------|---------|
| `mlCommand` | Command text passed to `--command` (e.g. `scan -p . -r json`) | `scan -p . -r json` |
| `mlModelName` | Custom collector/model identifier | `""` |
| `mlSourceType` | Source type for metadata | `azure` |

### SBOM (`sbom`)

| Input | Description | Default |
|-------|-------------|---------|
| `sbomScanType` | Target type: `image` or `filesystem` | `filesystem` |
| `sbomImageRef` | Image reference (required when `sbomScanType` is `image`) | `""` |
| `sbomScanPath` | Filesystem path (used when `sbomScanType` is `filesystem`) | `.` |
| `sbomCommand` | Raw command text passed to `--command`. Overrides the structured inputs above | `""` |
| `sbomSeverity` | Comma-separated severities | `""` |
| `sbomProjectName` | Project name (AccuKnox entity). **Required** when `sbom` is selected | `""` |

---

## 🔍 How It Works

1. **Pipeline runs** – A push/PR triggers the pipeline containing the task.
2. **Scanner setup (once)** – The task validates credentials, parses `scanType`, and downloads the `accuknox-aspm-scanner` binary for the requested `scannerVersion` and the tools for the selected scans. Anything an earlier run already downloaded is reused.
3. **Selected scans run** – SAST, SCA, Secret and SBOM run together, natively on the agent, in one `accuknox-aspm-scanner pipeline --scans ...` run built from your `*Command` and scan-specific inputs. IaC always runs in its container, so it gets a second `pipeline` run of its own; ML runs as its own scan, also in its container. Set `containerMode: true` to run every scanner in a container, in a single run:
   - **SAST** → static application security analysis (optional **AI-SAST** via `enableAiSast`)
   - **SCA** → dependency/composition analysis
   - **Secret** → secret detection
   - **IaC** → infrastructure-as-code misconfiguration checks (optionally per framework)
   - **ML** → static ML model analysis
   - **SBOM** → CycloneDX bill of materials for an image or filesystem
4. **Results uploaded to AccuKnox Console** – Using the provided `accuknoxToken` and `accuknoxLabel`. With `qualityGate`, the native scans and IaC each get their own verdict; the task fails if either one fails.
5. **Review findings** – Available in the AccuKnox Console: **Dashboard → Issues → Findings**, filtered by scan type.
6. **Pipeline decision** – If `softFail` is `false`, the task fails when any selected scan reports findings. With `qualityGate`, the AccuKnox policy verdict decides instead. Results are uploaded either way, including when the gate fails.

---

## ⚡ Caching

The first run on an agent downloads what it needs; later runs on that agent reuse it. Nothing has to be configured.

| What | Where it is kept | Reused when |
|------|------------------|-------------|
| `accuknox-aspm-scanner` binary | `<Agent.ToolsDirectory>/accuknox-aspm-scanner/<scannerVersion>/` | The same `scannerVersion` is requested again |
| Scan tools (SAST, SCA, Secret, SBOM) | Linux: `~/.local/bin/accuknox` · Windows: `%USERPROFILE%\AppData\Local\Programs\AccuKnox` | The tool is already there |

- **Self-hosted agents (Linux and Windows)** keep both between runs, so only the first run downloads.
- **Microsoft-hosted agents** start from a clean machine for every job, so each job downloads again.
- Changing `scannerVersion` downloads that version once and keeps the older one beside it.
- To force a fresh download, delete the folders above on the agent.

---

## 📖 Support & Documentation

- 📚 **Read More:** [AccuKnox Docs](https://help.accuknox.com/)
- 📧 **Contact Support:** support@accuknox.com

---

**🔐 Shift Left with AccuKnox – Secure Your Code from Commit to Cloud! ☁️🛡️**
