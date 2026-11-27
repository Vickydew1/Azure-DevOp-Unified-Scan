import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as https from 'https';
import { spawn } from 'child_process';

const SCANNER_BASE_URL = 'https://github.com/accuknox/aspm-scanner-cli/releases/download';

export interface ScannerConfig {
  endpoint: string;
  token: string;
  label: string;
  version: string;
  softFail: boolean;
  /** Run every scanner in a container (needs Docker) instead of natively. */
  containerMode: boolean;
}

export interface SastInputs {
  command: string;
  aiAnalysis: boolean;
  aiScanSeverity: string;
  codeassureConfig: string;
}

export interface ScaInputs {
  command: string;
}

export interface SecretInputs {
  command: string;
  additionalArguments: string;
}

export interface IacInputs {
  command: string;
  directory: string;
  file: string;
  framework: string;
  compact: boolean;
  quiet: boolean;
}

export interface MlInputs {
  command: string;
  modelName: string;
  sourceType: string;
}

export interface SbomInputs {
  scanType: string;
  imageRef: string;
  scanPath: string;
  command: string;
  severity: string;
  projectName: string;
}

/** Scans that always run through the CLI's `pipeline` command; ml runs as its own scan. */
export const PIPELINE_SCANS = ['sast', 'sca', 'secret', 'iac', 'sbom'];

export interface PipelineInputs {
  /** Subset of PIPELINE_SCANS, in run order. */
  scans: string[];
  qualityGate: boolean;
  gateToken: string;
  /** Seconds to wait for the verdict; empty = CLI default (300). */
  gateTimeout: string;
  /** 'fail' | 'pass' when no verdict arrives in time; empty = CLI default (fail). */
  gateOnTimeout: string;
  sast: SastInputs;
  sca: ScaInputs;
  secret: SecretInputs;
  iac: IacInputs;
  sbom: SbomInputs;
}

export function secretCommand(i: SecretInputs): string {
  const extra = i.additionalArguments.trim();
  return extra ? `${i.command} ${extra}` : i.command;
}

export function iacCommand(i: IacInputs): string {
  if (i.command.trim()) return i.command.trim();
  const parts: string[] = [];
  // --file and --directory are mutually exclusive in the IaC scanner; prefer file when set.
  if (i.file.trim()) {
    parts.push('--file', i.file.trim());
  } else if (i.directory.trim()) {
    parts.push('--directory', i.directory.trim());
  }
  if (i.compact) parts.push('--compact');
  if (i.quiet) parts.push('--quiet');
  for (const fw of i.framework.split(',').map((f) => f.trim()).filter(Boolean)) {
    parts.push('--framework', fw);
  }
  return parts.join(' ');
}

export function sbomCommand(i: SbomInputs): string {
  if (!i.projectName.trim()) {
    throw new Error('sbomProjectName is required when sbom is selected.');
  }
  if (i.command.trim()) return i.command.trim();
  const sbomType = i.scanType.trim();
  let cmd: string;
  if (sbomType === 'image') {
    if (!i.imageRef.trim()) {
      throw new Error('sbomImageRef is required when sbomScanType is image.');
    }
    cmd = `image ${i.imageRef.trim()}`;
  } else if (sbomType === 'filesystem' || sbomType === 'path' || sbomType === 'fs') {
    cmd = `filesystem ${i.scanPath.trim()}`;
  } else {
    throw new Error(`Invalid sbomScanType: ${sbomType}. Expected image or filesystem.`);
  }
  return i.severity.trim() ? `${cmd} --severity ${i.severity.trim()}` : cmd;
}

/**
 * Split the selected scans into `pipeline` runs. The CLI has one --container-mode switch per
 * run, and iac always runs in its container (its native tool needs a newer glibc than many
 * agents have), so without containerMode iac gets a run of its own.
 */
export function pipelineRuns(scans: string[], containerMode: boolean): { scans: string[]; containerMode: boolean }[] {
  if (!scans.length) return [];
  if (containerMode || !scans.includes('iac')) return [{ scans, containerMode }];
  const native = scans.filter((s) => s !== 'iac');
  return [...(native.length ? [{ scans: native, containerMode: false }] : []), { scans: ['iac'], containerMode: true }];
}

/** argv for `accuknox-aspm-scanner pipeline`. The gate token travels by env, never argv (argv is logged). */
export function buildPipelineArgs(i: PipelineInputs, softFail: boolean, containerMode = false): string[] {
  const has = (scan: string) => i.scans.includes(scan);
  const args = ['pipeline', '--scans', i.scans.join(','), '--keep-results'];
  if (softFail) args.push('--softfail');
  if (containerMode) args.push('--container-mode');
  if (i.qualityGate) {
    args.push('--quality-gate');
    if (i.gateTimeout.trim()) args.push('--gate-timeout', i.gateTimeout.trim());
    if (i.gateOnTimeout.trim()) args.push('--gate-on-timeout', i.gateOnTimeout.trim());
  }
  if (has('sast')) {
    args.push('--sast-command', i.sast.command);
    if (i.sast.aiAnalysis) {
      args.push('--ai-analysis');
      if (i.sast.aiScanSeverity.trim()) args.push('--aiscan-severity', i.sast.aiScanSeverity.trim());
      if (i.sast.codeassureConfig.trim()) args.push('--codeassure-config', i.sast.codeassureConfig.trim());
    }
  }
  if (has('sca')) args.push('--sca-command', i.sca.command);
  if (has('secret')) args.push('--secret-command', secretCommand(i.secret));
  if (has('iac')) args.push('--iac-command', iacCommand(i.iac));
  if (has('sbom')) args.push('--sbom-command', sbomCommand(i.sbom), '--project-name', i.sbom.projectName.trim());
  return args;
}

/**
 * Azure DevOps predefined variables the scanner is told about:
 *   BUILD_REPOSITORY_URI    -> repo URL
 *   BUILD_SOURCEVERSION     -> full commit SHA
 *   BUILD_SOURCEBRANCHNAME  -> branch name (ml scan)
 *   BUILD_BUILDID           -> run id (the CLI reads this variable itself; it has no override)
 *   collection + project + build/job/task ids -> job URL
 */
export class CodeAnalysisScanner {
  private cfg: ScannerConfig;
  private scannerBin: string = '';

  readonly repoUrl: string;
  readonly commitSha: string;
  readonly commitRef: string;
  readonly jobUrl: string;

  constructor(cfg: ScannerConfig) {
    this.cfg = cfg;
    const env = process.env;
    this.repoUrl = env.BUILD_REPOSITORY_URI || '';
    this.commitSha = env.BUILD_SOURCEVERSION || '';
    this.commitRef = env.BUILD_SOURCEBRANCHNAME || '';
    this.jobUrl =
      env.SYSTEM_COLLECTIONURI && env.SYSTEM_TEAMPROJECT && env.BUILD_BUILDID
        ? `${env.SYSTEM_COLLECTIONURI.replace(/\/?$/, '/')}${encodeURIComponent(env.SYSTEM_TEAMPROJECT)}` +
          `/_build/results?buildId=${env.BUILD_BUILDID}` +
          (env.SYSTEM_JOBID && env.SYSTEM_TASKINSTANCEID
            ? `&view=logs&j=${env.SYSTEM_JOBID}&t=${env.SYSTEM_TASKINSTANCEID}`
            : '')
        : '';
  }

  /**
   * Download the accuknox-aspm-scanner binary, or reuse the copy an earlier run left in the
   * agent's tool cache (Agent.ToolsDirectory, kept between runs on self-hosted agents).
   */
  async setup(): Promise<void> {
    const isWindows = process.platform === 'win32';
    const binName = isWindows ? 'accuknox-aspm-scanner.exe' : 'accuknox-aspm-scanner';
    const dir = path.join(process.env.AGENT_TOOLSDIRECTORY || os.tmpdir(), 'accuknox-aspm-scanner', this.cfg.version);
    const dest = path.join(dir, binName);
    if (fs.existsSync(dest) && fs.statSync(dest).size > 0) {
      console.log(`Using cached AccuKnox ASPM Scanner ${this.cfg.version} at ${dest}`);
    } else {
      fs.mkdirSync(dir, { recursive: true });
      const url = `${SCANNER_BASE_URL}/${this.cfg.version}/${binName}`;
      console.log(`Downloading AccuKnox ASPM Scanner (${this.cfg.version}, ${process.platform})...`);
      // Download beside the target and rename, so a broken download is never taken for a cached binary.
      const part = `${dest}.part`;
      await this.download(url, part);
      fs.renameSync(part, dest);
      console.log(`AccuKnox ASPM scanner installed at ${dest}`);
    }
    if (!isWindows) fs.chmodSync(dest, 0o755);
    this.scannerBin = dest;
  }

  private download(url: string, dest: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const file = fs.createWriteStream(dest);
      const request = (currentUrl: string, redirects: number) => {
        if (redirects > 10) {
          reject(new Error('Too many redirects while downloading scanner.'));
          return;
        }
        https
          .get(currentUrl, (res) => {
            if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
              res.resume();
              request(res.headers.location, redirects + 1);
              return;
            }
            if (res.statusCode !== 200) {
              res.resume();
              reject(new Error(`Failed to download scanner. HTTP ${res.statusCode}`));
              return;
            }
            res.pipe(file);
            file.on('finish', () => file.close(() => resolve()));
          })
          .on('error', (err) => {
            fs.unlink(dest, () => reject(err));
          });
      };
      request(url, 0);
    });
  }

  /**
   * Scans that run natively, mapped to [tool install --type, path to verify].
   * Verify paths mirror the CLI's ToolManager.TOOL_PATHS. sca and sbom both
   * shell out to Trivy, which ships as the `container` tool.
   * ml is absent: it has no local tool; the CLI (0.17+) scans models in its container by itself.
   */
  private static readonly TOOL_FOR_SCAN: Record<string, [string, string][]> = {
    sast: [['sast', path.join('sast', 'sast')]],
    sca: [['container', 'container']],
    // 0.17 merges Trivy and Syft output into the SBOM.
    sbom: [['container', 'container'], ['syft', 'syft']],
    secret: [['secret', 'secret']],
    // iac is absent: it always runs in its container.
  };

  /** Where `tool install` places binaries — mirrors the CLI's ToolManager. */
  private get toolsDir(): string {
    if (process.platform === 'win32') {
      return path.join(process.env.USERPROFILE || os.homedir(), 'AppData', 'Local', 'Programs', 'AccuKnox');
    }
    const globalDir = '/usr/share/accuknox-aspm-scanner/tools';
    return fs.existsSync(globalDir) ? globalDir : path.join(os.homedir(), '.local', 'bin', 'accuknox');
  }

  /** Windows tools land as .exe/.bat companions, so check those too. */
  private toolExists(relPath: string): boolean {
    const base = path.join(this.toolsDir, relPath);
    return [base, `${base}.exe`, `${base}.bat`, `${base}.cmd`].some((p) => fs.existsSync(p));
  }

  private async installTool(type: string, verifyRel: string): Promise<void> {
    if (this.toolExists(verifyRel)) {
      console.log(`Scanner tool '${type}' already present, skipping install.`);
      return;
    }
    for (let attempt = 1; attempt <= 3; attempt++) {
      console.log(`Installing scanner tool '${type}' (attempt ${attempt}/3)...`);
      // `tool install` exits 0 even when the download fails, so the exit code
      // proves nothing — verify the binary actually landed instead.
      await this.exec(['tool', 'install', '--type', type]);
      if (this.toolExists(verifyRel)) return;
      console.log(`WARNING: '${type}' not found under ${this.toolsDir} after install; retrying...`);
    }
    throw new Error(
      `Failed to install scanner tool '${type}' after 3 attempts (expected ${path.join(this.toolsDir, verifyRel)}).`
    );
  }

  /** Install local tool binaries for whichever selected scans run natively. */
  async installTools(selected: Set<string>): Promise<void> {
    const needed = new Map<string, string>();
    for (const scan of selected) {
      for (const [type, verifyRel] of CodeAnalysisScanner.TOOL_FOR_SCAN[scan] || []) {
        needed.set(type, verifyRel);
      }
    }
    for (const [type, verifyRel] of needed) {
      await this.installTool(type, verifyRel);
    }
  }

  /** Common env injected into every scanner invocation. */
  private scanEnv(): NodeJS.ProcessEnv {
    const env: NodeJS.ProcessEnv = {
      ...process.env,
      ACCUKNOX_ENDPOINT: this.cfg.endpoint,
      ACCUKNOX_TOKEN: this.cfg.token,
      ACCUKNOX_LABEL: this.cfg.label,
    };
    // `pipeline` has no --repo-url/--commit-sha/--job-url flags, so the run's identity goes by
    // the CLI's override variables. A value the user set on the task wins.
    const identity: Record<string, string> = {
      ACCUKNOX_REPO_URL: this.repoUrl,
      ACCUKNOX_COMMIT_SHA: this.commitSha,
      ACCUKNOX_PIPELINE_URL: this.jobUrl, // run URL on the upload
      // The SAST report's job URL has no ACCUKNOX_* override: the CLI only reads the CI's own
      // run-URL variables, and Azure DevOps has none, so the generic one it accepts is set.
      CI_JOB_URL: this.jobUrl,
    };
    for (const [name, value] of Object.entries(identity)) {
      if (value && !env[name]) env[name] = value;
    }
    return env;
  }

  private get softFailArg(): string[] {
    return this.cfg.softFail ? ['--softfail'] : [];
  }

  private get containerArg(): string[] {
    return this.cfg.containerMode ? ['--container-mode'] : [];
  }

  /** Run the scanner binary with the given args; resolves the exit code. */
  private exec(args: string[], extraEnv: NodeJS.ProcessEnv = {}): Promise<number> {
    if (!this.scannerBin) {
      throw new Error('Scanner not set up. Call setup() first.');
    }
    console.log(`Executing: accuknox-aspm-scanner ${args.join(' ')}`);
    return new Promise((resolve) => {
      const child = spawn(this.scannerBin, args, {
        env: { ...this.scanEnv(), ...extraEnv },
        stdio: 'inherit',
        shell: false,
      });
      child.on('error', (err) => {
        console.error(`Failed to start scanner: ${err.message}`);
        resolve(1);
      });
      child.on('close', (code) => resolve(code === null ? 1 : code));
    });
  }

  private async ensureCodeassure(): Promise<void> {
    try {
      await this.installTool('codeassure', path.join('codeassure', 'codeassure'));
    } catch (e) {
      console.warn(
        `WARNING: could not install codeassure (${e instanceof Error ? e.message : e}). ` +
          'AI-SAST may be skipped; OpenGrep SAST will still run.'
      );
    }
  }

  /**
   * One `pipeline` run: every scan in i.scans, one upload, optional quality gate.
   * Exit code: 0 pass, 1 policy failure, 2 a scan could not run / upload / be evaluated.
   */
  async runPipeline(i: PipelineInputs, containerMode = this.cfg.containerMode, cliId = ''): Promise<number> {
    console.log(
      `Starting AccuKnox pipeline (${i.scans.join(', ')})${containerMode ? ' in container mode' : ''}` +
        `${i.qualityGate ? ' with quality gate' : ''}...`
    );
    if (i.sast.aiAnalysis && i.scans.includes('sast')) await this.ensureCodeassure();
    const args = buildPipelineArgs(i, this.cfg.softFail, containerMode);
    // The CLI also turns the gate on from ACCUKNOX_QUALITY_GATE; only the qualityGate input may.
    const env: NodeJS.ProcessEnv = { ACCUKNOX_QUALITY_GATE: i.qualityGate ? 'true' : 'false' };
    // The CLI derives one gate run id per build; a second run in the same build needs its own.
    if (cliId) env.ACCUKNOX_CLI_ID = cliId;
    if (i.gateToken) env.ACCUKNOX_GATE_TOKEN = i.gateToken;
    return this.exec(args, env);
  }

  async runMl(i: MlInputs): Promise<number> {
    console.log('Starting AccuKnox ML Static scan...');
    // No local ModelScan tool: without --container-mode the CLI (0.17+) still scans in its
    // container, so this scan needs Docker either way.
    const args = ['scan', ...this.softFailArg, 'ml-scan', '--command', i.command, ...this.containerArg];
    if (this.repoUrl) args.push('--repo-url', this.repoUrl);
    if (this.commitRef) args.push('--commit-ref', this.commitRef);
    if (i.modelName.trim()) args.push('--model-name', i.modelName.trim());
    if (i.sourceType.trim()) args.push('--source-type', i.sourceType.trim());
    return this.exec(args);
  }
}
