import tl = require('azure-pipelines-task-lib');
import { randomUUID } from 'crypto';
import { CodeAnalysisScanner, PIPELINE_SCANS, pipelineRuns, ScannerConfig } from './scanner';

export const VALID_SCANS = ['sast', 'sca', 'secret', 'iac', 'ml', 'sbom'];

/** Same truthy values the CLI accepts for ACCUKNOX_ENABLE_AI_SAST. */
export function envFlagTrue(name: string): boolean {
  return ['TRUE', '1', 'YES'].includes((process.env[name] || '').toUpperCase());
}

/** Normalise the scanType input (comma/space separated, case-insensitive) into a set of tokens. */
export function parseScanTypes(raw: string): Set<string> {
  const selected = new Set<string>();
  const tokens = raw.toLowerCase().split(/[\s,]+/).filter(Boolean);
  for (const t of tokens) {
    switch (t) {
      case 'sast':
        selected.add('sast');
        break;
      case 'sca':
        selected.add('sca');
        break;
      case 'secret':
      case 'secrets':
        selected.add('secret');
        break;
      case 'iac':
        selected.add('iac');
        break;
      case 'ml':
      case 'ml-scan':
      case 'mlscan':
        selected.add('ml');
        break;
      case 'sbom':
        selected.add('sbom');
        break;
      default:
        console.log(`WARNING: unknown scan type '${t}' (valid: ${VALID_SCANS.join(', ')})`);
    }
  }
  return selected;
}

export async function run(): Promise<void> {
  try {
    const endpoint = tl.getInput('accuknoxEndpoint', true) as string;
    const token = tl.getInput('accuknoxToken', true) as string;
    const label = tl.getInput('accuknoxLabel', true) as string;

    const rawScanType = tl.getInput('scanType', true) as string;
    const selected = parseScanTypes(rawScanType);
    if (selected.size === 0) {
      tl.setResult(
        tl.TaskResult.Failed,
        `scanType did not match any known scan. Provide one or more of: ${VALID_SCANS.join(', ')}.`
      );
      return;
    }

    const softFail = tl.getBoolInput('softFail', false);
    const containerMode = tl.getBoolInput('containerMode', false);
    const cfg: ScannerConfig = {
      endpoint,
      token,
      label,
      version: tl.getInput('scannerVersion', false) || 'v0.17.0',
      softFail,
      containerMode,
    };

    const scanner = new CodeAnalysisScanner(cfg);
    await scanner.setup();
    // Container mode pulls scanner images instead, so there are no native tools to install.
    if (!containerMode) await scanner.installTools(selected);

    const sast = {
      command: tl.getInput('sastCommand', false) || '.',
      aiAnalysis: tl.getBoolInput('enableAiSast', false) || envFlagTrue('ACCUKNOX_ENABLE_AI_SAST'),
      aiScanSeverity: tl.getInput('sastAiScanSeverity', false) || 'HIGH,CRITICAL',
      codeassureConfig: tl.getInput('sastCodeassureConfig', false) || '',
    };
    const sca = {
      command: tl.getInput('scaCommand', false) || 'fs .',
    };
    const secret = {
      command: tl.getInput('secretCommand', false) || 'git file://.',
      additionalArguments: tl.getInput('secretAdditionalArguments', false) || '',
    };
    const iac = {
      command: tl.getInput('iacCommand', false) || '',
      directory: tl.getInput('iacDirectory', false) || '.',
      file: tl.getInput('iacFile', false) || '',
      framework: tl.getInput('iacFramework', false) || '',
      compact: tl.getBoolInput('iacCompact', false),
      quiet: tl.getBoolInput('iacQuiet', false),
    };
    const sbom = {
      scanType: tl.getInput('sbomScanType', false) || 'filesystem',
      imageRef: tl.getInput('sbomImageRef', false) || '',
      scanPath: tl.getInput('sbomScanPath', false) || '.',
      command: tl.getInput('sbomCommand', false) || '',
      severity: tl.getInput('sbomSeverity', false) || '',
      projectName: tl.getInput('sbomProjectName', false) || '',
    };

    // sast, sca, secret, iac and sbom always go through the `pipeline` command: one run, or two
    // when iac has to run in its container beside native scans. The quality gate is on only
    // when qualityGate is true. ml runs as its own scan below.
    const qualityGate = tl.getBoolInput('qualityGate', false);
    const pipelineScans = PIPELINE_SCANS.filter((s) => selected.has(s));
    // The CLI already applied soft fail to the pipeline exit code; what is left must fail the task.
    let pipelineFailure = '';
    const runs = pipelineRuns(pipelineScans, containerMode);
    for (const [n, run] of runs.entries()) {
      const code = await scanner.runPipeline(
        {
          scans: run.scans,
          qualityGate,
          gateToken: tl.getInput('accuknoxGateToken', false) || '',
          gateTimeout: tl.getInput('gateTimeout', false) || '',
          gateOnTimeout: tl.getInput('gateOnTimeout', false) || '',
          sast,
          sca,
          secret,
          iac,
          sbom,
        },
        run.containerMode,
        // Every run after the first gets its own gate run id, so the two verdicts stay apart.
        qualityGate && n > 0 ? randomUUID() : ''
      );
      // A run that could not run or upload (2) outranks a policy failure (1) in the message.
      if (code === 1) {
        pipelineFailure ||= qualityGate
          ? 'AccuKnox quality gate failed: a policy blocked this build.'
          : 'One or more scans reported findings.';
      } else if (code !== 0) {
        pipelineFailure = `AccuKnox pipeline could not run, upload or be evaluated (exit code ${code}).`;
      }
    }
    if (runs.length === 0 && qualityGate) {
      tl.warning('qualityGate is enabled but none of the selected scans support it (sast, sca, secret, iac, sbom).');
    }

    let mlExit = 0;
    if (selected.has('ml')) {
      mlExit = await scanner.runMl({
        command: tl.getInput('mlCommand', false) || 'scan -p . -r json',
        modelName: tl.getInput('mlModelName', false) || '',
        sourceType: tl.getInput('mlSourceType', false) || 'azure',
      });
    }

    // -------------------- HANDLE RESULT --------------------
    if (pipelineFailure) {
      tl.setResult(tl.TaskResult.Failed, pipelineFailure);
    } else if (mlExit !== 0) {
      const msg = 'The ML scan reported findings or errors.';
      if (softFail) {
        console.log(`${msg} Soft fail is enabled, continuing...`);
        tl.setResult(tl.TaskResult.Succeeded, `${msg} Soft fail enabled.`);
      } else {
        tl.setResult(tl.TaskResult.Failed, `${msg} Soft fail is disabled, failing the task.`);
      }
    } else {
      console.log('All selected scans completed successfully.');
      tl.setResult(tl.TaskResult.Succeeded, 'All selected scans completed successfully.');
    }
  } catch (err: any) {
    tl.setResult(tl.TaskResult.Failed, err.message);
  }
}

// Only auto-run when invoked directly by the Azure DevOps agent (not when imported by tests).
if (require.main === module) {
  run();
}
