/* eslint-disable */
// Lightweight test harness (no framework) for the AccuKnox Unified Scan task.
// It mocks CodeAnalysisScanner.exec to capture the argument vectors instead of
// spawning the real binary, and asserts the constructed command lines.
//
// Run:  npm test     (compiles with tsc, then runs this file)

const assert = require('assert');
const fs = require('fs');
const { CodeAnalysisScanner, buildPipelineArgs, pipelineRuns, iacCommand, sbomCommand, secretCommand } = require('./scanner');
const { parseScanTypes, VALID_SCANS } = require('./index');

let passed = 0;
let failed = 0;
function check(name, fn) {
  try {
    fn();
    passed++;
    console.log(`  ✓ ${name}`);
  } catch (e) {
    failed++;
    console.error(`  ✗ ${name}\n      ${e.message}`);
  }
}

// Build a scanner whose exec() records args/env instead of spawning.
function makeScanner(softFail, containerMode) {
  const s = new CodeAnalysisScanner({
    endpoint: 'cspm.demo.accuknox.com',
    token: 'tok',
    label: 'lbl',
    version: 'v0.17.0',
    softFail: !!softFail,
    containerMode: !!containerMode,
  });
  s.captured = null;
  s.env = null;
  s.exitCode = 0;
  s.exec = function (args, extraEnv) {
    this.captured = args;
    this.env = extraEnv;
    return Promise.resolve(this.exitCode);
  };
  return s;
}

const iacIn = (over) => ({ command: '', directory: '.', file: '', framework: '', compact: true, quiet: true, ...over });
const sbomIn = (over) => ({ scanType: 'filesystem', imageRef: '', scanPath: '.', command: '', severity: '', projectName: 'proj1', ...over });
const pipe = (over) => ({
  scans: ['sast', 'sca', 'secret', 'iac', 'sbom'],
  qualityGate: true,
  gateToken: 'gate-secret',
  gateTimeout: '',
  gateOnTimeout: '',
  sast: { command: '.', aiAnalysis: false, aiScanSeverity: 'HIGH,CRITICAL', codeassureConfig: '' },
  sca: { command: 'fs .' },
  secret: { command: 'git file://.', additionalArguments: '--results verified' },
  iac: iacIn({ framework: 'Terraform' }),
  sbom: sbomIn(),
  ...over,
});
const after = (args, flag) => args[args.indexOf(flag) + 1];

async function main() {
  // Pretend we're on an Azure DevOps agent.
  process.env.BUILD_REPOSITORY_URI = 'https://dev.azure.com/org/proj/_git/repo';
  process.env.BUILD_SOURCEBRANCHNAME = 'main';

  console.log('parseScanTypes:');
  check('valid list comma+space', () => {
    assert.deepStrictEqual([...parseScanTypes('sast, sca secret')].sort(), ['sast', 'sca', 'secret']);
  });
  check('case-insensitive + aliases', () => {
    assert.deepStrictEqual([...parseScanTypes('SAST, Secrets, ML, mlscan')].sort(), ['ml', 'sast', 'secret']);
  });
  check('unknown tokens dropped', () => {
    assert.deepStrictEqual([...parseScanTypes('sast foobar iac')].sort(), ['iac', 'sast']);
  });
  check('api-discovery is no longer a scan', () => {
    assert.strictEqual(parseScanTypes('api, api-discovery').size, 0);
  });
  check('empty -> empty set', () => {
    assert.strictEqual(parseScanTypes('   ').size, 0);
  });
  check('all six recognised', () => {
    assert.strictEqual(parseScanTypes(VALID_SCANS.join(',')).size, 6);
  });

  console.log('\nPer-scan command text:');
  check('secret command appends additional args', () => {
    assert.strictEqual(secretCommand({ command: 'git file://.', additionalArguments: ' --results verified ' }), 'git file://. --results verified');
    assert.strictEqual(secretCommand({ command: 'filesystem .', additionalArguments: '' }), 'filesystem .');
  });
  check('structured iac builds --directory/--compact/--quiet/--framework x2', () => {
    assert.strictEqual(
      iacCommand(iacIn({ framework: 'Kubernetes, Terraform' })),
      '--directory . --compact --quiet --framework Kubernetes --framework Terraform'
    );
  });
  check('raw iacCommand overrides structured inputs', () => {
    assert.strictEqual(iacCommand(iacIn({ command: '--directory custom --quiet' })), '--directory custom --quiet');
  });
  check('iacFile takes precedence over the default directory (mutually exclusive)', () => {
    assert.strictEqual(iacCommand(iacIn({ file: 'main.tf', compact: false, quiet: false })), '--file main.tf');
  });
  check('filesystem and image sbom commands', () => {
    assert.strictEqual(sbomCommand(sbomIn({ severity: 'HIGH' })), 'filesystem . --severity HIGH');
    assert.strictEqual(sbomCommand(sbomIn({ scanType: 'image', imageRef: 'myapp:latest' })), 'image myapp:latest');
    assert.strictEqual(sbomCommand(sbomIn({ command: 'image raw:1' })), 'image raw:1');
  });
  check('sbom validation: project name, image ref, target type', () => {
    assert.throws(() => sbomCommand(sbomIn({ projectName: ' ' })), /sbomProjectName is required/);
    assert.throws(() => sbomCommand(sbomIn({ scanType: 'image' })), /sbomImageRef is required/);
    assert.throws(() => sbomCommand(sbomIn({ scanType: 'tarball' })), /Invalid sbomScanType/);
  });

  console.log('\nPipeline (sast, sca, secret, iac, sbom):');
  check('all scans: one pipeline run with the gate and per-scan commands', () => {
    const a = buildPipelineArgs(pipe(), false);
    assert.deepStrictEqual(a.slice(0, 5), ['pipeline', '--scans', 'sast,sca,secret,iac,sbom', '--keep-results', '--quality-gate']);
    assert.strictEqual(after(a, '--sast-command'), '.');
    assert.strictEqual(after(a, '--sca-command'), 'fs .');
    assert.strictEqual(after(a, '--secret-command'), 'git file://. --results verified');
    assert.strictEqual(after(a, '--iac-command'), '--directory . --compact --quiet --framework Terraform');
    assert.strictEqual(after(a, '--sbom-command'), 'filesystem .');
    assert.strictEqual(after(a, '--project-name'), 'proj1');
    assert.ok(!a.includes('--softfail') && !a.includes('--ai-analysis') && !a.includes('--container-mode'), a.join(' '));
  });
  check('quality gate only when qualityGate is true', () => {
    const a = buildPipelineArgs(pipe({ scans: ['sca'], qualityGate: false, gateTimeout: '900', gateOnTimeout: 'pass' }), true);
    assert.deepStrictEqual(a, ['pipeline', '--scans', 'sca', '--keep-results', '--softfail', '--sca-command', 'fs .']);
  });
  check('gate timeout options pass through with the gate on', () => {
    const on = buildPipelineArgs(pipe({ gateTimeout: '900', gateOnTimeout: 'pass' }), false).join(' ');
    assert.ok(on.includes('--quality-gate --gate-timeout 900 --gate-on-timeout pass'), on);
  });
  check('--container-mode only when asked', () => {
    assert.ok(buildPipelineArgs(pipe(), false, true).includes('--container-mode'));
  });
  check('gate token never appears in argv', () => {
    assert.ok(!buildPipelineArgs(pipe(), true).join(' ').includes('gate-secret'));
  });
  check('AI options only with sast selected and AI on', () => {
    const ai = { command: '.', aiAnalysis: true, aiScanSeverity: 'HIGH', codeassureConfig: 'c.json' };
    const on = buildPipelineArgs(pipe({ scans: ['sast'], sast: ai }), false).join(' ');
    assert.ok(on.includes('--ai-analysis --aiscan-severity HIGH --codeassure-config c.json'), on);
    const off = buildPipelineArgs(pipe({ scans: ['sca'], sast: ai }), false).join(' ');
    assert.ok(!off.includes('--ai-analysis'), off);
  });
  check('sbom in the pipeline still requires a project name', () => {
    assert.throws(() => buildPipelineArgs(pipe({ sbom: sbomIn({ projectName: '' }) }), false), /sbomProjectName is required/);
  });
  {
    const s = makeScanner(false);
    s.exitCode = 1;
    const code = await s.runPipeline(pipe());
    check('runPipeline: gate on -> token and gate flag by env, exit code returned', () => {
      assert.strictEqual(code, 1);
      assert.deepStrictEqual(s.env, { ACCUKNOX_QUALITY_GATE: 'true', ACCUKNOX_GATE_TOKEN: 'gate-secret' });
    });
  }
  {
    const s = makeScanner(false);
    await s.runPipeline(pipe({ qualityGate: false, gateToken: '' }));
    check('runPipeline: gate off -> an inherited ACCUKNOX_QUALITY_GATE cannot turn it on', () => {
      assert.deepStrictEqual(s.env, { ACCUKNOX_QUALITY_GATE: 'false' });
      assert.ok(!s.captured.includes('--quality-gate'));
    });
  }

  console.log('\nRun identity passed to the scanner:');
  {
    const saved = { ...process.env };
    Object.assign(process.env, {
      BUILD_SOURCEVERSION: 'abc1234def',
      BUILD_BUILDID: '42',
      SYSTEM_COLLECTIONURI: 'https://dev.azure.com/org/',
      SYSTEM_TEAMPROJECT: 'My Proj',
      SYSTEM_JOBID: 'job-1',
      SYSTEM_TASKINSTANCEID: 'task-1',
    });
    const jobUrl = 'https://dev.azure.com/org/My%20Proj/_build/results?buildId=42&view=logs&j=job-1&t=task-1';
    const env = makeScanner(false).scanEnv();
    check('repo URL, commit, run id and job URL reach the scanner env', () => {
      assert.strictEqual(env.ACCUKNOX_REPO_URL, 'https://dev.azure.com/org/proj/_git/repo');
      assert.strictEqual(env.ACCUKNOX_COMMIT_SHA, 'abc1234def');
      assert.strictEqual(env.BUILD_BUILDID, '42');
      assert.strictEqual(env.ACCUKNOX_PIPELINE_URL, jobUrl);
      assert.strictEqual(env.CI_JOB_URL, jobUrl);
    });
    process.env.ACCUKNOX_REPO_URL = 'https://example.com/me/override';
    check('a value the user set on the task wins', () => {
      assert.strictEqual(makeScanner(false).scanEnv().ACCUKNOX_REPO_URL, 'https://example.com/me/override');
    });
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    check('no job URL outside a pipeline run -> variables left unset', () => {
      const e = makeScanner(false).scanEnv();
      assert.ok(!('ACCUKNOX_PIPELINE_URL' in e) && !('CI_JOB_URL' in e));
    });
  }

  console.log('\nML scan (separate from the pipeline):');
  {
    const s = makeScanner(true);
    await s.runMl({ command: 'scan -p . -r json', modelName: 'mymodel', sourceType: 'azure' });
    const j = s.captured.join(' ');
    check('ml-scan subcommand with repo, commit-ref, model-name, source-type; native by default', () => {
      assert.ok(j.startsWith('scan --softfail ml-scan --command scan -p . -r json'), j);
      assert.ok(j.includes('--repo-url https://dev.azure.com/org/proj/_git/repo'), j);
      assert.ok(j.includes('--commit-ref main'), j);
      assert.ok(j.includes('--model-name mymodel'), j);
      assert.ok(j.includes('--source-type azure'), j);
      assert.ok(!j.includes('--container-mode'), j);
    });
    const c = makeScanner(false, true);
    await c.runMl({ command: 'scan -p . -r json', modelName: '', sourceType: '' });
    check('ml-scan gets --container-mode when containerMode is on', () => {
      assert.ok(c.captured.includes('--container-mode'), c.captured.join(' '));
    });
  }

  console.log('\nTool install:');
  // Record every exec() call; a tool counts as present once its install was called.
  const installer = (present) => {
    const s = makeScanner(false);
    const calls = [];
    s.exec = (args) => {
      calls.push(args.join(' '));
      return Promise.resolve(0);
    };
    s.toolExists = present === undefined ? (rel) => calls.some((c) => c.endsWith(` ${rel.split(/[\\/]/)[0]}`)) : () => present;
    return { s, calls };
  };
  {
    const { s, calls } = installer(true);
    await s.installTools(new Set(['sast', 'sca', 'sbom', 'iac', 'secret']));
    check('skips install when the tool is already present', () => {
      assert.strictEqual(calls.length, 0, calls.join(' | '));
    });
  }
  {
    const { s, calls } = installer();
    await s.installTools(new Set(['sca', 'sbom', 'ml']));
    check('sca+sbom share the container tool, sbom adds syft, ml installs nothing', () => {
      assert.deepStrictEqual(calls, ['tool install --type container', 'tool install --type syft'], calls.join(' | '));
    });
  }
  {
    const { s, calls } = installer();
    await s.installTools(new Set(['sast']));
    check('sast installs the sast tool', () => {
      assert.deepStrictEqual(calls, ['tool install --type sast'], calls.join(' | '));
    });
  }
  {
    // `tool install` exits 0 even on a failed download, so a never-appearing
    // binary must retry 3x and then throw rather than scan with no tool.
    const { s, calls } = installer(false);
    let threw = null;
    await s.installTools(new Set(['secret'])).catch((e) => (threw = e));
    check('retries 3x then throws when the binary never appears', () => {
      assert.strictEqual(calls.length, 3, calls.join(' | '));
      assert.ok(threw && /Failed to install scanner tool 'secret'/.test(threw.message), String(threw));
    });
  }

  console.log('\nIaC container split:');
  check('iac runs in its own container-mode run, the rest stay native', () => {
    assert.deepStrictEqual(pipelineRuns(['sast', 'iac', 'sbom'], false), [
      { scans: ['sast', 'sbom'], containerMode: false },
      { scans: ['iac'], containerMode: true },
    ]);
    assert.deepStrictEqual(pipelineRuns(['iac'], false), [{ scans: ['iac'], containerMode: true }]);
  });
  check('no iac, or containerMode on, keeps a single run', () => {
    assert.deepStrictEqual(pipelineRuns(['sast', 'sca'], false), [{ scans: ['sast', 'sca'], containerMode: false }]);
    assert.deepStrictEqual(pipelineRuns(['sast', 'iac'], true), [{ scans: ['sast', 'iac'], containerMode: true }]);
  });
  check('ml only: no pipeline run', () => {
    assert.deepStrictEqual(pipelineRuns([], false), []);
    assert.deepStrictEqual(pipelineRuns([], true), []);
  });
  {
    const { s, calls } = installer();
    await s.installTools(new Set(['iac']));
    check('iac installs no native tool', () => assert.deepStrictEqual(calls, []));
  }
  {
    const s = makeScanner(false);
    await s.runPipeline(pipe({ scans: ['iac'] }), true, 'run-2');
    check('runPipeline: per-run container mode and gate run id', () => {
      assert.ok(s.captured.includes('--container-mode'), s.captured.join(' '));
      assert.strictEqual(s.env.ACCUKNOX_CLI_ID, 'run-2');
    });
  }

  console.log('\nDownload URL:');
  // Drive setup() per platform with the network call stubbed out.
  // A fresh tool cache per test run, so earlier runs cannot satisfy the download.
  process.env.AGENT_TOOLSDIRECTORY = fs.mkdtempSync(require('path').join(require('os').tmpdir(), 'ak-tools-'));
  const setupOn = async (platform) => {
    const original = Object.getOwnPropertyDescriptor(process, 'platform');
    Object.defineProperty(process, 'platform', { value: platform, configurable: true });
    try {
      const s = makeScanner(false);
      let url = '';
      s.download = (u, dest) => {
        url = u;
        fs.writeFileSync(dest, 'bin'); // setup() chmods this on POSIX
        return Promise.resolve();
      };
      await s.setup();
      return { url, bin: s.scannerBin };
    } finally {
      Object.defineProperty(process, 'platform', original);
    }
  };

  const linux = await setupOn('linux');
  check('linux setup downloads the bare binary and makes it executable', () => {
    assert.ok(linux.url.endsWith('/v0.17.0/accuknox-aspm-scanner'), linux.url);
    // Windows filesystems have no executable bit, so only assert it on POSIX hosts.
    if (process.platform !== 'win32') assert.ok(fs.statSync(linux.bin).mode & 0o111);
  });

  const win = await setupOn('win32');
  check('windows setup downloads the .exe', () => {
    assert.ok(win.url.endsWith('/v0.17.0/accuknox-aspm-scanner.exe'), win.url);
    assert.ok(win.bin.endsWith('accuknox-aspm-scanner.exe'), win.bin);
  });

  const again = await setupOn('linux');
  check('second setup reuses the cached binary without downloading', () => {
    assert.strictEqual(again.url, '');
    assert.strictEqual(again.bin, linux.bin);
    assert.ok(linux.bin.includes(require('path').join('accuknox-aspm-scanner', 'v0.17.0')), linux.bin);
  });

  console.log(`\nResult: ${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

main();
