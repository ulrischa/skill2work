<?php
declare(strict_types=1);

require dirname(__DIR__) . '/src/Archive.php';
require dirname(__DIR__) . '/src/Profile.php';
require dirname(__DIR__) . '/src/Analyzer.php';
require dirname(__DIR__) . '/src/SkillReferences.php';
require_once dirname(__DIR__) . '/src/CodexCompatibility.php';
require dirname(__DIR__) . '/src/Converter.php';

use Skill2Work\Archive;
use Skill2Work\Analyzer;
use Skill2Work\Converter;
use Skill2Work\Profile;

$passed = 0;
function check(bool $condition, string $message): void
{
    global $passed;
    if (!$condition) {
        throw new RuntimeException('FAILED: ' . $message);
    }
    $passed++;
}
function fails(callable $callback, string $message): void
{
    global $passed;
    try {
        $callback();
    } catch (Throwable $error) {
        $passed++;
        return;
    }
    throw new RuntimeException('FAILED (expected exception): ' . $message);
}

$profile = Profile::parse(json_encode([
    'schema_version' => 1,
    'source' => 'skill2work-probe',
    'timestamp' => gmdate('c'),
    'commands' => [
        'python' => ['available' => false],
        'python3' => ['available' => true],
        'node' => ['available' => false],
        'ffmpeg' => ['available' => false],
    ],
    'python_modules' => ['requests' => ['available' => false]],
    'features' => ['temporary_file_write' => true],
], JSON_THROW_ON_ERROR));

check(Profile::status($profile, 'python') === 'missing', 'profile knows missing Python alias');
check(Profile::status($profile, 'python3') === 'available', 'profile knows Python 3');
check(Profile::status($profile, 'git') === 'unknown', 'unknown command remains unknown');
fails(fn() => Profile::parse('{"source":"fake","schema_version":1}'), 'reject invalid profile');
fails(fn() => Archive::validatePath('../SKILL.md'), 'path traversal');
fails(fn() => Archive::validatePath('/etc/passwd'), 'absolute path');
fails(fn() => Archive::validatePath('C:/secret'), 'Windows drive path');
fails(fn() => Archive::validatePath('a\\b'), 'backslash path');

$input = [
    'repo/skills/pretty/SKILL.md' => "---\nname: Pretty Skill\ndescription: Format a sample\n---\n\nRun:\n\n```bash\npython scripts/run.py\nffmpeg -i input.mp4 output.mp4\n```\n",
    'repo/skills/pretty/scripts/run.py' => "import requests\nimport json\nprint('hello')\n",
    'repo/skills/pretty/requirements.txt' => "requests>=2.30\n",
    'repo/skills/another/SKILL.md' => "---\nname: another\ndescription: Another\n---\n\nReview the user's document.\n",
    'repo/docs/README.md' => 'External notes',
];
$paths = Converter::discover($input);
check(count($paths) === 2, 'discovers two skills');
$result = Converter::convert($input, $paths[1], $profile);
$report = $result['report'];
check($report['skill'] === 'pretty-skill', 'normalizes name');
check($report['commands']['python3']['status'] === 'found_untested', 'python3 observed');
check($report['commands']['ffmpeg']['status'] === 'not_found', 'ffmpeg absent');
check($report['modules']['requests']['status'] === 'missing', 'requests absent');
check($report['overall'] === 'incompatible', 'missing dependency makes skill incompatible in snapshot');
check(count($report['rewrites']) === 1, 'rewrites exact alias once');
check(str_contains($result['archive']['pretty-skill/SKILL.md'], 'python3 scripts/run.py'), 'markdown command converted');
check($result['archive']['pretty-skill/scripts/run.py'] === $input['repo/skills/pretty/scripts/run.py'], 'code byte-preserved');
check(!isset($result['archive']['pretty-skill/README.md']), 'does not capture repo files outside skill');
check(isset($result['archive']['pretty-skill/references/skill2work-compatibility.md']), 'report generated');

// Full v2 runtime inventories must be accepted; missing names are definite only
// when the PATH scan was complete. Importable modules are never inferred absent.
$v2_data = [
    'schema_version' => 2,
    'source' => 'skill2work-probe',
    'timestamp' => gmdate('c'),
    'commands' => ['python3' => ['available' => true, 'evidence' => 'executable_in_PATH']],
    'python_modules' => ['requests' => ['available' => true, 'evidence' => 'import_spec_without_import']],
    'features' => ['python_script_execution' => true, 'temporary_file_write' => true],
    'inventory' => [
        'system_packages' => [['name' => 'curl', 'version' => '1.0']],
        'python_distributions' => [['name' => 'requests', 'version' => '2.0']],
        'installed_extensions' => ['vscode' => [['name' => 'publisher.extension', 'version' => '1.0']]],
        'executables_outside_path' => [['name' => 'ffmpeg', 'path' => '/opt/bin/ffmpeg']],
    ],
    'coverage' => ['path_inventory_complete' => true,
                   'python_module_metadata_complete' => true,
                   'agent_tools_complete' => false],
];
$v2_profile = Profile::parse(json_encode($v2_data, JSON_THROW_ON_ERROR));
check(Profile::status($v2_profile, 'missing-cli-tool') === 'missing', 'complete PATH reports missing command');
check(Profile::moduleStatus($v2_profile, 'unseen_python_module') === 'unknown', 'python absence remains unproven');
check(Profile::status($v2_profile, 'python3') === 'available', 'v2 imported program available');
$v2_data['coverage']['path_inventory_complete'] = false;
$v2_incomplete = Profile::parse(json_encode($v2_data, JSON_THROW_ON_ERROR));
check(Profile::status($v2_incomplete, 'missing-cli-tool') === 'unknown', 'incomplete PATH is unknown');
$v2_output = Converter::convert($input, $paths[1], $v2_profile);
check(str_contains(implode(' ', $v2_output['report']['warnings']), 'outside PATH'), 'off-PATH binary reported but not rewritten');
check(str_contains($v2_output['archive']['pretty-skill/references/skill2work-compatibility.md'], 'Runtime inventory coverage'), 'v2 coverage added to report');
$extended_shell = Analyzer::analyze(['SKILL.md' => "---\nname: a\ndescription: b\n---\n\n```bash\ncustom-automation --check\n```\n"], $v2_profile);
check(isset($extended_shell['commands']['custom-automation']), 'detect previously unknown command from shell fence');
check($extended_shell['commands']['custom-automation']['status'] === 'not_found', 'cross-check novel command against complete PATH');
fails(fn() => Profile::parse(json_encode(array_merge($v2_data, ['coverage' => []]), JSON_THROW_ON_ERROR)), 'reject invalid v2 coverage');

$plain = Converter::convert($input, $paths[0], Profile::parse(null));
check($plain['report']['overall'] === 'instructions-only', 'instructions-only skill can be identified');
check($plain['report']['rewrites'] === [], 'no invented conversion without profile');

$testpath = sys_get_temp_dir() . '/skill2work-' . bin2hex(random_bytes(8)) . '.zip';
try {
    Archive::write($testpath, $result['archive']);
    $read = Archive::read($testpath);
    check($read === $result['archive'], 'round-trip ZIP package');
    $temp_without_extension = tempnam(sys_get_temp_dir(), 's2w-');
    copy($testpath, $temp_without_extension);
    $read = Archive::read($temp_without_extension);
    check(count($read) === count($result['archive']), 'works for extensionless PHP upload');
    unlink($temp_without_extension);
} finally {
    @unlink($testpath);
}

// Malformed and dangerous archives must never become exported skills.
$unsafe_path = sys_get_temp_dir() . '/skill2work-' . bin2hex(random_bytes(8)) . '.zip';
try {
    Archive::write($unsafe_path, ['aa/SKILL.md' => 'x']);
    $bytes = file_get_contents($unsafe_path);
    $bytes = str_replace('aa/SKILL.md', '../SKILL.md', $bytes);
    file_put_contents($unsafe_path, $bytes);
    fails(fn() => Archive::read($unsafe_path), 'reject traversal even without ZipArchive extension');
} finally {
    @unlink($unsafe_path);
}
fails(fn() => Converter::convert(['x/SKILL.md' => "---\nname: x\ndescription: |\n  two lines\n---\n"], 'x/SKILL.md', $profile), 'multiline YAML must be reviewed, not destroyed');
check(!str_contains($result['archive']['pretty-skill/SKILL.md'], 'python scripts/run.py'), 'old command no longer emitted');

$code = "# comment\nsubprocess.run(['git', 'status'])\n";
$scan = Analyzer::analyze(['SKILL.md' => "---\nname: demo\ndescription: demo\n---\n", 'scripts/task.py' => $code], Profile::parse(null));
check(isset($scan['commands']['git']), 'detect subprocess');
check($scan['commands']['git']['status'] === 'unknown', 'no-probe command remains unknown');

// Codex invocation syntax: preserve shell, migrate human-facing skill references.
$skill_text = "---\nname: my-agent\ndescription: skill demo\n---\n\nUse `\$skill-creator` then /skills. Invoke \$test-helper when ready.\n\n```bash\necho \$test-helper\ncodex exec 'Use \$skill-creator'\n```\n\nKeep \$PATH and /skills.md unchanged.\n";
$ref_source = [
    'SKILL.md' => $skill_text,
    'references/dependencies.md' => 'Then use $second-helper.',
    'scripts/demo.sh' => "#!/bin/sh\necho \$test-helper\n",
];
$ref_repo = $ref_source + ['AGENTS.md' => '# repo policy'];
$ref_output = Converter::convert($ref_repo, 'SKILL.md', Profile::parse(null));
$converted_text = $ref_output['archive']['my-agent/SKILL.md'];
check(str_contains($converted_text, '`@skill-creator`'), 'inline Codex skill selector migrates');
check(str_contains($converted_text, '@test-helper'), 'prose skill reference migrates');
check(str_contains($converted_text, 'the `@` picker in the ChatGPT composer'), 'slash picker migrates to descriptive Work UI');
check(str_contains($converted_text, "echo \$test-helper"), 'shell blocks left unchanged');
check(str_contains(implode(' ', $ref_output['report']['warnings']), 'code block'), 'nonmigrated script skill syntax flagged');
check(str_contains($converted_text, 'codex exec'), 'Codex CLI not silently translated');
check(str_contains($converted_text, '/skills.md'), 'file paths are not slash commands');
check(str_contains($converted_text, '$PATH'), 'environment variables untouched');
check($ref_output['archive']['my-agent/scripts/demo.sh'] === $ref_source['scripts/demo.sh'], 'script files byte-preserved');
check(str_contains($ref_output['archive']['my-agent/references/dependencies.md'], '@second-helper'), 'nested Markdown dependencies also rewritten');
check(count($ref_output['report']['skill_dependencies']) === 3, 'external skill dependencies reported');
check(str_contains(implode(' ', $ref_output['report']['warnings']), 'AGENTS.md'), 'repository-level AGENTS.md not silently transferred');
check($ref_output['report']['overall'] === 'unverified', 'missing external skills make conversion unverified');

// The probe ZIP metadata declares an optional start prompt without executing on install.
$probe_metadata = file_get_contents(dirname(__DIR__) . '/probe-skill/agents/openai.yaml');
check(is_string($probe_metadata) && str_contains($probe_metadata, 'default_prompt:'), 'skill UI start prompt metadata exists');
check(str_contains(file_get_contents(dirname(__DIR__) . '/probe-skill/SKILL.md'), 'never run the probe automatically'), 'probe never runs on installation alone');



// Codex CLI provides task-level counterparts but not a Work subprocess API.
$codex_input = ['SKILL.md' => "---\nname: nested-agent\ndescription: run an agent task\n---\n\nRun `codex exec --json 'Audit the project'` in CI.\n\n```bash\ncodex exec --full-auto 'Update PHP files'\n```\n\nPlease /plan first, then /review.\n",
              'scripts/runner.sh' => "#!/bin/sh\ncodex exec --json \"Do job\"\n"];
$codex_result = Converter::convert($codex_input, 'SKILL.md', Profile::parse(null));
check(isset($codex_result['archive']['nested-agent/references/skill2work-work-actions.md']), 'generates task-level alternatives');
check(str_contains($codex_result['archive']['nested-agent/references/skill2work-work-actions.md'], 'No equivalent for subprocess'), 'documents codex exec CLI mismatch');
check($codex_result['archive']['nested-agent/scripts/runner.sh'] === $codex_input['scripts/runner.sh'], 'does not rewrite executable subprocess calls');
check(str_contains($codex_result['archive']['nested-agent/SKILL.md'], 'codex exec --full-auto'), 'code fences preserved');
check(count($codex_result['report']['codex_work_mappings']) >= 4, 'codex CLI and slash commands recognized');
check($codex_result['report']['overall'] === 'unverified', 'agent task mapping is not certified executable');



$changes = [];
$direct = "Run `codex exec \"Review the code\"`";
$migrated = \Skill2Work\CodexCompatibility::migrate($direct, 'SKILL.md', $changes);
check(str_contains($migrated, 'Work task') && !str_contains($migrated, 'codex exec'), 'migrates complete literal prose instruction');
check(count($changes) === 1, 'records concrete migration');
foreach (["Run `codex exec --json \"Task\"`", "Run `codex exec \"Task\" | jq`", "Run `codex resume abc`", "Run `codex exec \"Hello \$USER\"`", "Never run `codex exec \"Task\"`", "    Run `codex exec \"Task\"`", "~~~sh\n$direct\n~~~", "```sh\n$direct\n```"] as $unchanged) {
    $ignored = [];
    check(\Skill2Work\CodexCompatibility::migrate($unchanged, 'SKILL.md', $ignored) === $unchanged, 'preserves non-equivalent or code invocation');
}
$script_changes = [];
check(\Skill2Work\CodexCompatibility::migrate($direct, 'task.sh', $script_changes) === $direct, 'never rewrites source scripts');
$result = Converter::convert(['SKILL.md' => "---\nname: simple-migrate\ndescription: demo\n---\n" . $direct], 'SKILL.md', Profile::parse(null));
check(str_contains($result['archive']['simple-migrate/SKILL.md'], 'Work task'), 'migration reaches exported skill');
check(count($result['report']['rewrites']) > 0, 'migration shown in output report');
$unmapped = Converter::convert(['SKILL.md' => "---\nname: complex-migrate\ndescription: demo\n---\nRun `codex exec --output-schema schema.json \"Task\"`"], 'SKILL.md', Profile::parse(null));
check(str_contains(implode(' ', $unmapped['report']['warnings']), 'Not converted automatically'), 'unsupported semantics shown in output');

// Off-PATH candidates are evidence, not missing dependencies or universal test passes.
$evidence_data = $v2_data;
$evidence_data['coverage']['path_inventory_complete'] = true;
$evidence_data['commands'] = [];
$evidence_data['inventory']['executables_outside_path'] = [
    ['name' => 'widget', 'path' => '/opt/widget', 'invocation_path' => '/opt/widget'],
    ['name' => 'widget', 'path' => '/srv/widget', 'invocation_path' => '/srv/widget'],
];
$evidence_profile = Profile::parse(json_encode($evidence_data));
$evidence = Profile::commandEvidence($evidence_profile, 'widget');
check($evidence['status'] === 'found_untested' && count($evidence['candidates']) === 2, 'all off-PATH candidates count as found');
check($evidence['selection_required'], 'off-PATH use requires explicit selection');
$widget = ['SKILL.md' => "---\nname: widget-demo\ndescription: demo\n---\n```sh\nwidget --help\n```\n"];
$converted_widget = Converter::convert($widget, 'SKILL.md', $evidence_profile);
check($converted_widget['report']['overall'] === 'unverified', 'untested off-PATH tool is not incompatible');
check(str_contains($converted_widget['archive']['widget-demo/references/skill2work-compatibility.md'], '/srv/widget'), 'report includes invocation paths');
check(str_contains($converted_widget['archive']['widget-demo/SKILL.md'], 'a found tool may be invoked'), 'skill guidance permits reviewed tool invocation');
check(Profile::commandEvidence($evidence_profile, 'absent')['status'] === 'not_found', 'negative evidence distinguishes not found');
check(Profile::commandEvidence(Profile::parse(null), 'absent')['status'] === 'unknown', 'no profile is unknown, not absent');
$evidence_data['functional_tests']['results'] = [
    ['command' => 'widget', 'target' => 'runtime', 'scope' => 'arithmetic only', 'executable' => '/opt/widget', 'status' => 'passed'],
];
$evidence = Profile::commandEvidence(Profile::parse(json_encode($evidence_data)), 'widget');
check($evidence['candidates'][0]['state'] === 'tested' && $evidence['candidates'][1]['state'] === 'found_untested', 'successful test applies only to exact path');
$evidence_data['functional_tests']['results'][0]['status'] = 'failed';
$evidence_data['functional_tests']['results'][0]['reason'] = 'nonzero_exit';
$evidence = Profile::commandEvidence(Profile::parse(json_encode($evidence_data)), 'widget');
check($evidence['candidates'][0]['state'] === 'test_failed' && $evidence['status'] === 'found_untested', 'failed candidate does not invalidate untested alternative');
$evidence_data['commands']['widget'] = ['available' => true, 'path' => '/opt/widget'];
$evidence = Profile::commandEvidence(Profile::parse(json_encode($evidence_data)), 'widget');
check($evidence['status'] === 'test_failed', 'failed PATH selection cannot be hidden by alternate candidates');
$evidence_data['functional_tests']['results'][0]['target'] = 'python:json';
$evidence_data['functional_tests']['results'][0]['status'] = 'passed';
check(Profile::commandEvidence(Profile::parse(json_encode($evidence_data)), 'widget')['status'] === 'found_untested', 'module import is not runtime baseline evidence');
$evidence_data['inventory']['executables_outside_path'][0]['invocation_path'] = [1];
fails(fn() => Profile::parse(json_encode($evidence_data)), 'reject invalid invocation path');


$evidence_data['inventory']['executables_outside_path'][0]['invocation_path'] = '/opt/widget';
$evidence_profile = Profile::parse(json_encode($evidence_data));
check(!isset($converted_widget['report']['commands']['sh']), 'fence language is not an inline program call');
$absolute = Analyzer::analyze(['SKILL.md' => "```sh\n/srv/widget --help\n```"], $evidence_profile);
check($absolute['commands']['/srv/widget']['status'] === 'found_untested', 'absolute command path matches discovered candidate');
check(!$absolute['commands']['/srv/widget']['selection_required'], 'explicit path does not require choosing another location');
check(Profile::commandEvidence($evidence_profile, '/unscanned/widget')['status'] === 'unknown', 'PATH coverage cannot prove absolute path absence');
$failed_data = $evidence_data;
$failed_data['inventory']['executables_outside_path'] = [];
$failed_data['functional_tests']['results'][0]['target'] = 'runtime';
$failed_data['functional_tests']['results'][0]['status'] = 'timeout';
$failed_profile = Profile::parse(json_encode($failed_data));
$failed_result = Converter::convert($widget, 'SKILL.md', $failed_profile);
check($failed_result['report']['commands']['widget']['status'] === 'test_failed', 'timeout is a failed test, not missing');
check($failed_result['report']['overall'] === 'unverified', 'failed baseline does not claim universal incompatibility');
$failed_data['functional_tests']['results'][0]['status'] = 'passed';
$passed_result = Converter::convert($widget, 'SKILL.md', Profile::parse(json_encode($failed_data)));
check($passed_result['report']['commands']['widget']['status'] === 'tested', 'exact baseline success displayed');
check(str_contains($passed_result['archive']['widget-demo/SKILL.md'], 'not all features or the entire skill'), 'baseline success is explicitly scoped');
$legacy = Profile::parse(json_encode(array_replace($v2_data, ['inventory' => ['executables_outside_path' => [['name' => 'widget', 'path' => '~/bin/widget']]]])));
check(Profile::commandEvidence($legacy, 'widget')['candidates'][0]['invocation_path'] === null, 'legacy redacted paths are not invented');


$alias_data = $v2_data;
$alias_data['commands']['python3']['path'] = '/usr/bin/python3';
$alias_data['coverage']['path_inventory_complete'] = true;
$alias_data['functional_tests']['results'] = [['command' => 'python3', 'target' => 'runtime', 'scope' => 'baseline', 'status' => 'failed', 'executable' => '/usr/bin/python3']];
$alias_result = Converter::convert(['SKILL.md' => "---\nname: alias-check\ndescription: demo\n---\nRun `python script.py`"], 'SKILL.md', Profile::parse(json_encode($alias_data)));
check(str_contains($alias_result['archive']['alias-check/SKILL.md'], '`python script.py`'), 'failed alias target is not used for automatic rewriting');

fwrite(STDOUT, "All $passed tests passed.\n");
