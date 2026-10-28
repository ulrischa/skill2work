<?php
declare(strict_types=1);

use Skill2Work\Archive;
use Skill2Work\Converter;
use Skill2Work\Profile;

require_once dirname(__DIR__) . '/src/Archive.php';
require_once dirname(__DIR__) . '/src/Profile.php';
require_once dirname(__DIR__) . '/src/Analyzer.php';
require_once dirname(__DIR__) . '/src/SkillReferences.php';
require_once dirname(__DIR__) . '/src/CodexCompatibility.php';
require_once dirname(__DIR__) . '/src/Converter.php';

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Content-Security-Policy: default-src \'none\'; style-src \'self\'; img-src \'self\'; form-action \'self\'; base-uri \'none\'; frame-ancestors \'none\'');
header('Cache-Control: no-store');
umask(0077);

$access_user = getenv('SKILL2WORK_HTTP_USER');
$access_password = getenv('SKILL2WORK_HTTP_PASSWORD');
if (is_string($access_user) && $access_user !== '' && is_string($access_password) && $access_password !== '') {
    $provided_user = $_SERVER['PHP_AUTH_USER'] ?? '';
    $provided_password = $_SERVER['PHP_AUTH_PW'] ?? '';
    if (!hash_equals($access_user, $provided_user) || !hash_equals($access_password, $provided_password)) {
        header('WWW-Authenticate: Basic realm="skill2work", charset="UTF-8"');
        http_response_code(401);
        exit('Authentication required.');
    }
} elseif (!in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1'], true)) {
    http_response_code(403);
    exit('For remote access, configure SKILL2WORK_HTTP_USER and SKILL2WORK_HTTP_PASSWORD (and HTTPS).');
}

session_name('skill2work_session');
session_set_cookie_params([
    'httponly' => true,
    'secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'samesite' => 'Lax',
    'path' => '/',
]);
session_start();
if (!isset($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(24));
}

function escape_html(string $text): string
{
    return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function clean_jobs(): void
{
    foreach (($_SESSION['jobs'] ?? []) as $id => $job) {
        if (!is_array($job) || (int) ($job['created'] ?? 0) < time() - 3600) {
            if (isset($job['path']) && is_string($job['path']) && str_starts_with(basename($job['path']), 'skill2work-')) {
                @unlink($job['path']);
            }
            unset($_SESSION['jobs'][$id]);
        }
    }
}
clean_jobs();

if (isset($_GET['download'])) {
    $id = (string) $_GET['download'];
    $job = $_SESSION['jobs'][$id] ?? null;
    if (!is_array($job) || !is_file($job['path'] ?? '')) {
        http_response_code(404);
        exit('Download expired or not found.');
    }
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . $job['filename'] . '"');
    header('Content-Length: ' . filesize($job['path']));
    readfile($job['path']);
    exit;
}
if (isset($_GET['probe'])) {
    $files = [];
    $probe_root = dirname(__DIR__) . '/probe-skill';
    foreach (['SKILL.md', 'agents/openai.yaml', 'scripts/probe.py', 'scripts/checks.py'] as $name) {
        $content = file_get_contents($probe_root . '/' . $name);
        if ($content === false) {
            http_response_code(500);
            exit('Probe file missing.');
        }
        $files['skill2work-runtime-probe/' . $name] = $content;
    }
    $path = sys_get_temp_dir() . '/skill2work-' . bin2hex(random_bytes(16)) . '.zip';
    try {
        Archive::write($path, $files);
        header('Content-Type: application/zip');
        header('Content-Disposition: attachment; filename="skill2work-runtime-probe.zip"');
        header('Content-Length: ' . filesize($path));
        readfile($path);
    } catch (Throwable $error) {
        http_response_code(500);
        echo 'Probe ZIP could not be created.';
    } finally {
        @unlink($path);
    }
    exit;
}

$error_message = null;
$results = [];
$profile_warnings = [];
$profile_summary = null;
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (!hash_equals($_SESSION['csrf'], (string) ($_POST['csrf'] ?? ''))) {
            throw new RuntimeException('Security check failed. Reload the page.');
        }
        if (empty($_FILES['skill']) || ($_FILES['skill']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK || !is_uploaded_file($_FILES['skill']['tmp_name'])) {
            throw new RuntimeException('Upload a valid ZIP. Check PHP upload limits.');
        }
        $path = $_FILES['skill']['tmp_name'];
        $head = file_get_contents($path, false, null, 0, 4);
        if (!in_array($head, ["PK\x03\x04", "PK\x05\x06", "PK\x07\x08"], true)) {
            throw new RuntimeException('Only ZIP archives are accepted.');
        }
        $profile_text = null;
        if (isset($_FILES['profile']) && ($_FILES['profile']['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE) {
            if ($_FILES['profile']['error'] !== UPLOAD_ERR_OK || !is_uploaded_file($_FILES['profile']['tmp_name']) || $_FILES['profile']['size'] > Profile::MAX_BYTES) {
                throw new RuntimeException('Invalid JSON profile file (maximum 64 MiB).');
            }
            $profile_text = file_get_contents($_FILES['profile']['tmp_name']);
            if ($profile_text === false) throw new RuntimeException('Profile is not readable.');
        }
        $profile = Profile::parse($profile_text);
        $profile_warnings = $profile['warnings'];
        if (($profile['schema_version'] ?? null) === Profile::VERSION) {
            $inventory = $profile['inventory'];
            $extensions = 0;
            foreach (($inventory['installed_extensions'] ?? []) as $group) {
                if (is_array($group)) {
                    $extensions += count($group);
                }
            }
            $profile_summary = [
                'Directories inspected' => (int) ($inventory['filesystem_scan']['directories_scanned'] ?? 0),
                'Programs in PATH' => count($profile['commands']),
                'Programs outside PATH' => count($inventory['executables_outside_path'] ?? []),
                'Candidate skill/plugin manifests' => array_sum(array_map('count', $inventory['filesystem_scan']['candidate_manifests'] ?? [])),
                'Python packages' => count($inventory['python_distributions'] ?? []),
                'System packages' => count($inventory['system_packages'] ?? []),
                'PHP extensions' => count($inventory['php_extensions'] ?? []),
                'Skills/editor extensions' => $extensions,
            ];
        }
        $files = Archive::read($path);
        $manifests = Converter::discover($files);
        foreach ($manifests as $manifest) {
            try {
                $converted = Converter::convert($files, $manifest, $profile);
                $id = bin2hex(random_bytes(16));
                $target = sys_get_temp_dir() . '/skill2work-' . $id . '.zip';
                Archive::write($target, $converted['archive']);
                $filename = $converted['report']['skill'] . '-work.zip';
                $_SESSION['jobs'][$id] = ['path' => $target, 'filename' => $filename, 'created' => time()];
                $results[] = ['id' => $id, 'report' => $converted['report'], 'filename' => $filename];
            } catch (Throwable $error) {
                $results[] = ['error' => $error->getMessage(), 'manifest' => $manifest];
            }
        }
    } catch (Throwable $error) {
        $error_message = $error->getMessage();
    }
}

$labels = [
    'observed' => 'Found in profile – functionality not guaranteed',
    'instructions-only' => 'No program execution detected',
    'unverified' => 'Not fully verified',
    'incompatible' => 'Dependency missing from profile',
    'review' => 'Security review required',
    'available' => 'Found',
    'missing' => 'Missing',
    'unknown' => 'Unknown',
];
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light">
    <title>skill2work · Inspect and migrate skills</title>
    <link rel="stylesheet" href="assets/app.css">
</head>
<body>
<div class="app-shell">
    <header class="topbar">
        <a href="./" class="brand"><span class="brand-icon">s<span class="arrow">→</span>w</span><span>skill2work</span></a>
        <span class="badge">PHP · Local · No uploaded code execution</span>
    </header>
    <main>
        <section class="intro">
            <div class="eyebrow">SKILL COMPATIBILITY WORKBENCH</div>
            <h1>Prepare Codex skills for <em>Work</em>.</h1>
            <p>Import a ZIP, inspect commands and dependencies, apply supported changes and create a ZIP for each skill. Uploaded code is never executed.</p>
        </section>
        <section class="work-grid">
            <article class="panel main-panel">
                <div class="panel-head"><span class="step">01</span><div><h2>Inspect and convert a skill</h2><p>A single skill or a repository ZIP containing multiple skills.</p></div></div>
                <form action="" method="post" enctype="multipart/form-data">
                    <input type="hidden" name="csrf" value="<?= escape_html($_SESSION['csrf']) ?>">
                    <label for="skill" class="field-label">Codex skill or repository <strong>ZIP</strong></label>
                    <input id="skill" type="file" name="skill" accept=".zip,application/zip" required>
                    <div class="divider"></div>
                    <label for="profile" class="field-label">Work runtime profile <span class="optional">optional · JSON</span></label>
                    <input id="profile" type="file" name="profile" accept=".json,application/json">
                    <p class="field-help">Without a profile, program availability remains unknown. A profile records observations from your Work session.</p>
                    <button class="button-primary" type="submit">Analyze &amp; create ZIP <span aria-hidden="true">→</span></button>
                </form>
            </article>
            <aside class="panel side-panel">
                <div class="panel-head"><span class="step secondary">02</span><div><h2>Inspect the Work runtime</h2><p>Measure the actual environment.</p></div></div>
                <p>The probe inventories PATH programs, other installation locations such as /opt and /srv, Python and system packages, PHP extensions and discoverable skills. It generates <code>skill2work-runtime.json</code>.</p>
                <a class="button-secondary" href="?probe=1">Download runtime probe <span aria-hidden="true">↓</span></a>
                <div class="notice">The skill defaults to a bounded recursive scan from / and reviewed runtime smoke tests. Optional prompt settings control scan and test budgets. It records package, extension and environment variable names, with selected sanitized path values. Inspect the JSON before sharing. Run it <strong>inside Work</strong>; a local computer profile does not describe Work. Skill import availability depends on your account.</div>
            </aside>
        </section>
        <?php if ($error_message !== null): ?>
            <div class="alert alert-error" role="alert"><strong>Analysis stopped:</strong> <?= escape_html($error_message) ?></div>
        <?php endif; ?>
        <?php if ($results): ?>
            <section class="results" aria-live="polite">
                <?php if ($profile_summary !== null): ?>
                    <article class="panel result-card">
                        <h3>Runtime inventory detected</h3>
                        <div class="metrics">
                            <?php foreach ($profile_summary as $label => $value): ?>
                            <div><strong><?= (int) $value ?></strong><span><?= escape_html($label) ?></span></div>
                            <?php endforeach; ?>
                        </div>
                        <p class="muted">The inventory describes the environment inspected by the probe. It cannot fully enumerate Work agent tools or cloud plugins.</p>
                        <?php if ($profile_warnings): ?><details><summary>Runtime profile notes</summary><ul><?php foreach ($profile_warnings as $warning): ?><li><?= escape_html($warning) ?></li><?php endforeach; ?></ul></details><?php endif; ?>
                    </article>
                <?php endif; ?>
                <div class="section-title"><div><span class="eyebrow">RESULT</span><h2><?= count($results) ?> <?= count($results) === 1 ? 'Skill' : 'Skills' ?> inspected</h2></div><span class="badge">Downloads available for 1 hour</span></div>
                <?php foreach ($results as $result): ?>
                    <?php if (isset($result['error'])): ?>
                        <div class="alert alert-error"><strong><?= escape_html($result['manifest']) ?>:</strong> <?= escape_html($result['error']) ?></div>
                    <?php continue; endif; ?>
                    <?php $report = $result['report']; ?>
                    <article class="panel result-card">
                        <div class="result-head"><div><span class="eyebrow">SKILL</span><h3><?= escape_html($report['skill']) ?></h3><p class="muted"><?= escape_html($report['source']) ?></p></div><a class="button-primary button-download" href="?download=<?= escape_html($result['id']) ?>">Download ZIP ↓</a></div>
                        <p class="status status-<?= escape_html($report['overall']) ?>"><?= escape_html($labels[$report['overall']] ?? $report['overall']) ?></p>
                        <div class="metrics"><div><strong><?= count($report['commands']) ?></strong><span>Programs</span></div><div><strong><?= count($report['modules']) ?></strong><span>Python modules</span></div><div><strong><?= count($report['rewrites']) ?></strong><span>Changes</span></div><div><strong><?= count($report['security']) ?></strong><span>Security findings</span></div></div>
                        <?php if ($report['commands']): ?>
                            <h4>Program calls</h4>
                            <div class="table-scroll"><table><thead><tr><th>Program</th><th>Evidence</th><th>Detected in</th></tr></thead><tbody>
                            <?php foreach ($report['commands'] as $command => $detail): ?><tr><td><code><?= escape_html($command) ?></code></td><td><span class="mini mini-<?= escape_html($detail['status']) ?>"><?= escape_html($labels[$detail['status']] ?? $detail['status']) ?></span></td><td><?= escape_html(implode(', ', $detail['sources'])) ?></td></tr><?php endforeach; ?>
                            </tbody></table></div>
                        <?php endif; ?>
                        <?php if ($report['modules']): ?>
                            <details><summary>Python modules (<?= count($report['modules']) ?>)</summary><div class="table-scroll"><table><thead><tr><th>Module</th><th>Evidence</th><th>Detected in</th></tr></thead><tbody>
                            <?php foreach ($report['modules'] as $module => $detail): ?><tr><td><code><?= escape_html($module) ?></code></td><td><span class="mini mini-<?= escape_html($detail['status']) ?>"><?= escape_html($labels[$detail['status']] ?? $detail['status']) ?></span></td><td><?= escape_html(implode(', ', $detail['sources'])) ?></td></tr><?php endforeach; ?>
                            </tbody></table></div></details>
                        <?php endif; ?>
                        <?php if (!empty($report['codex_work_mappings'])): ?>
                            <details class="findings"><summary>Codex → Work: Task alternatives (<?= count($report['codex_work_mappings']) ?>)</summary>
                                <div class="table-scroll"><table><thead><tr><th>Location</th><th>Codex invocation</th><th>Work alternative</th><th>Limitation</th></tr></thead><tbody>
                                <?php foreach ($report['codex_work_mappings'] as $entry): ?>
                                    <tr><td><?= escape_html($entry['file']) ?></td><td><code><?= escape_html($entry['kind']) ?></code></td><td><?= escape_html($entry['equivalent']) ?></td><td><?= escape_html($entry['limitation']) ?></td></tr>
                                <?php endforeach; ?>
                                </tbody></table></div>
                            </details>
                        <?php endif; ?>
                        <?php foreach (['rewrites'=>'Automatic changes','skill_dependencies'=>'External skill dependencies','security'=>'Security findings','warnings'=>'Limitations','metadata_notes'=>'Metadata'] as $key => $title): ?>
                            <?php if (!empty($report[$key])): ?><div class="findings"><strong><?= escape_html($title) ?></strong><ul><?php foreach ($report[$key] as $item): ?><li><?= escape_html($item) ?></li><?php endforeach; ?></ul></div><?php endif; ?>
                        <?php endforeach; ?>
                        <?php if (!empty($report['functional_evidence'])): ?>
                        <details class="findings"><summary>Runtime functional tests</summary><ul>
                        <?php foreach ($report['functional_evidence'] as $evidence): ?><li><?= htmlspecialchars($evidence, ENT_QUOTES, 'UTF-8') ?></li><?php endforeach; ?>
                        </ul></details>
                        <?php endif; ?>
                        <p class="result-note">The detailed report is in <code>references/skill2work-compatibility.md</code>; for Codex agent invocations, Work task alternatives are also documented in <code>references/skill2work-work-actions.md</code>.</p>
                    </article>
                <?php endforeach; ?>
            </section>
        <?php endif; ?>
        <section class="footnotes">
            <div><strong>What changes automatically</strong><p>Unambiguous simple codex exec instructions in Markdown prose, human-facing skill references ($name → @name), /skills selection and profile-supported command aliases in <code>SKILL.md</code>, for example <code>python</code> to <code>python3</code>. Scripts and dependencies are not silently changed or installed.</p></div>
            <div><strong>What cannot be guaranteed</strong><p>Work environments can change. A program inventory alone does not establish version compatibility, permissions, network access or skill import eligibility.</p></div>
        </section>
    </main>
    <footer>skill2work · Static analysis · No network requests · No uploaded scripts executed</footer>
</div>
</body>
</html>
