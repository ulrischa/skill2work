<?php
declare(strict_types=1);

namespace Skill2Work;

use RuntimeException;

final class Converter
{
    /** @param array<string,string> $files @return list<string> */
    public static function discover(array $files): array
    {
        $paths = [];
        foreach ($files as $name => $_) {
            if (strcasecmp(basename($name), 'SKILL.md') === 0) {
                $paths[] = $name;
            }
        }
        sort($paths);
        if (count($paths) > 24) {
            throw new RuntimeException('More than 24 skills in ZIP. Split the archive.');
        }
        if ($paths === []) {
            throw new RuntimeException('No SKILL.md found. Upload a Codex skill or skill repository.');
        }
        return $paths;
    }

    /** @param array<string,string> $files @param array<string,mixed> $profile @return array{archive:array<string,string>,report:array<string,mixed>} */
    public static function convert(array $files, string $manifestPath, array $profile): array
    {
        if (!isset($files[$manifestPath])) {
            throw new RuntimeException('SKILL.md is missing.');
        }
        $base = dirname($manifestPath) === '.' ? '' : dirname($manifestPath) . '/';
        $source = [];
        foreach ($files as $path => $content) {
            if ($base === '' || str_starts_with($path, $base)) {
                $relative = substr($path, strlen($base));
                if ($relative !== '') {
                    $source[$relative] = $content;
                }
            }
        }
        if (count($source) > 498) {
            throw new RuntimeException('This skill contains more than 498 files (output limit: 500).');
        }
        $manifestName = substr($manifestPath, strlen($base));
        if ($manifestName !== 'SKILL.md') {
            $source['SKILL.md'] = $source[$manifestName];
            unset($source[$manifestName]);
        }
        $raw = $source['SKILL.md'];
        if (str_contains($raw, "\0") || strlen($raw) > 750_000 || !preg_match('//u', $raw)) {
            throw new RuntimeException('SKILL.md must be UTF-8 text under 750 KB.');
        }
        $fallback = $base !== '' ? basename(rtrim($base, '/')) : 'imported-skill';
        [$name, $description, $updated, $metadataNotes] = self::normalizeFrontmatter($raw, $fallback);
        if (isset($source['references/skill2work-work-actions.md'])) {
            throw new RuntimeException('references/skill2work-work-actions.md already exists. Rename it first.');
        }
        if (isset($source['references/skill2work-compatibility.md'])) {
            throw new RuntimeException('references/skill2work-compatibility.md already exists. Rename it first.');
        }
        $migration = SkillReferences::migrate($updated, $source, $files);
        $updated = $migration['markdown'];
        foreach ($source as $path => $content) {
            if ($path === 'SKILL.md' || !preg_match('/\.md$/i', $path) || str_contains($content, "\0")
                || strlen($content) > 750_000 || !preg_match('//u', $content)) {
                continue;
            }
            $document = SkillReferences::migrate($content, [], []);
            $source[$path] = $document['markdown'];
            foreach ($document['rewrites'] as $change) {
                $migration['rewrites'][] = $path . ': ' . $change;
            }
            foreach ($document['warnings'] as $warning) {
                $migration['warnings'][] = $path . ': ' . $warning;
            }
            $migration['dependencies'] = array_merge($migration['dependencies'], $document['dependencies']);
        }
        $migration['dependencies'] = array_values(array_unique($migration['dependencies']));
        $migration['warnings'] = array_values(array_unique($migration['warnings']));
        $codexChanges = [];
        $updated = CodexCompatibility::migrate($updated, 'SKILL.md', $codexChanges);
        foreach ($source as $path => $content) {
            if ($path !== 'SKILL.md') $source[$path] = CodexCompatibility::migrate($content, $path, $codexChanges);
        }
        $migration['rewrites'] = array_merge($migration['rewrites'], $codexChanges);
        $originalAnalysis = Analyzer::analyze($source, $profile);
        $rewrites = $migration['rewrites'];
        $updated = self::rewriteMarkdownCommands($updated, $profile, $rewrites);
        $source['SKILL.md'] = $updated;
        $analysis = Analyzer::analyze($source, $profile);
        $analysis['warnings'] = array_values(array_unique(array_merge($analysis['warnings'], $migration['warnings'])));
        $analysis['skill_dependencies'] = $migration['dependencies'];
        if ($migration['warnings'] !== [] && in_array($analysis['overall'], ['observed', 'instructions-only'], true)) {
            $analysis['overall'] = 'unverified';
        }
        $codexMapping = CodexCompatibility::analyze($source);
        $analysis['codex_work_mappings'] = $codexMapping['matches'];
        $analysis['warnings'] = array_values(array_unique(array_merge($analysis['warnings'], $codexMapping['warnings'])));
        if ($codexMapping['matches'] !== [] && in_array($analysis['overall'], ['observed', 'instructions-only'], true)) {
            $analysis['overall'] = 'unverified';
        }
        $analysis['functional_evidence'] = [];
        foreach (($profile['functional_tests']['results'] ?? []) as $test) {
            if (!is_array($test)) continue;
            $analysis['functional_evidence'][] = ($test['command'] ?? '?') . ' / ' . ($test['target'] ?? '?') .
                ': ' . ($test['status'] ?? 'unknown') . ' (' . ($test['scope'] ?? 'unknown scope') . ')';
        }
        if (!$analysis['functional_evidence']) $analysis['functional_evidence'][] = 'No functional tests in the profile.';
        foreach (($profile['functional_tests']['results'] ?? []) as $test) {
            if (!is_array($test)) continue;
            $relevant = isset($analysis['commands'][$test['command'] ?? '']) ||
                isset($analysis['modules'][str_replace('python:', '', $test['target'] ?? '')]);
            if ($relevant && ($test['status'] ?? 'unknown') !== 'passed') {
                $analysis['warnings'][] = 'Required runtime/library not confirmed by a functional test: ' .
                    ($test['command'] ?? '?') . '/' . ($test['target'] ?? '?') . ': ' . ($test['status'] ?? 'unknown');
                if (in_array($analysis['overall'], ['observed', 'instructions-only'], true)) $analysis['overall'] = 'unverified';
            }
        }
        $analysis['metadata_notes'] = $metadataNotes;
        $analysis['rewrites'] = $rewrites;
        if (($originalAnalysis['overall'] ?? '') === 'incompatible' && ($analysis['overall'] ?? '') !== 'incompatible') {
            $analysis['warnings'][] = 'Alias rewriting does not automatically resolve all runtime dependencies.';
        }
        $analysis['skill'] = $name;
        $analysis['source'] = $manifestPath;
        $analysis['profile_source'] = $profile['source'] ?? 'unverified';
        $analysis['profile_timestamp'] = $profile['timestamp'] ?? null;
        $analysis['profile_warnings'] = $profile['warnings'] ?? [];
        $analysis['profile_inventory'] = self::profileInventorySummary($profile);
        if (($profile['schema_version'] ?? 0) === Profile::VERSION) {
            $outside = $profile['inventory']['executables_outside_path'] ?? [];
            $outsideByName = [];
            foreach ($outside as $entry) {
                if (is_array($entry) && isset($entry['name'], $entry['path'])) {
                    $outsideByName[strtolower((string) $entry['name'])][] = (string) $entry['path'];
                }
            }
            foreach ($analysis['commands'] as $command => $detail) {
                if ($detail['status'] === 'missing' && isset($outsideByName[strtolower($command)])) {
                    $analysis['warnings'][] = $command . ': found as a file outside PATH (' .
                        implode(', ', array_slice($outsideByName[strtolower($command)], 0, 3)) .
                        '). Not rewritten automatically: execution and dependencies are unverified.';
                }
            }
        }
        foreach (($profile['warnings'] ?? []) as $warning) {
            if (str_contains($warning, 'older than 30 days') && $analysis['overall'] === 'observed') {
                $analysis['overall'] = 'unverified';
            }
        }
        $analysis['assurance'] = 'Static analysis and optionally a user-supplied snapshot. No source scripts were executed. No ChatGPT Work import was performed.';

        $guidance = "\n\n## Runtime compatibility (skill2work)\n\n" .
            "Treat `@name` as a ChatGPT composer selector, NOT as a shell command, programmatic API, or guarantee another skill is installed. " .
            "If another skill is required, ask the user to install/select it explicitly or follow the documented alternative; never pretend a skill-to-skill call succeeded. " .
            "Before executing bundled programs, read `references/skill2work-compatibility.md`. " .
            "Only invoke commands when the current environment exposes the required executable and dependencies. " .
            "A previous runtime probe is a snapshot, not a guarantee. " .
            "If a requirement is missing or unverified, tell the user what is unavailable and do not fabricate results. " .
            "Do not auto-install dependencies, run privileged commands, or send local files to external services without explicit user approval.\n";
        $source['SKILL.md'] .= $guidance;
        if ($codexMapping['matches'] !== []) {
            $source['SKILL.md'] .= "\nReview `references/skill2work-work-actions.md` for task-level Work alternatives to Codex agent invocations. " .
                "Do not execute a Codex CLI example as though Work had an equivalent CLI.\n";
            $source['references/skill2work-work-actions.md'] = CodexCompatibility::report($codexMapping);
        }
        $source['references/skill2work-compatibility.md'] = self::renderReport($analysis);
        $package = [];
        foreach ($source as $path => $content) {
            $package[$name . '/' . $path] = $content;
        }
        ksort($package);
        return ['archive' => $package, 'report' => $analysis];
    }

    /** @param array<string,mixed> $profile @return list<string> */
    private static function profileInventorySummary(array $profile): array
    {
        if (($profile['schema_version'] ?? 0) !== Profile::VERSION) {
            return ['No schema 2 inventory available.'];
        }
        $inventory = $profile['inventory'] ?? [];
        $extensions = $inventory['installed_extensions'] ?? [];
        $extensionTotal = 0;
        foreach ($extensions as $entries) {
            if (is_array($entries)) {
                $extensionTotal += count($entries);
            }
        }
        return [
            'Filesystem mode: ' . ($inventory['filesystem_scan']['mode'] ?? 'not recorded'),
            'Filesystem directories inspected: ' . ($inventory['filesystem_scan']['directories_scanned'] ?? 'unknown'),
            'Filesystem scan: mount-aware metadata, bounded; virtual kernel trees use whitelisted kernel APIs; no executable content read.',
            'Filesystem complete within permitted scope: ' . (($inventory['filesystem_scan']['complete'] ?? false) ? 'yes' : 'no'),
            'Regular mounts crossed: ' . (($inventory['filesystem_scan']['cross_device_mounts'] ?? false) ? 'yes' : 'no'),
            'Executable names in PATH: ' . count($profile['commands'] ?? []),
            'Off-PATH executable files: ' . count($inventory['executables_outside_path'] ?? []),
            'Candidate skill/plugin manifests: ' . array_sum(array_map('count', $inventory['filesystem_scan']['candidate_manifests'] ?? [])),
            'Python modules with import spec: ' . count($profile['python_modules'] ?? []),
            'Python distributions: ' . count($inventory['python_distributions'] ?? []),
            'System packages: ' . count($inventory['system_packages'] ?? []),
            'PHP extensions: ' . count($inventory['php_extensions'] ?? []),
            'Recognized installed extensions/skills: ' . $extensionTotal,
            'Complete PATH scan: ' . (($profile['coverage']['path_inventory_complete'] ?? false) ? 'yes' : 'no'),
            'ChatGPT/Work tools fully inventoried: NO (not discoverable from Python)',
        ];
    }

    /** @return array{string,string,string,list<string>} */
    private static function normalizeFrontmatter(string $raw, string $fallback): array
    {
        $notes = [];
        if (preg_match('/\A---\h*\R(.*?)\R---\h*(?:\R|\z)/s', $raw, $match)) {
            $front = $match[1];
            $body = substr($raw, strlen($match[0]));
            foreach (['name', 'description'] as $field) {
                $count = preg_match_all('/^' . $field . '\h*:/mi', $front);
                if ($count > 1) {
                    throw new RuntimeException('Duplicate YAML frontmatter field: ' . $field);
                }
                if (preg_match('/^' . $field . '\h*:\h*[|>][+-]?\h*$/mi', $front)) {
                    throw new RuntimeException('Multiline YAML field ' . $field . ' must be simplified before conversion.');
                }
            }
        } else {
            if (str_starts_with($raw, '---')) {
                throw new RuntimeException('Incomplete YAML frontmatter in SKILL.md.');
            }
            $front = '';
            $body = $raw;
            $notes[] = 'Added missing YAML frontmatter.';
        }
        $name = self::yamlScalar($front, 'name');
        if ($name === null || trim($name) === '') {
            $name = $fallback;
            $notes[] = 'Derived skill name from its directory.';
        }
        $clean = self::slug($name);
        if ($clean !== $name) {
            $notes[] = 'Normalized skill name to a valid slug: ' . $clean;
        }
        $description = self::yamlScalar($front, 'description');
        if ($description === null || $description === '') {
            $description = 'Follow the procedures and resources of the ' . $clean . ' skill.';
            $notes[] = 'Added missing description; review the wording before import.';
        }
        // Preserve unrelated frontmatter, but replace standard scalar fields only.
        $front = preg_replace('/^(?:name|description)\h*:\h*[^\r\n]*(?:\r?\n|$)/mi', '', $front) ?? $front;
        $front = trim($front);
        $newFront = '---' . "\n" . 'name: ' . $clean . "\n" .
            'description: ' . self::quoteYaml($description) . "\n" .
            ($front !== '' ? $front . "\n" : '') . '---' . "\n\n";
        return [$clean, $description, $newFront . ltrim($body, "\r\n"), $notes];
    }

    private static function yamlScalar(string $front, string $key): ?string
    {
        if (!preg_match('/^' . preg_quote($key, '/') . '\h*:\h*(.*?)\h*$/mi', $front, $match)) {
            return null;
        }
        $value = trim($match[1]);
        if (preg_match('/^"((?:[^"\\\\]|\\\\.)*)"$/s', $value, $quoted)) {
            return stripcslashes($quoted[1]);
        }
        if (preg_match("/^'((?:[^']|'')*)'$/s", $value, $quoted)) {
            return str_replace("''", "'", $quoted[1]);
        }
        return $value;
    }

    private static function quoteYaml(string $value): string
    {
        return json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
    }

    private static function slug(string $input): string
    {
        $value = strtolower(trim($input));
        $value = preg_replace('/[^a-z0-9]+/', '-', $value) ?? '';
        $value = substr(trim($value, '-'), 0, 62);
        return $value !== '' ? $value : 'imported-skill';
    }

    /** @param array<string,mixed> $profile @param list<string> $rewrites */
    private static function rewriteMarkdownCommands(string $text, array $profile, array &$rewrites): string
    {
        $map = [];
        if (Profile::status($profile, 'python') === 'missing' && Profile::status($profile, 'python3') === 'available') {
            $map['python'] = 'python3';
        }
        if (Profile::status($profile, 'nodejs') === 'missing' && Profile::status($profile, 'node') === 'available') {
            $map['nodejs'] = 'node';
        }
        if ($map === []) {
            return $text;
        }
        foreach ($map as $old => $new) {
            $count = 0;
            // Only standalone command tokens inside shell fences and inline commands.
            $text = preg_replace_callback('/(```(?:bash|sh|shell|console|zsh)\h*\R)(.*?)(```)/si', static function ($match) use ($old, $new, &$count) {
                $updated = preg_replace('/(?<![\w\/.-])' . preg_quote($old, '/') . '(?=\s+[-\w.\/])/i', $new, $match[2], -1, $hits);
                $count += $hits;
                return $match[1] . $updated . $match[3];
            }, $text) ?? $text;
            $text = preg_replace_callback('/`([^`\r\n]+)`/', static function ($match) use ($old, $new, &$count) {
                $updated = preg_replace('/^' . preg_quote($old, '/') . '(?=\s+[-\w.\/])/i', $new, $match[1], 1, $hits);
                $count += $hits;
                return '`' . $updated . '`';
            }, $text) ?? $text;
            if ($count > 0) {
                $rewrites[] = $old . ' → ' . $new . ' (' . $count . ' occurrences, SKILL.md only)';
            }
        }
        return $text;
    }

    /** @param array<string,mixed> $report */
    private static function renderReport(array $report): string
    {
        $lines = [
            '# Skill2Work compatibility report', '',
            'Skill: `' . $report['skill'] . '`',
            'Source: `' . $report['source'] . '`',
            'Assessment: **' . $report['overall'] . '**',
            'Profile source: `' . $report['profile_source'] . '`',
            'Profile date: ' . ($report['profile_timestamp'] ?: 'not provided'), '',
            '> This assessment is not proof of ChatGPT Work support, package acceptance, successful execution, or entitlement to install Skills.',
            '> Scripts were not executed by skill2work. The profile is user-supplied and may be stale.', '',
            '## Executables', '',
            '| Program | Snapshot | Source |', '| --- | --- | --- |',
        ];
        foreach ($report['commands'] as $command => $detail) {
            $lines[] = '| `' . $command . '` | ' . $detail['status'] . ' | ' . self::cell(implode(', ', $detail['sources'])) . ' |';
        }
        if (!$report['commands']) $lines[] = '| — | no detected commands | — |';
        $lines = array_merge($lines, ['', '## Python imports', '', '| Module | Snapshot | Source |', '| --- | --- | --- |']);
        foreach ($report['modules'] as $module => $detail) {
            $lines[] = '| `' . $module . '` | ' . $detail['status'] . ' | ' . self::cell(implode(', ', $detail['sources'])) . ' |';
        }
        if (!$report['modules']) $lines[] = '| — | no detected imports | — |';
        foreach (['functional_evidence' => 'Functional test evidence (limited to each tested operation)', 'skill_dependencies' => 'Referenced external skills (installation not verified)', 'profile_inventory' => 'Runtime inventory coverage', 'packages' => 'Declared dependencies', 'rewrites' => 'Applied command rewrites', 'metadata_notes' => 'Metadata normalization', 'warnings' => 'Limitations', 'security' => 'Security review', 'profile_warnings' => 'Runtime profile caveats'] as $key => $heading) {
            $lines[] = '';
            $lines[] = '## ' . $heading;
            $lines[] = '';
            foreach (($report[$key] ?? []) as $item) {
                $lines[] = '- ' . str_replace(["\r", "\n"], ' ', (string) $item);
            }
            if (($report[$key] ?? []) === []) $lines[] = '- None detected.';
        }
        $lines[] = '';
        $lines[] = '## Operational rules';
        $lines[] = '';
        $lines[] = '- Never assume `available` guarantees correct versions, package health, filesystem permissions, network access, or successful execution.';
        $lines[] = '- With v2 and complete PATH coverage, `missing` means not invocable by bare command name via that PATH; it is not a permanent platform restriction.';
        $lines[] = '- `unknown` means no evidence. Test in the actual Work session before use.';
        $lines[] = '- Python imports from requirements may need manual package-name-to-module mapping.';
        $lines[] = '- Review all scripts from untrusted origins before execution.';
        return implode("\n", $lines) . "\n";
    }

    private static function cell(string $value): string
    {
        return str_replace(['|', "\n", "\r"], ['\\|', ' ', ' '], $value);
    }
}
