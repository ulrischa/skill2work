<?php
declare(strict_types=1);

namespace Skill2Work;

use RuntimeException;

final class Profile
{
    public const VERSION = 2;
    public const MAX_BYTES = 64 * 1024 * 1024;

    /** @return array<string,mixed> */
    public static function parse(?string $json): array
    {
        if ($json === null || trim($json) === '') {
            return [
                'source' => 'unverified',
                'commands' => [], 'python_modules' => [], 'features' => [],
                'warnings' => ['No runtime profile: Work capabilities are unverified.'],
            ];
        }
        if (strlen($json) > self::MAX_BYTES) {
            throw new RuntimeException('Runtime profile is too large (maximum 64 MiB).');
        }
        $profile = json_decode($json, true, 32, JSON_THROW_ON_ERROR);
        $version = is_array($profile) ? ($profile['schema_version'] ?? null) : null;
        if (!is_array($profile) || !in_array($version, [1, self::VERSION], true)
            || ($profile['source'] ?? null) !== 'skill2work-probe') {
            throw new RuntimeException('Unknown runtime profile. Expected a skill2work profile (schema 1 or 2).');
        }
        $limits = ['commands' => 12000, 'python_modules' => 16000, 'features' => 100];
        foreach ($limits as $field => $limit) {
            if (!isset($profile[$field]) || !is_array($profile[$field]) || count($profile[$field]) > $limit) {
                throw new RuntimeException('Invalid or oversized profile field: ' . $field);
            }
            foreach ($profile[$field] as $name => $value) {
                if (!is_string($name) || strlen($name) > 160 || !preg_match('/^[a-zA-Z0-9_@.+-]+$/', $name)) {
                    throw new RuntimeException('Invalid profile name in ' . $field);
                }
                if ($field === 'features') {
                    if (!is_bool($value)) {
                        throw new RuntimeException('Invalid feature value.');
                    }
                } elseif (!is_array($value) || !array_key_exists('available', $value) || !is_bool($value['available'])) {
                    throw new RuntimeException('Invalid profile value for ' . $name);
                }
            }
        }
        if ($version === self::VERSION) {
            if (!isset($profile['inventory'], $profile['coverage'])
                || !is_array($profile['inventory']) || !is_array($profile['coverage'])) {
                throw new RuntimeException('Schema 2 profiles require inventory and coverage data.');
            }
            foreach (['path_inventory_complete', 'python_module_metadata_complete', 'agent_tools_complete'] as $flag) {
                if (!isset($profile['coverage'][$flag]) || !is_bool($profile['coverage'][$flag])) {
                    throw new RuntimeException('Missing or invalid coverage flag: ' . $flag);
                }
            }
            if (isset($profile['inventory']['installed_extensions']) && !is_array($profile['inventory']['installed_extensions'])) {
                throw new RuntimeException('Invalid extension list.');
            }
        }
        if (isset($profile['functional_tests'])) {
            $tests = $profile['functional_tests']['results'] ?? null;
            if (!is_array($tests) || count($tests) > 10000) throw new RuntimeException('Invalid functional tests.');
            foreach ($tests as $test) {
                if (!is_array($test)) throw new RuntimeException('Invalid functional test.');
                foreach (['command', 'target', 'status', 'scope'] as $key) {
                    if (!isset($test[$key]) || !is_string($test[$key]) || strlen($test[$key]) > 500)
                        throw new RuntimeException('Invalid functional test field: ' . $key);
                }
                if (!in_array($test['status'], ['passed', 'failed', 'timeout', 'start_failed', 'not_tested', 'unknown'], true))
                    throw new RuntimeException('Unknown test status.');
            }
        }
        $warnings = [];
        if (($profile['partial'] ?? false) === true) $warnings[] = 'Incomplete partial profile: resume the probe.';
        foreach (($profile['functional_tests']['results'] ?? []) as $test) {
            if ($test['status'] !== 'passed') $warnings[] = 'Functional test ' . $test['command'] . '/' . $test['target'] . ': ' . $test['status'];
        }
        if (!isset($profile['timestamp']) || !is_string($profile['timestamp'])) {
            $warnings[] = 'Profile has no valid timestamp.';
        } else {
            $age = strtotime($profile['timestamp']);
            if ($age === false || $age > time() + 3600 || $age < time() - 30 * 86400) {
                $warnings[] = 'Runtime profile is older than 30 days or its timestamp is implausible.';
            }
        }
        if ($version === 1) {
            $warnings[] = 'Legacy fixed-list probe: run the current probe for a systematic inventory.';
        } else {
            if (($profile['coverage']['path_inventory_complete'] ?? false) !== true) {
                $warnings[] = 'PATH inventory is incomplete: unlisted programs remain unknown.';
            }
            if (isset($profile['inventory']['filesystem_scan']) && is_array($profile['inventory']['filesystem_scan'])) {
                $mode = (string) ($profile['inventory']['filesystem_scan']['mode'] ?? 'unknown');
                $scanned = (int) ($profile['inventory']['filesystem_scan']['directories_scanned'] ?? 0);
                $warnings[] = 'Recursive filesystem scan: ' . $mode . ' (' . $scanned . ' directories); review virtual kernel mounts, limits and permission failures in the profile.';
                if (($profile['inventory']['filesystem_scan']['truncated'] ?? false) === true) {
                    $warnings[] = 'Filesystem scan stopped at its limits; absent program names remain inconclusive.';
                }
            }
            $warnings[] = 'Python filesystem inspection cannot fully discover Work plugins and agent tools.';
        }
        $warnings[] = 'The profile is a user-supplied snapshot, not a guarantee of execution or import permissions.';
        $profile['warnings'] = $warnings;
        $profile['_command_candidates'] = self::indexCandidates($profile);
        return $profile;
    }

    /** Build a per-name index once; never confuse PATH absence with tool absence. */
    private static function indexCandidates(array $profile): array
    {
        $index = [];
        $tests = [];
        foreach (($profile['functional_tests']['results'] ?? []) as $test) {
            if (($test['target'] ?? '') === 'runtime' && is_string($test['executable'] ?? null)) {
                $tests[$test['executable']][] = $test;
            }
        }
        $add = static function (string $name, array $entry, bool $inPath) use (&$index, $tests): void {
            $display = $entry['path'] ?? null;
            $path = $entry['invocation_path'] ?? null;
            // Old profiles redact paths. Never invent an executable path from a placeholder.
            if ($path === null && is_string($display) && str_starts_with($display, '/')
                && !str_contains($display, '<')) $path = $display;
            foreach (['path' => $display, 'invocation_path' => $path, 'resolved_path' => $entry['resolved_path'] ?? null] as $key => $value) {
                if ($value !== null && (!is_string($value) || strlen($value) > 4096 || preg_match('/[\x00-\x1f]/', $value))) {
                    throw new RuntimeException('Invalid executable path field: ' . $key);
                }
            }
            if ($path !== null && !str_starts_with($path, '/')) $path = null;
            $matched = $tests[$entry['resolved_path'] ?? $path ?? ''] ?? [];
            $failures = array_values(array_filter($matched, static fn($t) => in_array($t['status'], ['failed', 'start_failed', 'timeout'], true)));
            $passed = array_filter($matched, static fn($t) => $t['status'] === 'passed');
            $state = $failures ? 'test_failed' : ($passed ? 'tested' : 'found_untested');
            $reason = $failures ? ($failures[0]['reason'] ?? $failures[0]['status']) :
                ($passed ? 'only_recorded_operation_passed' : ($matched[0]['reason'] ?? 'no_reviewed_test_for_this_path'));
            if (!is_string($reason)) $reason = 'invalid_test_reason';
            $index[strtolower($name)][] = ['path' => $display, 'invocation_path' => $path,
                'resolved_path' => $entry['resolved_path'] ?? $path,
                'in_path' => $inPath, 'invocable_by_name' => $inPath && ($entry['invocable_by_name'] ?? true),
                'state' => $state, 'reason' => $reason, 'tests' => $matched];
        };
        foreach (($profile['commands'] ?? []) as $name => $entry) {
            if (!($entry['available'] ?? false)) continue;
            $candidates = $entry['candidates'] ?? [$entry];
            if (!is_array($candidates) || !$candidates) throw new RuntimeException('Invalid executable candidates.');
            foreach ($candidates as $candidate) {
                if (!is_array($candidate)) throw new RuntimeException('Invalid executable candidate.');
                $add($name, $candidate, true);
            }
        }
        $outside = $profile['inventory']['executables_outside_path'] ?? [];
        if (!is_array($outside)) throw new RuntimeException('Invalid off-PATH inventory.');
        foreach ($outside as $entry) {
            if (!is_array($entry) || !is_string($entry['name'] ?? null) || strlen($entry['name']) > 160) {
                throw new RuntimeException('Invalid off-PATH executable.');
            }
            $add($entry['name'], $entry, false);
        }
        foreach ($tests as $path => $records) {
            if (!str_starts_with($path, '/') || str_contains($path, '<')) continue;
            $name = $records[0]['command'];
            $existing = $index[strtolower($name)] ?? [];
            if (!array_filter($existing, static fn($c) => $c['resolved_path'] === $path)) {
                $add($name, ['path' => $path, 'invocation_path' => $path], false);
            }
        }
        return $index;
    }

    /** Evidence about all candidates; tests apply only to the exact recorded file. */
    public static function commandEvidence(array $profile, string $command): array
    {
        $index = $profile['_command_candidates'] ?? self::indexCandidates($profile);
        $explicit = str_starts_with($command, '/');
        $candidates = $explicit ? array_values(array_filter(array_merge([], ...array_values($index)),
            static fn($c) => $c['invocation_path'] === $command || $c['resolved_path'] === $command)) : ($index[strtolower($command)] ?? []);
        if (!$candidates) {
            return ['status' => !$explicit && self::status($profile, $command) === 'missing' ? 'not_found' : 'unknown',
                'candidates' => [], 'selection_required' => false];
        }
        // Prefer the actual PATH-selected binary. Alternative paths remain explicit choices.
        $selected = array_values(array_filter($candidates, static fn($c) => $c['invocable_by_name']));
        $states = array_column($selected ?: $candidates, 'state');
        $state = $selected ? $selected[0]['state'] :
            (in_array('tested', $states, true) ? 'tested' : (in_array('found_untested', $states, true) ? 'found_untested' : 'test_failed'));
        return ['status' => $state, 'candidates' => $candidates, 'selection_required' => !$explicit && !$selected];
    }

    /** @param array<string,mixed> $profile */
    public static function status(array $profile, string $command): string
    {
        $command = strtolower($command);
        // An absent binary in a complete PATH inventory is not invocable by name.
        if (!array_key_exists($command, $profile['commands'] ?? [])) {
            if (($profile['schema_version'] ?? null) === self::VERSION
                && ($profile['coverage']['path_inventory_complete'] ?? false) === true) {
                return 'missing';
            }
            return 'unknown';
        }
        return $profile['commands'][$command]['available'] === true ? 'available' : 'missing';
    }

    /** @param array<string,mixed> $profile */
    public static function moduleStatus(array $profile, string $module): string
    {
        if (!array_key_exists($module, $profile['python_modules'] ?? [])) {
            // Packages without metadata and local modules make absence inconclusive.
            return 'unknown';
        }
        return $profile['python_modules'][$module]['available'] === true ? 'available' : 'missing';
    }
}
