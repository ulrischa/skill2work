<?php
declare(strict_types=1);

namespace Skill2Work;

final class Analyzer
{
    private const STDLIB = [
        'abc','argparse','array','asyncio','base64','binascii','bisect','builtins',
        'calendar','collections','concurrent','contextlib','copy','csv','ctypes',
        'dataclasses','datetime','decimal','difflib','email','enum','functools',
        'glob','gzip','hashlib','heapq','html','http','importlib','inspect','io',
        'itertools','json','logging','math','mimetypes','multiprocessing','operator',
        'os','pathlib','pickle','platform','pprint','queue','random','re','secrets',
        'shlex','shutil','signal','socket','sqlite3','ssl','statistics','string',
        'struct','subprocess','sys','tempfile','textwrap','threading','time','timeit',
        'tkinter','traceback','typing','unicodedata','unittest','urllib','uuid',
        'warnings','weakref','xml','zipfile','zlib','zoneinfo','types','typing_extensions'
    ];

    private const MODULE_MAP = [
        'pillow' => 'PIL', 'beautifulsoup4' => 'bs4', 'pyyaml' => 'yaml',
        'opencv-python' => 'cv2', 'opencv-python-headless' => 'cv2',
        'python-docx' => 'docx', 'scikit-learn' => 'sklearn',
        'python-magic' => 'magic', 'pymupdf' => 'fitz', 'pypdf' => 'pypdf',
        'numpy' => 'numpy', 'pandas' => 'pandas', 'requests' => 'requests',
        'scrapy' => 'scrapy', 'lxml' => 'lxml', 'matplotlib' => 'matplotlib',
        'openpyxl' => 'openpyxl', 'reportlab' => 'reportlab', 'jinja2' => 'jinja2',
        'pytest' => 'pytest', 'httpx' => 'httpx', 'flask' => 'flask',
        'fastapi' => 'fastapi', 'selenium' => 'selenium'
    ];

    /** @param array<string,string> $files @param array<string,mixed> $profile @return array<string,mixed> */
    public static function analyze(array $files, array $profile): array
    {
        $commands = [];
        $modules = [];
        $warnings = [];
        $packages = [];
        $risky = [];
        $codeFiles = 0;

        $recordCommand = static function (string $command, string $source) use (&$commands): void {
            if (!str_starts_with($command, '/')) $command = strtolower($command);
            // Parse command positions rather than restricting detection to a fixed list.
            // Shell built-ins are not external executable dependencies.
            $builtins = ['cd','echo','export','set','unset','alias','source','read','exit','return',
                'if','then','else','elif','fi','for','do','done','while','case','esac','function',
                'local','declare','typeset','shift','trap','wait','break','continue','pwd'];
            if ((preg_match('/^[a-z][a-z0-9_.+@-]{0,127}$/', $command) || preg_match('~^/[A-Za-z0-9_./+@-]+$~', $command))
                && !in_array($command, $builtins, true)) {
                $commands[$command][$source] = true;
            }
        };
        $recordModule = static function (string $module, string $source) use (&$modules): void {
            if ($module !== '' && preg_match('/^[A-Za-z_][\w]*$/', $module)) {
                $modules[$module][$source] = true;
            }
        };

        foreach ($files as $name => $content) {
            $base = strtolower(basename($name));
            $extension = strtolower(pathinfo($name, PATHINFO_EXTENSION));
            $isText = in_array($extension, ['md','txt','py','sh','bash','zsh','js','mjs','cjs','php','json','toml','yaml','yml'], true)
                || in_array($base, ['dockerfile', 'makefile', 'requirements.txt'], true);
            if (!$isText || str_contains($content, "\0") || strlen($content) > 2_000_000) {
                continue;
            }
            if (preg_match('/\b(?:curl|wget)\b[^\n]{0,250}\|\s*(?:sh|bash)\b/i', $content)) {
                $risky[] = $name . ': Network script piped into a shell';
            }
            if (preg_match('/\b(?:sudo\s+|rm\s+-[a-z]*r[a-z]*f|eval\s*\(|os\.system\s*\(|shell\s*:\s*true)/i', $content)) {
                $risky[] = $name . ': Privileged, destructive or dynamic command';
            }
            if (preg_match('/\b(?:api[_-]?key|password|secret|access[_-]?token)\s*[:=]\s*["\x27][^"\x27\r\n]{8,}/i', $content)) {
                $risky[] = $name . ': Potential embedded secret (content not displayed)';
            }
            if (preg_match('/(?:\.\.\/|\.\.\\\\)/', $content) && ($extension === 'md' || $base === 'skill.md')) {
                $warnings[] = $name . ': Review relative references outside the skill directory.';
            }

            if ($extension === 'py') {
                $codeFiles++;
                $recordCommand('python3', $name . ' (Python file)');
                if (preg_match_all('/^\s*(?:import\s+([\w., ]+)|from\s+([\w.]+)\s+import\b)/m', $content, $matches, PREG_SET_ORDER)) {
                    foreach ($matches as $match) {
                        $raw = ($match[1] ?? '') !== '' ? $match[1] : ($match[2] ?? '');
                        foreach (explode(',', $raw) as $part) {
                            $root = explode('.', trim(explode(' as ', trim($part))[0]))[0];
                            if ($root && !in_array($root, self::STDLIB, true)) {
                                $recordModule($root, $name . ' (Import)');
                            }
                        }
                    }
                }
                if (preg_match_all('/(?:subprocess\.(?:run|Popen|check_call|check_output|call)|os\.system)\s*\(\s*(?:\[\s*)?["\x27]([A-Za-z][\w.+-]*)/m', $content, $found)) {
                    foreach ($found[1] as $command) {
                        $recordCommand($command, $name . ' (Subprocess)');
                    }
                }
                if (str_contains($content, 'shell=True')) {
                    $warnings[] = $name . ': subprocess with shell=True requires manual security review.';
                }
            } elseif (in_array($extension, ['js','mjs','cjs'], true)) {
                $codeFiles++;
                $recordCommand('node', $name . ' (JavaScript file)');
                if (preg_match_all('/(?:execSync|execFileSync|spawnSync|exec|execFile|spawn)\s*\(\s*["\x27]([\w.+-]+)/m', $content, $found)) {
                    foreach ($found[1] as $command) {
                        $recordCommand($command, $name . ' (child_process)');
                    }
                }
            } elseif ($extension === 'php') {
                $codeFiles++;
                $recordCommand('php', $name . ' (PHP file)');
            } elseif (in_array($extension, ['sh','bash','zsh'], true)) {
                $codeFiles++;
                $recordCommand($extension === 'sh' ? 'sh' : ($extension === 'zsh' ? 'zsh' : 'bash'), $name . ' (Shell file)');
                self::scanShell($content, $name, $recordCommand);
            }

            if ($base === 'skill.md' || $extension === 'md') {
                if (preg_match_all('/```(?:bash|sh|shell|console|zsh)\s*\n(.*?)```/si', $content, $matches)) {
                    foreach ($matches[1] as $block) {
                        self::scanShell($block, $name . ' (code block)', $recordCommand);
                    }
                }
                if (preg_match_all('/(?<!`)`([A-Za-z\/][\w.\/+@-]{0,4095}\h+(?:[-\w.\/]+\h*){1,12})`(?!`)/i', $content, $matches)) {
                    foreach ($matches[1] as $command) {
                        self::scanShell($command, $name . ' (Inline)', $recordCommand);
                    }
                }
            }
            if ($base === 'requirements.txt') {
                $recordCommand('python3', $name . ' (requirements.txt)');
                foreach (preg_split('/\R/', $content) ?: [] as $line) {
                    $line = trim($line);
                    if ($line === '' || str_starts_with($line, '#')) {
                        continue;
                    }
                    if (preg_match('/^([\w-]+)(?:\[[^\]]+\])?(?:[=<>!~;\s]|$)/', $line, $match)) {
                        $package = strtolower($match[1]);
                        $module = self::MODULE_MAP[$package] ?? str_replace('-', '_', $package);
                        $packages[] = 'pip: ' . $line;
                        $recordModule($module, $name . ' (requirements.txt; package name may differ from import name)');
                    } else {
                        $warnings[] = $name . ': Dynamic pip requirement cannot be verified automatically.';
                    }
                }
            }
            if ($base === 'package.json') {
                $recordCommand('node', $name . ' (package.json)');
                $data = json_decode($content, true);
                if (is_array($data)) {
                    foreach (['dependencies','devDependencies'] as $section) {
                        foreach (($data[$section] ?? []) as $pkg => $version) {
                            if (is_string($pkg) && is_string($version)) {
                                $packages[] = 'npm: ' . $pkg . '@' . $version;
                            }
                        }
                    }
                } else {
                    $warnings[] = $name . ': Invalid package.json.';
                }
            }
            if ($base === 'composer.json') {
                $recordCommand('php', $name . ' (composer.json)');
                $data = json_decode($content, true);
                if (is_array($data)) {
                    foreach (($data['require'] ?? []) as $pkg => $version) {
                        if (is_string($pkg) && is_string($version) && $pkg !== 'php') {
                            $packages[] = 'composer: ' . $pkg . ' ' . $version;
                        }
                    }
                }
            }
            if ($base === 'dockerfile' || preg_match('/\.dockerfile$/i', $name)) {
                $recordCommand('docker', $name . ' (Dockerfile)');
                $warnings[] = $name . ': A Dockerfile does not prove Work can run Docker.';
            }
        }

        $commandResults = [];
        foreach ($commands as $command => $sources) {
            $commandResults[$command] = Profile::commandEvidence($profile, $command) + ['sources' => array_keys($sources)];
        }
        ksort($commandResults);
        $moduleResults = [];
        foreach ($modules as $module => $sources) {
            $moduleResults[$module] = ['status' => Profile::moduleStatus($profile, $module), 'sources' => array_keys($sources)];
        }
        ksort($moduleResults);
        // Runtime command discovery cannot prove third-party dependency versions or installability.
        $packages = array_values(array_unique($packages));
        $statuses = array_merge(array_column($commandResults, 'status'), array_column($moduleResults, 'status'));

        if (in_array('missing', $statuses, true) || in_array('not_found', $statuses, true)) {
            $overall = 'incompatible';
        } elseif (count(array_intersect(['unknown', 'found_untested', 'test_failed'], $statuses)) > 0
            || count(array_filter($commandResults, static fn($c) => $c['selection_required'])) > 0 || count($warnings) > 0 || count($packages) > 0) {
            $overall = 'unverified';
        } elseif (count($statuses) === 0 && $codeFiles === 0) {
            $overall = 'instructions-only';
        } else {
            $overall = 'observed';
        }
        $warnings = array_values(array_unique($warnings));
        $risky = array_values(array_unique($risky));
        if ($risky !== []) {
            $overall = $overall === 'incompatible' ? 'incompatible' : 'review';
        }
        return [
            'overall' => $overall,
            'commands' => $commandResults,
            'modules' => $moduleResults,
            'packages' => $packages,
            'warnings' => $warnings,
            'security' => $risky,
            'code_files' => $codeFiles,
        ];
    }

    /** @param callable(string,string):void $recordCommand */
    private static function scanShell(string $text, string $source, callable $recordCommand): void
    {
        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $line = preg_replace('/^(?:\$\s+|>\s+)/', '', $line);
            // Detect commands after pipes and separators, but never execute them.
            foreach (preg_split('/\s*(?:\|\||&&|[;|])\s*/', $line) ?: [] as $chunk) {
                $chunk = preg_replace('/^(?:(?:[A-Za-z_]\w*=\S*|env)\s+)*/', '', trim($chunk));
                if (preg_match('~^([A-Za-z/][\w./+@-]*)(?=\s|$)~', $chunk, $matches)) {
                    $recordCommand($matches[1], $source);
                }
            }
        }
    }
}
