<?php
declare(strict_types=1);

namespace Skill2Work;

/**
 * Describe documented task-level Work alternatives without confusing an
 * agent instruction with a callable CLI or a process API.
 */
final class CodexCompatibility
{
    /** @var array<string,array{0:string,1:string,2:string}> */
    private const MAPPINGS = [
        'exec' => ['Work task', 'Ask Work to perform the requested task with its available tools.', 'No equivalent for subprocess/stdout/stderr, noninteractive CI, sandbox flags, JSONL events or --output-schema.'],
        'review' => ['Work review task', 'Request a code review of the accessible files in Work.', 'Does not reproduce Codex review CLI exit codes or automated review output.'],
        'resume' => ['Continue Work conversation', 'Continue in the existing Work conversation if its context is available.', 'Cannot import a Codex session ID or reconstruct missing context.'],
        'apply' => ['Work file editing', 'Request the same patch/change with accessible file editing tools.', 'Cannot apply a Codex patch by invoking a Work CLI equivalent.'],
        'mcp' => ['Connected Work plugin/MCP tool', 'Use a configured, authorized plugin or MCP tool if available.', 'Requires separately installed and authorized plugin/MCP connection.'],
        'cloud' => ['Work task', 'Submit the work as a Work task where supported.', 'Separate Codex Cloud environment, task lifecycle and APIs are not interchangeable.'],
        'login' => ['ChatGPT account connection', 'Use the account and plugin connection flow of ChatGPT.', 'Not a substitute for Codex CLI authentication or tokens.'],
    ];

    /** Only an entire, explicit prose instruction with a literal prompt is migrated. */
    public static function migrate(string $text, string $filename, array &$changes): string
    {
        if (!preg_match('/\.md$/i', $filename)) return $text;
        $lines = explode("\n", $text);
        $fence = null;
        foreach ($lines as $number => &$line) {
            if (preg_match('/^ {0,3}(`{3,}|~{3,})/', $line, $f)) {
                if ($fence === null) $fence = $f[1];
                elseif ($f[1][0] === $fence[0] && strlen($f[1]) >= strlen($fence)) $fence = null;
                continue;
            }
            if ($fence !== null) continue;
            if (!preg_match('/^( {0,3}(?:(?:[-*]|[0-9]+[.)]) )?)(?:Run|Execute|Führe aus|Führe|Nutze|Verwende) +`codex exec (["\'])([^`\r\n]+)\2`[.!]? *$/ui', $line, $m)) continue;
            $prompt = $m[3];
            // Reject shell expansion, escapes, nested quotes and empty instructions.
            if (trim($prompt) === '' || strpbrk($prompt, "$\\\'\"") !== false) continue;
            $replacement = $m[1] . '**Work task: carry out the following instruction directly using available tools. ' .
                'Check required files and permissions first; report any missing capabilities.** ' . $prompt;
            $changes[] = $filename . ':' . ($number + 1) . ': ' . trim($line) . ' → ' . trim($replacement);
            $line = $replacement;
        }
        unset($line);
        return implode("\n", $lines);
    }

    /** @param array<string,string> $files
     *  @return array{matches:list<array{file:string,kind:string,context:string,equivalent:string,limitation:string}>,warnings:list<string>,work_instructions:list<string>}
     */
    public static function analyze(array $files): array
    {
        $matches = [];
        $warnings = [];
        $instructions = [];
        foreach ($files as $filename => $contents) {
            if (!preg_match('/\.(md|txt|py|sh|bash|zsh|js|mjs|cjs|php|json|toml|yaml|yml)$/i', $filename)
                || str_contains($contents, "\0") || strlen($contents) > 2_000_000) {
                continue;
            }
            $lines = preg_split('/\R/', $contents) ?: [];
            $fence = false;
            foreach ($lines as $number => $line) {
                if (preg_match('/^\s*(```|~~~)/', $line)) {
                    $fence = !$fence;
                }
                if (preg_match_all('/\bcodex\s+(exec|review|resume|apply|mcp|cloud|login)\b/i', $line, $found)) {
                    foreach ($found[1] as $subcommand) {
                        $subcommand = strtolower($subcommand);
                        [$equivalent, $instruction, $limitation] = self::MAPPINGS[$subcommand];
                        // Markdown code blocks and source code are executable examples,
                        // never automatically replaced with a chat instruction.
                        $context = (preg_match('/\.md$/i', $filename) && !$fence) ? 'prose' : 'code-or-shell';
                        $matches[] = ['file' => $filename . ':' . ($number + 1), 'kind' => 'codex ' . $subcommand,
                                      'context' => $context, 'equivalent' => $equivalent, 'limitation' => $limitation];
                        if ($context === 'prose') {
                            $instructions[] = 'For prose referring to codex ' . $subcommand . ': ' . $instruction;
                        } else {
                            $warnings[] = $filename . ': codex ' . $subcommand . ' in executable/example context remains a CLI dependency. ' . $limitation;
                        }
                    }
                }
                if (preg_match_all('~(?<![A-Za-z0-9_/.])/(plan|review|compact|init|status|diff|permissions)(?![\w.-])~i', $line, $slash)) {
                    foreach ($slash[1] as $name) {
                        $name = strtolower($name);
                        $equivalent = match ($name) {
                            'plan' => 'Ask Work to prepare a plan; no UI command.',
                            'review' => 'Ask Work to review available code; no guaranteed review output format.',
                            'status', 'diff' => 'Ask Work for status/differences if the needed files are accessible.',
                            'init' => 'Ask Work to prepare project guidance explicitly; no automatic /init.',
                            'permissions' => 'Use actual Work permissions and approval controls.',
                            default => 'No supported direct Work command mapping.',
                        };
                        $matches[] = ['file' => $filename . ':' . ($number + 1), 'kind' => '/' . $name,
                                      'context' => $fence ? 'code-or-shell' : 'prose',
                                      'equivalent' => $equivalent, 'limitation' => 'Do not insert this slash command into Work as-is.'];
                    }
                }
            }
        }
        return ['matches' => $matches,
                'warnings' => array_values(array_unique(array_merge($warnings, array_map(static fn($m) => $m['file'] . ': Not converted automatically: ' . $m['kind'] . '. ' . $m['limitation'], $matches)))),
                'work_instructions' => array_values(array_unique($instructions))];
    }

    /** @param array<string,mixed> $analysis */
    public static function report(array $analysis): string
    {
        $lines = [
            '# Codex → ChatGPT Work: task equivalents', '',
            'These mappings adapt **human-facing instructions**, not executable processes.',
            'There is no documented 1:1 Work replacement for the `codex exec` CLI subprocess API.',
            'Never treat `@skill` as a command runnable from a shell script.', '',
        ];
        foreach ($analysis['matches'] as $item) {
            $lines[] = '- **' . $item['file'] . '** — `' . $item['kind'] . '` (' . $item['context'] . '): ' .
                $item['equivalent'] . ' **Limitation:** ' . $item['limitation'];
        }
        if (!$analysis['matches']) {
            $lines[] = 'No recognized Codex agent/CLI invocations found.';
        }
        $lines[] = '';
        $lines[] = '## When a prose instruction invokes an agent';
        $lines[] = 'If the underlying request can be completed with the tools available in the **current Work task**, do it directly in Work rather than launching a nested Codex agent.';
        $lines[] = 'Do not silently ignore requested sandbox/approval, streaming, JSON, CI, session-resume or authenticated MCP semantics.';
        $lines[] = 'If an actual source-code process invocation remains, keep it as a dependency and verify the Codex CLI and its authentication separately.';
        $lines[] = '';
        $lines[] = '## Work-specific access';
        $lines[] = 'Skills and plugin/MCP capabilities depend on installation, plan, permissions and the specific Work surface. Bundled hooks require runtime availability and explicit trust; a web ZIP upload does not deploy hook scripts.';
        $lines[] = 'The filesystem probe cannot enumerate ChatGPT-hosted plugins or agent tools.';
        return implode("\n", $lines) . "\n";
    }
}
