<?php
declare(strict_types=1);

namespace Skill2Work;

/**
 * Translate human-facing Codex skill selectors only. Shell commands and source
 * code must never be rewritten as though @mentions were executable commands.
 */
final class SkillReferences
{
    /** @param array<string,string> $source @param array<string,string> $repository
     *  @return array{markdown:string,rewrites:list<string>,warnings:list<string>,dependencies:list<string>}
     */
    public static function migrate(string $markdown, array $source, array $repository): array
    {
        $rewrites = [];
        $warnings = [];
        $dependencies = [];
        $counts = ['skill' => 0, 'selector' => 0];
        $selfName = '';
        if (preg_match('/^name:\s*([a-z0-9-]+)\s*$/mi', $markdown, $match)) {
            $selfName = $match[1];
        }
        // Preserve fenced code literally, even if it documents a Codex command.
        // Code fences are preserved with offsets rather than rewritten.
        $fences = [];
        preg_match_all('/^[ \t]*(`{3,}|~{3,})[^\r\n]*\R.*?^[ \t]*\1[ \t]*$/ms', $markdown, $matches, PREG_OFFSET_CAPTURE);
        foreach ($matches[0] as $fence) {
            $fences[] = [$fence[1], $fence[1] + strlen($fence[0])];
            if (preg_match('~(?<![\w/:])/skills(?![\w/.-])~i', $fence[0])) {
                $warnings[] = 'Codex /skills found in a code block: not a runnable Work shell command; preserved unchanged.';
            }
            if (preg_match('/\$[a-z][a-z0-9]*(?:-[a-z0-9]+)+\b/', $fence[0])) {
                $warnings[] = 'Skill references with $ found in a code block: possible Codex CLI calls; code was not rewritten to @.';
            }
        }
        $cursor = 0;
        $output = '';
        foreach ($fences as [$start, $end]) {
            $output .= self::rewriteProse(substr($markdown, $cursor, $start - $cursor), $dependencies, $counts, $selfName);
            $output .= substr($markdown, $start, $end - $start);
            $cursor = $end;
        }
        $output .= self::rewriteProse(substr($markdown, $cursor), $dependencies, $counts, $selfName);
        if ($counts['skill'] > 0) {
            $rewrites[] = 'Codex $skill-name → ChatGPT @skill-name (' . $counts['skill'] . ' human-facing references in SKILL.md; not shell commands).';
        }
        if ($counts['selector'] > 0) {
            $rewrites[] = 'Codex /skills → ChatGPT @ composer picker (' . $counts['selector'] . ' prose references).';
        }
        foreach ($dependencies as $name) {
            $warnings[] = 'External skill ' . $name . ': install separately in ChatGPT and select with @; automatic skill-to-skill execution is not guaranteed.';
        }
        // Review even unconverted references. These are not Work chat commands.
        if (preg_match('/(?<![\w\/])\/(?:review|compact|plan|permissions|status|model|init|diff|mcp|agent)(?![\w-])/i', $markdown)) {
            $warnings[] = 'Codex slash commands other than /skills detected; no general Work equivalent, review manually.';
        }
        if (preg_match('/\bcodex\s+(?:exec|resume|apply|mcp|login|review|cloud)\b/i', $markdown)) {
            $warnings[] = 'Codex CLI calls detected: an @mention cannot replace them even when a codex binary exists.';
        }
        if (preg_match('#(?:\$CODEX_HOME|~/\.codex|\.codex/|\.agents/skills/|\bAGENTS\.md\b)#i', $markdown)) {
            $warnings[] = 'Codex paths or AGENTS.md referenced: instructions/paths outside the skill ZIP are not loaded automatically.';
        }
        if (preg_match('/\b(?:apply_patch|functions\.shell|functions\.exec_command|multi_tool_use\.parallel)\b/i', $markdown)) {
            $warnings[] = 'Codex-specific tools or tool names detected: verify Work capabilities separately.';
        }
        if (preg_match('/(?:^|\R)\s*(?:allowed-tools|disable-model-invocation|context|agent|argument-hint|model)\s*:/mi', $markdown)) {
            $warnings[] = 'Codex/agent-specific frontmatter fields detected: review Work interpretation; unknown fields were preserved.';
        }
        if (preg_match('/\$ARGUMENTS\b|\$\{?CODEX_HOME\}?|\$\{?SKILL_ROOT\}?/i', $markdown)) {
            $warnings[] = 'Codex placeholders or installation variables detected: they may differ or be absent in Work.';
        }
        foreach (array_keys($source) as $path) {
            if (preg_match('~(?:^|/)(?:hooks\.json|config\.toml|mcp\.json|\.mcp\.json|plugin\.json|AGENTS\.md)$~i', $path)) {
                $warnings[] = $path . ': configuration/integration file requires separate review; ZIP import does not activate it automatically.';
            }
        }
        foreach (array_keys($repository) as $path) {
            if (isset($source[$path])) {
                continue;
            }
            if (preg_match('~(?:^|/)(?:AGENTS\.md|\.codex/config\.toml|\.codex/hooks\.json|\.mcp\.json|mcp\.json)$~i', $path)) {
                $warnings[] = $path . ': outside this skill and excluded from the output ZIP.';
            }
        }
        if (isset($source['agents/openai.yaml']) && preg_match('/\bdependencies\s*:\s*\R|\btype\s*:\s*["\x27]?mcp\b/i', $source['agents/openai.yaml'])) {
            $warnings[] = 'agents/openai.yaml contains tool/MCP dependencies: verify availability, permissions and transport in Work separately.';
        }
        $warnings = array_values(array_unique($warnings));
        return ['markdown' => $output, 'rewrites' => $rewrites, 'warnings' => $warnings, 'dependencies' => array_values(array_unique($dependencies))];
    }

    /** @param list<string> $dependencies @param array<string,int> $counts */
    private static function rewriteProse(string $text, array &$dependencies, array &$counts, string $selfName): string
    {
        // Inline Markdown code examples need their surrounding ticks replaced as
        // a unit. Otherwise `/skills` would create malformed nested backticks.
        $parts = preg_split('/(`[^`\r\n]+`)/', $text, -1, PREG_SPLIT_DELIM_CAPTURE);
        if (!is_array($parts)) {
            return $text;
        }
        foreach ($parts as &$part) {
            if (preg_match('/^`([^`]+)`$/', $part, $quoted)) {
                if ($quoted[1] === '/skills') {
                    $counts['selector']++;
                    $part = 'the `@` picker in the ChatGPT composer';
                } elseif (preg_match('/^\$([a-z][a-z0-9]*(?:-[a-z0-9]+)+)$/', $quoted[1], $match)) {
                    $counts['skill']++;
                    if ($match[1] !== $selfName) {
                        $dependencies[] = $match[1];
                    }
                    $part = '`@' . $match[1] . '`';
                }
                continue;
            }
            $part = preg_replace_callback('/(?<![A-Za-z0-9_])\$([a-z][a-z0-9]*(?:-[a-z0-9]+)+)\b(?![\w=])/u',
                static function (array $match) use (&$dependencies, &$counts, $selfName): string {
                    $name = $match[1];
                    if ($name !== $selfName) {
                        $dependencies[] = $name;
                    }
                    $counts['skill']++;
                    return '@' . $name;
                }, $part) ?? $part;
            $part = preg_replace_callback('~(?<![\w/:])(/skills)(?![\w/-]|\.[A-Za-z0-9])~i',
                static function () use (&$counts): string {
                    $counts['selector']++;
                    return 'the `@` picker in the ChatGPT composer';
                }, $part) ?? $part;
        }
        unset($part);
        return implode('', $parts);
    }
}
