<?php
declare(strict_types=1);

namespace Skill2Work;

use PharData;
use RuntimeException;
use RecursiveIteratorIterator;
use ZipArchive;

final class Archive
{
    public const MAX_FILES = 1500;
    public const MAX_TOTAL_BYTES = 35_000_000;
    public const MAX_FILE_BYTES = 15_000_000;

    /** @return array<string,string> */
    public static function read(string $path): array
    {
        if (!is_file($path) || filesize($path) > 30_000_000) {
            throw new RuntimeException('ZIP is missing or exceeds 30 MB.');
        }
        $expected = self::preflight($path);
        if (class_exists(ZipArchive::class)) {
            $files = self::readWithZip($path);
            self::compareManifest($files, $expected);
            return $files;
        }
        if (!class_exists(PharData::class)) {
            throw new RuntimeException('PHP requires ZipArchive or PharData.');
        }
        // PharData determines archive format from the extension; PHP upload paths have none.
        $temporary = sys_get_temp_dir() . '/skill2work-' . bin2hex(random_bytes(16)) . '.zip';
        if (!copy($path, $temporary)) {
            throw new RuntimeException('Could not read ZIP for the PharData fallback.');
        }
        try {
            $files = self::readWithPhar($temporary);
            self::compareManifest($files, $expected);
            return $files;
        } finally {
            @unlink($temporary);
        }
    }

    /**
     * Validate original central-directory metadata before a ZIP library normalizes paths.
     * ZIP64 and multi-volume archives are intentionally not accepted.
     * @return array<string,int>
     */
    private static function preflight(string $path): array
    {
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            throw new RuntimeException('ZIP is not readable.');
        }
        try {
            $size = (int) filesize($path);
            $tailSize = min($size, 65_557);
            fseek($handle, $size - $tailSize);
            $tail = fread($handle, $tailSize);
            if (!is_string($tail)) {
                throw new RuntimeException('Cannot read the end of the ZIP.');
            }
            $position = strrpos($tail, "PK\x05\x06");
            if ($position === false || strlen($tail) < $position + 22) {
                throw new RuntimeException('ZIP end-of-central-directory record is missing.');
            }
            $end = unpack('vdisk/vdirectoryDisk/ventriesDisk/ventries/VdirectorySize/VdirectoryOffset/vcomment', substr($tail, $position + 4, 18));
            if (!$end || $end['disk'] !== 0 || $end['directoryDisk'] !== 0 || $end['entriesDisk'] !== $end['entries'] || $end['entries'] === 65535
                || $end['directorySize'] === 0xFFFFFFFF || $end['directoryOffset'] === 0xFFFFFFFF) {
                throw new RuntimeException('Multi-volume and ZIP64 archives are not supported.');
            }
            $endOffset = $size - $tailSize + $position;
            if ($endOffset + 22 + $end['comment'] !== $size || $end['directoryOffset'] + $end['directorySize'] > $endOffset) {
                throw new RuntimeException('Inconsistent ZIP directory offset.');
            }
            if ($end['entries'] > self::MAX_FILES) {
                throw new RuntimeException('Too many ZIP entries.');
            }
            fseek($handle, $end['directoryOffset']);
            $expected = [];
            $total = 0;
            for ($index = 0; $index < $end['entries']; $index++) {
                $header = fread($handle, 46);
                if (!is_string($header) || strlen($header) !== 46 || substr($header, 0, 4) !== "PK\x01\x02") {
                    throw new RuntimeException('Invalid ZIP central directory.');
                }
                $entry = unpack('vcreated/vneeded/vflags/vmethod/vtime/vdate/Vcrc/Vpacked/Vunpacked/vnameLength/vextraLength/vcommentLength/vdisk/vinternal/Vexternal/Vlocal', substr($header, 4));
                if (!$entry || ($entry['flags'] & 1) || !in_array($entry['method'], [0,8], true) || $entry['disk'] !== 0
                    || $entry['packed'] === 0xFFFFFFFF || $entry['unpacked'] === 0xFFFFFFFF || $entry['local'] >= $end['directoryOffset']) {
                    throw new RuntimeException('Encrypted, ZIP64 or unsupported compression entries are not accepted.');
                }
                if ($entry['nameLength'] < 1 || $entry['nameLength'] > 400 || $entry['extraLength'] > 60_000 || $entry['commentLength'] > 60_000) {
                    throw new RuntimeException('Invalid ZIP path or metadata length.');
                }
                $name = fread($handle, $entry['nameLength']);
                if (!is_string($name) || strlen($name) !== $entry['nameLength']) {
                    throw new RuntimeException('Cannot read ZIP filename.');
                }
                self::validatePath($name);
                if (($entry['created'] >> 8) === 3 && (($entry['external'] >> 16) & 0170000) === 0120000) {
                    throw new RuntimeException('Symbolic links are not allowed in ZIP archives.');
                }
                if (isset($expected[strtolower($name)])) {
                    throw new RuntimeException('Duplicate ZIP path (case-insensitive).');
                }
                $expected[strtolower($name)] = ['name' => $name, 'size' => $entry['unpacked']];
                if (!str_ends_with($name, '/')) {
                    self::checkSize($entry['unpacked'], $entry['packed'], $total);
                }
                fseek($handle, $entry['extraLength'] + $entry['commentLength'], SEEK_CUR);
            }
            if (ftell($handle) !== $end['directoryOffset'] + $end['directorySize']) {
                throw new RuntimeException('ZIP directory signature does not match.');
            }
            $files = [];
            foreach ($expected as $item) {
                if (!str_ends_with($item['name'], '/')) {
                    $files[$item['name']] = $item['size'];
                }
            }
            return $files;
        } finally {
            fclose($handle);
        }
    }

    /** @param array<string,string> $files @param array<string,int> $expected */
    private static function compareManifest(array $files, array $expected): void
    {
        if (count($files) !== count($expected)) {
            throw new RuntimeException('ZIP reader did not return all validated files.');
        }
        foreach ($expected as $name => $size) {
            if (!isset($files[$name]) || strlen($files[$name]) !== $size) {
                throw new RuntimeException('ZIP entries differ from the central directory.');
            }
        }
    }

    /** @return array<string,string> */
    private static function readWithZip(string $path): array
    {
        $archive = new ZipArchive();
        if ($archive->open($path) !== true) {
            throw new RuntimeException('Invalid or damaged ZIP.');
        }
        try {
            $files = [];
            $total = 0;
            if ($archive->numFiles > self::MAX_FILES) {
                throw new RuntimeException('Too many ZIP entries (maximum 1500).');
            }
            for ($i = 0; $i < $archive->numFiles; $i++) {
                $stat = $archive->statIndex($i);
                if (!is_array($stat)) {
                    throw new RuntimeException('Could not read ZIP entry.');
                }
                $name = (string) $stat['name'];
                self::validatePath($name);
                if (str_ends_with($name, '/')) {
                    continue;
                }
                $size = (int) ($stat['size'] ?? 0);
                $compressed = (int) ($stat['comp_size'] ?? 0);
                self::checkSize($size, $compressed, $total);
                $opsys = 0;
                $attributes = 0;
                if ($archive->getExternalAttributesIndex($i, $opsys, $attributes) && $opsys === ZipArchive::OPSYS_UNIX) {
                    $kind = ($attributes >> 16) & 0170000;
                    if ($kind === 0120000) {
                        throw new RuntimeException('Symbolic links are not allowed in ZIP archives.');
                    }
                }
                $content = $archive->getFromIndex($i, $size + 1);
                if (!is_string($content) || strlen($content) !== $size) {
                    throw new RuntimeException('ZIP contains an unreadable or inconsistent entry.');
                }
                self::addFile($files, $name, $content);
            }
            return $files;
        } finally {
            $archive->close();
        }
    }

    /** @return array<string,string> */
    private static function readWithPhar(string $path): array
    {
        try {
            $archive = new PharData($path);
            $files = [];
            $total = 0;
            $count = 0;
            $prefix = 'phar://' . realpath($path) . '/';
            foreach (new RecursiveIteratorIterator($archive) as $entry) {
                $count++;
                if ($count > self::MAX_FILES) {
                    throw new RuntimeException('Too many ZIP entries (maximum 1500).');
                }
                $name = substr($entry->getPathname(), strlen($prefix));
                self::validatePath($name);
                if ($entry->isLink()) {
                    throw new RuntimeException('Symbolic links are not allowed in ZIP archives.');
                }
                $size = $entry->getSize();
                $compressed = method_exists($entry, 'getCompressedSize') ? $entry->getCompressedSize() : $size;
                self::checkSize($size, $compressed, $total);
                $content = $entry->getContent();
                if (strlen($content) !== $size) {
                    throw new RuntimeException('ZIP contains inconsistent data.');
                }
                self::addFile($files, $name, $content);
            }
            return $files;
        } catch (RuntimeException $error) {
            throw $error;
        } catch (\Throwable $error) {
            throw new RuntimeException('Could not safely read ZIP: ' . $error->getMessage());
        }
    }

    private static function checkSize(int $size, int $compressed, int &$total): void
    {
        if ($size < 0 || $size > self::MAX_FILE_BYTES || $total + $size > self::MAX_TOTAL_BYTES) {
            throw new RuntimeException('ZIP exceeds size limits (15 MB per file, 35 MB total).');
        }
        if ($size > 500_000 && ($compressed === 0 || $size / $compressed > 150)) {
            throw new RuntimeException('Suspected ZIP bomb: excessive compression ratio.');
        }
        $total += $size;
    }

    public static function validatePath(string $name): void
    {
        if ($name === '' || strlen($name) > 400 || str_contains($name, "\0") || str_contains($name, '\\') || str_starts_with($name, '/') || preg_match('/^[A-Za-z]:/', $name)) {
            throw new RuntimeException('Unsafe archive file path.');
        }
        foreach (explode('/', $name) as $part) {
            if ($part === '.' || $part === '..' || ($part === '' && !str_ends_with($name, '/'))) {
                throw new RuntimeException('ZIP contains an unsafe relative path.');
            }
        }
    }

    /** @param array<string,string> $files */
    private static function addFile(array &$files, string $name, string $content): void
    {
        foreach ($files as $existing => $_) {
            if (strcasecmp($existing, $name) === 0) {
                throw new RuntimeException('Duplicate file path in ZIP: ' . $name);
            }
        }
        $files[$name] = $content;
    }

    /** @param array<string,string> $files */
    public static function write(string $path, array $files): void
    {
        if (count($files) > 500) {
            throw new RuntimeException('Output contains more than 500 files.');
        }
        $total = 0;
        foreach ($files as $name => $content) {
            self::validatePath($name);
            if (!is_string($content) || strlen($content) > 25_000_000) {
                throw new RuntimeException('An output file is too large.');
            }
            $total += strlen($content);
            if ($total > 25_000_000) {
                throw new RuntimeException('Output archive exceeds 25 MB uncompressed.');
            }
        }
        if (class_exists(ZipArchive::class)) {
            $zip = new ZipArchive();
            if ($zip->open($path, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
                throw new RuntimeException('Could not create ZIP.');
            }
            foreach ($files as $name => $content) {
                if (!$zip->addFromString($name, $content)) {
                    $zip->close();
                    throw new RuntimeException('ZIP write error.');
                }
                $permissions = self::isRunnable($name, $content) ? 0755 : 0644;
                $zip->setExternalAttributesName($name, ZipArchive::OPSYS_UNIX, (0100000 | $permissions) << 16);
            }
            if (!$zip->close()) {
                throw new RuntimeException('Could not close ZIP.');
            }
        } else {
            if (file_exists($path)) {
                unlink($path);
            }
            $zip = new PharData($path);
            foreach ($files as $name => $content) {
                $zip->addFromString($name, $content);
                $zip[$name]->chmod(self::isRunnable($name, $content) ? 0755 : 0644);
            }
            unset($zip);
        }
        @chmod($path, 0600);
    }

    private static function isRunnable(string $name, string $content): bool
    {
        $extension = strtolower(pathinfo($name, PATHINFO_EXTENSION));
        return in_array($extension, ['sh','bash','zsh'], true) || str_starts_with($content, '#!');
    }
}
