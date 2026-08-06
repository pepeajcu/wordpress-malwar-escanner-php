<?php

declare(strict_types=1);

final class FileWalker
{
    /**
     * Walks all configured scan roots and inserts every eligible file path into scan_queue
     * for the given run. Cheap pass: no content is read here, only stat().
     */
    public static function enqueueAll(int $runId): int
    {
        $pdo = Database::connection();
        $excludeDirs = array_map('strtolower', Config::get('exclude_dirs', []));

        $insert = $pdo->prepare(
            'INSERT INTO scan_queue (run_id, path, size, mtime, status) VALUES (:run_id, :path, :size, :mtime, "pending")'
        );

        $count = 0;
        $seen = [];

        foreach (PathGuard::scanRoots() as $root) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveCallbackFilterIterator(
                    new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS),
                    function (SplFileInfo $file) use ($excludeDirs): bool {
                        if ($file->isDir()) {
                            $name = strtolower($file->getFilename());
                            return !in_array($name, $excludeDirs, true);
                        }
                        return true;
                    }
                ),
                RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $fileInfo) {
                /** @var SplFileInfo $fileInfo */
                if (!$fileInfo->isFile() || $fileInfo->isLink()) {
                    continue;
                }

                $realPath = $fileInfo->getRealPath();
                if ($realPath === false || isset($seen[$realPath])) {
                    continue;
                }
                $seen[$realPath] = true;

                $insert->execute([
                    ':run_id' => $runId,
                    ':path' => $realPath,
                    ':size' => $fileInfo->getSize(),
                    ':mtime' => $fileInfo->getMTime(),
                ]);
                $count++;
            }
        }

        $pdo->prepare('UPDATE scan_runs SET total_files = :total WHERE id = :id')
            ->execute([':total' => $count, ':id' => $runId]);

        return $count;
    }
}
