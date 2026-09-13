<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;

return RectorConfig::configure()
    ->withPaths([
        __DIR__.'/src',
        __DIR__.'/config',
        __DIR__.'/routes',
        __DIR__.'/tests',
        __DIR__.'/workbench/app',
    ])
    ->withCache(cacheDirectory: __DIR__.'/.rector-cache')
    ->withPhpSets(php84: true)
    ->withPreparedSets(
        deadCode: true,
        codeQuality: true,
        typeDeclarations: true,
    );
