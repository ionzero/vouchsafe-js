#!/usr/bin/env node

import { writeInteropCorpus } from '../test-support/interop-corpus.mjs';

const outputDir = process.argv[2];
const { outputDir: resolvedDir } = await writeInteropCorpus(outputDir, 'js');
process.stdout.write(`${resolvedDir}\n`);
