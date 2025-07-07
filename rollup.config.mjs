// rollup.config.js
import path from 'path';
import { nodeResolve } from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import json from '@rollup/plugin-json';

export default [
{
    input: 'src/index.mjs',
    output: {
        dir: 'dist',
        format: 'cjs',
        exports: 'named'
    },
    plugins: [
        nodeResolve(),
        commonjs(),
        json()
    ]
},
{
    input: 'src/index.mjs',
    output: {
        dir: 'dist/browser',
        format: 'es',
        name: 'Vouchsafe', 
        sourcemap: true
    },
    external: ['node:crypto'], 
    plugins: [
        nodeResolve({
            browser: true,
            preferBuiltins: false
        }),
        commonjs(),
        json()
    ]
}
]

