import {build} from 'esbuild';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
await mkdir('dist',{recursive:true});
await build({entryPoints:['src/main.tsx'],bundle:true,minify:true,outfile:'dist/app.js',format:'iife',target:'es2022',define:{'process.env.NODE_ENV':'"production"'},legalComments:'eof'});
await writeFile('dist/index.html','<!doctype html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="Connect evidence, findings and human judgment with ReadinessOps for AWS."><meta name="referrer" content="no-referrer"><title>ReadinessOps · AWS workspace</title><link rel="stylesheet" href="app.css"></head><body><div id="root"></div><script src="app.js" defer></script></body></html>');
const manifest={};for(const name of ['index.html','app.js','app.css'])manifest[name]=createHash('sha256').update(await readFile('dist/'+name)).digest('hex');
await writeFile('dist/manifest.json',JSON.stringify(manifest,null,2)+'\n');
console.log('Workbench compiled; '+Object.keys(manifest).length+' local assets.');
