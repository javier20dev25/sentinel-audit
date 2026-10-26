'use strict';

const readline = require('node:readline/promises');
const { stdin, stdout } = require('node:process');

async function interactiveArgs(io) {
  const ownsInterface = !io;
  io = io || readline.createInterface({ input: stdin, output: stdout });
  try {
    io.output.write('\nSentinel Audit · guided terminal workflow\n');
    io.output.write('Choose what to do:\n  1) Check tools and configuration\n  2) Preflight a pinned repository\n  3) Run an audit on a pinned commit\n  4) Render a report from an existing execution\n  5) Exit\n');
    const choice = (await io.question('Select [1-5]: ')).trim();
    if (choice === '1') return ['doctor'];
    if (choice === '5') return null;
    if (choice === '2' || choice === '3') {
      const repo = (await io.question('Repository path: ')).trim();
      if (!repo) throw new Error('Repository path is required');
      const commit = (await io.question('Full 40-character commit SHA: ')).trim();
      if (!/^[a-f0-9]{40}$/i.test(commit)) throw new Error('Enter a full 40-character commit SHA');
      if (choice === '2') return ['preflight', repo, '--commit', commit];
      const routing = (await io.question('Scope [file/directory/repo] (default file): ')).trim() || 'file';
      if (!['file', 'directory', 'repo'].includes(routing)) throw new Error('Scope must be file, directory, or repo');
      const confirm = (await io.question(`Run analyzers on ${repo} at ${commit}? [y/N]: `)).trim().toLowerCase();
      if (confirm !== 'y' && confirm !== 'yes') return null;
      return ['run', repo, '--commit', commit, '--routing', routing];
    }
    if (choice === '4') {
      const executionDir = (await io.question('Execution directory: ')).trim();
      if (!executionDir) throw new Error('Execution directory is required');
      return ['report', executionDir];
    }
    throw new Error('Choose one of the listed options');
  } finally {
    if (ownsInterface) io.close();
  }
}

module.exports = { interactiveArgs };
