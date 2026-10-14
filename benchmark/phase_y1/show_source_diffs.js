const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

function showDiffFile(clonePath, v, p, file) {
  try {
    const fullClone = path.resolve(__dirname, '../..', clonePath);
    const d = execSync(`git -C "${fullClone}" diff ${v} ${p} -- ${file}`, { encoding: 'utf8' });
    console.log(`=== ${file} ===\n${d}`);
  } catch (e) {
    console.log(e.message);
  }
}

showDiffFile('benchmark/phase5/clones/unclechu_node-deep-extend', '9653940a', '9423fae8', 'lib/deep-extend.js');
showDiffFile('benchmark/phase5/clones/jonschlinkert_mixin-deep', '9925af76', '8f464c8c', 'index.js');
showDiffFile('benchmark/phase5/clones/salesforce_tough-cookie', 'fcc8abfa', 'f1ed420a', 'lib/cookie.js');
showDiffFile('benchmark/phase5/clones/moxystudio_node-cross-spawn', '9521e2da', '5ff3a07d', 'lib/util/escape.js');
showDiffFile('benchmark/phase5/clones/jonschlinkert_set-value', '7bd5011d', '95e9d992', 'index.js');
showDiffFile('benchmark/phase5/clones/npm_node-semver', 'a685e01b', '5c4c9f6e', 'semver.js');
