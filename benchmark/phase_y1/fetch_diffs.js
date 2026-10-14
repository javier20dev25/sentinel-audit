const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const cases = [
  { id: 'P5-013', repo: 'unclechu_node-deep-extend', v: '9653940a', p: '9423fae8' },
  { id: 'P5-015', repo: 'jonschlinkert_mixin-deep', v: '9925af76', p: '8f464c8c' },
  { id: 'P5-033', repo: 'salesforce_tough-cookie', v: 'fcc8abfa', p: 'f1ed420a' },
  { id: 'P5-041', repo: 'moxystudio_node-cross-spawn', v: '9521e2da', p: '5ff3a07d' },
  { id: 'P5-014', repo: 'jonschlinkert_set-value', v: '7bd5011d', p: '95e9d992' },
  { id: 'P5-016', repo: 'janl_node-json-pointer', v: '9b5ea8e3', p: '859c9984' },
  { id: 'P5-031', repo: 'npm_node-semver', v: 'a685e01b', p: '5c4c9f6e' }
];

cases.forEach(c => {
  const clone = path.resolve(__dirname, '../phase5/clones', c.repo);
  console.log(`=== ${c.id} Diff ===`);
  try {
    const diff = execSync(`git -C "${clone}" diff ${c.v} ${c.p}`, { encoding: 'utf8' });
    console.log(diff.slice(0, 400));
  } catch (e) {
    console.log('Error fetching diff:', e.message);
  }
});
