'use strict';

/**
 * Phase 3 — Central Append-Only Result Writer
 *
 * Writes to PHASE3_RESULTS.jsonl and PHASE3_ERRORS.jsonl.
 * Uses 'a' (append) flag by default to support checkpoint/resume.
 * Pass { overwrite: true } to start fresh.
 */

const fs = require('fs');
const { PATHS } = require('./config');

class CentralResultWriter {
  constructor(options = {}) {
    const flag = options.overwrite ? 'w' : 'a';
    this.resultsStream = fs.createWriteStream(PATHS.resultsFile, { flags: flag, encoding: 'utf8' });
    this.errorsStream = fs.createWriteStream(PATHS.errorsFile, { flags: flag, encoding: 'utf8' });
    this.writtenCount = 0;
    this.errorCount = 0;
  }

  writeResult(record) {
    this.writtenCount++;
    const line = JSON.stringify(record) + '\n';
    this.resultsStream.write(line);
  }

  writeError(errorRecord) {
    this.errorCount++;
    const line = JSON.stringify(errorRecord) + '\n';
    this.errorsStream.write(line);
  }

  async close() {
    return new Promise(resolve => {
      this.resultsStream.end(() => {
        this.errorsStream.end(() => {
          resolve({
            totalWritten: this.writtenCount,
            totalErrors: this.errorCount
          });
        });
      });
    });
  }
}

module.exports = { CentralResultWriter };
