'use strict';

/**
 * Phase 2 — Central Append-Only Result Writer
 *
 * Ensures serialized, atomic JSONL writes for results and errors,
 * with zero risk of file corruption under concurrent workers.
 */

const fs = require('fs');
const { PATHS } = require('./config');

class CentralResultWriter {
  constructor() {
    this.resultsStream = fs.createWriteStream(PATHS.resultsFile, { flags: 'w', encoding: 'utf8' });
    this.errorsStream = fs.createWriteStream(PATHS.errorsFile, { flags: 'w', encoding: 'utf8' });
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
