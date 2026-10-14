/**
 * Sentinel Y - Semantic Vulnerability Analyzer Entry Point
 * Version: 0.2.0 (Hardened Semantic Edition)
 *
 * To load specific engine versions:
 *   const v01 = require('./v0.1');
 *   const v02 = require('./v0.2');
 */

const v02 = require('./v0.2');

module.exports = {
  version: '0.2.0',
  ...v02,
  v01: require('./v0.1'),
  v02
};
