# Phase 5 Forensic Adjudication of Apparent True Positives (N=21)

## Executive Summary

| Classification | Count | Percentage |
|:---|:---:|:---:|
| CVE_SPECIFIC_DETECTION | 0 | 0.00% |
| UNRELATED_SECURITY_ALERT | 21 | 100.00% |
| OUT_OF_SCOPE | 0 | 0.00% |
| AMBIGUOUS | 0 | 0.00% |

## Forensic Case Breakdown

| ID | Package | Advisory / CVE | CWE | Matched Vuln | Matched Patch | Same on Patch | Adjudicated Class | Justification |
|:---|:---|:---|:---|:---:|:---:|:---:|:---|:---|
| P5-001 | handlebars | GHSA-2w6w-674q-4c4q (CVE-2026-33937) | CWE-843 | 1 | 1 | YES | UNRELATED_SECURITY_ALERT | AST type confusion vulnerability in parser logic. Sentinel flagged process spawning / exec in helper script. |
| P5-004 | tar | GHSA-23hp-3jrh-7fpw (CVE-2026-59873) | CWE-770 | 2 | 2 | YES | UNRELATED_SECURITY_ALERT | Argument injection or command injection vulnerability. Sentinel flagged existing child_process or regex exec in codebase. |
| P5-005 | underscore | GHSA-cf4h-3jhx-xvhq (CVE-2021-23358) | CWE-94 | 5 | 5 | YES | UNRELATED_SECURITY_ALERT | File uses legitimate Function/eval template compilation sink (flagged by SAST-EVAL). The CVE was unescaped variable interpolation in the template parser. |
| P5-007 | mongoose | GHSA-9m93-w8w6-76hh (CVE-2023-3696) | CWE-1321 | 1 | 1 | YES | UNRELATED_SECURITY_ALERT | Prototype pollution vulnerability via object merge/extend logic. Sentinel flagged background sinks in the file, not prototype key validation. |
| P5-009 | sequelize | GHSA-5v9h-q3gj-c32x (CVE-2016-1000225) | CWE-89 | 1 | 1 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
| P5-012 | nodemailer | GHSA-48ww-j4fc-435p (CVE-2020-7769) | CWE-88 | 37 | 37 | YES | UNRELATED_SECURITY_ALERT | Argument injection or command injection vulnerability. Sentinel flagged existing child_process or regex exec in codebase. |
| P5-017 | lodash | GHSA-35jh-r3h4-6jhm (CVE-2021-23337, CVE-2026-4800) | CWE-77 | 2 | 2 | YES | UNRELATED_SECURITY_ALERT | Argument injection or command injection vulnerability. Sentinel flagged existing child_process or regex exec in codebase. |
| P5-018 | lodash | GHSA-4xc9-xhrj-v574 (CVE-2018-16487) | CWE-400 | 2 | 2 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
| P5-019 | axios | GHSA-3pq3-5fj3-cg6v (CVE-2026-101898) | CWE-918 | 15 | 15 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
| P5-023 | node-fetch | GHSA-r683-j2x4-v87g (CVE-2022-0235) | CWE-173 | 3 | 3 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
| P5-024 | handlebars | GHSA-3cqr-58rm-57f8 (CVE-2019-20920) | CWE-94 | 1 | 1 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
| P5-025 | ejs | GHSA-6x77-rpqf-j6mw (CVE-2017-1000189) | CWE-20 | 1 | 1 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
| P5-026 | vm2 | GHSA-2v2p-6j97-cjg9 (CVE-2026-100722) | CWE-248 | 4 | 6 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
| P5-028 | braces | GHSA-grv7-fg5c-xmjg (CVE-2024-4068) | CWE-1050 | 2 | 2 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
| P5-030 | semver | GHSA-c2qf-rxjj-qqgw (CVE-2022-25883) | CWE-1333 | 2 | 3 | YES | UNRELATED_SECURITY_ALERT | ReDoS vulnerability in regex pattern. Sentinel does not compute regex automata polynomial complexity; alert triggered on file presence/API call. |
| P5-032 | tar | GHSA-34x7-hfp2-rc4v (CVE-2026-24842) | CWE-22 | 1 | 1 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
| P5-034 | ws | GHSA-3h5v-q93c-6h6q (CVE-2024-37890) | CWE-476 | 3 | 3 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
| P5-035 | underscore | GHSA-qpx9-hpmf-5gmw (CVE-2026-27601) | CWE-674 | 6 | 6 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
| P5-039 | debug | GHSA-9vvw-cc9w-f27h (CVE-2017-20165) | CWE-1333 | 4 | 4 | YES | UNRELATED_SECURITY_ALERT | ReDoS vulnerability in regex pattern. Sentinel does not compute regex automata polynomial complexity; alert triggered on file presence/API call. |
| P5-040 | shelljs | GHSA-4rq4-32rv-6wp6 (CVE-2022-0144) | CWE-269 | 15 | 16 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
| P5-045 | socket.io | GHSA-qv2v-m59f-v5fw (CVE-2017-16031) | CWE-330 | 1 | 1 | YES | UNRELATED_SECURITY_ALERT | Alert stems from generic behavioral pattern/sink resident in the affected file (e.g. dynamic code evaluation, process spawning, network communication, or regex exec), not the specific vulnerability weakness logic. |
