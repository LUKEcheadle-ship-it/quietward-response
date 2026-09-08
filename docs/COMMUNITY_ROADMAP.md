# QuietWard Response community roadmap

QuietWard Response is building toward a useful local incident-investigation and controlled-response platform without introducing a generic remote-command surface.

This roadmap is public so users can understand the direction of the project and contributors can choose work that improves the product without expanding endpoint authority casually.

## Near term: make the first 10 minutes excellent

- ship `scripts/quick_demo.py` for one-command startup with safe synthetic incidents;
- improve first-run error messages and prerequisite checks;
- make QuietWard pairing and bridge health easier to understand;
- add a guided sample incident that demonstrates timeline -> recommendation -> approval -> diagnostic -> signed result;
- improve screenshots and user-facing documentation.

## Investigation experience

- faster incident search and filtering;
- clearer severity, provenance, and recommendation presentation;
- stronger timeline navigation;
- better analyst notes and sanitized export workflows;
- clearer distinction between observation, recommendation, approval, execution, and verification.

## Read-only diagnostics

The next useful capability work should stay bounded and investigation-focused:

- improve Windows diagnostic parity;
- enrich host/process/network summaries without collecting raw unnecessary secrets;
- add clearer capability/availability explanations when an action is unsupported;
- improve crash/retry visibility;
- keep diagnostics parameterless or tightly typed rather than exposing arbitrary commands.

## QuietWard integration

- easier local pairing;
- bridge health/status surfaced in the UI;
- better provenance navigation back to QuietWard evidence-chain context;
- clearer backpressure and handoff error reporting;
- continued rejection of raw finding subjects and untrusted nested evidence.

## Community-friendly work

Good contribution areas include:

- frontend usability and accessibility;
- documentation and screenshots;
- synthetic demo scenarios;
- API documentation;
- tests and migration coverage;
- Windows/Linux portability;
- sanitized export formats;
- installer and bootstrap ergonomics.

## Security boundary

Future contributions must not silently add:

- arbitrary shell / PowerShell / cmd / bash execution;
- arbitrary PID/path/network-address targeting;
- autonomous remediation;
- general-purpose remote administration;
- unrestricted process, service, firewall, or host-isolation control.

Security-sensitive capability expansion requires explicit threat-model changes, tests, and release qualification.
