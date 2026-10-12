# October 12 maintenance update

This main-line maintenance change is deliberately separate from the larger guided
incident-response development branch. It includes the reviewed frontend dependency
update, browser regression checks, and safer private state/enrollment file writers.

The private writers use exclusive binary temporary files, preserve the previous
destination after failed writes, reject symlink destinations, and refuse atomic
no-replace enrollment rather than overwrite a concurrent winner. The enrollment
CLI preserves the final path component and rejects a symlink or unapproved
existing destination before contacting the enrollment API.

The original parameterless, approval-gated action registry, policy service,
analyst authentication and protocol schema are unchanged. A regression locks the
four main-line actions and rejects arbitrary PID or command parameters. No process
containment, triage evidence store, quarantine, firewall action, autonomous response
or expanded vNext handoff was imported into the public default application.

The main-based Linux backend suite passed 122 tests with warnings treated as errors;
production-file hashes were checked during preparation. The maintained CI also
runs the Windows backend suite, source audit, frontend typecheck/build/dependency
audit and a real six-route Chromium check with synthetic incidents. The browser
test starts no endpoint agents and requests no response actions. For a candidate,
use its actual CI outcomes; the presence of tests alone is not a passing result.

Keep the agent state directory owner-controlled. This targeted repair is not a
claim of exhaustive operating-system ACL/reparse security or Internet-facing
production readiness. The separate full vNext remediation-coverage requirements
remain unchanged and are not satisfied by this maintenance update.
