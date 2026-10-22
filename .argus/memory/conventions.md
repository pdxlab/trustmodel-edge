# Conventions in trustmodel-edge

## This runs on the customer's infrastructure

Edge is packaged as a Helm chart and installed into the customer's cluster.
Three consequences a reviewer should hold onto:

- **There is no rollback button.** A bad release is one the customer has
  already installed. Backwards compatibility of on-disk state and of the
  control-plane contract matters more here than in a service we deploy.
- **Egress is a promise, not a detail.** TRUS-2004 records a written
  "data never leaves" commitment that this component is the boundary for.
  Any new outbound call, hostname, or telemetry field is a material change
  and should be treated as `data-protection`, not plumbing.
- **The operator reading the logs is not us.** Error text and failure modes
  land in front of a customer's SRE who cannot read our source.

## Failing closed vs failing open

Enrolment failure currently **exits** rather than degrading, so a governance
failure takes down the host service. That is deliberate today and is being
revisited under TRUS-2375 (xspan asked for an optional degraded mode). Do not
report the current behaviour as a bug; do report a change that makes it
degrade silently.

## Credential files

`src/edge/identity.py` owns the on-disk credential set. It is read at startup
by `enroll.py` and on every rotation. Anything that writes these files is
security-critical — see `accepted-patterns.md` for the known gap.

## Versioning

`CHANGELOG.md` and `chart/trustmodel-edge/Chart.yaml` move together on a
release. A PR that changes one without the other is a real finding.
