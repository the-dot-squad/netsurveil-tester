# Security policy

People run this node inside networks that censor and monitor them. A flaw
that lets someone fingerprint a node, forge or read requests, or make a node
attack a third party can put its operator at risk, so please report it
privately.

## Reporting a vulnerability

Report it through
[GitHub private vulnerability reporting](https://github.com/the-dot-squad/netsurveil-tester/security/advisories/new).
Do not open a public issue or pull request.

Include the affected version (`nst-node -version`), the steps to reproduce,
and the impact you expect. Leave out real node IDs, secrets, addresses and
locations.

We aim to acknowledge reports within 3 working days and to agree a disclosure
date with you once a fix is ready.

## Scope

In scope:

- the node binary, the container image and `install.sh`;
- the envelope and transport protocol described in [PROTOCOL.md](docs/PROTOCOL.md);
- anything that lets an observer distinguish a node from an ordinary web
  server, or links a node to the netsurveil website.

Out of scope: the netsurveil website itself, and censorship detection that is
inaccurate but harmless (open a normal issue for those).

## Supported versions

Only the latest release receives security fixes.
