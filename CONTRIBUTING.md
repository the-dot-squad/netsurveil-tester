# Contributing

Thanks for helping. This node runs on networks whose operators may be looking
for it, so changes are reviewed for how they affect the people running it as
much as for what they add.

Found a vulnerability? Do not open an issue; follow [SECURITY.md](SECURITY.md).

## Before you start

- For anything larger than a small fix, open an issue first so the approach
  can be agreed before you write code.
- Never put real node IDs, secrets, feed URLs, IP addresses or locations in
  issues, pull requests, logs or test fixtures.

## Setup

You need the Go version in [`go.mod`](go.mod), Docker with Compose for the e2e
suite, and `shellcheck` if you touch `install.sh`.

```sh
git clone https://github.com/the-dot-squad/netsurveil-tester.git
cd netsurveil-tester
make ci     # vet, lint, race tests, coverage floor, govulncheck, build
make e2e    # simulated censored network, needed for changes to checks or transports
```

## Ground rules for changes

- **Stay low-profile.** Don't add outbound traffic the node didn't already
  make, endpoints that answer unauthenticated requests with anything but an
  empty `404`, or log lines that contain targets, results or secrets. The
  reasoning is in [OPERATIONS.md](docs/OPERATIONS.md#3-low-profile-operation).
- **Keep the protocol in sync.** Changes to the envelope, transports or result
  format must update [PROTOCOL.md](docs/PROTOCOL.md), and `make vectors` if the
  envelope changes.
- **Test checks against the simulation, not the internet.** New check types or
  mechanisms need a case in `test/e2e` that reproduces the censorship they
  detect.
- **Fuzz untrusted input.** New parsers of network or request data get a fuzz
  target added to `FUZZ` in the `Makefile`.

## Pull requests

1. Fork the repository and branch from `main`.
2. Keep each pull request to one change, and run `make ci` before pushing.
3. Give the pull request a [Conventional Commits](https://www.conventionalcommits.org/)
   title. Pull requests are squash-merged, and the title becomes the changelog
   entry:
   - `feat(check): detect QUIC version downgrade`
   - `fix(feed): retry mirrors after a 403`
   - `docs: clarify the S3 bucket policy`

   Use `feat` and `fix` for changes users will notice, and `docs`, `test`,
   `refactor`, `build`, `ci` or `chore` for everything else. Mark breaking
   changes with `!` (`feat!: ...`) and describe them in the body.
4. CI must pass, and a maintainer must approve the change.

## License

By contributing, you agree that your contributions are licensed under the
[GNU Affero General Public License v3.0](LICENSE), the license of this project.
