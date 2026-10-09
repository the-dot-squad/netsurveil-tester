# Changelog

## [0.1.1](https://github.com/the-dot-squad/netsurveil-tester/compare/v0.1.0...v0.1.1) (2026-10-09)


### Features

* **config:** let NODE_PORT set the node's listen port ([#17](https://github.com/the-dot-squad/netsurveil-tester/issues/17)) ([dae2daf](https://github.com/the-dot-squad/netsurveil-tester/commit/dae2daf01f31ba07d7dc576997ba7ebb41d24886))
* **node:** rate-limit only rejected requests and add TRUSTED_PROXIES ([#16](https://github.com/the-dot-squad/netsurveil-tester/issues/16)) ([52a7d4e](https://github.com/the-dot-squad/netsurveil-tester/commit/52a7d4ee3a15f36d31c03da1c494ac732c129d77))


### Bug Fixes

* **check:** find the public IP on networks that block 1.1.1.1 ([#13](https://github.com/the-dot-squad/netsurveil-tester/issues/13)) ([4fc3a19](https://github.com/the-dot-squad/netsurveil-tester/commit/4fc3a19ec96a19a919a86e4cf8a4096f0f0dbbb8))
* **deps:** move to Go 1.27.2 and golang.org/x/net 0.60.0 ([#12](https://github.com/the-dot-squad/netsurveil-tester/issues/12)) ([e76ad8f](https://github.com/the-dot-squad/netsurveil-tester/commit/e76ad8f388806b0cc38ff8bcffcf619a40d3dac0))


### Performance

* **check:** race DNS controls so a blocked resolver cannot stall checks ([#15](https://github.com/the-dot-squad/netsurveil-tester/issues/15)) ([4c16ca6](https://github.com/the-dot-squad/netsurveil-tester/commit/4c16ca688c7029c0d38b4ee938b92ad37c290f99))

## 0.1.0 (2026-10-08)


### Features

* initial release of the NetSurveil tester node ([65aac48](https://github.com/the-dot-squad/netsurveil-tester/commit/65aac48511b79b4a1e55a3a6d0ea5344509e5c05))


### Bug Fixes

* **check:** report check_timeout when an I/O deadline beats the context timer ([#6](https://github.com/the-dot-squad/netsurveil-tester/issues/6)) ([e87a8a4](https://github.com/the-dot-squad/netsurveil-tester/commit/e87a8a41cabc9864d9eafd912652fe70b7b623f6))
* **deps:** Bump the go group across 1 directory with 2 updates ([#1](https://github.com/the-dot-squad/netsurveil-tester/issues/1)) ([e64c61b](https://github.com/the-dot-squad/netsurveil-tester/commit/e64c61b533b4c3ef127288e5a7245d0589493f7f))


### Documentation

* drop repository setup notes from the README ([#7](https://github.com/the-dot-squad/netsurveil-tester/issues/7)) ([564ea81](https://github.com/the-dot-squad/netsurveil-tester/commit/564ea816ddbf7acfc1e39ef616bbc3344ca244e9))
