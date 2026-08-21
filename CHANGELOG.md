# Changelog

## [0.7.1](https://github.com/mmartinez/postern/compare/v0.7.0...v0.7.1) (2026-08-21)


### Bug Fixes

* **broker:** canonicalize trailing-dot FQDN hosts ([#73](https://github.com/mmartinez/postern/issues/73)) ([2932c69](https://github.com/mmartinez/postern/commit/2932c69ef3f4826f213dd86317e057e0f1d41445))
* **config:** survive silent watch death in config hot reload ([#72](https://github.com/mmartinez/postern/issues/72)) ([28d0c54](https://github.com/mmartinez/postern/commit/28d0c5491c96c8f6288abe0972226ae70d723343))
* **proxy:** bind inner MITM requests to the CONNECT authority ([#71](https://github.com/mmartinez/postern/issues/71)) ([381e4db](https://github.com/mmartinez/postern/commit/381e4db411c51fc744943bb8eb12e3e038c9e1e4))
* **proxy:** bound outbound transport, tunnel dials, inbound idle conns; sanitize connection errors ([#70](https://github.com/mmartinez/postern/issues/70)) ([82bccd2](https://github.com/mmartinez/postern/commit/82bccd2da0ab00021512cd5533d388c51f3b1668))

## [0.7.0](https://github.com/mmartinez/postern/compare/v0.6.1...v0.7.0) (2026-08-14)


### Features

* multi-header credential injection ([#66](https://github.com/mmartinez/postern/issues/66)) ([da10869](https://github.com/mmartinez/postern/commit/da10869cd6de9f2a9e808c462d6f1438484cc275))

## [0.6.1](https://github.com/mmartinez/postern/compare/v0.6.0...v0.6.1) (2026-08-09)


### Bug Fixes

* **proxy:** hold goproxy at 1.8.4 to keep streaming unbuffered ([#61](https://github.com/mmartinez/postern/issues/61)) ([f5f45a0](https://github.com/mmartinez/postern/commit/f5f45a01b5352b7cb97e991f4e853b67b65f7021))

## [0.6.0](https://github.com/mmartinez/postern/compare/v0.5.0...v0.6.0) (2026-06-19)


### Features

* **oauth2:** persist rotated refresh tokens across restarts ([#52](https://github.com/mmartinez/postern/issues/52)) ([65e1c7c](https://github.com/mmartinez/postern/commit/65e1c7cd83a6ff22250bcf002ae06be0af2581f3))
* **proxy:** selective MITM — tunnel non-brokered hosts ([#56](https://github.com/mmartinez/postern/issues/56)) ([237f31f](https://github.com/mmartinez/postern/commit/237f31fa76bcd680748c06575a9510c1f1bdf0cc)), closes [#55](https://github.com/mmartinez/postern/issues/55)

## [0.5.0](https://github.com/mmartinez/postern/compare/v0.4.0...v0.5.0) (2026-06-13)


### Features

* OAuth2 and OAuth 1.0a credential brokering ([#48](https://github.com/mmartinez/postern/issues/48)) ([ec5b757](https://github.com/mmartinez/postern/commit/ec5b75784bfde8436163fc56e758ef5bff430535))

## [0.4.0](https://github.com/mmartinez/postern/compare/v0.3.3...v0.4.0) (2026-06-07)


### Features

* **broker:** route placeholder tokens to per-agent secrets ([#45](https://github.com/mmartinez/postern/issues/45)) ([287fec6](https://github.com/mmartinez/postern/commit/287fec6a4162d174a394b84f7c2663c7fb80d679))

## [0.3.3](https://github.com/mmartinez/postern/compare/v0.3.2...v0.3.3) (2026-06-05)


### Bug Fixes

* **credstore:** make credential cache background-refreshing to stop 502 storms ([#43](https://github.com/mmartinez/postern/issues/43)) ([8d44947](https://github.com/mmartinez/postern/commit/8d44947968eaf693172b5545bfeb174a1461885b))

## [0.3.2](https://github.com/mmartinez/postern/compare/v0.3.1...v0.3.2) (2026-06-03)


### Bug Fixes

* **credstore:** retain 1Password SDK client so GC finalizer can't free it ([#38](https://github.com/mmartinez/postern/issues/38)) ([ae97b67](https://github.com/mmartinez/postern/commit/ae97b678ccc46fb6fc2b5506eb820d1751c02c94))

## [0.3.1](https://github.com/mmartinez/postern/compare/v0.3.0...v0.3.1) (2026-06-03)


### Bug Fixes

* **broker:** forward oversized compressed/multipart bodies instead of 413 ([#36](https://github.com/mmartinez/postern/issues/36)) ([6a9a3c8](https://github.com/mmartinez/postern/commit/6a9a3c82f68d7183a54b328d044210b6474215da))

## [0.3.0](https://github.com/mmartinez/postern/compare/v0.2.1...v0.3.0) (2026-06-03)


### Features

* **broker:** substitute placeholders in body, path, and query ([#17](https://github.com/mmartinez/postern/issues/17)) ([#32](https://github.com/mmartinez/postern/issues/32)) ([a2698e6](https://github.com/mmartinez/postern/commit/a2698e627b2c758b1d278af335e1e135252e5bff))

## [0.2.1](https://github.com/mmartinez/postern/compare/v0.2.0...v0.2.1) (2026-06-02)


### Bug Fixes

* **config:** change default proxy port to 1701 ([2217fa9](https://github.com/mmartinez/postern/commit/2217fa9820cec695e09ee50be24915c3bfd09781))

## [0.2.0](https://github.com/mmartinez/postern/compare/v0.1.1...v0.2.0) (2026-06-02)


### Features

* initial public release ([e725ba3](https://github.com/mmartinez/postern/commit/e725ba33799bfa768168ba2aea22d7546713afc5))


### Bug Fixes

* **broker:** fail closed on empty placeholder token ([d733a93](https://github.com/mmartinez/postern/commit/d733a938bd1c6641830a9c4a1017646a2002d4f1))
* **ca:** refuse CA key with group- or world-readable permissions ([052d777](https://github.com/mmartinez/postern/commit/052d7771adaae08c17607e9ef300914cb698f0dc))
* **release:** append assets to the published release (immutability off) ([686fd76](https://github.com/mmartinez/postern/commit/686fd76a89ebfc9507cad4ecd3a52e62019aba1e))
* **release:** publish release-please draft so assets survive immutable releases ([c58b010](https://github.com/mmartinez/postern/commit/c58b010fd60e26f015115b5a17b5e13d953d0b6d))

## [0.1.1](https://github.com/mmartinez/postern/compare/v0.1.0...v0.1.1) (2026-06-02)


### Bug Fixes

* **release:** publish release-please draft so assets survive immutable releases ([c58b010](https://github.com/mmartinez/postern/commit/c58b010fd60e26f015115b5a17b5e13d953d0b6d))

## [0.1.0](https://github.com/mmartinez/postern/compare/v0.0.1...v0.1.0) (2026-06-02)


### Features

* initial public release ([e725ba3](https://github.com/mmartinez/postern/commit/e725ba33799bfa768168ba2aea22d7546713afc5))


### Bug Fixes

* **broker:** fail closed on empty placeholder token ([d733a93](https://github.com/mmartinez/postern/commit/d733a938bd1c6641830a9c4a1017646a2002d4f1))
* **ca:** refuse CA key with group- or world-readable permissions ([052d777](https://github.com/mmartinez/postern/commit/052d7771adaae08c17607e9ef300914cb698f0dc))
