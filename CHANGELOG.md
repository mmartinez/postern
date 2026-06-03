# Changelog

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
