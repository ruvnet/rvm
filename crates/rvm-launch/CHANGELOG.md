# Changelog

## 0.2.1

- Fix: a refused stream never leaves an `ok` admission report. When the WASM
  segment's completion was the stream's completion, the report was built before
  `validator.finish()` ran, and a module that full validation refused could still
  be turned into a `VerifiedPackage`. `StreamSession::fail()` now calls
  `refuse_report()`. Requires rvm-rvf 0.2.1. (#85, QA by @martinvlad)
- Randomized panic-hunt tests over walk/verify and `StreamSession`
  (`RVM_PANIC_HUNT_ITERS`, 1,000 iterations by default). (#85)
- Package metadata: `homepage = "https://ruv.io"`.
