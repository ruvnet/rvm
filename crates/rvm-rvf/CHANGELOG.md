# Changelog

## 0.2.1

- `StreamAdmission::refuse_report()` marks an already-built admission report as
  refused when a later gate (module validation, replay check) fails. The report
  stays readable, but `ok` is false, so `VerifiedPackage::from_report` rejects
  it. (#85)
- The two `/proc/self/task` thread-count tests in `identity_worker_lifetime.rs`
  are ignored off Linux. (#86)
- Package metadata: `homepage = "https://ruv.io"`.
