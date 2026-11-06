**Unreleased**

- Upgrade to Splunk SOAR SDK 7.1.3 and refresh dependencies. App packages now support Python 3.13 and 3.15; Python 3.14 is no longer supported.
- Restore automatic playbook triggering for ingested detections and sub-events while preserving existing deduplication identifiers (SOARHELP-7363).
- Validate OAuth token caches, token responses, and datafeed descriptors; retain the correct tenant during session refresh and report token persistence failures clearly (PAPP-37903).
- Close streams reliably and identify ingestion stages, partial batches, and checkpoint staging in logs. Checkpoints commit through the SDK only after successful saves.
- Save valid events received before a session-refresh failure and warn when malformed records are skipped. Committing a later valid offset can permanently skip earlier malformed records. Transport, parsing, and save failures preserve the previous checkpoint.

Authored by OpenAI Codex.
