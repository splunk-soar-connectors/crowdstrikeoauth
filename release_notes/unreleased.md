**Unreleased**

* Preserve the existing IOA rule and rule-group enabled state when the optional enabled parameter is omitted. This corrects the prior replace-style default and requires a major release.
* Update the Splunk SOAR SDK dependency to 3.28.1.
* Bound pagination and stop when an API page makes no progress.
* Report when list-process results are truncated from the API's authoritative total.
* Bound command-result polling by time, sequence count, and response size.
* Report detonation polling timeouts as action failures while preserving the resource ID for follow-up.
* Reject device lookup metacharacters and verify resolved device identities before device actions.
* Fail batch device and indicator operations when the API reports any item errors.
* Escape dynamic values before embedding them in widget JavaScript string literals.
* Validate generic query endpoints as canonical query paths before dispatch [PAPP-37947]
