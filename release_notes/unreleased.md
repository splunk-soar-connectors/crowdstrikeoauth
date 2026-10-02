**Unreleased**

* Replace the IOA rule and rule-group update actions' `enabled` checkbox with a `preserve` (default), `enable`, or `disable` choice. This prevents an unchecked SOAR checkbox from silently disabling a rule or group. Existing playbooks passing a boolean `enabled` value must use the corresponding string choice. This breaking action contract requires a major release.
* Bound pagination and stop when an API page makes no progress.
* Report when list-process results are truncated from the API's authoritative total.
* Bound command-result polling by time, sequence count, and response size.
* Report detonation polling timeouts as action failures while preserving the resource ID for follow-up.
* Reject device lookup metacharacters and verify resolved device identities before device actions.
* Fail batch device and indicator operations when the API reports any item errors.
* Escape dynamic values before embedding them in widget JavaScript string literals.
* Render action widgets with Jinja inheritance first, before any HTML comments.
* Validate generic query endpoints as canonical query paths before dispatch [PAPP-37947]
* Require approval for generic query actions and report process-result truncation accurately.
