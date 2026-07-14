**Unreleased**

* Removed executable asset preprocessing so asset configuration cannot run connector code.
* Escaped connector widget values before embedding them in inline JavaScript handlers.
* Restricted the run query action to bare CrowdStrike query endpoint paths and corrected its read-only declaration.
* Corrected read-only declarations for tenant-wide detection, incident, RTR, IOA, and indicator retrieval actions.
* Encoded ingestion container lookups and limited container reuse to the current asset.
* Reported the authoritative process total and whether list process results were truncated by the requested limit.
* Bounded shared, custom-indicator, and IOA pagination loops and rejected non-advancing server cursors.
