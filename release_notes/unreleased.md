**Unreleased**

* Add `field_values_substitutions` parameter to the custom IOA rule creation action, allowing comma-separated values to be substituted into `{0}`, `{1}`, ... placeholders in `field_values` JSON. This makes it easier to map playbook datapaths directly to rule parameters without embedding dynamic values inside a JSON string.
