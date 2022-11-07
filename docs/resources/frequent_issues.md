---
layout: ""
page_title: dynatrace_frequent_issues Resource - terraform-provider-dynatrace"
description: |-
  The resource `dynatrace_frequent_issues` covers configuration for frequent issue detection
---

# dynatrace_frequent_issues (Resource)

## Dynatrace Documentation

- Detection of frequent issues - https://www.dynatrace.com/support/help/how-to-use-dynatrace/problem-detection-and-analysis/problem-detection/detection-of-frequent-issues

- Settings API - https://www.dynatrace.com/support/help/dynatrace-api/environment-api/settings (schemaId: `builtin:anomaly-detection.frequent-issues`)

## Export Example Usage

- `terraform-provider-dynatrace export dynatrace_frequent_issues` downloads the existing frequent issue detection configuration

The full documentation of the export feature is available [here](https://registry.terraform.io/providers/dynatrace-oss/dynatrace/latest/docs#exporting-existing-configuration-from-a-dynatrace-environment).

## Resource Example Usage

```terraform
resource "dynatrace_frequent_issues" "#name#" {
  detect_apps = true
  detect_txn = true
  detect_infra = true
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `detect_apps` (Boolean) Detect frequent issues within applications, enabled (`true`) or disabled (`false`)
- `detect_infra` (Boolean) Detect frequent issues within infrastructure, enabled (`true`) or disabled (`false`)
- `detect_txn` (Boolean) Detect frequent issues within transactions and services, enabled (`true`) or disabled (`false`)

### Read-Only

- `id` (String) The ID of this resource.
 