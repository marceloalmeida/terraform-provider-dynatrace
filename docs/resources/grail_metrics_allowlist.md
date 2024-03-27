---
layout: ""
page_title: dynatrace_grail_metrics_allowlist Resource - terraform-provider-dynatrace"
subcategory: "Platform"
description: |-
  The resource `dynatrace_grail_metrics_allowlist` covers allow list configuration of custom metric ingestion to Grail
---

# dynatrace_grail_metrics_allowlist (Resource)

-> This resource requires the API token scopes **Read settings** (`settings.read`) and **Write settings** (`settings.write`)

## Dynatrace Documentation

- Grail - https://docs.dynatrace.com/docs/platform/grail

- Settings API - https://www.dynatrace.com/support/help/dynatrace-api/environment-api/settings (schemaId: `builtin:grail.metrics.allow-list`)

## Export Example Usage

- `terraform-provider-dynatrace -export dynatrace_grail_metrics_allowlist` downloads existing grail metrics configuration

The full documentation of the export feature is available [here](https://registry.terraform.io/providers/dynatrace-oss/dynatrace/latest/docs/guides/export-v2).

## Resource Example Usage

```terraform
resource "dynatrace_grail_metrics_allowlist" "#name#" {
  allow_rules {
    allow_rule {
      enabled = false
      metric_key = "terraform"
      pattern = "CONTAINS"
    }
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `allow_rules` (Block List, Max: 1) Specify rules for forwarding metrics (see [below for nested schema](#nestedblock--allow_rules))

### Read-Only

- `id` (String) The ID of this resource.

<a id="nestedblock--allow_rules"></a>
### Nested Schema for `allow_rules`

Required:

- `allow_rule` (Block Set, Min: 1) (see [below for nested schema](#nestedblock--allow_rules--allow_rule))

<a id="nestedblock--allow_rules--allow_rule"></a>
### Nested Schema for `allow_rules.allow_rule`

Required:

- `enabled` (Boolean) This setting is enabled (`true`) or disabled (`false`)
- `metric_key` (String) Metric key
- `pattern` (String) Possible Values: `CONTAINS`, `EQUALS`, `STARTSWITH`
 