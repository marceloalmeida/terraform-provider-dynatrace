---
layout: ""
page_title: dynatrace_web_app_key_performance_xhr Resource - terraform-provider-dynatrace"
description: |-
  The resource `dynatrace_web_app_key_performance_xhr` covers apdex threshold configuration for XHR actions

---

# dynatrace_web_app_key_performance_xhr (Resource)

-> **Settings 2.0** Certain field(s) of this resource has overlap with `dynatrace_web_application`, therefore it is excluded from the default export. To retrieve this resource via export, directly specify it as a command line argument. 

## Dynatrace Documentation

- Adjust Apdex settings for web applications - https://www.dynatrace.com/support/help/platform-modules/digital-experience/web-applications/additional-configuration/configure-apdex-web

- Settings API - https://www.dynatrace.com/support/help/dynatrace-api/environment-api/settings (schemaId: `builtin:rum.web.key-performance-metric-xhr-actions`)

## Export Example Usage

- `terraform-provider-dynatrace -export dynatrace_web_app_key_performance_xhr` downloads all existing apdex threshold configuration for XHR actions

The full documentation of the export feature is available [here](https://registry.terraform.io/providers/dynatrace-oss/dynatrace/latest/docs/guides/export-v2).

## Resource Example Usage

```terraform
resource "dynatrace_web_app_key_performance_xhr" "#name#" {
  kpm   = "VISUALLY_COMPLETE"
  scope = "APPLICATION_METHOD-1234567890000000"
  fallback_thresholds {
    frustrating_fallback_threshold_seconds = 12
    tolerated_fallback_threshold_seconds   = 3
  }
  thresholds {
    frustrating_threshold_seconds = 12
    tolerated_threshold_seconds   = 3
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `kpm` (String) Possible Values: `RESPONSE_END`, `RESPONSE_START`, `USER_ACTION_DURATION`, `VISUALLY_COMPLETE`
- `scope` (String) The scope of this setting (APPLICATION_METHOD, APPLICATION)
- `thresholds` (Block List, Min: 1, Max: 1) Set the Tolerating and Frustrated performance thresholds for this action type. (see [below for nested schema](#nestedblock--thresholds))

### Optional

- `fallback_thresholds` (Block List, Max: 1) If the selected key performance metric is not detected, the **User action duration** metric is used instead. (see [below for nested schema](#nestedblock--fallback_thresholds))

### Read-Only

- `id` (String) The ID of this resource.

<a id="nestedblock--thresholds"></a>
### Nested Schema for `thresholds`

Required:

- `frustrating_threshold_seconds` (Number) If the key performance metric is above this value, the action is assigned to the Frustrated performance zone.
- `tolerated_threshold_seconds` (Number) If the key performance metric is below this value, the action is assigned to the Satisfied performance zone.


<a id="nestedblock--fallback_thresholds"></a>
### Nested Schema for `fallback_thresholds`

Required:

- `frustrating_fallback_threshold_seconds` (Number) If **User action duration** is above this value, the action is assigned to the Frustrated performance zone.
- `tolerated_fallback_threshold_seconds` (Number) If **User action duration** is below this value, the action is assigned to the Satisfied performance zone.
 