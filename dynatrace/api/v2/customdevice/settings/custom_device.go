package customdevice

import (
	"github.com/dynatrace-oss/terraform-provider-dynatrace/terraform/hcl"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type CustomDevice struct {
	EntityId       string  `json:"entityId,omitempty"`       // The ID of the custom device.
	DisplayName    *string `json:"displayName,omitempty"`    // The name of the custom device, displayed in the UI.
	CustomDeviceID string  `json:"customDeviceId,omitempty"` // A unique name that can be provided or generated by the provider
}

type CustomDeviceGetResponse struct {
	Entities []*CustomDevice `json:"entities,omitempty"` // An unordered list of custom devices
}

func (me *CustomDevice) Schema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"entity_id": {
			Type:        schema.TypeString,
			Description: "The Dynatrace EntityID of this resource. If you need to refer to this custom device within other resources you want to use this ID",
			Computed:    true,
		},
		"display_name": {
			Type:        schema.TypeString,
			Description: "The name of the custom device, displayed in the UI.",
			Required:    true,
		},
		"custom_device_id": {
			Type:        schema.TypeString,
			Description: "The unique name of the custom device. This Id can either be provided in the resource or generated by Terraform when the resource is created. If you use the ID of an existing device, the respective parameters will be updated",
			Optional:    true,
			Computed:    true,
			ForceNew:    true,
		},
	}
}

func (me *CustomDeviceGetResponse) Schema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"entities": {
			Type:        schema.TypeString,
			Description: "The list of entities returned by the GET call.",
			Optional:    true,
			Computed:    true,
		},
	}
}

func (me *CustomDeviceGetResponse) MarshalHCL(properties hcl.Properties) error {
	if err := properties.EncodeAll(map[string]any{
		"entities": me.Entities,
	}); err != nil {
		return err
	}
	return nil
}

func (me *CustomDeviceGetResponse) UnmarshalHCL(decoder hcl.Decoder) error {
	return decoder.DecodeAll(map[string]any{
		"entities": &me.Entities,
	})
}

func (me *CustomDevice) MarshalHCL(properties hcl.Properties) error {
	if err := properties.EncodeAll(map[string]any{
		"entity_id":        me.EntityId,
		"display_name":     me.DisplayName,
		"custom_device_id": me.CustomDeviceID,
	}); err != nil {
		return err
	}
	return nil
}

func (me *CustomDevice) UnmarshalHCL(decoder hcl.Decoder) error {
	return decoder.DecodeAll(map[string]any{
		"entity_id":        &me.EntityId,
		"display_name":     &me.DisplayName,
		"custom_device_id": &me.CustomDeviceID,
	})
}

func (me *CustomDevice) Name() string {
	return *me.DisplayName
}