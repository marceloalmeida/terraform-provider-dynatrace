/**
* @license
* Copyright 2020 Dynatrace LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
 */

package processavailability

import (
	"fmt"

	"github.com/dynatrace-oss/terraform-provider-dynatrace/dynatrace/api"
	processavailability "github.com/dynatrace-oss/terraform-provider-dynatrace/dynatrace/api/builtin/processavailability/settings"
	"github.com/dynatrace-oss/terraform-provider-dynatrace/dynatrace/settings"
	"github.com/dynatrace-oss/terraform-provider-dynatrace/dynatrace/settings/services/settings20"
)

const SchemaVersion = "1.0.2"
const SchemaID = "builtin:processavailability"

func Service(credentials *settings.Credentials) settings.CRUDService[*processavailability.Settings] {
	return settings20.Service[*processavailability.Settings](credentials, SchemaID, SchemaVersion, &settings20.ServiceOptions[*processavailability.Settings]{Duplicates: Duplicates})
}

func Duplicates(service settings.RService[*processavailability.Settings], v *processavailability.Settings) (*api.Stub, error) {
	if settings.RejectDuplicate("dynatrace_process_availability") {
		var err error
		var stubs api.Stubs
		if stubs, err = service.List(); err != nil {
			return nil, err
		}
		for _, stub := range stubs {
			if v.Name == stub.Name {
				return nil, fmt.Errorf("Process Availability Rule with name `%s` already exists", v.Name)
			}
		}
	} else if settings.HijackDuplicate("dynatrace_process_availability") {
		var err error
		var stubs api.Stubs
		if stubs, err = service.List(); err != nil {
			return nil, err
		}
		for _, stub := range stubs {
			if v.Name == stub.Name {
				return stub, nil
			}
		}
	}
	return nil, nil
}
