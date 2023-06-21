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

package entrypoints

import (
	"github.com/dynatrace-oss/terraform-provider-dynatrace/dynatrace/settings"
	"github.com/dynatrace-oss/terraform-provider-dynatrace/dynatrace/settings/services/settings20"

	entrypoints "github.com/dynatrace-oss/terraform-provider-dynatrace/dynatrace/api/builtin/span/entrypoints/settings"
)

const SchemaID = "builtin:span-entry-points"
const SchemaVersion = "0.1.16"

func Service(credentials *settings.Credentials) settings.CRUDService[*entrypoints.SpanEntryPoint] {
	return settings20.Service[*entrypoints.SpanEntryPoint](credentials, SchemaID, SchemaVersion)
}