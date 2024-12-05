/**
 * (C) Copyright IBM Corp. 2024.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * IBM OpenAPI SDK Code Generator Version: 3.96.1-5136e54a-20241108-203028
 */

package main

import (
	ibm_cloud_plugin "github.com/IBM-Cloud/ibm-cloud-cli-sdk/plugin"
	"ibmcloud-backup-recovery-cli/plugin"
	"ibmcloud-backup-recovery-cli/plugin/commands"
)

func main() {
	commands.Init()
	ibm_cloud_plugin.Start(new(plugin.Plugin))
}
