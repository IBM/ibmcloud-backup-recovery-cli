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

package backuprecoveryv1

import (
	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/bluemix/terminal"
	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/plugin"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/ibm-backup-recovery-sdk-go/backuprecoveryv1"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	translation "ibmcloud-backup-recovery-cli/i18n"
	"io"
)

type Utilities interface {
	HandleError(error, string)
	ConfirmRunningCommand()
	GetServiceURL(func(string) (string, error)) string
	ProcessResponse(*core.DetailedResponse, error)
	ProcessEmptyResponse(*core.DetailedResponse, error)
	ProcessBinaryResponse(*core.DetailedResponse, error, string)
	ExposeOutputFormatVar() *string
	ExposeJMESQueryVar() *string
	SetJMESQuery(string)
	GetJMESQuery() string
	SetJMESQueries(interface{}) error
	SetTableHeaderOrder([]string)
	SetOperationMetadata(interface{}) error
	CheckResponseForError(*core.DetailedResponse, error) (bool, interface{})
	NonZeroExit()
	Verbose(string)
	Print(string)
	Warn(string)
	Ok()
	Prompt(string, *terminal.PromptOptions) *terminal.Prompt
	ConfirmDelete(bool) bool
	WriteFile(interface{}, string) error
	PrintOutput(interface{}, io.Writer)
	OutputIsNotMachineReadable() bool
	GetAuthenticator(string) (core.Authenticator, error)
	GetRegionFromContext() string
	IsPrivateEndpointEnabled() bool
	PostProcessServiceConfiguration(*core.BaseService, string) error
	InitializeLogger(bool)
	ValidateRequiredFlags([]string, *pflag.FlagSet, string) error
	CreateErrorWithMessage(error, string) error
	SetServiceErrorMessages(map[string]string)
	GetPluginConfig() plugin.PluginConfig
	ValidateJSON(string, string) ([]string, error)
}

var ServiceInstance *backuprecoveryv1.BackupRecoveryV1

type BackupRecoveryV1CommandHelper struct {
	ServiceURL string
	RequiredFlags []string
	utils Utilities
}

type ServiceCommandHelper interface {
	InitializeServiceInstance(*pflag.FlagSet)
}

var Service ServiceCommandHelper

var serviceErrors = map[string]string{
	"badURL": translation.T("backup-recovery-bad-url-error-message"),
}

// add a function to return the super-command
func GetBackupRecoveryV1Command(utils Utilities) *cobra.Command {
	InitializeService(utils)
	localService := Service.(*BackupRecoveryV1CommandHelper) // convert variable for local use

	serviceCommands := []*cobra.Command{
		GetProtectionSourceGroup(utils),
		GetAgentUpgradeTaskGroup(utils),
		GetProtectionPolicyGroup(utils),
		GetProtectionGroupGroup(utils),
		GetProtectionGroupRunGroup(utils),
		GetRecoveryGroup(utils),
		GetDataSourceConnectionGroup(utils),
		GetDataSourceConnectorGroup(utils),
		GetDownloadAgentCommand(NewDownloadAgentCommandRunner(utils, DownloadAgentRequestSender{})),
		GetGetConnectorMetadataCommand(NewGetConnectorMetadataCommandRunner(utils, GetConnectorMetadataRequestSender{})),
		GetGetObjectSnapshotsCommand(NewGetObjectSnapshotsCommandRunner(utils, GetObjectSnapshotsRequestSender{})),
		GetCreateDownloadFilesAndFoldersRecoveryCommand(NewCreateDownloadFilesAndFoldersRecoveryCommandRunner(utils, CreateDownloadFilesAndFoldersRecoveryRequestSender{})),
		GetGetRestorePointsInTimeRangeCommand(NewGetRestorePointsInTimeRangeCommandRunner(utils, GetRestorePointsInTimeRangeRequestSender{})),
		GetDownloadIndexedFileCommand(NewDownloadIndexedFileCommandRunner(utils, DownloadIndexedFileRequestSender{})),
		GetSearchIndexedObjectsCommand(NewSearchIndexedObjectsCommandRunner(utils, SearchIndexedObjectsRequestSender{})),
		GetSearchObjectsCommand(NewSearchObjectsCommandRunner(utils, SearchObjectsRequestSender{})),
		GetSearchProtectedObjectsCommand(NewSearchProtectedObjectsCommandRunner(utils, SearchProtectedObjectsRequestSender{})),
		GetConfigCommand(NewConfigCommandRunner(utils)),
	}

	backupRecoveryCommand := &cobra.Command{
		Use: "backup-recovery [command] [options]",
		Short: translation.T("backup-recovery-short-description"),
		Long: translation.T("backup-recovery-long-description"),
		DisableFlagsInUseLine: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// ignore the error passed here - it just checks for a faulty implementation of the quiet flag
			quiet, _ := cmd.Flags().GetBool("quiet")
			utils.InitializeLogger(quiet)

			// these must only be set once the service command is actually executed
			utils.SetServiceErrorMessages(serviceErrors)
		},
	}

	// these flags pertain to all commands
	backupRecoveryCommand.PersistentFlags().StringVar(utils.ExposeOutputFormatVar(), "output", "table", translation.T("output-global-flag-description"))
	backupRecoveryCommand.PersistentFlags().StringVarP(utils.ExposeJMESQueryVar(), "jmes-query", "j", "", translation.T("jmes-query-global-flag-description"))
	backupRecoveryCommand.PersistentFlags().StringVar(&localService.ServiceURL, "service-url", "", translation.T("service-url-global-flag-description"))
	backupRecoveryCommand.PersistentFlags().BoolP("quiet", "q", false, translation.T("quiet-global-flag-description"))

	backupRecoveryCommand.AddCommand(serviceCommands...)

	return backupRecoveryCommand
}

func InitializeService(utils Utilities) {
	Service = &BackupRecoveryV1CommandHelper{utils: utils}
}
