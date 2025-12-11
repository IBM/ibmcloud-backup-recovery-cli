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
	translation "ibmcloud-backup-recovery-cli/i18n"
	"io"

	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/bluemix/terminal"
	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/plugin"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/ibm-backup-recovery-sdk-go/backuprecoveryv1"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
var ConnectorServiceInstance *backuprecoveryv1.BackupRecoveryV1Connector
var ManagementConsoleServiceInstance *backuprecoveryv1.BackupRecoveryManagementReportingApiV1
var ManagementConsoleSreServiceInstance *backuprecoveryv1.BackupRecoveryManagementSreApiV1

type BackupRecoveryV1CommandHelper struct {
	ServiceURL                            string
	ConnectorURL                          string
	ManagementConsoleReportingUrl         string
	ManagementConsoleSreUrl               string
	ManagementConsoleSreAuthenticationUrl string
	ManagementConsoleSreUsername          string
	ManagementConsoleSrePassword          string
	ManagementConsoleSreApikey            string
	RequiredFlags                         []string
	utils                                 Utilities
}

type ServiceCommandHelper interface {
	InitializeServiceInstance(*pflag.FlagSet)
	InitializeConnectorServiceInstance(*pflag.FlagSet)
	InitializeManagementReportingServiceInstance(*pflag.FlagSet)
	InitializeManagementSreServiceInstance(*pflag.FlagSet)
}

var Service ServiceCommandHelper

var serviceErrors = map[string]string{
	"badURL":                          translation.T("backup-recovery-bad-url-error-message"),
	"badConnectorURL":                 translation.T("backup-recovery-bad-connector-url-error-message"),
	"badManagementConsoleURL":         translation.T("backup-recovery-bad-management-console-reporting-url-error-message"),
	"badManagementConsoleSreURL":      translation.T("backup-recovery-bad-management-console-sre-url-error-message"),
	"badManagementConsoleSreUsername": translation.T("backup-recovery-bad-management-console-sre-username-error-message"),
	"badManagementConsoleSreAuthUrl":  translation.T("backup-recovery-bad-management-console-sre-authentication-url-error-message"),
	"badManagementConsoleSrePassword": translation.T("backup-recovery-bad-management-console-sre-password-error-message"),
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
		GetManagementConsoleGroup(utils),
		GetClusterUpgradeGroup(utils),
		GetAlertsGroup(utils),
		GetGetProviderInstancesCommand(NewGetProviderInstancesCommandRunner(utils, GetProviderInstancesRequestSender{})),
		GetManagementConsoleAlertsGroup(utils),
		GetClusterGroup(utils),
		GetDataSourceConnectionGroup(utils),
		GetDataSourceConnectorGroup(utils),
		GetCreateAccessTokenCommand(NewCreateAccessTokenCommandRunner(utils, CreateAccessTokenRequestSender{})),
		GetDownloadAgentCommand(NewDownloadAgentCommandRunner(utils, DownloadAgentRequestSender{})),
		GetGetConnectorMetadataCommand(NewGetConnectorMetadataCommandRunner(utils, GetConnectorMetadataRequestSender{})),
		GetGetDataSourceConnectorLogsCommand(NewGetDataSourceConnectorLogsCommandRunner(utils, GetDataSourceConnectorLogsRequestSender{})),
		GetRegisterDataSourceConnectorCommand(NewRegisterDataSourceConnectorCommandRunner(utils, RegisterDataSourceConnectorRequestSender{})),
		GetGetDataSourceConnectorStatusCommand(NewGetDataSourceConnectorStatusCommandRunner(utils, GetDataSourceConnectorStatusRequestSender{})),
		GetGetObjectSnapshotsCommand(NewGetObjectSnapshotsCommandRunner(utils, GetObjectSnapshotsRequestSender{})),
		GetCreateDownloadFilesAndFoldersRecoveryCommand(NewCreateDownloadFilesAndFoldersRecoveryCommandRunner(utils, CreateDownloadFilesAndFoldersRecoveryRequestSender{})),
		GetGetRestorePointsInTimeRangeCommand(NewGetRestorePointsInTimeRangeCommandRunner(utils, GetRestorePointsInTimeRangeRequestSender{})),
		GetDownloadIndexedFileCommand(NewDownloadIndexedFileCommandRunner(utils, DownloadIndexedFileRequestSender{})),
		GetSearchIndexedObjectsCommand(NewSearchIndexedObjectsCommandRunner(utils, SearchIndexedObjectsRequestSender{})),
		GetSearchObjectsCommand(NewSearchObjectsCommandRunner(utils, SearchObjectsRequestSender{})),
		GetSearchProtectedObjectsCommand(NewSearchProtectedObjectsCommandRunner(utils, SearchProtectedObjectsRequestSender{})),
		GetGetUsersCommand(NewGetUsersCommandRunner(utils, GetUsersRequestSender{})),
		GetUpdateUserCommand(NewUpdateUserCommandRunner(utils, UpdateUserRequestSender{})),
		GetConfigCommand(NewConfigCommandRunner(utils)),
	}

	backupRecoveryCommand := &cobra.Command{
		Use:                   "backup-recovery [command] [options]",
		Short:                 translation.T("backup-recovery-short-description"),
		Long:                  translation.T("backup-recovery-long-description"),
		DisableFlagsInUseLine: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// ignore the error passed here - it just checks for a faulty implementation of the quiet flag
			quiet, _ := cmd.Flags().GetBool("quiet")
			utils.InitializeLogger(quiet)

			// these must only be set once the service command is actually executed
			utils.SetServiceErrorMessages(serviceErrors)
		},
	}

	backupRecoveryCommand.Flags().StringVar(&localService.ServiceURL, "service-url", "", translation.T("service-url-global-flag-description"))
	backupRecoveryCommand.PersistentFlags().StringVar(&localService.ConnectorURL, "connector-service-url", "", translation.T("connector-service-url-global-flag-description"))
	backupRecoveryCommand.PersistentFlags().StringVar(&localService.ManagementConsoleReportingUrl, "management-reporting-service-url", "", translation.T("management-reporting-service-url-global-flag-description"))
	backupRecoveryCommand.PersistentFlags().StringVar(&localService.ManagementConsoleSreUrl, "management-sre-service-url", "", translation.T("management-sre-url-global-flag-description"))
	backupRecoveryCommand.PersistentFlags().StringVar(&localService.ManagementConsoleSreAuthenticationUrl, "management-sre-service-authentication-url", "", translation.T("management-sre-service-authentication-url-global-flag-description"))
	backupRecoveryCommand.PersistentFlags().StringVar(&localService.ManagementConsoleSrePassword, "management-sre-service-password", "", translation.T("management-sre-service-password-global-flag-description"))
	backupRecoveryCommand.PersistentFlags().StringVar(&localService.ManagementConsoleSreUsername, "management-sre-service-username", "", translation.T("management-sre-service-username-global-flag-description"))
	backupRecoveryCommand.PersistentFlags().StringVar(&localService.ManagementConsoleSreApikey, "management-sre-service-apikey", "", translation.T("management-sre-service-apikey-global-flag-description"))

	// these flags pertain to all commands
	backupRecoveryCommand.PersistentFlags().StringVar(utils.ExposeOutputFormatVar(), "output", "table", translation.T("output-global-flag-description"))
	backupRecoveryCommand.PersistentFlags().StringVarP(utils.ExposeJMESQueryVar(), "jmes-query", "j", "", translation.T("jmes-query-global-flag-description"))
	backupRecoveryCommand.PersistentFlags().BoolP("quiet", "q", false, translation.T("quiet-global-flag-description"))

	backupRecoveryCommand.AddCommand(serviceCommands...)
	return backupRecoveryCommand
}

func InitializeService(utils Utilities) {
	Service = &BackupRecoveryV1CommandHelper{utils: utils}
}
