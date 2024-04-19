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

package backuprecoveryv1

import (
	"errors"
	translation "ibmcloud-backup-recovery-cli/i18n"
	"ibmcloud-backup-recovery-cli/plugin/version"
	"ibmcloud-backup-recovery-cli/utils"
	"ibmcloud-backup-recovery-cli/utils/deserialize"
	"net/http"
	"reflect"
	"strings"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/ibm-backup-recovery-sdk-go/backuprecoveryv1"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var serviceName string = "backup_recovery"

func (r *BackupRecoveryV1CommandHelper) GetAuthenticatorAndURL() (core.Authenticator, string) {
	authenticator, err := r.utils.GetAuthenticator(serviceName)
	r.utils.HandleError(err, translation.T("credentials-error"))

	serviceUrl := r.utils.GetServiceURL(backuprecoveryv1.GetServiceURLForRegion)

	return authenticator, serviceUrl
}

func (r *BackupRecoveryV1CommandHelper) CreateServiceInstance(options backuprecoveryv1.BackupRecoveryV1Options) {
	configurationErrorMessage := translation.T("config-error")

	backupRecovery, backupRecoveryErr := backuprecoveryv1.NewBackupRecoveryV1UsingExternalConfig(&options)
	r.utils.HandleError(backupRecoveryErr, configurationErrorMessage)

	// the cli differs from the sdk on configuration priority
	// ensure the correct priority is being used
	configErr := r.utils.PostProcessServiceConfiguration(backupRecovery.Service, serviceName)
	r.utils.HandleError(configErr, configurationErrorMessage)

	config := r.utils.GetPluginConfig()
	if r.ServiceURL != "" {
		configErr = backupRecovery.SetServiceURL(r.ServiceURL)
		r.utils.HandleError(configErr, configurationErrorMessage)
	} else if config.Exists(serviceName + "-service-url") {
		url, err := config.GetString(serviceName + "-service-url")
		if err != nil {
			core.GetLogger().Warn(translation.T("config-reading-read-error", getConfigCmdNameMap("service-url")))
			core.GetLogger().Info(err.Error())
		} else {
			configErr = backupRecovery.SetServiceURL(url)
			r.utils.HandleError(configErr, configurationErrorMessage)
		}
	}

	// set custom analytics header for the CLI
	customHeaders := http.Header{}
	customHeaders.Add("X-Original-User-Agent", "ibmcloud-backup-recovery-cli/"+version.GetPluginVersion().String())
	backupRecovery.SetDefaultHeaders(customHeaders)

	ServiceInstance = backupRecovery
}

func (r *BackupRecoveryV1CommandHelper) InitializeServiceInstance(parentFlags *pflag.FlagSet) {
	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, parentFlags, serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	authenticator, serviceUrl := r.GetAuthenticatorAndURL()
	options := backuprecoveryv1.BackupRecoveryV1Options{
		Authenticator: authenticator,
		// default to the contextual url, it may be overridden by an environment variable
		URL: serviceUrl,
	}

	r.CreateServiceInstance(options)
}

type RequestSender interface {
	Send(interface{}) (interface{}, *core.DetailedResponse, error)
}

func GetProtectionSourceGroup(utils Utilities) *cobra.Command {
	commands := []*cobra.Command{
		GetListProtectionSourcesCommand(NewListProtectionSourcesCommandRunner(utils, ListProtectionSourcesRequestSender{})),
		GetGetSourceRegistrationsCommand(NewGetSourceRegistrationsCommandRunner(utils, GetSourceRegistrationsRequestSender{})),
		GetRegisterProtectionSourceCommand(NewRegisterProtectionSourceCommandRunner(utils, RegisterProtectionSourceRequestSender{})),
		GetGetProtectionSourceRegistrationCommand(NewGetProtectionSourceRegistrationCommandRunner(utils, GetProtectionSourceRegistrationRequestSender{})),
		GetUpdateProtectionSourceRegistrationCommand(NewUpdateProtectionSourceRegistrationCommandRunner(utils, UpdateProtectionSourceRegistrationRequestSender{})),
		GetPatchProtectionSourceRegistrationCommand(NewPatchProtectionSourceRegistrationCommandRunner(utils, PatchProtectionSourceRegistrationRequestSender{})),
		GetDeleteProtectionSourceRegistrationCommand(NewDeleteProtectionSourceRegistrationCommandRunner(utils, DeleteProtectionSourceRegistrationRequestSender{})),
		GetRefreshProtectionSourceByIDCommand(NewRefreshProtectionSourceByIDCommandRunner(utils, RefreshProtectionSourceByIDRequestSender{})),
	}

	command := &cobra.Command{
		Use:                   "protection-source [action]",
		Short:                 translation.T("backup-recovery-protection-source-group-short-description"),
		Long:                  translation.T("backup-recovery-protection-source-group-long-description"),
		DisableFlagsInUseLine: true,
	}

	command.AddCommand(commands...)

	return command
}

// RequestSender for ListProtectionSources command
type ListProtectionSourcesRequestSender struct{}

func (s ListProtectionSourcesRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.ListProtectionSources(optionsModel.(*backuprecoveryv1.ListProtectionSourcesOptions))
}

// Command Runner for ListProtectionSources command
func NewListProtectionSourcesCommandRunner(utils Utilities, sender RequestSender) *ListProtectionSourcesCommandRunner {
	return &ListProtectionSourcesCommandRunner{utils: utils, sender: sender}
}

type ListProtectionSourcesCommandRunner struct {
	XIBMTenantID                string
	ExcludeOffice365Types       string
	GetTeamsChannels            bool
	AfterCursorEntityID         int64
	BeforeCursorEntityID        int64
	NodeID                      int64
	PageSize                    int64
	HasValidMailbox             bool
	HasValidOnedrive            bool
	IsSecurityGroup             bool
	ID                          int64
	NumLevels                   float64
	ExcludeTypes                string
	ExcludeAwsTypes             string
	ExcludeKubernetesTypes      string
	IncludeDatastores           bool
	IncludeNetworks             bool
	IncludeVMFolders            bool
	IncludeSfdcFields           bool
	IncludeSystemVApps          bool
	Environments                string
	Environment                 string
	IncludeEntityPermissionInfo bool
	Sids                        string
	IncludeSourceCredentials    bool
	EncryptionKey               string
	IncludeObjectProtectionInfo bool
	PruneNonCriticalInfo        bool
	PruneAggregationInfo        bool
	RequestInitiatorType        string
	UseCachedData               bool
	AllUnderHierarchy           bool
	RequiredFlags               []string
	sender                      RequestSender
	utils                       Utilities
}

// Command mapping: protection-source list, GetListProtectionSourcesCommand
func GetListProtectionSourcesCommand(r *ListProtectionSourcesCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "list [command options]",
		Short:                 translation.T("backup-recovery-protection-source-list-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-source-list-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-source",
			"x-cli-command":       "list",
		},
		Example: `  ibmcloud backup-recovery protection-source list \
    --xibm-tenant-id tenantId \
    --exclude-office365-types kDomain,kOutlook,kMailbox,kUsers,kUser,kGroups,kGroup,kSites,kSite \
    --get-teams-channels=true \
    --after-cursor-entity-id 26 \
    --before-cursor-entity-id 26 \
    --node-id 26 \
    --page-size 26 \
    --has-valid-mailbox=true \
    --has-valid-onedrive=true \
    --is-security-group=true \
    --id 26 \
    --num-levels 72.5 \
    --exclude-types kVCenter,kFolder,kDatacenter,kComputeResource,kClusterComputeResource,kResourcePool,kDatastore,kHostSystem,kVirtualMachine,kVirtualApp,kStandaloneHost,kStoragePod,kNetwork,kDistributedVirtualPortgroup,kTagCategory,kTag \
    --exclude-aws-types kEC2Instance,kRDSInstance,kAuroraCluster,kS3Bucket,kTag,kRDSTag,kAuroraTag,kS3Tag \
    --exclude-kubernetes-types kService \
    --include-datastores=true \
    --include-networks=true \
    --include-vm-folders=true \
    --include-sfdc-fields=true \
    --include-system-v-apps=true \
    --environments kVMware,kHyperV,kSQL,kView,kPuppeteer,kPhysical,kPure,kNimble,kAzure,kNetapp,kAgent,kGenericNas,kAcropolis,kPhysicalFiles,kIsilon,kGPFS,kKVM,kAWS,kExchange,kHyperVVSS,kOracle,kGCP,kFlashBlade,kAWSNative,kO365,kO365Outlook,kHyperFlex,kGCPNative,kAzureNative,kKubernetes,kElastifile,kAD,kRDSSnapshotManager,kCassandra,kMongoDB,kCouchbase,kHdfs,kHBase,kUDA,KSfdc,kAwsS3 \
    --environment kPhysical \
    --include-entity-permission-info=true \
    --sids sid1 \
    --include-source-credentials=true \
    --encryption-key encryptionKey \
    --include-object-protection-info=true \
    --prune-non-critical-info=true \
    --prune-aggregation-info=true \
    --request-initiator-type requestInitiatorType \
    --use-cached-data=true \
    --all-under-hierarchy=true`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-source-list-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.ExcludeOffice365Types, "exclude-office365-types", "", "", translation.T("backup-recovery-protection-source-list-exclude-office365-types-flag-description"))
	cmd.Flags().BoolVarP(&r.GetTeamsChannels, "get-teams-channels", "", false, translation.T("backup-recovery-protection-source-list-get-teams-channels-flag-description"))
	cmd.Flags().Int64VarP(&r.AfterCursorEntityID, "after-cursor-entity-id", "", 0, translation.T("backup-recovery-protection-source-list-after-cursor-entity-id-flag-description"))
	cmd.Flags().Int64VarP(&r.BeforeCursorEntityID, "before-cursor-entity-id", "", 0, translation.T("backup-recovery-protection-source-list-before-cursor-entity-id-flag-description"))
	cmd.Flags().Int64VarP(&r.NodeID, "node-id", "", 0, translation.T("backup-recovery-protection-source-list-node-id-flag-description"))
	cmd.Flags().Int64VarP(&r.PageSize, "page-size", "", 0, translation.T("backup-recovery-protection-source-list-page-size-flag-description"))
	cmd.Flags().BoolVarP(&r.HasValidMailbox, "has-valid-mailbox", "", false, translation.T("backup-recovery-protection-source-list-has-valid-mailbox-flag-description"))
	cmd.Flags().BoolVarP(&r.HasValidOnedrive, "has-valid-onedrive", "", false, translation.T("backup-recovery-protection-source-list-has-valid-onedrive-flag-description"))
	cmd.Flags().BoolVarP(&r.IsSecurityGroup, "is-security-group", "", false, translation.T("backup-recovery-protection-source-list-is-security-group-flag-description"))
	cmd.Flags().Int64VarP(&r.ID, "id", "", 0, translation.T("backup-recovery-protection-source-list-id-flag-description"))
	cmd.Flags().Float64VarP(&r.NumLevels, "num-levels", "", 0, translation.T("backup-recovery-protection-source-list-num-levels-flag-description"))
	cmd.Flags().StringVarP(&r.ExcludeTypes, "exclude-types", "", "", translation.T("backup-recovery-protection-source-list-exclude-types-flag-description"))
	cmd.Flags().StringVarP(&r.ExcludeAwsTypes, "exclude-aws-types", "", "", translation.T("backup-recovery-protection-source-list-exclude-aws-types-flag-description"))
	cmd.Flags().StringVarP(&r.ExcludeKubernetesTypes, "exclude-kubernetes-types", "", "", translation.T("backup-recovery-protection-source-list-exclude-kubernetes-types-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeDatastores, "include-datastores", "", false, translation.T("backup-recovery-protection-source-list-include-datastores-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeNetworks, "include-networks", "", false, translation.T("backup-recovery-protection-source-list-include-networks-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeVMFolders, "include-vm-folders", "", false, translation.T("backup-recovery-protection-source-list-include-vm-folders-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeSfdcFields, "include-sfdc-fields", "", false, translation.T("backup-recovery-protection-source-list-include-sfdc-fields-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeSystemVApps, "include-system-v-apps", "", false, translation.T("backup-recovery-protection-source-list-include-system-v-apps-flag-description"))
	cmd.Flags().StringVarP(&r.Environments, "environments", "", "", translation.T("backup-recovery-protection-source-list-environments-flag-description"))
	cmd.Flags().StringVarP(&r.Environment, "environment", "", "", translation.T("backup-recovery-protection-source-list-environment-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeEntityPermissionInfo, "include-entity-permission-info", "", false, translation.T("backup-recovery-protection-source-list-include-entity-permission-info-flag-description"))
	cmd.Flags().StringVarP(&r.Sids, "sids", "", "", translation.T("backup-recovery-protection-source-list-sids-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeSourceCredentials, "include-source-credentials", "", false, translation.T("backup-recovery-protection-source-list-include-source-credentials-flag-description"))
	cmd.Flags().StringVarP(&r.EncryptionKey, "encryption-key", "", "", translation.T("backup-recovery-protection-source-list-encryption-key-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeObjectProtectionInfo, "include-object-protection-info", "", false, translation.T("backup-recovery-protection-source-list-include-object-protection-info-flag-description"))
	cmd.Flags().BoolVarP(&r.PruneNonCriticalInfo, "prune-non-critical-info", "", false, translation.T("backup-recovery-protection-source-list-prune-non-critical-info-flag-description"))
	cmd.Flags().BoolVarP(&r.PruneAggregationInfo, "prune-aggregation-info", "", false, translation.T("backup-recovery-protection-source-list-prune-aggregation-info-flag-description"))
	cmd.Flags().StringVarP(&r.RequestInitiatorType, "request-initiator-type", "", "", translation.T("backup-recovery-protection-source-list-request-initiator-type-flag-description"))
	cmd.Flags().BoolVarP(&r.UseCachedData, "use-cached-data", "", false, translation.T("backup-recovery-protection-source-list-use-cached-data-flag-description"))
	cmd.Flags().BoolVarP(&r.AllUnderHierarchy, "all-under-hierarchy", "", false, translation.T("backup-recovery-protection-source-list-all-under-hierarchy-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running ListProtectionSources
func (r *ListProtectionSourcesCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.ListProtectionSourcesOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "exclude-office365-types" {
			var ExcludeOffice365Types []string
			err, msg := deserialize.List(r.ExcludeOffice365Types, "exclude-office365-types", "JSON", &ExcludeOffice365Types)
			r.utils.HandleError(err, msg)
			OptionsModel.SetExcludeOffice365Types(ExcludeOffice365Types)
		}
		if flag.Name == "get-teams-channels" {
			OptionsModel.SetGetTeamsChannels(r.GetTeamsChannels)
		}
		if flag.Name == "after-cursor-entity-id" {
			OptionsModel.SetAfterCursorEntityID(r.AfterCursorEntityID)
		}
		if flag.Name == "before-cursor-entity-id" {
			OptionsModel.SetBeforeCursorEntityID(r.BeforeCursorEntityID)
		}
		if flag.Name == "node-id" {
			OptionsModel.SetNodeID(r.NodeID)
		}
		if flag.Name == "page-size" {
			OptionsModel.SetPageSize(r.PageSize)
		}
		if flag.Name == "has-valid-mailbox" {
			OptionsModel.SetHasValidMailbox(r.HasValidMailbox)
		}
		if flag.Name == "has-valid-onedrive" {
			OptionsModel.SetHasValidOnedrive(r.HasValidOnedrive)
		}
		if flag.Name == "is-security-group" {
			OptionsModel.SetIsSecurityGroup(r.IsSecurityGroup)
		}
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "num-levels" {
			OptionsModel.SetNumLevels(r.NumLevels)
		}
		if flag.Name == "exclude-types" {
			var ExcludeTypes []string
			err, msg := deserialize.List(r.ExcludeTypes, "exclude-types", "JSON", &ExcludeTypes)
			r.utils.HandleError(err, msg)
			OptionsModel.SetExcludeTypes(ExcludeTypes)
		}
		if flag.Name == "exclude-aws-types" {
			var ExcludeAwsTypes []string
			err, msg := deserialize.List(r.ExcludeAwsTypes, "exclude-aws-types", "JSON", &ExcludeAwsTypes)
			r.utils.HandleError(err, msg)
			OptionsModel.SetExcludeAwsTypes(ExcludeAwsTypes)
		}
		if flag.Name == "exclude-kubernetes-types" {
			var ExcludeKubernetesTypes []string
			err, msg := deserialize.List(r.ExcludeKubernetesTypes, "exclude-kubernetes-types", "JSON", &ExcludeKubernetesTypes)
			r.utils.HandleError(err, msg)
			OptionsModel.SetExcludeKubernetesTypes(ExcludeKubernetesTypes)
		}
		if flag.Name == "include-datastores" {
			OptionsModel.SetIncludeDatastores(r.IncludeDatastores)
		}
		if flag.Name == "include-networks" {
			OptionsModel.SetIncludeNetworks(r.IncludeNetworks)
		}
		if flag.Name == "include-vm-folders" {
			OptionsModel.SetIncludeVMFolders(r.IncludeVMFolders)
		}
		if flag.Name == "include-sfdc-fields" {
			OptionsModel.SetIncludeSfdcFields(r.IncludeSfdcFields)
		}
		if flag.Name == "include-system-v-apps" {
			OptionsModel.SetIncludeSystemVApps(r.IncludeSystemVApps)
		}
		if flag.Name == "environments" {
			var Environments []string
			err, msg := deserialize.List(r.Environments, "environments", "JSON", &Environments)
			r.utils.HandleError(err, msg)
			OptionsModel.SetEnvironments(Environments)
		}
		if flag.Name == "environment" {
			OptionsModel.SetEnvironment(r.Environment)
		}
		if flag.Name == "include-entity-permission-info" {
			OptionsModel.SetIncludeEntityPermissionInfo(r.IncludeEntityPermissionInfo)
		}
		if flag.Name == "sids" {
			var Sids []string
			err, msg := deserialize.List(r.Sids, "sids", "JSON", &Sids)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSids(Sids)
		}
		if flag.Name == "include-source-credentials" {
			OptionsModel.SetIncludeSourceCredentials(r.IncludeSourceCredentials)
		}
		if flag.Name == "encryption-key" {
			OptionsModel.SetEncryptionKey(r.EncryptionKey)
		}
		if flag.Name == "include-object-protection-info" {
			OptionsModel.SetIncludeObjectProtectionInfo(r.IncludeObjectProtectionInfo)
		}
		if flag.Name == "prune-non-critical-info" {
			OptionsModel.SetPruneNonCriticalInfo(r.PruneNonCriticalInfo)
		}
		if flag.Name == "prune-aggregation-info" {
			OptionsModel.SetPruneAggregationInfo(r.PruneAggregationInfo)
		}
		if flag.Name == "request-initiator-type" {
			OptionsModel.SetRequestInitiatorType(r.RequestInitiatorType)
		}
		if flag.Name == "use-cached-data" {
			OptionsModel.SetUseCachedData(r.UseCachedData)
		}
		if flag.Name == "all-under-hierarchy" {
			OptionsModel.SetAllUnderHierarchy(r.AllUnderHierarchy)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *ListProtectionSourcesCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.ListProtectionSourcesOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	// Manually added code to display the desired result in text format.
	//********************************************
	r.utils.SetTableHeaderOrder([]string{
		"protectionSources",
	})
	DetailedResponse.Result = map[string]interface{}{"protectionSources": DetailedResponse.Result}
	//********************************************

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for GetSourceRegistrations command
type GetSourceRegistrationsRequestSender struct{}

func (s GetSourceRegistrationsRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetSourceRegistrations(optionsModel.(*backuprecoveryv1.GetSourceRegistrationsOptions))
}

// Command Runner for GetSourceRegistrations command
func NewGetSourceRegistrationsCommandRunner(utils Utilities, sender RequestSender) *GetSourceRegistrationsCommandRunner {
	return &GetSourceRegistrationsCommandRunner{utils: utils, sender: sender}
}

type GetSourceRegistrationsCommandRunner struct {
	XIBMTenantID                         string
	Ids                                  string
	IncludeSourceCredentials             bool
	EncryptionKey                        string
	UseCachedData                        bool
	IncludeExternalMetadata              bool
	IgnoreTenantMigrationInProgressCheck bool
	RequiredFlags                        []string
	sender                               RequestSender
	utils                                Utilities
}

// Command mapping: protection-source registrations-list, GetGetSourceRegistrationsCommand
func GetGetSourceRegistrationsCommand(r *GetSourceRegistrationsCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "registrations-list --xibm-tenant-id XIBM-TENANT-ID [--ids IDS] [--include-source-credentials=INCLUDE-SOURCE-CREDENTIALS] [--encryption-key ENCRYPTION-KEY] [--use-cached-data=USE-CACHED-DATA] [--include-external-metadata=INCLUDE-EXTERNAL-METADATA] [--ignore-tenant-migration-in-progress-check=IGNORE-TENANT-MIGRATION-IN-PROGRESS-CHECK]",
		Short:                 translation.T("backup-recovery-protection-source-registrations-list-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-source-registrations-list-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-source",
			"x-cli-command":       "registrations-list",
		},
		Example: `  ibmcloud backup-recovery protection-source registrations-list \
    --xibm-tenant-id tenantId \
    --ids 38,39 \
    --include-source-credentials=true \
    --encryption-key encryptionKey \
    --use-cached-data=true \
    --include-external-metadata=true \
    --ignore-tenant-migration-in-progress-check=true`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-source-registrations-list-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Ids, "ids", "", "", translation.T("backup-recovery-protection-source-registrations-list-ids-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeSourceCredentials, "include-source-credentials", "", false, translation.T("backup-recovery-protection-source-registrations-list-include-source-credentials-flag-description"))
	cmd.Flags().StringVarP(&r.EncryptionKey, "encryption-key", "", "", translation.T("backup-recovery-protection-source-registrations-list-encryption-key-flag-description"))
	cmd.Flags().BoolVarP(&r.UseCachedData, "use-cached-data", "", false, translation.T("backup-recovery-protection-source-registrations-list-use-cached-data-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeExternalMetadata, "include-external-metadata", "", false, translation.T("backup-recovery-protection-source-registrations-list-include-external-metadata-flag-description"))
	cmd.Flags().BoolVarP(&r.IgnoreTenantMigrationInProgressCheck, "ignore-tenant-migration-in-progress-check", "", false, translation.T("backup-recovery-protection-source-registrations-list-ignore-tenant-migration-in-progress-check-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetSourceRegistrations
func (r *GetSourceRegistrationsCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetSourceRegistrationsOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "ids" {
			var Ids []int64
			err, msg := deserialize.List(r.Ids, "ids", "JSON", &Ids)
			r.utils.HandleError(err, msg)
			OptionsModel.SetIds(Ids)
		}
		if flag.Name == "include-source-credentials" {
			OptionsModel.SetIncludeSourceCredentials(r.IncludeSourceCredentials)
		}
		if flag.Name == "encryption-key" {
			OptionsModel.SetEncryptionKey(r.EncryptionKey)
		}
		if flag.Name == "use-cached-data" {
			OptionsModel.SetUseCachedData(r.UseCachedData)
		}
		if flag.Name == "include-external-metadata" {
			OptionsModel.SetIncludeExternalMetadata(r.IncludeExternalMetadata)
		}
		if flag.Name == "ignore-tenant-migration-in-progress-check" {
			OptionsModel.SetIgnoreTenantMigrationInProgressCheck(r.IgnoreTenantMigrationInProgressCheck)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetSourceRegistrationsCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetSourceRegistrationsOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"registrations",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for RegisterProtectionSource command
type RegisterProtectionSourceRequestSender struct{}

func (s RegisterProtectionSourceRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.RegisterProtectionSource(optionsModel.(*backuprecoveryv1.RegisterProtectionSourceOptions))
}

// Command Runner for RegisterProtectionSource command
func NewRegisterProtectionSourceCommandRunner(utils Utilities, sender RequestSender) *RegisterProtectionSourceCommandRunner {
	return &RegisterProtectionSourceCommandRunner{utils: utils, sender: sender}
}

type RegisterProtectionSourceCommandRunner struct {
	XIBMTenantID                string
	Environment                 string
	Name                        string
	IsInternalEncrypted         bool
	EncryptionKey               string
	ConnectionID                int64
	Connections                 string
	ConnectorGroupID            int64
	AdvancedConfigs             string
	DataSourceConnectionID      string
	PhysicalParams              string
	PhysicalParamsEndpoint      string
	PhysicalParamsForceRegister bool
	PhysicalParamsHostType      string
	PhysicalParamsPhysicalType  string
	PhysicalParamsApplications  string
	RequiredFlags               []string
	sender                      RequestSender
	utils                       Utilities
}

// Command mapping: protection-source register, GetRegisterProtectionSourceCommand
func GetRegisterProtectionSourceCommand(r *RegisterProtectionSourceCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "register [command options]",
		Short:                 translation.T("backup-recovery-protection-source-register-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-source-register-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-source",
			"x-cli-command":       "register",
		},
		Example: `  ibmcloud backup-recovery protection-source register \
    --xibm-tenant-id tenantId \
    --environment kPhysical \
    --name register-protection-source \
    --is-internal-encrypted=true \
    --encryption-key encryptionKey \
    --connection-id 26 \
    --connections '[{"connectionId": 26, "entityId": 26, "connectorGroupId": 26, "dataSourceConnectionId": "DatasourceConnectionId"}]' \
    --connector-group-id 26 \
    --advanced-configs '[{"key": "configKey", "value": "configValue"}]' \
    --data-source-connection-id DatasourceConnectionId \
    --physical-params '{"endpoint": "xxx.xx.xx.xx", "forceRegister": true, "hostType": "kLinux", "physicalType": "kGroup", "applications": ["kSQL","kOracle"]}'`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-source-register-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Environment, "environment", "", "", translation.T("backup-recovery-protection-source-register-environment-flag-description"))
	cmd.Flags().StringVarP(&r.Name, "name", "", "", translation.T("backup-recovery-protection-source-register-name-flag-description"))
	cmd.Flags().BoolVarP(&r.IsInternalEncrypted, "is-internal-encrypted", "", false, translation.T("backup-recovery-protection-source-register-is-internal-encrypted-flag-description"))
	cmd.Flags().StringVarP(&r.EncryptionKey, "encryption-key", "", "", translation.T("backup-recovery-protection-source-register-encryption-key-flag-description"))
	cmd.Flags().Int64VarP(&r.ConnectionID, "connection-id", "", 0, translation.T("backup-recovery-protection-source-register-connection-id-flag-description"))
	cmd.Flags().StringVarP(&r.Connections, "connections", "", "", translation.T("backup-recovery-protection-source-register-connections-flag-description"))
	cmd.Flags().Int64VarP(&r.ConnectorGroupID, "connector-group-id", "", 0, translation.T("backup-recovery-protection-source-register-connector-group-id-flag-description"))
	cmd.Flags().StringVarP(&r.AdvancedConfigs, "advanced-configs", "", "", translation.T("backup-recovery-protection-source-register-advanced-configs-flag-description"))
	cmd.Flags().StringVarP(&r.DataSourceConnectionID, "data-source-connection-id", "", "", translation.T("backup-recovery-protection-source-register-data-source-connection-id-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParams, "physical-params", "", "", translation.T("backup-recovery-protection-source-register-physical-params-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsEndpoint, "physical-params-endpoint", "", "", translation.T("backup-recovery-protection-source-register-physical-params-endpoint-flag-description"))
	cmd.Flags().BoolVarP(&r.PhysicalParamsForceRegister, "physical-params-force-register", "", false, translation.T("backup-recovery-protection-source-register-physical-params-force-register-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsHostType, "physical-params-host-type", "", "", translation.T("backup-recovery-protection-source-register-physical-params-host-type-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsPhysicalType, "physical-params-physical-type", "", "", translation.T("backup-recovery-protection-source-register-physical-params-physical-type-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsApplications, "physical-params-applications", "", "", translation.T("backup-recovery-protection-source-register-physical-params-applications-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
		"environment",
	}

	return cmd
}

// Primary logic for running RegisterProtectionSource
func (r *RegisterProtectionSourceCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.RegisterProtectionSourceOptions{}
	PhysicalParamsHelper := &backuprecoveryv1.PhysicalSourceRegistrationParams{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "environment" {
			OptionsModel.SetEnvironment(r.Environment)
		}
		if flag.Name == "name" {
			OptionsModel.SetName(r.Name)
		}
		if flag.Name == "is-internal-encrypted" {
			OptionsModel.SetIsInternalEncrypted(r.IsInternalEncrypted)
		}
		if flag.Name == "encryption-key" {
			OptionsModel.SetEncryptionKey(r.EncryptionKey)
		}
		if flag.Name == "connection-id" {
			OptionsModel.SetConnectionID(r.ConnectionID)
		}
		if flag.Name == "connections" {
			var Connections []backuprecoveryv1.ConnectionConfig
			err, msg := deserialize.ModelSlice(
				r.Connections,
				"connections",
				"ConnectionConfig",
				backuprecoveryv1.UnmarshalConnectionConfig,
				&Connections,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetConnections(Connections)
			extraFieldPaths, err := r.utils.ValidateJSON(r.Connections, `{"fields":["dataSourceConnectionId","connectorGroupId","connectionId","entityId"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "connections",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "connections",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "connections",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "connector-group-id" {
			OptionsModel.SetConnectorGroupID(r.ConnectorGroupID)
		}
		if flag.Name == "advanced-configs" {
			var AdvancedConfigs []backuprecoveryv1.KeyValuePair
			err, msg := deserialize.ModelSlice(
				r.AdvancedConfigs,
				"advanced-configs",
				"KeyValuePair",
				backuprecoveryv1.UnmarshalKeyValuePair,
				&AdvancedConfigs,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetAdvancedConfigs(AdvancedConfigs)
			extraFieldPaths, err := r.utils.ValidateJSON(r.AdvancedConfigs, `{"fields":["value","key"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "advanced-configs",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "advanced-configs",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "advanced-configs",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "data-source-connection-id" {
			OptionsModel.SetDataSourceConnectionID(r.DataSourceConnectionID)
		}
		if flag.Name == "physical-params" {
			var PhysicalParams *backuprecoveryv1.PhysicalSourceRegistrationParams
			err, msg := deserialize.Model(
				r.PhysicalParams,
				"physical-params",
				"PhysicalSourceRegistrationParams",
				backuprecoveryv1.UnmarshalPhysicalSourceRegistrationParams,
				&PhysicalParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetPhysicalParams(PhysicalParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParams, `{"fields":["endpoint","hostType","physicalType","forceRegister","applications"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "physical-params-endpoint" {
			PhysicalParamsHelper.Endpoint = core.StringPtr(r.PhysicalParamsEndpoint)
		}
		if flag.Name == "physical-params-force-register" {
			PhysicalParamsHelper.ForceRegister = core.BoolPtr(r.PhysicalParamsForceRegister)
		}
		if flag.Name == "physical-params-host-type" {
			PhysicalParamsHelper.HostType = core.StringPtr(r.PhysicalParamsHostType)
		}
		if flag.Name == "physical-params-physical-type" {
			PhysicalParamsHelper.PhysicalType = core.StringPtr(r.PhysicalParamsPhysicalType)
		}
		if flag.Name == "physical-params-applications" {
			var PhysicalParamsApplications []string
			err, msg := deserialize.List(r.PhysicalParamsApplications, "physical-params-applications", "JSON", &PhysicalParamsApplications)
			r.utils.HandleError(err, msg)
			PhysicalParamsHelper.Applications = PhysicalParamsApplications
		}
	})

	if !reflect.ValueOf(*PhysicalParamsHelper).IsZero() {
		if OptionsModel.PhysicalParams == nil {
			OptionsModel.SetPhysicalParams(PhysicalParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "PhysicalParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}

	r.MakeRequest(OptionsModel)
}

func (r *RegisterProtectionSourceCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.RegisterProtectionSourceOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"id",
		"sourceId",
		"sourceInfo",
		"environment",
		"name",
		"connectionId",
		"connections",
		"connectorGroupId",
		"dataSourceConnectionId",
		"advancedConfigs",
		"authenticationStatus",
		"registrationTimeMsecs",
		"lastRefreshedTimeMsecs",
		"externalMetadata",
		"physicalParams",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for GetProtectionSourceRegistration command
type GetProtectionSourceRegistrationRequestSender struct{}

func (s GetProtectionSourceRegistrationRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetProtectionSourceRegistration(optionsModel.(*backuprecoveryv1.GetProtectionSourceRegistrationOptions))
}

// Command Runner for GetProtectionSourceRegistration command
func NewGetProtectionSourceRegistrationCommandRunner(utils Utilities, sender RequestSender) *GetProtectionSourceRegistrationCommandRunner {
	return &GetProtectionSourceRegistrationCommandRunner{utils: utils, sender: sender}
}

type GetProtectionSourceRegistrationCommandRunner struct {
	ID                   int64
	XIBMTenantID         string
	RequestInitiatorType string
	RequiredFlags        []string
	sender               RequestSender
	utils                Utilities
}

// Command mapping: protection-source registration-get, GetGetProtectionSourceRegistrationCommand
func GetGetProtectionSourceRegistrationCommand(r *GetProtectionSourceRegistrationCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "registration-get --id ID --xibm-tenant-id XIBM-TENANT-ID [--request-initiator-type REQUEST-INITIATOR-TYPE]",
		Short:                 translation.T("backup-recovery-protection-source-registration-get-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-source-registration-get-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-source",
			"x-cli-command":       "registration-get",
		},
		Example: `  ibmcloud backup-recovery protection-source registration-get \
    --id 26 \
    --xibm-tenant-id tenantId \
    --request-initiator-type UIUser`,
	}

	cmd.Flags().Int64VarP(&r.ID, "id", "", 0, translation.T("backup-recovery-protection-source-registration-get-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-source-registration-get-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.RequestInitiatorType, "request-initiator-type", "", "", translation.T("backup-recovery-protection-source-registration-get-request-initiator-type-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetProtectionSourceRegistration
func (r *GetProtectionSourceRegistrationCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetProtectionSourceRegistrationOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "request-initiator-type" {
			OptionsModel.SetRequestInitiatorType(r.RequestInitiatorType)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetProtectionSourceRegistrationCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetProtectionSourceRegistrationOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"id",
		"sourceId",
		"sourceInfo",
		"environment",
		"name",
		"connectionId",
		"connections",
		"connectorGroupId",
		"dataSourceConnectionId",
		"advancedConfigs",
		"authenticationStatus",
		"registrationTimeMsecs",
		"lastRefreshedTimeMsecs",
		"externalMetadata",
		"physicalParams",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for UpdateProtectionSourceRegistration command
type UpdateProtectionSourceRegistrationRequestSender struct{}

func (s UpdateProtectionSourceRegistrationRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.UpdateProtectionSourceRegistration(optionsModel.(*backuprecoveryv1.UpdateProtectionSourceRegistrationOptions))
}

// Command Runner for UpdateProtectionSourceRegistration command
func NewUpdateProtectionSourceRegistrationCommandRunner(utils Utilities, sender RequestSender) *UpdateProtectionSourceRegistrationCommandRunner {
	return &UpdateProtectionSourceRegistrationCommandRunner{utils: utils, sender: sender}
}

type UpdateProtectionSourceRegistrationCommandRunner struct {
	ID                          int64
	XIBMTenantID                string
	Environment                 string
	Name                        string
	IsInternalEncrypted         bool
	EncryptionKey               string
	ConnectionID                int64
	Connections                 string
	ConnectorGroupID            int64
	AdvancedConfigs             string
	DataSourceConnectionID      string
	LastModifiedTimestampUsecs  int64
	PhysicalParams              string
	PhysicalParamsEndpoint      string
	PhysicalParamsForceRegister bool
	PhysicalParamsHostType      string
	PhysicalParamsPhysicalType  string
	PhysicalParamsApplications  string
	RequiredFlags               []string
	sender                      RequestSender
	utils                       Utilities
}

// Command mapping: protection-source registration-update, GetUpdateProtectionSourceRegistrationCommand
func GetUpdateProtectionSourceRegistrationCommand(r *UpdateProtectionSourceRegistrationCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "registration-update [command options]",
		Short:                 translation.T("backup-recovery-protection-source-registration-update-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-source-registration-update-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-source",
			"x-cli-command":       "registration-update",
		},
		Example: `  ibmcloud backup-recovery protection-source registration-update \
    --id 26 \
    --xibm-tenant-id tenantId \
    --environment kPhysical \
    --name update-protection-source \
    --is-internal-encrypted=true \
    --encryption-key encryptionKey \
    --connection-id 26 \
    --connections '[{"connectionId": 26, "entityId": 26, "connectorGroupId": 26, "dataSourceConnectionId": "DatasourceConnectionId"}]' \
    --connector-group-id 26 \
    --advanced-configs '[{"key": "configKey", "value": "configValue"}]' \
    --data-source-connection-id DatasourceConnectionId \
    --last-modified-timestamp-usecs 26 \
    --physical-params '{"endpoint": "xxx.xx.xx.xx", "forceRegister": true, "hostType": "kLinux", "physicalType": "kGroup", "applications": ["kSQL","kOracle"]}'`,
	}

	cmd.Flags().Int64VarP(&r.ID, "id", "", 0, translation.T("backup-recovery-protection-source-registration-update-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-source-registration-update-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Environment, "environment", "", "", translation.T("backup-recovery-protection-source-registration-update-environment-flag-description"))
	cmd.Flags().StringVarP(&r.Name, "name", "", "", translation.T("backup-recovery-protection-source-registration-update-name-flag-description"))
	cmd.Flags().BoolVarP(&r.IsInternalEncrypted, "is-internal-encrypted", "", false, translation.T("backup-recovery-protection-source-registration-update-is-internal-encrypted-flag-description"))
	cmd.Flags().StringVarP(&r.EncryptionKey, "encryption-key", "", "", translation.T("backup-recovery-protection-source-registration-update-encryption-key-flag-description"))
	cmd.Flags().Int64VarP(&r.ConnectionID, "connection-id", "", 0, translation.T("backup-recovery-protection-source-registration-update-connection-id-flag-description"))
	cmd.Flags().StringVarP(&r.Connections, "connections", "", "", translation.T("backup-recovery-protection-source-registration-update-connections-flag-description"))
	cmd.Flags().Int64VarP(&r.ConnectorGroupID, "connector-group-id", "", 0, translation.T("backup-recovery-protection-source-registration-update-connector-group-id-flag-description"))
	cmd.Flags().StringVarP(&r.AdvancedConfigs, "advanced-configs", "", "", translation.T("backup-recovery-protection-source-registration-update-advanced-configs-flag-description"))
	cmd.Flags().StringVarP(&r.DataSourceConnectionID, "data-source-connection-id", "", "", translation.T("backup-recovery-protection-source-registration-update-data-source-connection-id-flag-description"))
	cmd.Flags().Int64VarP(&r.LastModifiedTimestampUsecs, "last-modified-timestamp-usecs", "", 0, translation.T("backup-recovery-protection-source-registration-update-last-modified-timestamp-usecs-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParams, "physical-params", "", "", translation.T("backup-recovery-protection-source-registration-update-physical-params-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsEndpoint, "physical-params-endpoint", "", "", translation.T("backup-recovery-protection-source-registration-update-physical-params-endpoint-flag-description"))
	cmd.Flags().BoolVarP(&r.PhysicalParamsForceRegister, "physical-params-force-register", "", false, translation.T("backup-recovery-protection-source-registration-update-physical-params-force-register-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsHostType, "physical-params-host-type", "", "", translation.T("backup-recovery-protection-source-registration-update-physical-params-host-type-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsPhysicalType, "physical-params-physical-type", "", "", translation.T("backup-recovery-protection-source-registration-update-physical-params-physical-type-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsApplications, "physical-params-applications", "", "", translation.T("backup-recovery-protection-source-registration-update-physical-params-applications-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
		"environment",
	}

	return cmd
}

// Primary logic for running UpdateProtectionSourceRegistration
func (r *UpdateProtectionSourceRegistrationCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.UpdateProtectionSourceRegistrationOptions{}
	PhysicalParamsHelper := &backuprecoveryv1.PhysicalSourceRegistrationParams{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "environment" {
			OptionsModel.SetEnvironment(r.Environment)
		}
		if flag.Name == "name" {
			OptionsModel.SetName(r.Name)
		}
		if flag.Name == "is-internal-encrypted" {
			OptionsModel.SetIsInternalEncrypted(r.IsInternalEncrypted)
		}
		if flag.Name == "encryption-key" {
			OptionsModel.SetEncryptionKey(r.EncryptionKey)
		}
		if flag.Name == "connection-id" {
			OptionsModel.SetConnectionID(r.ConnectionID)
		}
		if flag.Name == "connections" {
			var Connections []backuprecoveryv1.ConnectionConfig
			err, msg := deserialize.ModelSlice(
				r.Connections,
				"connections",
				"ConnectionConfig",
				backuprecoveryv1.UnmarshalConnectionConfig,
				&Connections,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetConnections(Connections)
			extraFieldPaths, err := r.utils.ValidateJSON(r.Connections, `{"fields":["dataSourceConnectionId","connectorGroupId","connectionId","entityId"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "connections",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "connections",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "connections",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "connector-group-id" {
			OptionsModel.SetConnectorGroupID(r.ConnectorGroupID)
		}
		if flag.Name == "advanced-configs" {
			var AdvancedConfigs []backuprecoveryv1.KeyValuePair
			err, msg := deserialize.ModelSlice(
				r.AdvancedConfigs,
				"advanced-configs",
				"KeyValuePair",
				backuprecoveryv1.UnmarshalKeyValuePair,
				&AdvancedConfigs,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetAdvancedConfigs(AdvancedConfigs)
			extraFieldPaths, err := r.utils.ValidateJSON(r.AdvancedConfigs, `{"fields":["value","key"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "advanced-configs",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "advanced-configs",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "advanced-configs",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "data-source-connection-id" {
			OptionsModel.SetDataSourceConnectionID(r.DataSourceConnectionID)
		}
		if flag.Name == "last-modified-timestamp-usecs" {
			OptionsModel.SetLastModifiedTimestampUsecs(r.LastModifiedTimestampUsecs)
		}
		if flag.Name == "physical-params" {
			var PhysicalParams *backuprecoveryv1.PhysicalSourceRegistrationParams
			err, msg := deserialize.Model(
				r.PhysicalParams,
				"physical-params",
				"PhysicalSourceRegistrationParams",
				backuprecoveryv1.UnmarshalPhysicalSourceRegistrationParams,
				&PhysicalParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetPhysicalParams(PhysicalParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParams, `{"fields":["endpoint","hostType","physicalType","forceRegister","applications"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "physical-params-endpoint" {
			PhysicalParamsHelper.Endpoint = core.StringPtr(r.PhysicalParamsEndpoint)
		}
		if flag.Name == "physical-params-force-register" {
			PhysicalParamsHelper.ForceRegister = core.BoolPtr(r.PhysicalParamsForceRegister)
		}
		if flag.Name == "physical-params-host-type" {
			PhysicalParamsHelper.HostType = core.StringPtr(r.PhysicalParamsHostType)
		}
		if flag.Name == "physical-params-physical-type" {
			PhysicalParamsHelper.PhysicalType = core.StringPtr(r.PhysicalParamsPhysicalType)
		}
		if flag.Name == "physical-params-applications" {
			var PhysicalParamsApplications []string
			err, msg := deserialize.List(r.PhysicalParamsApplications, "physical-params-applications", "JSON", &PhysicalParamsApplications)
			r.utils.HandleError(err, msg)
			PhysicalParamsHelper.Applications = PhysicalParamsApplications
		}
	})

	if !reflect.ValueOf(*PhysicalParamsHelper).IsZero() {
		if OptionsModel.PhysicalParams == nil {
			OptionsModel.SetPhysicalParams(PhysicalParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "PhysicalParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}

	r.MakeRequest(OptionsModel)
}

func (r *UpdateProtectionSourceRegistrationCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.UpdateProtectionSourceRegistrationOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPUpdate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"id",
		"sourceId",
		"sourceInfo",
		"environment",
		"name",
		"connectionId",
		"connections",
		"connectorGroupId",
		"dataSourceConnectionId",
		"advancedConfigs",
		"authenticationStatus",
		"registrationTimeMsecs",
		"lastRefreshedTimeMsecs",
		"externalMetadata",
		"physicalParams",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for PatchProtectionSourceRegistration command
type PatchProtectionSourceRegistrationRequestSender struct{}

func (s PatchProtectionSourceRegistrationRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.PatchProtectionSourceRegistration(optionsModel.(*backuprecoveryv1.PatchProtectionSourceRegistrationOptions))
}

// Command Runner for PatchProtectionSourceRegistration command
func NewPatchProtectionSourceRegistrationCommandRunner(utils Utilities, sender RequestSender) *PatchProtectionSourceRegistrationCommandRunner {
	return &PatchProtectionSourceRegistrationCommandRunner{utils: utils, sender: sender}
}

type PatchProtectionSourceRegistrationCommandRunner struct {
	ID            int64
	XIBMTenantID  string
	Environment   string
	RequiredFlags []string
	sender        RequestSender
	utils         Utilities
}

// Command mapping: protection-source registration-patch, GetPatchProtectionSourceRegistrationCommand
func GetPatchProtectionSourceRegistrationCommand(r *PatchProtectionSourceRegistrationCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "registration-patch --id ID --xibm-tenant-id XIBM-TENANT-ID --environment ENVIRONMENT",
		Short:                 translation.T("backup-recovery-protection-source-registration-patch-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-source-registration-patch-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-source",
			"x-cli-command":       "registration-patch",
		},
		Example: `  ibmcloud backup-recovery protection-source registration-patch \
    --id 26 \
    --xibm-tenant-id tenantId \
    --environment kPhysical`,
	}

	cmd.Flags().Int64VarP(&r.ID, "id", "", 0, translation.T("backup-recovery-protection-source-registration-patch-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-source-registration-patch-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Environment, "environment", "", "", translation.T("backup-recovery-protection-source-registration-patch-environment-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
		"environment",
	}

	return cmd
}

// Primary logic for running PatchProtectionSourceRegistration
func (r *PatchProtectionSourceRegistrationCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.PatchProtectionSourceRegistrationOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "environment" {
			OptionsModel.SetEnvironment(r.Environment)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *PatchProtectionSourceRegistrationCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.PatchProtectionSourceRegistrationOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPUpdate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"id",
		"sourceId",
		"sourceInfo",
		"environment",
		"name",
		"connectionId",
		"connections",
		"connectorGroupId",
		"dataSourceConnectionId",
		"advancedConfigs",
		"authenticationStatus",
		"registrationTimeMsecs",
		"lastRefreshedTimeMsecs",
		"externalMetadata",
		"physicalParams",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for DeleteProtectionSourceRegistration command
type DeleteProtectionSourceRegistrationRequestSender struct{}

func (s DeleteProtectionSourceRegistrationRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	res, err := ServiceInstance.DeleteProtectionSourceRegistration(optionsModel.(*backuprecoveryv1.DeleteProtectionSourceRegistrationOptions))
	// DeleteProtectionSourceRegistration returns an empty response body
	return nil, res, err
}

// Command Runner for DeleteProtectionSourceRegistration command
func NewDeleteProtectionSourceRegistrationCommandRunner(utils Utilities, sender RequestSender) *DeleteProtectionSourceRegistrationCommandRunner {
	return &DeleteProtectionSourceRegistrationCommandRunner{utils: utils, sender: sender}
}

type DeleteProtectionSourceRegistrationCommandRunner struct {
	ID                        int64
	XIBMTenantID              string
	ForceDeleteWithoutConfirm bool
	RequiredFlags             []string
	sender                    RequestSender
	utils                     Utilities
}

// Command mapping: protection-source registration-delete, GetDeleteProtectionSourceRegistrationCommand
func GetDeleteProtectionSourceRegistrationCommand(r *DeleteProtectionSourceRegistrationCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "registration-delete --id ID --xibm-tenant-id XIBM-TENANT-ID",
		Short:                 translation.T("backup-recovery-protection-source-registration-delete-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-source-registration-delete-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-source",
			"x-cli-command":       "registration-delete",
		},
		Example: `  ibmcloud backup-recovery protection-source registration-delete \
    --id 26 \
    --xibm-tenant-id tenantId`,
	}

	cmd.Flags().Int64VarP(&r.ID, "id", "", 0, translation.T("backup-recovery-protection-source-registration-delete-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-source-registration-delete-xibm-tenant-id-flag-description"))
	cmd.Flags().BoolVarP(&r.ForceDeleteWithoutConfirm, "force", "f", false, translation.T("force-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running DeleteProtectionSourceRegistration
func (r *DeleteProtectionSourceRegistrationCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	if !r.utils.ConfirmDelete(r.ForceDeleteWithoutConfirm) {
		// confirm delete, exit otherwise
		return
	}

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.DeleteProtectionSourceRegistrationOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *DeleteProtectionSourceRegistrationCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.DeleteProtectionSourceRegistrationOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPDelete,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)
	r.utils.ProcessEmptyResponse(DetailedResponse, ResponseErr)
}

// RequestSender for RefreshProtectionSourceByID command
type RefreshProtectionSourceByIDRequestSender struct{}

func (s RefreshProtectionSourceByIDRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	res, err := ServiceInstance.RefreshProtectionSourceByID(optionsModel.(*backuprecoveryv1.RefreshProtectionSourceByIdOptions))
	// RefreshProtectionSourceByID returns an empty response body
	return nil, res, err
}

// Command Runner for RefreshProtectionSourceByID command
func NewRefreshProtectionSourceByIDCommandRunner(utils Utilities, sender RequestSender) *RefreshProtectionSourceByIDCommandRunner {
	return &RefreshProtectionSourceByIDCommandRunner{utils: utils, sender: sender}
}

type RefreshProtectionSourceByIDCommandRunner struct {
	ID            int64
	XIBMTenantID  string
	RequiredFlags []string
	sender        RequestSender
	utils         Utilities
}

// Command mapping: protection-source refresh, GetRefreshProtectionSourceByIDCommand
func GetRefreshProtectionSourceByIDCommand(r *RefreshProtectionSourceByIDCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "refresh --id ID --xibm-tenant-id XIBM-TENANT-ID",
		Short:                 translation.T("backup-recovery-protection-source-refresh-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-source-refresh-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-source",
			"x-cli-command":       "refresh",
		},
		Example: `  ibmcloud backup-recovery protection-source refresh \
    --id 26 \
    --xibm-tenant-id tenantId`,
	}

	cmd.Flags().Int64VarP(&r.ID, "id", "", 0, translation.T("backup-recovery-protection-source-refresh-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-source-refresh-xibm-tenant-id-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running RefreshProtectionSourceByID
func (r *RefreshProtectionSourceByIDCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.RefreshProtectionSourceByIdOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *RefreshProtectionSourceByIDCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.RefreshProtectionSourceByIdOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)
	r.utils.ProcessEmptyResponse(DetailedResponse, ResponseErr)
}

func GetAgentUpgradeTaskGroup(utils Utilities) *cobra.Command {
	commands := []*cobra.Command{
		GetGetUpgradeTasksCommand(NewGetUpgradeTasksCommandRunner(utils, GetUpgradeTasksRequestSender{})),
		GetCreateUpgradeTaskCommand(NewCreateUpgradeTaskCommandRunner(utils, CreateUpgradeTaskRequestSender{})),
	}

	command := &cobra.Command{
		Use:                   "agent-upgrade-task [action]",
		Short:                 translation.T("backup-recovery-agent-upgrade-task-group-short-description"),
		Long:                  translation.T("backup-recovery-agent-upgrade-task-group-long-description"),
		DisableFlagsInUseLine: true,
	}

	command.AddCommand(commands...)

	return command
}

// RequestSender for GetUpgradeTasks command
type GetUpgradeTasksRequestSender struct{}

func (s GetUpgradeTasksRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetUpgradeTasks(optionsModel.(*backuprecoveryv1.GetUpgradeTasksOptions))
}

// Command Runner for GetUpgradeTasks command
func NewGetUpgradeTasksCommandRunner(utils Utilities, sender RequestSender) *GetUpgradeTasksCommandRunner {
	return &GetUpgradeTasksCommandRunner{utils: utils, sender: sender}
}

type GetUpgradeTasksCommandRunner struct {
	XIBMTenantID  string
	Ids           string
	RequiredFlags []string
	sender        RequestSender
	utils         Utilities
}

// Command mapping: agent-upgrade-task list, GetGetUpgradeTasksCommand
func GetGetUpgradeTasksCommand(r *GetUpgradeTasksCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "list --xibm-tenant-id XIBM-TENANT-ID [--ids IDS]",
		Short:                 translation.T("backup-recovery-agent-upgrade-task-list-command-short-description"),
		Long:                  translation.T("backup-recovery-agent-upgrade-task-list-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "agent-upgrade-task",
			"x-cli-command":       "list",
		},
		Example: `  ibmcloud backup-recovery agent-upgrade-task list \
    --xibm-tenant-id tenantId \
    --ids 26,27`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-agent-upgrade-task-list-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Ids, "ids", "", "", translation.T("backup-recovery-agent-upgrade-task-list-ids-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetUpgradeTasks
func (r *GetUpgradeTasksCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetUpgradeTasksOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "ids" {
			var Ids []int64
			err, msg := deserialize.List(r.Ids, "ids", "JSON", &Ids)
			r.utils.HandleError(err, msg)
			OptionsModel.SetIds(Ids)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetUpgradeTasksCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetUpgradeTasksOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"tasks",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for CreateUpgradeTask command
type CreateUpgradeTaskRequestSender struct{}

func (s CreateUpgradeTaskRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.CreateUpgradeTask(optionsModel.(*backuprecoveryv1.CreateUpgradeTaskOptions))
}

// Command Runner for CreateUpgradeTask command
func NewCreateUpgradeTaskCommandRunner(utils Utilities, sender RequestSender) *CreateUpgradeTaskCommandRunner {
	return &CreateUpgradeTaskCommandRunner{utils: utils, sender: sender}
}

type CreateUpgradeTaskCommandRunner struct {
	XIBMTenantID         string
	AgentIDs             string
	Description          string
	Name                 string
	RetryTaskID          int64
	ScheduleEndTimeUsecs int64
	ScheduleTimeUsecs    int64
	RequiredFlags        []string
	sender               RequestSender
	utils                Utilities
}

// Command mapping: agent-upgrade-task create, GetCreateUpgradeTaskCommand
func GetCreateUpgradeTaskCommand(r *CreateUpgradeTaskCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "create --xibm-tenant-id XIBM-TENANT-ID [--agent-ids AGENT-IDS] [--description DESCRIPTION] [--name NAME] [--retry-task-id RETRY-TASK-ID] [--schedule-end-time-usecs SCHEDULE-END-TIME-USECS] [--schedule-time-usecs SCHEDULE-TIME-USECS]",
		Short:                 translation.T("backup-recovery-agent-upgrade-task-create-command-short-description"),
		Long:                  translation.T("backup-recovery-agent-upgrade-task-create-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "agent-upgrade-task",
			"x-cli-command":       "create",
		},
		Example: `  ibmcloud backup-recovery agent-upgrade-task create \
    --xibm-tenant-id tenantId \
    --agent-ids 26,27 \
    --description 'Upgrade task' \
    --name create-upgrade-task \
    --retry-task-id 26 \
    --schedule-end-time-usecs 26 \
    --schedule-time-usecs 26`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-agent-upgrade-task-create-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.AgentIDs, "agent-ids", "", "", translation.T("backup-recovery-agent-upgrade-task-create-agent-ids-flag-description"))
	cmd.Flags().StringVarP(&r.Description, "description", "", "", translation.T("backup-recovery-agent-upgrade-task-create-description-flag-description"))
	cmd.Flags().StringVarP(&r.Name, "name", "", "", translation.T("backup-recovery-agent-upgrade-task-create-name-flag-description"))
	cmd.Flags().Int64VarP(&r.RetryTaskID, "retry-task-id", "", 0, translation.T("backup-recovery-agent-upgrade-task-create-retry-task-id-flag-description"))
	cmd.Flags().Int64VarP(&r.ScheduleEndTimeUsecs, "schedule-end-time-usecs", "", 0, translation.T("backup-recovery-agent-upgrade-task-create-schedule-end-time-usecs-flag-description"))
	cmd.Flags().Int64VarP(&r.ScheduleTimeUsecs, "schedule-time-usecs", "", 0, translation.T("backup-recovery-agent-upgrade-task-create-schedule-time-usecs-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running CreateUpgradeTask
func (r *CreateUpgradeTaskCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.CreateUpgradeTaskOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "agent-ids" {
			var AgentIDs []int64
			err, msg := deserialize.List(r.AgentIDs, "agent-ids", "JSON", &AgentIDs)
			r.utils.HandleError(err, msg)
			OptionsModel.SetAgentIDs(AgentIDs)
		}
		if flag.Name == "description" {
			OptionsModel.SetDescription(r.Description)
		}
		if flag.Name == "name" {
			OptionsModel.SetName(r.Name)
		}
		if flag.Name == "retry-task-id" {
			OptionsModel.SetRetryTaskID(r.RetryTaskID)
		}
		if flag.Name == "schedule-end-time-usecs" {
			OptionsModel.SetScheduleEndTimeUsecs(r.ScheduleEndTimeUsecs)
		}
		if flag.Name == "schedule-time-usecs" {
			OptionsModel.SetScheduleTimeUsecs(r.ScheduleTimeUsecs)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *CreateUpgradeTaskCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.CreateUpgradeTaskOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"agentIDs",
		"agents",
		"clusterVersion",
		"description",
		"endTimeUsecs",
		"error",
		"id",
		"isRetryable",
		"name",
		"retriedTaskID",
		"scheduleEndTimeUsecs",
		"scheduleTimeUsecs",
		"startTimeUsecs",
		"status",
		"type",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

func GetProtectionPolicyGroup(utils Utilities) *cobra.Command {
	commands := []*cobra.Command{
		GetGetProtectionPoliciesCommand(NewGetProtectionPoliciesCommandRunner(utils, GetProtectionPoliciesRequestSender{})),
		GetCreateProtectionPolicyCommand(NewCreateProtectionPolicyCommandRunner(utils, CreateProtectionPolicyRequestSender{})),
		GetGetProtectionPolicyByIDCommand(NewGetProtectionPolicyByIDCommandRunner(utils, GetProtectionPolicyByIDRequestSender{})),
		GetUpdateProtectionPolicyCommand(NewUpdateProtectionPolicyCommandRunner(utils, UpdateProtectionPolicyRequestSender{})),
		GetDeleteProtectionPolicyCommand(NewDeleteProtectionPolicyCommandRunner(utils, DeleteProtectionPolicyRequestSender{})),
	}

	command := &cobra.Command{
		Use:                   "protection-policy [action]",
		Short:                 translation.T("backup-recovery-protection-policy-group-short-description"),
		Long:                  translation.T("backup-recovery-protection-policy-group-long-description"),
		DisableFlagsInUseLine: true,
	}

	command.AddCommand(commands...)

	return command
}

// RequestSender for GetProtectionPolicies command
type GetProtectionPoliciesRequestSender struct{}

func (s GetProtectionPoliciesRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetProtectionPolicies(optionsModel.(*backuprecoveryv1.GetProtectionPoliciesOptions))
}

// Command Runner for GetProtectionPolicies command
func NewGetProtectionPoliciesCommandRunner(utils Utilities, sender RequestSender) *GetProtectionPoliciesCommandRunner {
	return &GetProtectionPoliciesCommandRunner{utils: utils, sender: sender}
}

type GetProtectionPoliciesCommandRunner struct {
	XIBMTenantID              string
	RequestInitiatorType      string
	Ids                       string
	PolicyNames               string
	Types                     string
	ExcludeLinkedPolicies     bool
	IncludeReplicatedPolicies bool
	IncludeStats              bool
	RequiredFlags             []string
	sender                    RequestSender
	utils                     Utilities
}

// Command mapping: protection-policy list, GetGetProtectionPoliciesCommand
func GetGetProtectionPoliciesCommand(r *GetProtectionPoliciesCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "list --xibm-tenant-id XIBM-TENANT-ID [--request-initiator-type REQUEST-INITIATOR-TYPE] [--ids IDS] [--policy-names POLICY-NAMES] [--types TYPES] [--exclude-linked-policies=EXCLUDE-LINKED-POLICIES] [--include-replicated-policies=INCLUDE-REPLICATED-POLICIES] [--include-stats=INCLUDE-STATS]",
		Short:                 translation.T("backup-recovery-protection-policy-list-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-policy-list-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-policy",
			"x-cli-command":       "list",
		},
		Example: `  ibmcloud backup-recovery protection-policy list \
    --xibm-tenant-id tenantId \
    --request-initiator-type UIUser \
    --ids policyId1 \
    --policy-names policyName1 \
    --types Regular,Internal \
    --exclude-linked-policies=true \
    --include-replicated-policies=true \
    --include-stats=true`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-policy-list-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.RequestInitiatorType, "request-initiator-type", "", "", translation.T("backup-recovery-protection-policy-list-request-initiator-type-flag-description"))
	cmd.Flags().StringVarP(&r.Ids, "ids", "", "", translation.T("backup-recovery-protection-policy-list-ids-flag-description"))
	cmd.Flags().StringVarP(&r.PolicyNames, "policy-names", "", "", translation.T("backup-recovery-protection-policy-list-policy-names-flag-description"))
	cmd.Flags().StringVarP(&r.Types, "types", "", "", translation.T("backup-recovery-protection-policy-list-types-flag-description"))
	cmd.Flags().BoolVarP(&r.ExcludeLinkedPolicies, "exclude-linked-policies", "", false, translation.T("backup-recovery-protection-policy-list-exclude-linked-policies-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeReplicatedPolicies, "include-replicated-policies", "", false, translation.T("backup-recovery-protection-policy-list-include-replicated-policies-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeStats, "include-stats", "", false, translation.T("backup-recovery-protection-policy-list-include-stats-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetProtectionPolicies
func (r *GetProtectionPoliciesCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetProtectionPoliciesOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "request-initiator-type" {
			OptionsModel.SetRequestInitiatorType(r.RequestInitiatorType)
		}
		if flag.Name == "ids" {
			var Ids []string
			err, msg := deserialize.List(r.Ids, "ids", "JSON", &Ids)
			r.utils.HandleError(err, msg)
			OptionsModel.SetIds(Ids)
		}
		if flag.Name == "policy-names" {
			var PolicyNames []string
			err, msg := deserialize.List(r.PolicyNames, "policy-names", "JSON", &PolicyNames)
			r.utils.HandleError(err, msg)
			OptionsModel.SetPolicyNames(PolicyNames)
		}
		if flag.Name == "types" {
			var Types []string
			err, msg := deserialize.List(r.Types, "types", "JSON", &Types)
			r.utils.HandleError(err, msg)
			OptionsModel.SetTypes(Types)
		}
		if flag.Name == "exclude-linked-policies" {
			OptionsModel.SetExcludeLinkedPolicies(r.ExcludeLinkedPolicies)
		}
		if flag.Name == "include-replicated-policies" {
			OptionsModel.SetIncludeReplicatedPolicies(r.IncludeReplicatedPolicies)
		}
		if flag.Name == "include-stats" {
			OptionsModel.SetIncludeStats(r.IncludeStats)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetProtectionPoliciesCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetProtectionPoliciesOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"policies",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for CreateProtectionPolicy command
type CreateProtectionPolicyRequestSender struct{}

func (s CreateProtectionPolicyRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.CreateProtectionPolicy(optionsModel.(*backuprecoveryv1.CreateProtectionPolicyOptions))
}

// Command Runner for CreateProtectionPolicy command
func NewCreateProtectionPolicyCommandRunner(utils Utilities, sender RequestSender) *CreateProtectionPolicyCommandRunner {
	return &CreateProtectionPolicyCommandRunner{utils: utils, sender: sender}
}

type CreateProtectionPolicyCommandRunner struct {
	XIBMTenantID                          string
	Name                                  string
	BackupPolicy                          string
	Description                           string
	BlackoutWindow                        string
	ExtendedRetention                     string
	RemoteTargetPolicy                    string
	CascadedTargetsConfig                 string
	RetryOptions                          string
	DataLock                              string
	Version                               int64
	IsCBSEnabled                          bool
	LastModificationTimeUsecs             int64
	TemplateID                            string
	BackupPolicyRegular                   string
	BackupPolicyLog                       string
	BackupPolicyBmr                       string
	BackupPolicyCdp                       string
	BackupPolicyStorageArraySnapshot      string
	BackupPolicyRunTimeouts               string
	RemoteTargetPolicyReplicationTargets  string
	RemoteTargetPolicyArchivalTargets     string
	RemoteTargetPolicyCloudSpinTargets    string
	RemoteTargetPolicyOnpremDeployTargets string
	RemoteTargetPolicyRpaasTargets        string
	RetryOptionsRetries                   int64
	RetryOptionsRetryIntervalMins         int64
	RequiredFlags                         []string
	sender                                RequestSender
	utils                                 Utilities
}

// Command mapping: protection-policy create, GetCreateProtectionPolicyCommand
func GetCreateProtectionPolicyCommand(r *CreateProtectionPolicyCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "create [command options]",
		Short:                 translation.T("backup-recovery-protection-policy-create-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-policy-create-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-policy",
			"x-cli-command":       "create",
		},
		Example: `  ibmcloud backup-recovery protection-policy create \
    --xibm-tenant-id tenantId \
    --name create-protection-policy \
    --backup-policy '{"regular": {"incremental": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}, "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}}, "full": {"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}}, "fullBackups": [{"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}], "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "primaryBackupTarget": {"targetType": "Local", "archivalTargetSettings": {"targetId": 26, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}}, "useDefaultBackupTarget": true}}, "log": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "bmr": {"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "cdp": {"retention": {"unit": "Minutes", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "storageArraySnapshot": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}, "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}]}' \
    --description 'Protection Policy' \
    --blackout-window '[{"day": "Sunday", "startTime": {"hour": 1, "minute": 15, "timeZone": "America/Los_Angeles"}, "endTime": {"hour": 1, "minute": 15, "timeZone": "America/Los_Angeles"}, "configId": "Config-Id"}]' \
    --extended-retention '[{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]' \
    --remote-target-policy '{"replicationTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "awsTargetConfig": {"region": 26, "sourceId": 26}, "azureTargetConfig": {"resourceGroup": 26, "sourceId": 26}, "targetType": "RemoteCluster", "remoteTargetConfig": {"clusterId": 26}}], "archivalTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}, "extendedRetention": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]}], "cloudSpinTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "target": {"awsParams": {"customTagList": [{"key": "custom-tag-key", "value": "custom-tag-value"}], "region": 3, "subnetId": 26, "vpcId": 26}, "azureParams": {"availabilitySetId": 26, "networkResourceGroupId": 26, "resourceGroupId": 26, "storageAccountId": 26, "storageContainerId": 26, "storageResourceGroupId": 26, "tempVmResourceGroupId": 26, "tempVmStorageAccountId": 26, "tempVmStorageContainerId": 26, "tempVmSubnetId": 26, "tempVmVirtualNetworkId": 26}, "id": 2}}], "onpremDeployTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "params": {"id": 4}}], "rpaasTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "targetType": "Tape"}]}' \
    --cascaded-targets-config '[{"sourceClusterId": 26, "remoteTargets": {"replicationTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "awsTargetConfig": {"region": 26, "sourceId": 26}, "azureTargetConfig": {"resourceGroup": 26, "sourceId": 26}, "targetType": "RemoteCluster", "remoteTargetConfig": {"clusterId": 26}}], "archivalTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}, "extendedRetention": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]}], "cloudSpinTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "target": {"awsParams": {"customTagList": [{"key": "custom-tag-key", "value": "custom-tag-value"}], "region": 3, "subnetId": 26, "vpcId": 26}, "azureParams": {"availabilitySetId": 26, "networkResourceGroupId": 26, "resourceGroupId": 26, "storageAccountId": 26, "storageContainerId": 26, "storageResourceGroupId": 26, "tempVmResourceGroupId": 26, "tempVmStorageAccountId": 26, "tempVmStorageContainerId": 26, "tempVmSubnetId": 26, "tempVmVirtualNetworkId": 26}, "id": 2}}], "onpremDeployTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "params": {"id": 4}}], "rpaasTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "targetType": "Tape"}]}}]' \
    --retry-options '{"retries": 0, "retryIntervalMins": 1}' \
    --data-lock Compliance \
    --version 38 \
    --is-cbs-enabled=true \
    --last-modification-time-usecs 26 \
    --template-id protection-policy-template`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-policy-create-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Name, "name", "", "", translation.T("backup-recovery-protection-policy-create-name-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicy, "backup-policy", "", "", translation.T("backup-recovery-protection-policy-create-backup-policy-flag-description"))
	cmd.Flags().StringVarP(&r.Description, "description", "", "", translation.T("backup-recovery-protection-policy-create-description-flag-description"))
	cmd.Flags().StringVarP(&r.BlackoutWindow, "blackout-window", "", "", translation.T("backup-recovery-protection-policy-create-blackout-window-flag-description"))
	cmd.Flags().StringVarP(&r.ExtendedRetention, "extended-retention", "", "", translation.T("backup-recovery-protection-policy-create-extended-retention-flag-description"))
	cmd.Flags().StringVarP(&r.RemoteTargetPolicy, "remote-target-policy", "", "", translation.T("backup-recovery-protection-policy-create-remote-target-policy-flag-description"))
	cmd.Flags().StringVarP(&r.CascadedTargetsConfig, "cascaded-targets-config", "", "", translation.T("backup-recovery-protection-policy-create-cascaded-targets-config-flag-description"))
	cmd.Flags().StringVarP(&r.RetryOptions, "retry-options", "", "", translation.T("backup-recovery-protection-policy-create-retry-options-flag-description"))
	cmd.Flags().StringVarP(&r.DataLock, "data-lock", "", "", translation.T("backup-recovery-protection-policy-create-data-lock-flag-description"))
	cmd.Flags().Int64VarP(&r.Version, "version", "", 0, translation.T("backup-recovery-protection-policy-create-version-flag-description"))
	cmd.Flags().BoolVarP(&r.IsCBSEnabled, "is-cbs-enabled", "", false, translation.T("backup-recovery-protection-policy-create-is-cbs-enabled-flag-description"))
	cmd.Flags().Int64VarP(&r.LastModificationTimeUsecs, "last-modification-time-usecs", "", 0, translation.T("backup-recovery-protection-policy-create-last-modification-time-usecs-flag-description"))
	cmd.Flags().StringVarP(&r.TemplateID, "template-id", "", "", translation.T("backup-recovery-protection-policy-create-template-id-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicyRegular, "backup-policy-regular", "", "", translation.T("backup-recovery-protection-policy-create-backup-policy-regular-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicyLog, "backup-policy-log", "", "", translation.T("backup-recovery-protection-policy-create-backup-policy-log-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicyBmr, "backup-policy-bmr", "", "", translation.T("backup-recovery-protection-policy-create-backup-policy-bmr-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicyCdp, "backup-policy-cdp", "", "", translation.T("backup-recovery-protection-policy-create-backup-policy-cdp-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicyStorageArraySnapshot, "backup-policy-storage-array-snapshot", "", "", translation.T("backup-recovery-protection-policy-create-backup-policy-storage-array-snapshot-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicyRunTimeouts, "backup-policy-run-timeouts", "", "", translation.T("backup-recovery-protection-policy-create-backup-policy-run-timeouts-flag-description"))
	cmd.Flags().StringVarP(&r.RemoteTargetPolicyReplicationTargets, "remote-target-policy-replication-targets", "", "", translation.T("backup-recovery-protection-policy-create-remote-target-policy-replication-targets-flag-description"))
	cmd.Flags().StringVarP(&r.RemoteTargetPolicyArchivalTargets, "remote-target-policy-archival-targets", "", "", translation.T("backup-recovery-protection-policy-create-remote-target-policy-archival-targets-flag-description"))
	cmd.Flags().StringVarP(&r.RemoteTargetPolicyCloudSpinTargets, "remote-target-policy-cloud-spin-targets", "", "", translation.T("backup-recovery-protection-policy-create-remote-target-policy-cloud-spin-targets-flag-description"))
	cmd.Flags().StringVarP(&r.RemoteTargetPolicyOnpremDeployTargets, "remote-target-policy-onprem-deploy-targets", "", "", translation.T("backup-recovery-protection-policy-create-remote-target-policy-onprem-deploy-targets-flag-description"))
	cmd.Flags().StringVarP(&r.RemoteTargetPolicyRpaasTargets, "remote-target-policy-rpaas-targets", "", "", translation.T("backup-recovery-protection-policy-create-remote-target-policy-rpaas-targets-flag-description"))
	cmd.Flags().Int64VarP(&r.RetryOptionsRetries, "retry-options-retries", "", 0, translation.T("backup-recovery-protection-policy-create-retry-options-retries-flag-description"))
	cmd.Flags().Int64VarP(&r.RetryOptionsRetryIntervalMins, "retry-options-retry-interval-mins", "", 0, translation.T("backup-recovery-protection-policy-create-retry-options-retry-interval-mins-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
		"name",
	}

	return cmd
}

// Primary logic for running CreateProtectionPolicy
func (r *CreateProtectionPolicyCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.CreateProtectionPolicyOptions{}
	BackupPolicyHelper := &backuprecoveryv1.BackupPolicy{}
	RemoteTargetPolicyHelper := &backuprecoveryv1.TargetsConfiguration{}
	RetryOptionsHelper := &backuprecoveryv1.RetryOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "name" {
			OptionsModel.SetName(r.Name)
		}
		if flag.Name == "backup-policy" {
			var BackupPolicy *backuprecoveryv1.BackupPolicy
			err, msg := deserialize.Model(
				r.BackupPolicy,
				"backup-policy",
				"BackupPolicy",
				backuprecoveryv1.UnmarshalBackupPolicy,
				&BackupPolicy,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetBackupPolicy(BackupPolicy)
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicy, `{"schemas":{"OracleTiers":["tiers#OracleTier"],"GoogleTier":["moveAfterUnit","moveAfter","tierType"],"PrimaryArchivalTarget":["targetId","tierSettings#TierLevelSettings"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"FullBackupPolicy":["schedule#FullSchedule"],"CdpBackupPolicy":["retention#CdpRetention"],"HourSchedule":["frequency"],"FullSchedule":["unit","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"AzureTier":["moveAfterUnit","moveAfter","tierType"],"LogSchedule":["unit","minuteSchedule#MinuteSchedule","hourSchedule#HourSchedule"],"MonthSchedule":["dayOfWeek","weekOfMonth","dayOfMonth"],"DaySchedule":["frequency"],"YearSchedule":["dayOfYear"],"BmrBackupPolicy":["schedule#BmrSchedule","retention#Retention"],"StorageArraySnapshotBackupPolicy":["schedule#StorageArraySnapshotSchedule","retention#Retention"],"OracleTier":["moveAfterUnit","moveAfter","tierType"],"TierLevelSettings":["awsTiering#AWSTiers","azureTiering#AzureTiers","cloudPlatform","googleTiering#GoogleTiers","oracleTiering#OracleTiers"],"WeekSchedule":["dayOfWeek"],"CdpRetention":["unit","duration","dataLockConfig#DataLockConfig"],"AWSTiers":["tiers#AWSTier"],"LogBackupPolicy":["schedule#LogSchedule","retention#Retention"],"BmrSchedule":["unit","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"IncrementalBackupPolicy":["schedule#IncrementalSchedule"],"GoogleTiers":["tiers#GoogleTier"],"RegularBackupPolicy":["incremental#IncrementalBackupPolicy","full#FullBackupPolicy","fullBackups#FullScheduleAndRetention","retention#Retention","primaryBackupTarget#PrimaryBackupTarget"],"IncrementalSchedule":["unit","minuteSchedule#MinuteSchedule","hourSchedule#HourSchedule","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"FullScheduleAndRetention":["schedule#FullSchedule","retention#Retention"],"AWSTier":["moveAfterUnit","moveAfter","tierType"],"PrimaryBackupTarget":["targetType","archivalTargetSettings#PrimaryArchivalTarget","useDefaultBackupTarget"],"MinuteSchedule":["frequency"],"StorageArraySnapshotSchedule":["unit","minuteSchedule#MinuteSchedule","hourSchedule#HourSchedule","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"AzureTiers":["tiers#AzureTier"]},"fields":["log#LogBackupPolicy","runTimeouts#CancellationTimeoutParams","storageArraySnapshot#StorageArraySnapshotBackupPolicy","regular#RegularBackupPolicy","bmr#BmrBackupPolicy","cdp#CdpBackupPolicy"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "description" {
			OptionsModel.SetDescription(r.Description)
		}
		if flag.Name == "blackout-window" {
			var BlackoutWindow []backuprecoveryv1.BlackoutWindow
			err, msg := deserialize.ModelSlice(
				r.BlackoutWindow,
				"blackout-window",
				"BlackoutWindow",
				backuprecoveryv1.UnmarshalBlackoutWindow,
				&BlackoutWindow,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetBlackoutWindow(BlackoutWindow)
			extraFieldPaths, err := r.utils.ValidateJSON(r.BlackoutWindow, `{"schemas":{"TimeOfDay":["hour","minute","timeZone"]},"fields":["endTime#TimeOfDay","startTime#TimeOfDay","configId","day"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "blackout-window",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "blackout-window",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "blackout-window",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "extended-retention" {
			var ExtendedRetention []backuprecoveryv1.ExtendedRetentionPolicy
			err, msg := deserialize.ModelSlice(
				r.ExtendedRetention,
				"extended-retention",
				"ExtendedRetentionPolicy",
				backuprecoveryv1.UnmarshalExtendedRetentionPolicy,
				&ExtendedRetention,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetExtendedRetention(ExtendedRetention)
			extraFieldPaths, err := r.utils.ValidateJSON(r.ExtendedRetention, `{"schemas":{"ExtendedRetentionSchedule":["unit","frequency"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"]},"fields":["runType","configId","schedule#ExtendedRetentionSchedule","retention#Retention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "extended-retention",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "extended-retention",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "extended-retention",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "remote-target-policy" {
			var RemoteTargetPolicy *backuprecoveryv1.TargetsConfiguration
			err, msg := deserialize.Model(
				r.RemoteTargetPolicy,
				"remote-target-policy",
				"TargetsConfiguration",
				backuprecoveryv1.UnmarshalTargetsConfiguration,
				&RemoteTargetPolicy,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetRemoteTargetPolicy(RemoteTargetPolicy)
			extraFieldPaths, err := r.utils.ValidateJSON(r.RemoteTargetPolicy, `{"schemas":{"OracleTiers":["tiers#OracleTier"],"GoogleTier":["moveAfterUnit","moveAfter","tierType"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"OnpremDeployTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","params#OnpremDeployParams"],"RemoteTargetConfig":["clusterId"],"AwsCloudSpinParams":["customTagList#CustomTagParams","region","subnetId","vpcId"],"OnpremDeployParams":["id"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"AzureTier":["moveAfterUnit","moveAfter","tierType"],"AzureCloudSpinParams":["availabilitySetId","networkResourceGroupId","resourceGroupId","storageAccountId","storageContainerId","storageResourceGroupId","tempVmResourceGroupId","tempVmStorageAccountId","tempVmStorageContainerId","tempVmSubnetId","tempVmVirtualNetworkId"],"AzureTargetConfig":["resourceGroup","sourceId"],"RpaasTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","targetId","targetType"],"TargetSchedule":["unit","frequency"],"OracleTier":["moveAfterUnit","moveAfter","tierType"],"ReplicationTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","awsTargetConfig#AWSTargetConfig","azureTargetConfig#AzureTargetConfig","targetType","remoteTargetConfig#RemoteTargetConfig"],"ExtendedRetentionSchedule":["unit","frequency"],"TierLevelSettings":["awsTiering#AWSTiers","azureTiering#AzureTiers","cloudPlatform","googleTiering#GoogleTiers","oracleTiering#OracleTiers"],"CustomTagParams":["key","value"],"CloudSpinTarget":["awsParams#AwsCloudSpinParams","azureParams#AzureCloudSpinParams","id"],"AWSTiers":["tiers#AWSTier"],"GoogleTiers":["tiers#GoogleTier"],"ExtendedRetentionPolicy":["schedule#ExtendedRetentionSchedule","retention#Retention","runType","configId"],"AWSTier":["moveAfterUnit","moveAfter","tierType"],"CloudSpinTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","target#CloudSpinTarget"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"],"AWSTargetConfig":["region","sourceId"],"ArchivalTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","targetId","tierSettings#TierLevelSettings","extendedRetention#ExtendedRetentionPolicy"],"AzureTiers":["tiers#AzureTier"]},"fields":["rpaasTargets#RpaasTargetConfiguration","onpremDeployTargets#OnpremDeployTargetConfiguration","replicationTargets#ReplicationTargetConfiguration","archivalTargets#ArchivalTargetConfiguration","cloudSpinTargets#CloudSpinTargetConfiguration"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "remote-target-policy",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "cascaded-targets-config" {
			var CascadedTargetsConfig []backuprecoveryv1.CascadedTargetConfiguration
			err, msg := deserialize.ModelSlice(
				r.CascadedTargetsConfig,
				"cascaded-targets-config",
				"CascadedTargetConfiguration",
				backuprecoveryv1.UnmarshalCascadedTargetConfiguration,
				&CascadedTargetsConfig,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetCascadedTargetsConfig(CascadedTargetsConfig)
			extraFieldPaths, err := r.utils.ValidateJSON(r.CascadedTargetsConfig, `{"schemas":{"OracleTiers":["tiers#OracleTier"],"GoogleTier":["moveAfterUnit","moveAfter","tierType"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"OnpremDeployTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","params#OnpremDeployParams"],"TargetsConfiguration":["replicationTargets#ReplicationTargetConfiguration","archivalTargets#ArchivalTargetConfiguration","cloudSpinTargets#CloudSpinTargetConfiguration","onpremDeployTargets#OnpremDeployTargetConfiguration","rpaasTargets#RpaasTargetConfiguration"],"RemoteTargetConfig":["clusterId"],"AwsCloudSpinParams":["customTagList#CustomTagParams","region","subnetId","vpcId"],"OnpremDeployParams":["id"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"AzureTier":["moveAfterUnit","moveAfter","tierType"],"AzureCloudSpinParams":["availabilitySetId","networkResourceGroupId","resourceGroupId","storageAccountId","storageContainerId","storageResourceGroupId","tempVmResourceGroupId","tempVmStorageAccountId","tempVmStorageContainerId","tempVmSubnetId","tempVmVirtualNetworkId"],"AzureTargetConfig":["resourceGroup","sourceId"],"RpaasTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","targetId","targetType"],"TargetSchedule":["unit","frequency"],"OracleTier":["moveAfterUnit","moveAfter","tierType"],"ReplicationTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","awsTargetConfig#AWSTargetConfig","azureTargetConfig#AzureTargetConfig","targetType","remoteTargetConfig#RemoteTargetConfig"],"ExtendedRetentionSchedule":["unit","frequency"],"TierLevelSettings":["awsTiering#AWSTiers","azureTiering#AzureTiers","cloudPlatform","googleTiering#GoogleTiers","oracleTiering#OracleTiers"],"CustomTagParams":["key","value"],"CloudSpinTarget":["awsParams#AwsCloudSpinParams","azureParams#AzureCloudSpinParams","id"],"AWSTiers":["tiers#AWSTier"],"GoogleTiers":["tiers#GoogleTier"],"ExtendedRetentionPolicy":["schedule#ExtendedRetentionSchedule","retention#Retention","runType","configId"],"AWSTier":["moveAfterUnit","moveAfter","tierType"],"CloudSpinTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","target#CloudSpinTarget"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"],"AWSTargetConfig":["region","sourceId"],"ArchivalTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","targetId","tierSettings#TierLevelSettings","extendedRetention#ExtendedRetentionPolicy"],"AzureTiers":["tiers#AzureTier"]},"fields":["remoteTargets#TargetsConfiguration","sourceClusterId"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "cascaded-targets-config",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "cascaded-targets-config",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "cascaded-targets-config",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "retry-options" {
			var RetryOptions *backuprecoveryv1.RetryOptions
			err, msg := deserialize.Model(
				r.RetryOptions,
				"retry-options",
				"RetryOptions",
				backuprecoveryv1.UnmarshalRetryOptions,
				&RetryOptions,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetRetryOptions(RetryOptions)
			extraFieldPaths, err := r.utils.ValidateJSON(r.RetryOptions, `{"fields":["retries","retryIntervalMins"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "retry-options",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "retry-options",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "retry-options",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "data-lock" {
			OptionsModel.SetDataLock(r.DataLock)
		}
		if flag.Name == "version" {
			OptionsModel.SetVersion(r.Version)
		}
		if flag.Name == "is-cbs-enabled" {
			OptionsModel.SetIsCBSEnabled(r.IsCBSEnabled)
		}
		if flag.Name == "last-modification-time-usecs" {
			OptionsModel.SetLastModificationTimeUsecs(r.LastModificationTimeUsecs)
		}
		if flag.Name == "template-id" {
			OptionsModel.SetTemplateID(r.TemplateID)
		}
		if flag.Name == "backup-policy-regular" {
			var BackupPolicyRegular *backuprecoveryv1.RegularBackupPolicy
			err, msg := deserialize.Model(
				r.BackupPolicyRegular,
				"backup-policy-regular",
				"RegularBackupPolicy",
				backuprecoveryv1.UnmarshalRegularBackupPolicy,
				&BackupPolicyRegular,
			)
			r.utils.HandleError(err, msg)
			BackupPolicyHelper.Regular = BackupPolicyRegular
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicyRegular, `{"schemas":{"OracleTiers":["tiers#OracleTier"],"GoogleTier":["moveAfterUnit","moveAfter","tierType"],"PrimaryArchivalTarget":["targetId","tierSettings#TierLevelSettings"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"FullBackupPolicy":["schedule#FullSchedule"],"HourSchedule":["frequency"],"FullSchedule":["unit","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"AzureTier":["moveAfterUnit","moveAfter","tierType"],"MonthSchedule":["dayOfWeek","weekOfMonth","dayOfMonth"],"DaySchedule":["frequency"],"YearSchedule":["dayOfYear"],"OracleTier":["moveAfterUnit","moveAfter","tierType"],"TierLevelSettings":["awsTiering#AWSTiers","azureTiering#AzureTiers","cloudPlatform","googleTiering#GoogleTiers","oracleTiering#OracleTiers"],"WeekSchedule":["dayOfWeek"],"AWSTiers":["tiers#AWSTier"],"IncrementalBackupPolicy":["schedule#IncrementalSchedule"],"GoogleTiers":["tiers#GoogleTier"],"IncrementalSchedule":["unit","minuteSchedule#MinuteSchedule","hourSchedule#HourSchedule","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"FullScheduleAndRetention":["schedule#FullSchedule","retention#Retention"],"AWSTier":["moveAfterUnit","moveAfter","tierType"],"PrimaryBackupTarget":["targetType","archivalTargetSettings#PrimaryArchivalTarget","useDefaultBackupTarget"],"MinuteSchedule":["frequency"],"AzureTiers":["tiers#AzureTier"]},"fields":["primaryBackupTarget#PrimaryBackupTarget","incremental#IncrementalBackupPolicy","fullBackups#FullScheduleAndRetention","retention#Retention","full#FullBackupPolicy"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy-regular",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-regular",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-regular",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "backup-policy-log" {
			var BackupPolicyLog *backuprecoveryv1.LogBackupPolicy
			err, msg := deserialize.Model(
				r.BackupPolicyLog,
				"backup-policy-log",
				"LogBackupPolicy",
				backuprecoveryv1.UnmarshalLogBackupPolicy,
				&BackupPolicyLog,
			)
			r.utils.HandleError(err, msg)
			BackupPolicyHelper.Log = BackupPolicyLog
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicyLog, `{"schemas":{"HourSchedule":["frequency"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"MinuteSchedule":["frequency"],"LogSchedule":["unit","minuteSchedule#MinuteSchedule","hourSchedule#HourSchedule"]},"fields":["retention#Retention","schedule#LogSchedule"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy-log",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-log",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-log",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "backup-policy-bmr" {
			var BackupPolicyBmr *backuprecoveryv1.BmrBackupPolicy
			err, msg := deserialize.Model(
				r.BackupPolicyBmr,
				"backup-policy-bmr",
				"BmrBackupPolicy",
				backuprecoveryv1.UnmarshalBmrBackupPolicy,
				&BackupPolicyBmr,
			)
			r.utils.HandleError(err, msg)
			BackupPolicyHelper.Bmr = BackupPolicyBmr
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicyBmr, `{"schemas":{"WeekSchedule":["dayOfWeek"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"BmrSchedule":["unit","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"MonthSchedule":["dayOfWeek","weekOfMonth","dayOfMonth"],"DaySchedule":["frequency"],"YearSchedule":["dayOfYear"]},"fields":["schedule#BmrSchedule","retention#Retention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy-bmr",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-bmr",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-bmr",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "backup-policy-cdp" {
			var BackupPolicyCdp *backuprecoveryv1.CdpBackupPolicy
			err, msg := deserialize.Model(
				r.BackupPolicyCdp,
				"backup-policy-cdp",
				"CdpBackupPolicy",
				backuprecoveryv1.UnmarshalCdpBackupPolicy,
				&BackupPolicyCdp,
			)
			r.utils.HandleError(err, msg)
			BackupPolicyHelper.Cdp = BackupPolicyCdp
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicyCdp, `{"schemas":{"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CdpRetention":["unit","duration","dataLockConfig#DataLockConfig"]},"fields":["retention#CdpRetention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy-cdp",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-cdp",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-cdp",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "backup-policy-storage-array-snapshot" {
			var BackupPolicyStorageArraySnapshot *backuprecoveryv1.StorageArraySnapshotBackupPolicy
			err, msg := deserialize.Model(
				r.BackupPolicyStorageArraySnapshot,
				"backup-policy-storage-array-snapshot",
				"StorageArraySnapshotBackupPolicy",
				backuprecoveryv1.UnmarshalStorageArraySnapshotBackupPolicy,
				&BackupPolicyStorageArraySnapshot,
			)
			r.utils.HandleError(err, msg)
			BackupPolicyHelper.StorageArraySnapshot = BackupPolicyStorageArraySnapshot
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicyStorageArraySnapshot, `{"schemas":{"HourSchedule":["frequency"],"WeekSchedule":["dayOfWeek"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"MinuteSchedule":["frequency"],"StorageArraySnapshotSchedule":["unit","minuteSchedule#MinuteSchedule","hourSchedule#HourSchedule","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"MonthSchedule":["dayOfWeek","weekOfMonth","dayOfMonth"],"DaySchedule":["frequency"],"YearSchedule":["dayOfYear"]},"fields":["schedule#StorageArraySnapshotSchedule","retention#Retention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy-storage-array-snapshot",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-storage-array-snapshot",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-storage-array-snapshot",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "backup-policy-run-timeouts" {
			var BackupPolicyRunTimeouts []backuprecoveryv1.CancellationTimeoutParams
			err, msg := deserialize.ModelSlice(
				r.BackupPolicyRunTimeouts,
				"backup-policy-run-timeouts",
				"CancellationTimeoutParams",
				backuprecoveryv1.UnmarshalCancellationTimeoutParams,
				&BackupPolicyRunTimeouts,
			)
			r.utils.HandleError(err, msg)
			BackupPolicyHelper.RunTimeouts = BackupPolicyRunTimeouts
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicyRunTimeouts, `{"fields":["timeoutMins","backupType"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy-run-timeouts",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-run-timeouts",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-run-timeouts",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "remote-target-policy-replication-targets" {
			var RemoteTargetPolicyReplicationTargets []backuprecoveryv1.ReplicationTargetConfiguration
			err, msg := deserialize.ModelSlice(
				r.RemoteTargetPolicyReplicationTargets,
				"remote-target-policy-replication-targets",
				"ReplicationTargetConfiguration",
				backuprecoveryv1.UnmarshalReplicationTargetConfiguration,
				&RemoteTargetPolicyReplicationTargets,
			)
			r.utils.HandleError(err, msg)
			RemoteTargetPolicyHelper.ReplicationTargets = RemoteTargetPolicyReplicationTargets
			extraFieldPaths, err := r.utils.ValidateJSON(r.RemoteTargetPolicyReplicationTargets, `{"schemas":{"TargetSchedule":["unit","frequency"],"RemoteTargetConfig":["clusterId"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"],"AWSTargetConfig":["region","sourceId"],"AzureTargetConfig":["resourceGroup","sourceId"]},"fields":["schedule#TargetSchedule","remoteTargetConfig#RemoteTargetConfig","backupRunType","azureTargetConfig#AzureTargetConfig","runTimeouts#CancellationTimeoutParams","configId","retention#Retention","copyOnRunSuccess","logRetention#LogRetention","targetType","awsTargetConfig#AWSTargetConfig"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "remote-target-policy-replication-targets",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-replication-targets",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-replication-targets",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "remote-target-policy-archival-targets" {
			var RemoteTargetPolicyArchivalTargets []backuprecoveryv1.ArchivalTargetConfiguration
			err, msg := deserialize.ModelSlice(
				r.RemoteTargetPolicyArchivalTargets,
				"remote-target-policy-archival-targets",
				"ArchivalTargetConfiguration",
				backuprecoveryv1.UnmarshalArchivalTargetConfiguration,
				&RemoteTargetPolicyArchivalTargets,
			)
			r.utils.HandleError(err, msg)
			RemoteTargetPolicyHelper.ArchivalTargets = RemoteTargetPolicyArchivalTargets
			extraFieldPaths, err := r.utils.ValidateJSON(r.RemoteTargetPolicyArchivalTargets, `{"schemas":{"TargetSchedule":["unit","frequency"],"OracleTier":["moveAfterUnit","moveAfter","tierType"],"ExtendedRetentionSchedule":["unit","frequency"],"TierLevelSettings":["awsTiering#AWSTiers","azureTiering#AzureTiers","cloudPlatform","googleTiering#GoogleTiers","oracleTiering#OracleTiers"],"OracleTiers":["tiers#OracleTier"],"AWSTiers":["tiers#AWSTier"],"GoogleTier":["moveAfterUnit","moveAfter","tierType"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"GoogleTiers":["tiers#GoogleTier"],"ExtendedRetentionPolicy":["schedule#ExtendedRetentionSchedule","retention#Retention","runType","configId"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"AzureTier":["moveAfterUnit","moveAfter","tierType"],"AWSTier":["moveAfterUnit","moveAfter","tierType"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"],"AzureTiers":["tiers#AzureTier"]},"fields":["schedule#TargetSchedule","backupRunType","tierSettings#TierLevelSettings","runTimeouts#CancellationTimeoutParams","targetId","configId","extendedRetention#ExtendedRetentionPolicy","retention#Retention","copyOnRunSuccess","logRetention#LogRetention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "remote-target-policy-archival-targets",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-archival-targets",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-archival-targets",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "remote-target-policy-cloud-spin-targets" {
			var RemoteTargetPolicyCloudSpinTargets []backuprecoveryv1.CloudSpinTargetConfiguration
			err, msg := deserialize.ModelSlice(
				r.RemoteTargetPolicyCloudSpinTargets,
				"remote-target-policy-cloud-spin-targets",
				"CloudSpinTargetConfiguration",
				backuprecoveryv1.UnmarshalCloudSpinTargetConfiguration,
				&RemoteTargetPolicyCloudSpinTargets,
			)
			r.utils.HandleError(err, msg)
			RemoteTargetPolicyHelper.CloudSpinTargets = RemoteTargetPolicyCloudSpinTargets
			extraFieldPaths, err := r.utils.ValidateJSON(r.RemoteTargetPolicyCloudSpinTargets, `{"schemas":{"TargetSchedule":["unit","frequency"],"CustomTagParams":["key","value"],"AwsCloudSpinParams":["customTagList#CustomTagParams","region","subnetId","vpcId"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"CloudSpinTarget":["awsParams#AwsCloudSpinParams","azureParams#AzureCloudSpinParams","id"],"AzureCloudSpinParams":["availabilitySetId","networkResourceGroupId","resourceGroupId","storageAccountId","storageContainerId","storageResourceGroupId","tempVmResourceGroupId","tempVmStorageAccountId","tempVmStorageContainerId","tempVmSubnetId","tempVmVirtualNetworkId"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"]},"fields":["schedule#TargetSchedule","backupRunType","target#CloudSpinTarget","runTimeouts#CancellationTimeoutParams","configId","retention#Retention","copyOnRunSuccess","logRetention#LogRetention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "remote-target-policy-cloud-spin-targets",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-cloud-spin-targets",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-cloud-spin-targets",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "remote-target-policy-onprem-deploy-targets" {
			var RemoteTargetPolicyOnpremDeployTargets []backuprecoveryv1.OnpremDeployTargetConfiguration
			err, msg := deserialize.ModelSlice(
				r.RemoteTargetPolicyOnpremDeployTargets,
				"remote-target-policy-onprem-deploy-targets",
				"OnpremDeployTargetConfiguration",
				backuprecoveryv1.UnmarshalOnpremDeployTargetConfiguration,
				&RemoteTargetPolicyOnpremDeployTargets,
			)
			r.utils.HandleError(err, msg)
			RemoteTargetPolicyHelper.OnpremDeployTargets = RemoteTargetPolicyOnpremDeployTargets
			extraFieldPaths, err := r.utils.ValidateJSON(r.RemoteTargetPolicyOnpremDeployTargets, `{"schemas":{"TargetSchedule":["unit","frequency"],"OnpremDeployParams":["id"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"]},"fields":["schedule#TargetSchedule","backupRunType","runTimeouts#CancellationTimeoutParams","configId","params#OnpremDeployParams","retention#Retention","copyOnRunSuccess","logRetention#LogRetention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "remote-target-policy-onprem-deploy-targets",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-onprem-deploy-targets",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-onprem-deploy-targets",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "remote-target-policy-rpaas-targets" {
			var RemoteTargetPolicyRpaasTargets []backuprecoveryv1.RpaasTargetConfiguration
			err, msg := deserialize.ModelSlice(
				r.RemoteTargetPolicyRpaasTargets,
				"remote-target-policy-rpaas-targets",
				"RpaasTargetConfiguration",
				backuprecoveryv1.UnmarshalRpaasTargetConfiguration,
				&RemoteTargetPolicyRpaasTargets,
			)
			r.utils.HandleError(err, msg)
			RemoteTargetPolicyHelper.RpaasTargets = RemoteTargetPolicyRpaasTargets
			extraFieldPaths, err := r.utils.ValidateJSON(r.RemoteTargetPolicyRpaasTargets, `{"schemas":{"TargetSchedule":["unit","frequency"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"]},"fields":["schedule#TargetSchedule","backupRunType","runTimeouts#CancellationTimeoutParams","targetId","configId","retention#Retention","copyOnRunSuccess","logRetention#LogRetention","targetType"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "remote-target-policy-rpaas-targets",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-rpaas-targets",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-rpaas-targets",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "retry-options-retries" {
			RetryOptionsHelper.Retries = core.Int64Ptr(r.RetryOptionsRetries)
		}
		if flag.Name == "retry-options-retry-interval-mins" {
			RetryOptionsHelper.RetryIntervalMins = core.Int64Ptr(r.RetryOptionsRetryIntervalMins)
		}
	})

	if !reflect.ValueOf(*BackupPolicyHelper).IsZero() {
		if OptionsModel.BackupPolicy == nil {
			OptionsModel.SetBackupPolicy(BackupPolicyHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "BackupPolicy",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*RemoteTargetPolicyHelper).IsZero() {
		if OptionsModel.RemoteTargetPolicy == nil {
			OptionsModel.SetRemoteTargetPolicy(RemoteTargetPolicyHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "RemoteTargetPolicy",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*RetryOptionsHelper).IsZero() {
		if OptionsModel.RetryOptions == nil {
			OptionsModel.SetRetryOptions(RetryOptionsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "RetryOptions",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}

	r.MakeRequest(OptionsModel)
}

func (r *CreateProtectionPolicyCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.CreateProtectionPolicyOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"name",
		"backupPolicy",
		"description",
		"blackoutWindow",
		"extendedRetention",
		"remoteTargetPolicy",
		"cascadedTargetsConfig",
		"retryOptions",
		"dataLock",
		"version",
		"isCBSEnabled",
		"lastModificationTimeUsecs",
		"id",
		"templateId",
		"isUsable",
		"isReplicated",
		"numProtectionGroups",
		"numProtectedObjects",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for GetProtectionPolicyByID command
type GetProtectionPolicyByIDRequestSender struct{}

func (s GetProtectionPolicyByIDRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetProtectionPolicyByID(optionsModel.(*backuprecoveryv1.GetProtectionPolicyByIdOptions))
}

// Command Runner for GetProtectionPolicyByID command
func NewGetProtectionPolicyByIDCommandRunner(utils Utilities, sender RequestSender) *GetProtectionPolicyByIDCommandRunner {
	return &GetProtectionPolicyByIDCommandRunner{utils: utils, sender: sender}
}

type GetProtectionPolicyByIDCommandRunner struct {
	ID                   string
	XIBMTenantID         string
	RequestInitiatorType string
	RequiredFlags        []string
	sender               RequestSender
	utils                Utilities
}

// Command mapping: protection-policy get, GetGetProtectionPolicyByIDCommand
func GetGetProtectionPolicyByIDCommand(r *GetProtectionPolicyByIDCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "get --id ID --xibm-tenant-id XIBM-TENANT-ID [--request-initiator-type REQUEST-INITIATOR-TYPE]",
		Short:                 translation.T("backup-recovery-protection-policy-get-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-policy-get-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-policy",
			"x-cli-command":       "get",
		},
		Example: `  ibmcloud backup-recovery protection-policy get \
    --id exampleString \
    --xibm-tenant-id tenantId \
    --request-initiator-type UIUser`,
	}

	cmd.Flags().StringVarP(&r.ID, "id", "", "", translation.T("backup-recovery-protection-policy-get-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-policy-get-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.RequestInitiatorType, "request-initiator-type", "", "", translation.T("backup-recovery-protection-policy-get-request-initiator-type-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetProtectionPolicyByID
func (r *GetProtectionPolicyByIDCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetProtectionPolicyByIdOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "request-initiator-type" {
			OptionsModel.SetRequestInitiatorType(r.RequestInitiatorType)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetProtectionPolicyByIDCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetProtectionPolicyByIdOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"name",
		"backupPolicy",
		"description",
		"blackoutWindow",
		"extendedRetention",
		"remoteTargetPolicy",
		"cascadedTargetsConfig",
		"retryOptions",
		"dataLock",
		"version",
		"isCBSEnabled",
		"lastModificationTimeUsecs",
		"id",
		"templateId",
		"isUsable",
		"isReplicated",
		"numProtectionGroups",
		"numProtectedObjects",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for UpdateProtectionPolicy command
type UpdateProtectionPolicyRequestSender struct{}

func (s UpdateProtectionPolicyRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.UpdateProtectionPolicy(optionsModel.(*backuprecoveryv1.UpdateProtectionPolicyOptions))
}

// Command Runner for UpdateProtectionPolicy command
func NewUpdateProtectionPolicyCommandRunner(utils Utilities, sender RequestSender) *UpdateProtectionPolicyCommandRunner {
	return &UpdateProtectionPolicyCommandRunner{utils: utils, sender: sender}
}

type UpdateProtectionPolicyCommandRunner struct {
	ID                                    string
	XIBMTenantID                          string
	Name                                  string
	BackupPolicy                          string
	Description                           string
	BlackoutWindow                        string
	ExtendedRetention                     string
	RemoteTargetPolicy                    string
	CascadedTargetsConfig                 string
	RetryOptions                          string
	DataLock                              string
	Version                               int64
	IsCBSEnabled                          bool
	LastModificationTimeUsecs             int64
	TemplateID                            string
	BackupPolicyRegular                   string
	BackupPolicyLog                       string
	BackupPolicyBmr                       string
	BackupPolicyCdp                       string
	BackupPolicyStorageArraySnapshot      string
	BackupPolicyRunTimeouts               string
	RemoteTargetPolicyReplicationTargets  string
	RemoteTargetPolicyArchivalTargets     string
	RemoteTargetPolicyCloudSpinTargets    string
	RemoteTargetPolicyOnpremDeployTargets string
	RemoteTargetPolicyRpaasTargets        string
	RetryOptionsRetries                   int64
	RetryOptionsRetryIntervalMins         int64
	RequiredFlags                         []string
	sender                                RequestSender
	utils                                 Utilities
}

// Command mapping: protection-policy update, GetUpdateProtectionPolicyCommand
func GetUpdateProtectionPolicyCommand(r *UpdateProtectionPolicyCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "update [command options]",
		Short:                 translation.T("backup-recovery-protection-policy-update-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-policy-update-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-policy",
			"x-cli-command":       "update",
		},
		Example: `  ibmcloud backup-recovery protection-policy update \
    --id exampleString \
    --xibm-tenant-id tenantId \
    --name update-protection-policy \
    --backup-policy '{"regular": {"incremental": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}, "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}}, "full": {"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}}, "fullBackups": [{"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}], "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "primaryBackupTarget": {"targetType": "Local", "archivalTargetSettings": {"targetId": 26, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}}, "useDefaultBackupTarget": true}}, "log": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "bmr": {"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "cdp": {"retention": {"unit": "Minutes", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "storageArraySnapshot": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}, "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}]}' \
    --description 'Protection Policy' \
    --blackout-window '[{"day": "Sunday", "startTime": {"hour": 1, "minute": 15, "timeZone": "America/Los_Angeles"}, "endTime": {"hour": 1, "minute": 15, "timeZone": "America/Los_Angeles"}, "configId": "Config-Id"}]' \
    --extended-retention '[{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]' \
    --remote-target-policy '{"replicationTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "awsTargetConfig": {"region": 26, "sourceId": 26}, "azureTargetConfig": {"resourceGroup": 26, "sourceId": 26}, "targetType": "RemoteCluster", "remoteTargetConfig": {"clusterId": 26}}], "archivalTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}, "extendedRetention": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]}], "cloudSpinTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "target": {"awsParams": {"customTagList": [{"key": "custom-tag-key", "value": "custom-tag-value"}], "region": 3, "subnetId": 26, "vpcId": 26}, "azureParams": {"availabilitySetId": 26, "networkResourceGroupId": 26, "resourceGroupId": 26, "storageAccountId": 26, "storageContainerId": 26, "storageResourceGroupId": 26, "tempVmResourceGroupId": 26, "tempVmStorageAccountId": 26, "tempVmStorageContainerId": 26, "tempVmSubnetId": 26, "tempVmVirtualNetworkId": 26}, "id": 2}}], "onpremDeployTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "params": {"id": 4}}], "rpaasTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "targetType": "Tape"}]}' \
    --cascaded-targets-config '[{"sourceClusterId": 26, "remoteTargets": {"replicationTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "awsTargetConfig": {"region": 26, "sourceId": 26}, "azureTargetConfig": {"resourceGroup": 26, "sourceId": 26}, "targetType": "RemoteCluster", "remoteTargetConfig": {"clusterId": 26}}], "archivalTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}, "extendedRetention": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]}], "cloudSpinTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "target": {"awsParams": {"customTagList": [{"key": "custom-tag-key", "value": "custom-tag-value"}], "region": 3, "subnetId": 26, "vpcId": 26}, "azureParams": {"availabilitySetId": 26, "networkResourceGroupId": 26, "resourceGroupId": 26, "storageAccountId": 26, "storageContainerId": 26, "storageResourceGroupId": 26, "tempVmResourceGroupId": 26, "tempVmStorageAccountId": 26, "tempVmStorageContainerId": 26, "tempVmSubnetId": 26, "tempVmVirtualNetworkId": 26}, "id": 2}}], "onpremDeployTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "params": {"id": 4}}], "rpaasTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "targetType": "Tape"}]}}]' \
    --retry-options '{"retries": 0, "retryIntervalMins": 1}' \
    --data-lock Compliance \
    --version 38 \
    --is-cbs-enabled=true \
    --last-modification-time-usecs 26 \
    --template-id protection-policy-template`,
	}

	cmd.Flags().StringVarP(&r.ID, "id", "", "", translation.T("backup-recovery-protection-policy-update-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-policy-update-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Name, "name", "", "", translation.T("backup-recovery-protection-policy-update-name-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicy, "backup-policy", "", "", translation.T("backup-recovery-protection-policy-update-backup-policy-flag-description"))
	cmd.Flags().StringVarP(&r.Description, "description", "", "", translation.T("backup-recovery-protection-policy-update-description-flag-description"))
	cmd.Flags().StringVarP(&r.BlackoutWindow, "blackout-window", "", "", translation.T("backup-recovery-protection-policy-update-blackout-window-flag-description"))
	cmd.Flags().StringVarP(&r.ExtendedRetention, "extended-retention", "", "", translation.T("backup-recovery-protection-policy-update-extended-retention-flag-description"))
	cmd.Flags().StringVarP(&r.RemoteTargetPolicy, "remote-target-policy", "", "", translation.T("backup-recovery-protection-policy-update-remote-target-policy-flag-description"))
	cmd.Flags().StringVarP(&r.CascadedTargetsConfig, "cascaded-targets-config", "", "", translation.T("backup-recovery-protection-policy-update-cascaded-targets-config-flag-description"))
	cmd.Flags().StringVarP(&r.RetryOptions, "retry-options", "", "", translation.T("backup-recovery-protection-policy-update-retry-options-flag-description"))
	cmd.Flags().StringVarP(&r.DataLock, "data-lock", "", "", translation.T("backup-recovery-protection-policy-update-data-lock-flag-description"))
	cmd.Flags().Int64VarP(&r.Version, "version", "", 0, translation.T("backup-recovery-protection-policy-update-version-flag-description"))
	cmd.Flags().BoolVarP(&r.IsCBSEnabled, "is-cbs-enabled", "", false, translation.T("backup-recovery-protection-policy-update-is-cbs-enabled-flag-description"))
	cmd.Flags().Int64VarP(&r.LastModificationTimeUsecs, "last-modification-time-usecs", "", 0, translation.T("backup-recovery-protection-policy-update-last-modification-time-usecs-flag-description"))
	cmd.Flags().StringVarP(&r.TemplateID, "template-id", "", "", translation.T("backup-recovery-protection-policy-update-template-id-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicyRegular, "backup-policy-regular", "", "", translation.T("backup-recovery-protection-policy-update-backup-policy-regular-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicyLog, "backup-policy-log", "", "", translation.T("backup-recovery-protection-policy-update-backup-policy-log-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicyBmr, "backup-policy-bmr", "", "", translation.T("backup-recovery-protection-policy-update-backup-policy-bmr-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicyCdp, "backup-policy-cdp", "", "", translation.T("backup-recovery-protection-policy-update-backup-policy-cdp-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicyStorageArraySnapshot, "backup-policy-storage-array-snapshot", "", "", translation.T("backup-recovery-protection-policy-update-backup-policy-storage-array-snapshot-flag-description"))
	cmd.Flags().StringVarP(&r.BackupPolicyRunTimeouts, "backup-policy-run-timeouts", "", "", translation.T("backup-recovery-protection-policy-update-backup-policy-run-timeouts-flag-description"))
	cmd.Flags().StringVarP(&r.RemoteTargetPolicyReplicationTargets, "remote-target-policy-replication-targets", "", "", translation.T("backup-recovery-protection-policy-update-remote-target-policy-replication-targets-flag-description"))
	cmd.Flags().StringVarP(&r.RemoteTargetPolicyArchivalTargets, "remote-target-policy-archival-targets", "", "", translation.T("backup-recovery-protection-policy-update-remote-target-policy-archival-targets-flag-description"))
	cmd.Flags().StringVarP(&r.RemoteTargetPolicyCloudSpinTargets, "remote-target-policy-cloud-spin-targets", "", "", translation.T("backup-recovery-protection-policy-update-remote-target-policy-cloud-spin-targets-flag-description"))
	cmd.Flags().StringVarP(&r.RemoteTargetPolicyOnpremDeployTargets, "remote-target-policy-onprem-deploy-targets", "", "", translation.T("backup-recovery-protection-policy-update-remote-target-policy-onprem-deploy-targets-flag-description"))
	cmd.Flags().StringVarP(&r.RemoteTargetPolicyRpaasTargets, "remote-target-policy-rpaas-targets", "", "", translation.T("backup-recovery-protection-policy-update-remote-target-policy-rpaas-targets-flag-description"))
	cmd.Flags().Int64VarP(&r.RetryOptionsRetries, "retry-options-retries", "", 0, translation.T("backup-recovery-protection-policy-update-retry-options-retries-flag-description"))
	cmd.Flags().Int64VarP(&r.RetryOptionsRetryIntervalMins, "retry-options-retry-interval-mins", "", 0, translation.T("backup-recovery-protection-policy-update-retry-options-retry-interval-mins-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
		"name",
	}

	return cmd
}

// Primary logic for running UpdateProtectionPolicy
func (r *UpdateProtectionPolicyCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.UpdateProtectionPolicyOptions{}
	BackupPolicyHelper := &backuprecoveryv1.BackupPolicy{}
	RemoteTargetPolicyHelper := &backuprecoveryv1.TargetsConfiguration{}
	RetryOptionsHelper := &backuprecoveryv1.RetryOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "name" {
			OptionsModel.SetName(r.Name)
		}
		if flag.Name == "backup-policy" {
			var BackupPolicy *backuprecoveryv1.BackupPolicy
			err, msg := deserialize.Model(
				r.BackupPolicy,
				"backup-policy",
				"BackupPolicy",
				backuprecoveryv1.UnmarshalBackupPolicy,
				&BackupPolicy,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetBackupPolicy(BackupPolicy)
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicy, `{"schemas":{"OracleTiers":["tiers#OracleTier"],"GoogleTier":["moveAfterUnit","moveAfter","tierType"],"PrimaryArchivalTarget":["targetId","tierSettings#TierLevelSettings"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"FullBackupPolicy":["schedule#FullSchedule"],"CdpBackupPolicy":["retention#CdpRetention"],"HourSchedule":["frequency"],"FullSchedule":["unit","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"AzureTier":["moveAfterUnit","moveAfter","tierType"],"LogSchedule":["unit","minuteSchedule#MinuteSchedule","hourSchedule#HourSchedule"],"MonthSchedule":["dayOfWeek","weekOfMonth","dayOfMonth"],"DaySchedule":["frequency"],"YearSchedule":["dayOfYear"],"BmrBackupPolicy":["schedule#BmrSchedule","retention#Retention"],"StorageArraySnapshotBackupPolicy":["schedule#StorageArraySnapshotSchedule","retention#Retention"],"OracleTier":["moveAfterUnit","moveAfter","tierType"],"TierLevelSettings":["awsTiering#AWSTiers","azureTiering#AzureTiers","cloudPlatform","googleTiering#GoogleTiers","oracleTiering#OracleTiers"],"WeekSchedule":["dayOfWeek"],"CdpRetention":["unit","duration","dataLockConfig#DataLockConfig"],"AWSTiers":["tiers#AWSTier"],"LogBackupPolicy":["schedule#LogSchedule","retention#Retention"],"BmrSchedule":["unit","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"IncrementalBackupPolicy":["schedule#IncrementalSchedule"],"GoogleTiers":["tiers#GoogleTier"],"RegularBackupPolicy":["incremental#IncrementalBackupPolicy","full#FullBackupPolicy","fullBackups#FullScheduleAndRetention","retention#Retention","primaryBackupTarget#PrimaryBackupTarget"],"IncrementalSchedule":["unit","minuteSchedule#MinuteSchedule","hourSchedule#HourSchedule","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"FullScheduleAndRetention":["schedule#FullSchedule","retention#Retention"],"AWSTier":["moveAfterUnit","moveAfter","tierType"],"PrimaryBackupTarget":["targetType","archivalTargetSettings#PrimaryArchivalTarget","useDefaultBackupTarget"],"MinuteSchedule":["frequency"],"StorageArraySnapshotSchedule":["unit","minuteSchedule#MinuteSchedule","hourSchedule#HourSchedule","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"AzureTiers":["tiers#AzureTier"]},"fields":["log#LogBackupPolicy","runTimeouts#CancellationTimeoutParams","storageArraySnapshot#StorageArraySnapshotBackupPolicy","regular#RegularBackupPolicy","bmr#BmrBackupPolicy","cdp#CdpBackupPolicy"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "description" {
			OptionsModel.SetDescription(r.Description)
		}
		if flag.Name == "blackout-window" {
			var BlackoutWindow []backuprecoveryv1.BlackoutWindow
			err, msg := deserialize.ModelSlice(
				r.BlackoutWindow,
				"blackout-window",
				"BlackoutWindow",
				backuprecoveryv1.UnmarshalBlackoutWindow,
				&BlackoutWindow,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetBlackoutWindow(BlackoutWindow)
			extraFieldPaths, err := r.utils.ValidateJSON(r.BlackoutWindow, `{"schemas":{"TimeOfDay":["hour","minute","timeZone"]},"fields":["endTime#TimeOfDay","startTime#TimeOfDay","configId","day"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "blackout-window",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "blackout-window",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "blackout-window",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "extended-retention" {
			var ExtendedRetention []backuprecoveryv1.ExtendedRetentionPolicy
			err, msg := deserialize.ModelSlice(
				r.ExtendedRetention,
				"extended-retention",
				"ExtendedRetentionPolicy",
				backuprecoveryv1.UnmarshalExtendedRetentionPolicy,
				&ExtendedRetention,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetExtendedRetention(ExtendedRetention)
			extraFieldPaths, err := r.utils.ValidateJSON(r.ExtendedRetention, `{"schemas":{"ExtendedRetentionSchedule":["unit","frequency"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"]},"fields":["runType","configId","schedule#ExtendedRetentionSchedule","retention#Retention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "extended-retention",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "extended-retention",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "extended-retention",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "remote-target-policy" {
			var RemoteTargetPolicy *backuprecoveryv1.TargetsConfiguration
			err, msg := deserialize.Model(
				r.RemoteTargetPolicy,
				"remote-target-policy",
				"TargetsConfiguration",
				backuprecoveryv1.UnmarshalTargetsConfiguration,
				&RemoteTargetPolicy,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetRemoteTargetPolicy(RemoteTargetPolicy)
			extraFieldPaths, err := r.utils.ValidateJSON(r.RemoteTargetPolicy, `{"schemas":{"OracleTiers":["tiers#OracleTier"],"GoogleTier":["moveAfterUnit","moveAfter","tierType"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"OnpremDeployTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","params#OnpremDeployParams"],"RemoteTargetConfig":["clusterId"],"AwsCloudSpinParams":["customTagList#CustomTagParams","region","subnetId","vpcId"],"OnpremDeployParams":["id"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"AzureTier":["moveAfterUnit","moveAfter","tierType"],"AzureCloudSpinParams":["availabilitySetId","networkResourceGroupId","resourceGroupId","storageAccountId","storageContainerId","storageResourceGroupId","tempVmResourceGroupId","tempVmStorageAccountId","tempVmStorageContainerId","tempVmSubnetId","tempVmVirtualNetworkId"],"AzureTargetConfig":["resourceGroup","sourceId"],"RpaasTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","targetId","targetType"],"TargetSchedule":["unit","frequency"],"OracleTier":["moveAfterUnit","moveAfter","tierType"],"ReplicationTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","awsTargetConfig#AWSTargetConfig","azureTargetConfig#AzureTargetConfig","targetType","remoteTargetConfig#RemoteTargetConfig"],"ExtendedRetentionSchedule":["unit","frequency"],"TierLevelSettings":["awsTiering#AWSTiers","azureTiering#AzureTiers","cloudPlatform","googleTiering#GoogleTiers","oracleTiering#OracleTiers"],"CustomTagParams":["key","value"],"CloudSpinTarget":["awsParams#AwsCloudSpinParams","azureParams#AzureCloudSpinParams","id"],"AWSTiers":["tiers#AWSTier"],"GoogleTiers":["tiers#GoogleTier"],"ExtendedRetentionPolicy":["schedule#ExtendedRetentionSchedule","retention#Retention","runType","configId"],"AWSTier":["moveAfterUnit","moveAfter","tierType"],"CloudSpinTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","target#CloudSpinTarget"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"],"AWSTargetConfig":["region","sourceId"],"ArchivalTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","targetId","tierSettings#TierLevelSettings","extendedRetention#ExtendedRetentionPolicy"],"AzureTiers":["tiers#AzureTier"]},"fields":["rpaasTargets#RpaasTargetConfiguration","onpremDeployTargets#OnpremDeployTargetConfiguration","replicationTargets#ReplicationTargetConfiguration","archivalTargets#ArchivalTargetConfiguration","cloudSpinTargets#CloudSpinTargetConfiguration"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "remote-target-policy",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "cascaded-targets-config" {
			var CascadedTargetsConfig []backuprecoveryv1.CascadedTargetConfiguration
			err, msg := deserialize.ModelSlice(
				r.CascadedTargetsConfig,
				"cascaded-targets-config",
				"CascadedTargetConfiguration",
				backuprecoveryv1.UnmarshalCascadedTargetConfiguration,
				&CascadedTargetsConfig,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetCascadedTargetsConfig(CascadedTargetsConfig)
			extraFieldPaths, err := r.utils.ValidateJSON(r.CascadedTargetsConfig, `{"schemas":{"OracleTiers":["tiers#OracleTier"],"GoogleTier":["moveAfterUnit","moveAfter","tierType"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"OnpremDeployTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","params#OnpremDeployParams"],"TargetsConfiguration":["replicationTargets#ReplicationTargetConfiguration","archivalTargets#ArchivalTargetConfiguration","cloudSpinTargets#CloudSpinTargetConfiguration","onpremDeployTargets#OnpremDeployTargetConfiguration","rpaasTargets#RpaasTargetConfiguration"],"RemoteTargetConfig":["clusterId"],"AwsCloudSpinParams":["customTagList#CustomTagParams","region","subnetId","vpcId"],"OnpremDeployParams":["id"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"AzureTier":["moveAfterUnit","moveAfter","tierType"],"AzureCloudSpinParams":["availabilitySetId","networkResourceGroupId","resourceGroupId","storageAccountId","storageContainerId","storageResourceGroupId","tempVmResourceGroupId","tempVmStorageAccountId","tempVmStorageContainerId","tempVmSubnetId","tempVmVirtualNetworkId"],"AzureTargetConfig":["resourceGroup","sourceId"],"RpaasTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","targetId","targetType"],"TargetSchedule":["unit","frequency"],"OracleTier":["moveAfterUnit","moveAfter","tierType"],"ReplicationTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","awsTargetConfig#AWSTargetConfig","azureTargetConfig#AzureTargetConfig","targetType","remoteTargetConfig#RemoteTargetConfig"],"ExtendedRetentionSchedule":["unit","frequency"],"TierLevelSettings":["awsTiering#AWSTiers","azureTiering#AzureTiers","cloudPlatform","googleTiering#GoogleTiers","oracleTiering#OracleTiers"],"CustomTagParams":["key","value"],"CloudSpinTarget":["awsParams#AwsCloudSpinParams","azureParams#AzureCloudSpinParams","id"],"AWSTiers":["tiers#AWSTier"],"GoogleTiers":["tiers#GoogleTier"],"ExtendedRetentionPolicy":["schedule#ExtendedRetentionSchedule","retention#Retention","runType","configId"],"AWSTier":["moveAfterUnit","moveAfter","tierType"],"CloudSpinTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","target#CloudSpinTarget"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"],"AWSTargetConfig":["region","sourceId"],"ArchivalTargetConfiguration":["schedule#TargetSchedule","retention#Retention","copyOnRunSuccess","configId","backupRunType","runTimeouts#CancellationTimeoutParams","logRetention#LogRetention","targetId","tierSettings#TierLevelSettings","extendedRetention#ExtendedRetentionPolicy"],"AzureTiers":["tiers#AzureTier"]},"fields":["remoteTargets#TargetsConfiguration","sourceClusterId"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "cascaded-targets-config",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "cascaded-targets-config",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "cascaded-targets-config",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "retry-options" {
			var RetryOptions *backuprecoveryv1.RetryOptions
			err, msg := deserialize.Model(
				r.RetryOptions,
				"retry-options",
				"RetryOptions",
				backuprecoveryv1.UnmarshalRetryOptions,
				&RetryOptions,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetRetryOptions(RetryOptions)
			extraFieldPaths, err := r.utils.ValidateJSON(r.RetryOptions, `{"fields":["retries","retryIntervalMins"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "retry-options",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "retry-options",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "retry-options",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "data-lock" {
			OptionsModel.SetDataLock(r.DataLock)
		}
		if flag.Name == "version" {
			OptionsModel.SetVersion(r.Version)
		}
		if flag.Name == "is-cbs-enabled" {
			OptionsModel.SetIsCBSEnabled(r.IsCBSEnabled)
		}
		if flag.Name == "last-modification-time-usecs" {
			OptionsModel.SetLastModificationTimeUsecs(r.LastModificationTimeUsecs)
		}
		if flag.Name == "template-id" {
			OptionsModel.SetTemplateID(r.TemplateID)
		}
		if flag.Name == "backup-policy-regular" {
			var BackupPolicyRegular *backuprecoveryv1.RegularBackupPolicy
			err, msg := deserialize.Model(
				r.BackupPolicyRegular,
				"backup-policy-regular",
				"RegularBackupPolicy",
				backuprecoveryv1.UnmarshalRegularBackupPolicy,
				&BackupPolicyRegular,
			)
			r.utils.HandleError(err, msg)
			BackupPolicyHelper.Regular = BackupPolicyRegular
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicyRegular, `{"schemas":{"OracleTiers":["tiers#OracleTier"],"GoogleTier":["moveAfterUnit","moveAfter","tierType"],"PrimaryArchivalTarget":["targetId","tierSettings#TierLevelSettings"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"FullBackupPolicy":["schedule#FullSchedule"],"HourSchedule":["frequency"],"FullSchedule":["unit","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"AzureTier":["moveAfterUnit","moveAfter","tierType"],"MonthSchedule":["dayOfWeek","weekOfMonth","dayOfMonth"],"DaySchedule":["frequency"],"YearSchedule":["dayOfYear"],"OracleTier":["moveAfterUnit","moveAfter","tierType"],"TierLevelSettings":["awsTiering#AWSTiers","azureTiering#AzureTiers","cloudPlatform","googleTiering#GoogleTiers","oracleTiering#OracleTiers"],"WeekSchedule":["dayOfWeek"],"AWSTiers":["tiers#AWSTier"],"IncrementalBackupPolicy":["schedule#IncrementalSchedule"],"GoogleTiers":["tiers#GoogleTier"],"IncrementalSchedule":["unit","minuteSchedule#MinuteSchedule","hourSchedule#HourSchedule","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"FullScheduleAndRetention":["schedule#FullSchedule","retention#Retention"],"AWSTier":["moveAfterUnit","moveAfter","tierType"],"PrimaryBackupTarget":["targetType","archivalTargetSettings#PrimaryArchivalTarget","useDefaultBackupTarget"],"MinuteSchedule":["frequency"],"AzureTiers":["tiers#AzureTier"]},"fields":["primaryBackupTarget#PrimaryBackupTarget","incremental#IncrementalBackupPolicy","fullBackups#FullScheduleAndRetention","retention#Retention","full#FullBackupPolicy"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy-regular",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-regular",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-regular",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "backup-policy-log" {
			var BackupPolicyLog *backuprecoveryv1.LogBackupPolicy
			err, msg := deserialize.Model(
				r.BackupPolicyLog,
				"backup-policy-log",
				"LogBackupPolicy",
				backuprecoveryv1.UnmarshalLogBackupPolicy,
				&BackupPolicyLog,
			)
			r.utils.HandleError(err, msg)
			BackupPolicyHelper.Log = BackupPolicyLog
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicyLog, `{"schemas":{"HourSchedule":["frequency"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"MinuteSchedule":["frequency"],"LogSchedule":["unit","minuteSchedule#MinuteSchedule","hourSchedule#HourSchedule"]},"fields":["retention#Retention","schedule#LogSchedule"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy-log",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-log",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-log",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "backup-policy-bmr" {
			var BackupPolicyBmr *backuprecoveryv1.BmrBackupPolicy
			err, msg := deserialize.Model(
				r.BackupPolicyBmr,
				"backup-policy-bmr",
				"BmrBackupPolicy",
				backuprecoveryv1.UnmarshalBmrBackupPolicy,
				&BackupPolicyBmr,
			)
			r.utils.HandleError(err, msg)
			BackupPolicyHelper.Bmr = BackupPolicyBmr
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicyBmr, `{"schemas":{"WeekSchedule":["dayOfWeek"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"BmrSchedule":["unit","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"MonthSchedule":["dayOfWeek","weekOfMonth","dayOfMonth"],"DaySchedule":["frequency"],"YearSchedule":["dayOfYear"]},"fields":["schedule#BmrSchedule","retention#Retention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy-bmr",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-bmr",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-bmr",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "backup-policy-cdp" {
			var BackupPolicyCdp *backuprecoveryv1.CdpBackupPolicy
			err, msg := deserialize.Model(
				r.BackupPolicyCdp,
				"backup-policy-cdp",
				"CdpBackupPolicy",
				backuprecoveryv1.UnmarshalCdpBackupPolicy,
				&BackupPolicyCdp,
			)
			r.utils.HandleError(err, msg)
			BackupPolicyHelper.Cdp = BackupPolicyCdp
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicyCdp, `{"schemas":{"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CdpRetention":["unit","duration","dataLockConfig#DataLockConfig"]},"fields":["retention#CdpRetention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy-cdp",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-cdp",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-cdp",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "backup-policy-storage-array-snapshot" {
			var BackupPolicyStorageArraySnapshot *backuprecoveryv1.StorageArraySnapshotBackupPolicy
			err, msg := deserialize.Model(
				r.BackupPolicyStorageArraySnapshot,
				"backup-policy-storage-array-snapshot",
				"StorageArraySnapshotBackupPolicy",
				backuprecoveryv1.UnmarshalStorageArraySnapshotBackupPolicy,
				&BackupPolicyStorageArraySnapshot,
			)
			r.utils.HandleError(err, msg)
			BackupPolicyHelper.StorageArraySnapshot = BackupPolicyStorageArraySnapshot
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicyStorageArraySnapshot, `{"schemas":{"HourSchedule":["frequency"],"WeekSchedule":["dayOfWeek"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"MinuteSchedule":["frequency"],"StorageArraySnapshotSchedule":["unit","minuteSchedule#MinuteSchedule","hourSchedule#HourSchedule","daySchedule#DaySchedule","weekSchedule#WeekSchedule","monthSchedule#MonthSchedule","yearSchedule#YearSchedule"],"MonthSchedule":["dayOfWeek","weekOfMonth","dayOfMonth"],"DaySchedule":["frequency"],"YearSchedule":["dayOfYear"]},"fields":["schedule#StorageArraySnapshotSchedule","retention#Retention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy-storage-array-snapshot",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-storage-array-snapshot",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-storage-array-snapshot",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "backup-policy-run-timeouts" {
			var BackupPolicyRunTimeouts []backuprecoveryv1.CancellationTimeoutParams
			err, msg := deserialize.ModelSlice(
				r.BackupPolicyRunTimeouts,
				"backup-policy-run-timeouts",
				"CancellationTimeoutParams",
				backuprecoveryv1.UnmarshalCancellationTimeoutParams,
				&BackupPolicyRunTimeouts,
			)
			r.utils.HandleError(err, msg)
			BackupPolicyHelper.RunTimeouts = BackupPolicyRunTimeouts
			extraFieldPaths, err := r.utils.ValidateJSON(r.BackupPolicyRunTimeouts, `{"fields":["timeoutMins","backupType"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "backup-policy-run-timeouts",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-run-timeouts",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "backup-policy-run-timeouts",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "remote-target-policy-replication-targets" {
			var RemoteTargetPolicyReplicationTargets []backuprecoveryv1.ReplicationTargetConfiguration
			err, msg := deserialize.ModelSlice(
				r.RemoteTargetPolicyReplicationTargets,
				"remote-target-policy-replication-targets",
				"ReplicationTargetConfiguration",
				backuprecoveryv1.UnmarshalReplicationTargetConfiguration,
				&RemoteTargetPolicyReplicationTargets,
			)
			r.utils.HandleError(err, msg)
			RemoteTargetPolicyHelper.ReplicationTargets = RemoteTargetPolicyReplicationTargets
			extraFieldPaths, err := r.utils.ValidateJSON(r.RemoteTargetPolicyReplicationTargets, `{"schemas":{"TargetSchedule":["unit","frequency"],"RemoteTargetConfig":["clusterId"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"],"AWSTargetConfig":["region","sourceId"],"AzureTargetConfig":["resourceGroup","sourceId"]},"fields":["schedule#TargetSchedule","remoteTargetConfig#RemoteTargetConfig","backupRunType","azureTargetConfig#AzureTargetConfig","runTimeouts#CancellationTimeoutParams","configId","retention#Retention","copyOnRunSuccess","logRetention#LogRetention","targetType","awsTargetConfig#AWSTargetConfig"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "remote-target-policy-replication-targets",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-replication-targets",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-replication-targets",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "remote-target-policy-archival-targets" {
			var RemoteTargetPolicyArchivalTargets []backuprecoveryv1.ArchivalTargetConfiguration
			err, msg := deserialize.ModelSlice(
				r.RemoteTargetPolicyArchivalTargets,
				"remote-target-policy-archival-targets",
				"ArchivalTargetConfiguration",
				backuprecoveryv1.UnmarshalArchivalTargetConfiguration,
				&RemoteTargetPolicyArchivalTargets,
			)
			r.utils.HandleError(err, msg)
			RemoteTargetPolicyHelper.ArchivalTargets = RemoteTargetPolicyArchivalTargets
			extraFieldPaths, err := r.utils.ValidateJSON(r.RemoteTargetPolicyArchivalTargets, `{"schemas":{"TargetSchedule":["unit","frequency"],"OracleTier":["moveAfterUnit","moveAfter","tierType"],"ExtendedRetentionSchedule":["unit","frequency"],"TierLevelSettings":["awsTiering#AWSTiers","azureTiering#AzureTiers","cloudPlatform","googleTiering#GoogleTiers","oracleTiering#OracleTiers"],"OracleTiers":["tiers#OracleTier"],"AWSTiers":["tiers#AWSTier"],"GoogleTier":["moveAfterUnit","moveAfter","tierType"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"GoogleTiers":["tiers#GoogleTier"],"ExtendedRetentionPolicy":["schedule#ExtendedRetentionSchedule","retention#Retention","runType","configId"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"AzureTier":["moveAfterUnit","moveAfter","tierType"],"AWSTier":["moveAfterUnit","moveAfter","tierType"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"],"AzureTiers":["tiers#AzureTier"]},"fields":["schedule#TargetSchedule","backupRunType","tierSettings#TierLevelSettings","runTimeouts#CancellationTimeoutParams","targetId","configId","extendedRetention#ExtendedRetentionPolicy","retention#Retention","copyOnRunSuccess","logRetention#LogRetention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "remote-target-policy-archival-targets",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-archival-targets",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-archival-targets",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "remote-target-policy-cloud-spin-targets" {
			var RemoteTargetPolicyCloudSpinTargets []backuprecoveryv1.CloudSpinTargetConfiguration
			err, msg := deserialize.ModelSlice(
				r.RemoteTargetPolicyCloudSpinTargets,
				"remote-target-policy-cloud-spin-targets",
				"CloudSpinTargetConfiguration",
				backuprecoveryv1.UnmarshalCloudSpinTargetConfiguration,
				&RemoteTargetPolicyCloudSpinTargets,
			)
			r.utils.HandleError(err, msg)
			RemoteTargetPolicyHelper.CloudSpinTargets = RemoteTargetPolicyCloudSpinTargets
			extraFieldPaths, err := r.utils.ValidateJSON(r.RemoteTargetPolicyCloudSpinTargets, `{"schemas":{"TargetSchedule":["unit","frequency"],"CustomTagParams":["key","value"],"AwsCloudSpinParams":["customTagList#CustomTagParams","region","subnetId","vpcId"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"CloudSpinTarget":["awsParams#AwsCloudSpinParams","azureParams#AzureCloudSpinParams","id"],"AzureCloudSpinParams":["availabilitySetId","networkResourceGroupId","resourceGroupId","storageAccountId","storageContainerId","storageResourceGroupId","tempVmResourceGroupId","tempVmStorageAccountId","tempVmStorageContainerId","tempVmSubnetId","tempVmVirtualNetworkId"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"]},"fields":["schedule#TargetSchedule","backupRunType","target#CloudSpinTarget","runTimeouts#CancellationTimeoutParams","configId","retention#Retention","copyOnRunSuccess","logRetention#LogRetention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "remote-target-policy-cloud-spin-targets",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-cloud-spin-targets",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-cloud-spin-targets",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "remote-target-policy-onprem-deploy-targets" {
			var RemoteTargetPolicyOnpremDeployTargets []backuprecoveryv1.OnpremDeployTargetConfiguration
			err, msg := deserialize.ModelSlice(
				r.RemoteTargetPolicyOnpremDeployTargets,
				"remote-target-policy-onprem-deploy-targets",
				"OnpremDeployTargetConfiguration",
				backuprecoveryv1.UnmarshalOnpremDeployTargetConfiguration,
				&RemoteTargetPolicyOnpremDeployTargets,
			)
			r.utils.HandleError(err, msg)
			RemoteTargetPolicyHelper.OnpremDeployTargets = RemoteTargetPolicyOnpremDeployTargets
			extraFieldPaths, err := r.utils.ValidateJSON(r.RemoteTargetPolicyOnpremDeployTargets, `{"schemas":{"TargetSchedule":["unit","frequency"],"OnpremDeployParams":["id"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"]},"fields":["schedule#TargetSchedule","backupRunType","runTimeouts#CancellationTimeoutParams","configId","params#OnpremDeployParams","retention#Retention","copyOnRunSuccess","logRetention#LogRetention"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "remote-target-policy-onprem-deploy-targets",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-onprem-deploy-targets",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-onprem-deploy-targets",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "remote-target-policy-rpaas-targets" {
			var RemoteTargetPolicyRpaasTargets []backuprecoveryv1.RpaasTargetConfiguration
			err, msg := deserialize.ModelSlice(
				r.RemoteTargetPolicyRpaasTargets,
				"remote-target-policy-rpaas-targets",
				"RpaasTargetConfiguration",
				backuprecoveryv1.UnmarshalRpaasTargetConfiguration,
				&RemoteTargetPolicyRpaasTargets,
			)
			r.utils.HandleError(err, msg)
			RemoteTargetPolicyHelper.RpaasTargets = RemoteTargetPolicyRpaasTargets
			extraFieldPaths, err := r.utils.ValidateJSON(r.RemoteTargetPolicyRpaasTargets, `{"schemas":{"TargetSchedule":["unit","frequency"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"CancellationTimeoutParams":["timeoutMins","backupType"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"LogRetention":["unit","duration","dataLockConfig#DataLockConfig"]},"fields":["schedule#TargetSchedule","backupRunType","runTimeouts#CancellationTimeoutParams","targetId","configId","retention#Retention","copyOnRunSuccess","logRetention#LogRetention","targetType"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "remote-target-policy-rpaas-targets",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-rpaas-targets",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "remote-target-policy-rpaas-targets",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "retry-options-retries" {
			RetryOptionsHelper.Retries = core.Int64Ptr(r.RetryOptionsRetries)
		}
		if flag.Name == "retry-options-retry-interval-mins" {
			RetryOptionsHelper.RetryIntervalMins = core.Int64Ptr(r.RetryOptionsRetryIntervalMins)
		}
	})

	if !reflect.ValueOf(*BackupPolicyHelper).IsZero() {
		if OptionsModel.BackupPolicy == nil {
			OptionsModel.SetBackupPolicy(BackupPolicyHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "BackupPolicy",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*RemoteTargetPolicyHelper).IsZero() {
		if OptionsModel.RemoteTargetPolicy == nil {
			OptionsModel.SetRemoteTargetPolicy(RemoteTargetPolicyHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "RemoteTargetPolicy",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*RetryOptionsHelper).IsZero() {
		if OptionsModel.RetryOptions == nil {
			OptionsModel.SetRetryOptions(RetryOptionsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "RetryOptions",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}

	r.MakeRequest(OptionsModel)
}

func (r *UpdateProtectionPolicyCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.UpdateProtectionPolicyOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPUpdate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"name",
		"backupPolicy",
		"description",
		"blackoutWindow",
		"extendedRetention",
		"remoteTargetPolicy",
		"cascadedTargetsConfig",
		"retryOptions",
		"dataLock",
		"version",
		"isCBSEnabled",
		"lastModificationTimeUsecs",
		"id",
		"templateId",
		"isUsable",
		"isReplicated",
		"numProtectionGroups",
		"numProtectedObjects",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for DeleteProtectionPolicy command
type DeleteProtectionPolicyRequestSender struct{}

func (s DeleteProtectionPolicyRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	res, err := ServiceInstance.DeleteProtectionPolicy(optionsModel.(*backuprecoveryv1.DeleteProtectionPolicyOptions))
	// DeleteProtectionPolicy returns an empty response body
	return nil, res, err
}

// Command Runner for DeleteProtectionPolicy command
func NewDeleteProtectionPolicyCommandRunner(utils Utilities, sender RequestSender) *DeleteProtectionPolicyCommandRunner {
	return &DeleteProtectionPolicyCommandRunner{utils: utils, sender: sender}
}

type DeleteProtectionPolicyCommandRunner struct {
	ID                        string
	XIBMTenantID              string
	ForceDeleteWithoutConfirm bool
	RequiredFlags             []string
	sender                    RequestSender
	utils                     Utilities
}

// Command mapping: protection-policy delete, GetDeleteProtectionPolicyCommand
func GetDeleteProtectionPolicyCommand(r *DeleteProtectionPolicyCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "delete --id ID --xibm-tenant-id XIBM-TENANT-ID",
		Short:                 translation.T("backup-recovery-protection-policy-delete-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-policy-delete-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-policy",
			"x-cli-command":       "delete",
		},
		Example: `  ibmcloud backup-recovery protection-policy delete \
    --id exampleString \
    --xibm-tenant-id tenantId`,
	}

	cmd.Flags().StringVarP(&r.ID, "id", "", "", translation.T("backup-recovery-protection-policy-delete-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-policy-delete-xibm-tenant-id-flag-description"))
	cmd.Flags().BoolVarP(&r.ForceDeleteWithoutConfirm, "force", "f", false, translation.T("force-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running DeleteProtectionPolicy
func (r *DeleteProtectionPolicyCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	if !r.utils.ConfirmDelete(r.ForceDeleteWithoutConfirm) {
		// confirm delete, exit otherwise
		return
	}

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.DeleteProtectionPolicyOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *DeleteProtectionPolicyCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.DeleteProtectionPolicyOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPDelete,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)
	r.utils.ProcessEmptyResponse(DetailedResponse, ResponseErr)
}

func GetProtectionGroupGroup(utils Utilities) *cobra.Command {
	commands := []*cobra.Command{
		GetGetProtectionGroupsCommand(NewGetProtectionGroupsCommandRunner(utils, GetProtectionGroupsRequestSender{})),
		GetCreateProtectionGroupCommand(NewCreateProtectionGroupCommandRunner(utils, CreateProtectionGroupRequestSender{})),
		GetGetProtectionGroupByIDCommand(NewGetProtectionGroupByIDCommandRunner(utils, GetProtectionGroupByIDRequestSender{})),
		GetUpdateProtectionGroupCommand(NewUpdateProtectionGroupCommandRunner(utils, UpdateProtectionGroupRequestSender{})),
		GetDeleteProtectionGroupCommand(NewDeleteProtectionGroupCommandRunner(utils, DeleteProtectionGroupRequestSender{})),
	}

	command := &cobra.Command{
		Use:                   "protection-group [action]",
		Short:                 translation.T("backup-recovery-protection-group-group-short-description"),
		Long:                  translation.T("backup-recovery-protection-group-group-long-description"),
		DisableFlagsInUseLine: true,
	}

	command.AddCommand(commands...)

	return command
}

// RequestSender for GetProtectionGroups command
type GetProtectionGroupsRequestSender struct{}

func (s GetProtectionGroupsRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetProtectionGroups(optionsModel.(*backuprecoveryv1.GetProtectionGroupsOptions))
}

// Command Runner for GetProtectionGroups command
func NewGetProtectionGroupsCommandRunner(utils Utilities, sender RequestSender) *GetProtectionGroupsCommandRunner {
	return &GetProtectionGroupsCommandRunner{utils: utils, sender: sender}
}

type GetProtectionGroupsCommandRunner struct {
	XIBMTenantID                  string
	RequestInitiatorType          string
	Ids                           string
	Names                         string
	PolicyIds                     string
	IncludeGroupsWithDatalockOnly bool
	Environments                  string
	IsActive                      bool
	IsDeleted                     bool
	IsPaused                      bool
	LastRunLocalBackupStatus      string
	LastRunReplicationStatus      string
	LastRunArchivalStatus         string
	LastRunCloudSpinStatus        string
	LastRunAnyStatus              string
	IsLastRunSlaViolated          bool
	IncludeLastRunInfo            bool
	PruneExcludedSourceIds        bool
	PruneSourceIds                bool
	UseCachedData                 bool
	SourceIds                     string
	RequiredFlags                 []string
	sender                        RequestSender
	utils                         Utilities
}

// Command mapping: protection-group list, GetGetProtectionGroupsCommand
func GetGetProtectionGroupsCommand(r *GetProtectionGroupsCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "list [command options]",
		Short:                 translation.T("backup-recovery-protection-group-list-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-group-list-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-group",
			"x-cli-command":       "list",
		},
		Example: `  ibmcloud backup-recovery protection-group list \
    --xibm-tenant-id tenantID \
    --request-initiator-type UIUser \
    --ids protectionGroupId1 \
    --names policyName1 \
    --policy-ids policyId1 \
    --include-groups-with-datalock-only=true \
    --environments kPhysical,kSQL \
    --is-active=true \
    --is-deleted=true \
    --is-paused=true \
    --last-run-local-backup-status Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused \
    --last-run-replication-status Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused \
    --last-run-archival-status Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused \
    --last-run-cloud-spin-status Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused \
    --last-run-any-status Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused \
    --is-last-run-sla-violated=true \
    --include-last-run-info=true \
    --prune-excluded-source-ids=true \
    --prune-source-ids=true \
    --use-cached-data=true \
    --source-ids 26,27`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-group-list-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.RequestInitiatorType, "request-initiator-type", "", "", translation.T("backup-recovery-protection-group-list-request-initiator-type-flag-description"))
	cmd.Flags().StringVarP(&r.Ids, "ids", "", "", translation.T("backup-recovery-protection-group-list-ids-flag-description"))
	cmd.Flags().StringVarP(&r.Names, "names", "", "", translation.T("backup-recovery-protection-group-list-names-flag-description"))
	cmd.Flags().StringVarP(&r.PolicyIds, "policy-ids", "", "", translation.T("backup-recovery-protection-group-list-policy-ids-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeGroupsWithDatalockOnly, "include-groups-with-datalock-only", "", false, translation.T("backup-recovery-protection-group-list-include-groups-with-datalock-only-flag-description"))
	cmd.Flags().StringVarP(&r.Environments, "environments", "", "", translation.T("backup-recovery-protection-group-list-environments-flag-description"))
	cmd.Flags().BoolVarP(&r.IsActive, "is-active", "", false, translation.T("backup-recovery-protection-group-list-is-active-flag-description"))
	cmd.Flags().BoolVarP(&r.IsDeleted, "is-deleted", "", false, translation.T("backup-recovery-protection-group-list-is-deleted-flag-description"))
	cmd.Flags().BoolVarP(&r.IsPaused, "is-paused", "", false, translation.T("backup-recovery-protection-group-list-is-paused-flag-description"))
	cmd.Flags().StringVarP(&r.LastRunLocalBackupStatus, "last-run-local-backup-status", "", "", translation.T("backup-recovery-protection-group-list-last-run-local-backup-status-flag-description"))
	cmd.Flags().StringVarP(&r.LastRunReplicationStatus, "last-run-replication-status", "", "", translation.T("backup-recovery-protection-group-list-last-run-replication-status-flag-description"))
	cmd.Flags().StringVarP(&r.LastRunArchivalStatus, "last-run-archival-status", "", "", translation.T("backup-recovery-protection-group-list-last-run-archival-status-flag-description"))
	cmd.Flags().StringVarP(&r.LastRunCloudSpinStatus, "last-run-cloud-spin-status", "", "", translation.T("backup-recovery-protection-group-list-last-run-cloud-spin-status-flag-description"))
	cmd.Flags().StringVarP(&r.LastRunAnyStatus, "last-run-any-status", "", "", translation.T("backup-recovery-protection-group-list-last-run-any-status-flag-description"))
	cmd.Flags().BoolVarP(&r.IsLastRunSlaViolated, "is-last-run-sla-violated", "", false, translation.T("backup-recovery-protection-group-list-is-last-run-sla-violated-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeLastRunInfo, "include-last-run-info", "", false, translation.T("backup-recovery-protection-group-list-include-last-run-info-flag-description"))
	cmd.Flags().BoolVarP(&r.PruneExcludedSourceIds, "prune-excluded-source-ids", "", false, translation.T("backup-recovery-protection-group-list-prune-excluded-source-ids-flag-description"))
	cmd.Flags().BoolVarP(&r.PruneSourceIds, "prune-source-ids", "", false, translation.T("backup-recovery-protection-group-list-prune-source-ids-flag-description"))
	cmd.Flags().BoolVarP(&r.UseCachedData, "use-cached-data", "", false, translation.T("backup-recovery-protection-group-list-use-cached-data-flag-description"))
	cmd.Flags().StringVarP(&r.SourceIds, "source-ids", "", "", translation.T("backup-recovery-protection-group-list-source-ids-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetProtectionGroups
func (r *GetProtectionGroupsCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetProtectionGroupsOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "request-initiator-type" {
			OptionsModel.SetRequestInitiatorType(r.RequestInitiatorType)
		}
		if flag.Name == "ids" {
			var Ids []string
			err, msg := deserialize.List(r.Ids, "ids", "JSON", &Ids)
			r.utils.HandleError(err, msg)
			OptionsModel.SetIds(Ids)
		}
		if flag.Name == "names" {
			var Names []string
			err, msg := deserialize.List(r.Names, "names", "JSON", &Names)
			r.utils.HandleError(err, msg)
			OptionsModel.SetNames(Names)
		}
		if flag.Name == "policy-ids" {
			var PolicyIds []string
			err, msg := deserialize.List(r.PolicyIds, "policy-ids", "JSON", &PolicyIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetPolicyIds(PolicyIds)
		}
		if flag.Name == "include-groups-with-datalock-only" {
			OptionsModel.SetIncludeGroupsWithDatalockOnly(r.IncludeGroupsWithDatalockOnly)
		}
		if flag.Name == "environments" {
			var Environments []string
			err, msg := deserialize.List(r.Environments, "environments", "JSON", &Environments)
			r.utils.HandleError(err, msg)
			OptionsModel.SetEnvironments(Environments)
		}
		if flag.Name == "is-active" {
			OptionsModel.SetIsActive(r.IsActive)
		}
		if flag.Name == "is-deleted" {
			OptionsModel.SetIsDeleted(r.IsDeleted)
		}
		if flag.Name == "is-paused" {
			OptionsModel.SetIsPaused(r.IsPaused)
		}
		if flag.Name == "last-run-local-backup-status" {
			var LastRunLocalBackupStatus []string
			err, msg := deserialize.List(r.LastRunLocalBackupStatus, "last-run-local-backup-status", "JSON", &LastRunLocalBackupStatus)
			r.utils.HandleError(err, msg)
			OptionsModel.SetLastRunLocalBackupStatus(LastRunLocalBackupStatus)
		}
		if flag.Name == "last-run-replication-status" {
			var LastRunReplicationStatus []string
			err, msg := deserialize.List(r.LastRunReplicationStatus, "last-run-replication-status", "JSON", &LastRunReplicationStatus)
			r.utils.HandleError(err, msg)
			OptionsModel.SetLastRunReplicationStatus(LastRunReplicationStatus)
		}
		if flag.Name == "last-run-archival-status" {
			var LastRunArchivalStatus []string
			err, msg := deserialize.List(r.LastRunArchivalStatus, "last-run-archival-status", "JSON", &LastRunArchivalStatus)
			r.utils.HandleError(err, msg)
			OptionsModel.SetLastRunArchivalStatus(LastRunArchivalStatus)
		}
		if flag.Name == "last-run-cloud-spin-status" {
			var LastRunCloudSpinStatus []string
			err, msg := deserialize.List(r.LastRunCloudSpinStatus, "last-run-cloud-spin-status", "JSON", &LastRunCloudSpinStatus)
			r.utils.HandleError(err, msg)
			OptionsModel.SetLastRunCloudSpinStatus(LastRunCloudSpinStatus)
		}
		if flag.Name == "last-run-any-status" {
			var LastRunAnyStatus []string
			err, msg := deserialize.List(r.LastRunAnyStatus, "last-run-any-status", "JSON", &LastRunAnyStatus)
			r.utils.HandleError(err, msg)
			OptionsModel.SetLastRunAnyStatus(LastRunAnyStatus)
		}
		if flag.Name == "is-last-run-sla-violated" {
			OptionsModel.SetIsLastRunSlaViolated(r.IsLastRunSlaViolated)
		}
		if flag.Name == "include-last-run-info" {
			OptionsModel.SetIncludeLastRunInfo(r.IncludeLastRunInfo)
		}
		if flag.Name == "prune-excluded-source-ids" {
			OptionsModel.SetPruneExcludedSourceIds(r.PruneExcludedSourceIds)
		}
		if flag.Name == "prune-source-ids" {
			OptionsModel.SetPruneSourceIds(r.PruneSourceIds)
		}
		if flag.Name == "use-cached-data" {
			OptionsModel.SetUseCachedData(r.UseCachedData)
		}
		if flag.Name == "source-ids" {
			var SourceIds []int64
			err, msg := deserialize.List(r.SourceIds, "source-ids", "JSON", &SourceIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSourceIds(SourceIds)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetProtectionGroupsCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetProtectionGroupsOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"protectionGroups",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for CreateProtectionGroup command
type CreateProtectionGroupRequestSender struct{}

func (s CreateProtectionGroupRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.CreateProtectionGroup(optionsModel.(*backuprecoveryv1.CreateProtectionGroupOptions))
}

// Command Runner for CreateProtectionGroup command
func NewCreateProtectionGroupCommandRunner(utils Utilities, sender RequestSender) *CreateProtectionGroupCommandRunner {
	return &CreateProtectionGroupCommandRunner{utils: utils, sender: sender}
}

type CreateProtectionGroupCommandRunner struct {
	XIBMTenantID                                            string
	Name                                                    string
	PolicyID                                                string
	Environment                                             string
	Priority                                                string
	Description                                             string
	StartTime                                               string
	EndTimeUsecs                                            int64
	LastModifiedTimestampUsecs                              int64
	AlertPolicy                                             string
	Sla                                                     string
	QosPolicy                                               string
	AbortInBlackouts                                        bool
	PauseInBlackouts                                        bool
	IsPaused                                                bool
	AdvancedConfigs                                         string
	PhysicalParams                                          string
	MssqlParams                                             string
	StartTimeHour                                           int64
	StartTimeMinute                                         int64
	StartTimeTimeZone                                       string
	AlertPolicyBackupRunStatus                              string
	AlertPolicyAlertTargets                                 string
	AlertPolicyRaiseObjectLevelFailureAlert                 bool
	AlertPolicyRaiseObjectLevelFailureAlertAfterLastAttempt bool
	AlertPolicyRaiseObjectLevelFailureAlertAfterEachAttempt bool
	PhysicalParamsProtectionType                            string
	PhysicalParamsVolumeProtectionTypeParams                string
	PhysicalParamsFileProtectionTypeParams                  string
	MssqlParamsFileProtectionTypeParams                     string
	MssqlParamsNativeProtectionTypeParams                   string
	MssqlParamsProtectionType                               string
	MssqlParamsVolumeProtectionTypeParams                   string
	RequiredFlags                                           []string
	sender                                                  RequestSender
	utils                                                   Utilities
}

// Command mapping: protection-group create, GetCreateProtectionGroupCommand
func GetCreateProtectionGroupCommand(r *CreateProtectionGroupCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "create [command options]",
		Short:                 translation.T("backup-recovery-protection-group-create-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-group-create-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-group",
			"x-cli-command":       "create",
		},
		Example: `  ibmcloud backup-recovery protection-group create \
    --xibm-tenant-id tenantId \
    --name create-protection-group \
    --policy-id xxxxxxxxxxxxxxxx:xxxxxxxxxxxxx:xx \
    --environment kPhysical \
    --priority kLow \
    --description 'Protection Group' \
    --start-time '{"hour": 0, "minute": 0, "timeZone": "America/Los_Angeles"}' \
    --end-time-usecs 26 \
    --last-modified-timestamp-usecs 26 \
    --alert-policy '{"backupRunStatus": ["kSuccess","kFailure","kSlaViolation","kWarning"], "alertTargets": [{"emailAddress": "alert1@domain.com", "language": "en-us", "recipientType": "kTo"}], "raiseObjectLevelFailureAlert": true, "raiseObjectLevelFailureAlertAfterLastAttempt": true, "raiseObjectLevelFailureAlertAfterEachAttempt": true}' \
    --sla '[{"backupRunType": "kIncremental", "slaMinutes": 1}]' \
    --qos-policy kBackupHDD \
    --abort-in-blackouts=true \
    --pause-in-blackouts=true \
    --is-paused=true \
    --advanced-configs '[{"key": "configKey", "value": "configValue"}]' \
    --physical-params '{"protectionType": "kFile", "volumeProtectionTypeParams": {"objects": [{"id": 3, "volumeGuids": ["volumeGuid1"], "enableSystemBackup": true, "excludedVssWriters": ["writerName1","writerName2"]}], "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "performSourceSideDeduplication": true, "quiesce": true, "continueOnQuiesceFailure": true, "incrementalBackupAfterRestart": true, "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "dedupExclusionSourceIds": [26,27], "excludedVssWriters": ["writerName1","writerName2"], "cobmrBackup": true}, "fileProtectionTypeParams": {"excludedVssWriters": ["writerName1","writerName2"], "objects": [{"excludedVssWriters": ["writerName1","writerName2"], "id": 2, "filePaths": [{"includedPath": "~/dir1/", "excludedPaths": ["~/dir2"], "skipNestedVolumes": true}], "usesPathLevelSkipNestedVolumeSetting": true, "nestedVolumeTypesToSkip": ["volume1"], "followNasSymlinkTarget": true, "metadataFilePath": "~/dir3"}], "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "performSourceSideDeduplication": true, "performBrickBasedDeduplication": true, "taskTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "quiesce": true, "continueOnQuiesceFailure": true, "cobmrBackup": true, "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "dedupExclusionSourceIds": [26,27], "globalExcludePaths": ["~/dir1"], "globalExcludeFS": ["~/dir2"], "ignorableErrors": ["kEOF","kNonExistent"], "allowParallelRuns": true}}' \
    --mssql-params '{"fileProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "additionalHostParams": [{"disableSourceSideDeduplication": true, "hostId": 26}], "objects": [{"id": 6}], "performSourceSideDeduplication": true}, "nativeProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "numStreams": 38, "objects": [{"id": 6}], "withClause": "withClause"}, "protectionType": "kFile", "volumeProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "additionalHostParams": [{"enableSystemBackup": true, "hostId": 8, "volumeGuids": ["volumeGuid1"]}], "backupDbVolumesOnly": true, "incrementalBackupAfterRestart": true, "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "objects": [{"id": 6}]}}'`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-group-create-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Name, "name", "", "", translation.T("backup-recovery-protection-group-create-name-flag-description"))
	cmd.Flags().StringVarP(&r.PolicyID, "policy-id", "", "", translation.T("backup-recovery-protection-group-create-policy-id-flag-description"))
	cmd.Flags().StringVarP(&r.Environment, "environment", "", "", translation.T("backup-recovery-protection-group-create-environment-flag-description"))
	cmd.Flags().StringVarP(&r.Priority, "priority", "", "", translation.T("backup-recovery-protection-group-create-priority-flag-description"))
	cmd.Flags().StringVarP(&r.Description, "description", "", "", translation.T("backup-recovery-protection-group-create-description-flag-description"))
	cmd.Flags().StringVarP(&r.StartTime, "start-time", "", "", translation.T("backup-recovery-protection-group-create-start-time-flag-description"))
	cmd.Flags().Int64VarP(&r.EndTimeUsecs, "end-time-usecs", "", 0, translation.T("backup-recovery-protection-group-create-end-time-usecs-flag-description"))
	cmd.Flags().Int64VarP(&r.LastModifiedTimestampUsecs, "last-modified-timestamp-usecs", "", 0, translation.T("backup-recovery-protection-group-create-last-modified-timestamp-usecs-flag-description"))
	cmd.Flags().StringVarP(&r.AlertPolicy, "alert-policy", "", "", translation.T("backup-recovery-protection-group-create-alert-policy-flag-description"))
	cmd.Flags().StringVarP(&r.Sla, "sla", "", "", translation.T("backup-recovery-protection-group-create-sla-flag-description"))
	cmd.Flags().StringVarP(&r.QosPolicy, "qos-policy", "", "", translation.T("backup-recovery-protection-group-create-qos-policy-flag-description"))
	cmd.Flags().BoolVarP(&r.AbortInBlackouts, "abort-in-blackouts", "", false, translation.T("backup-recovery-protection-group-create-abort-in-blackouts-flag-description"))
	cmd.Flags().BoolVarP(&r.PauseInBlackouts, "pause-in-blackouts", "", false, translation.T("backup-recovery-protection-group-create-pause-in-blackouts-flag-description"))
	cmd.Flags().BoolVarP(&r.IsPaused, "is-paused", "", false, translation.T("backup-recovery-protection-group-create-is-paused-flag-description"))
	cmd.Flags().StringVarP(&r.AdvancedConfigs, "advanced-configs", "", "", translation.T("backup-recovery-protection-group-create-advanced-configs-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParams, "physical-params", "", "", translation.T("backup-recovery-protection-group-create-physical-params-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParams, "mssql-params", "", "", translation.T("backup-recovery-protection-group-create-mssql-params-flag-description"))
	cmd.Flags().Int64VarP(&r.StartTimeHour, "start-time-hour", "", 0, translation.T("backup-recovery-protection-group-create-start-time-hour-flag-description"))
	cmd.Flags().Int64VarP(&r.StartTimeMinute, "start-time-minute", "", 0, translation.T("backup-recovery-protection-group-create-start-time-minute-flag-description"))
	cmd.Flags().StringVarP(&r.StartTimeTimeZone, "start-time-time-zone", "", "", translation.T("backup-recovery-protection-group-create-start-time-time-zone-flag-description"))
	cmd.Flags().StringVarP(&r.AlertPolicyBackupRunStatus, "alert-policy-backup-run-status", "", "", translation.T("backup-recovery-protection-group-create-alert-policy-backup-run-status-flag-description"))
	cmd.Flags().StringVarP(&r.AlertPolicyAlertTargets, "alert-policy-alert-targets", "", "", translation.T("backup-recovery-protection-group-create-alert-policy-alert-targets-flag-description"))
	cmd.Flags().BoolVarP(&r.AlertPolicyRaiseObjectLevelFailureAlert, "alert-policy-raise-object-level-failure-alert", "", false, translation.T("backup-recovery-protection-group-create-alert-policy-raise-object-level-failure-alert-flag-description"))
	cmd.Flags().BoolVarP(&r.AlertPolicyRaiseObjectLevelFailureAlertAfterLastAttempt, "alert-policy-raise-object-level-failure-alert-after-last-attempt", "", false, translation.T("backup-recovery-protection-group-create-alert-policy-raise-object-level-failure-alert-after-last-attempt-flag-description"))
	cmd.Flags().BoolVarP(&r.AlertPolicyRaiseObjectLevelFailureAlertAfterEachAttempt, "alert-policy-raise-object-level-failure-alert-after-each-attempt", "", false, translation.T("backup-recovery-protection-group-create-alert-policy-raise-object-level-failure-alert-after-each-attempt-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsProtectionType, "physical-params-protection-type", "", "", translation.T("backup-recovery-protection-group-create-physical-params-protection-type-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsVolumeProtectionTypeParams, "physical-params-volume-protection-type-params", "", "", translation.T("backup-recovery-protection-group-create-physical-params-volume-protection-type-params-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsFileProtectionTypeParams, "physical-params-file-protection-type-params", "", "", translation.T("backup-recovery-protection-group-create-physical-params-file-protection-type-params-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParamsFileProtectionTypeParams, "mssql-params-file-protection-type-params", "", "", translation.T("backup-recovery-protection-group-create-mssql-params-file-protection-type-params-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParamsNativeProtectionTypeParams, "mssql-params-native-protection-type-params", "", "", translation.T("backup-recovery-protection-group-create-mssql-params-native-protection-type-params-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParamsProtectionType, "mssql-params-protection-type", "", "", translation.T("backup-recovery-protection-group-create-mssql-params-protection-type-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParamsVolumeProtectionTypeParams, "mssql-params-volume-protection-type-params", "", "", translation.T("backup-recovery-protection-group-create-mssql-params-volume-protection-type-params-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
		"name",
		"policy-id",
		"environment",
	}

	return cmd
}

// Primary logic for running CreateProtectionGroup
func (r *CreateProtectionGroupCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.CreateProtectionGroupOptions{}
	StartTimeHelper := &backuprecoveryv1.TimeOfDay{}
	AlertPolicyHelper := &backuprecoveryv1.ProtectionGroupAlertingPolicy{}
	PhysicalParamsHelper := &backuprecoveryv1.PhysicalProtectionGroupParams{}
	MssqlParamsHelper := &backuprecoveryv1.MSSQLProtectionGroupParams{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "name" {
			OptionsModel.SetName(r.Name)
		}
		if flag.Name == "policy-id" {
			OptionsModel.SetPolicyID(r.PolicyID)
		}
		if flag.Name == "environment" {
			OptionsModel.SetEnvironment(r.Environment)
		}
		if flag.Name == "priority" {
			OptionsModel.SetPriority(r.Priority)
		}
		if flag.Name == "description" {
			OptionsModel.SetDescription(r.Description)
		}
		if flag.Name == "start-time" {
			var StartTime *backuprecoveryv1.TimeOfDay
			err, msg := deserialize.Model(
				r.StartTime,
				"start-time",
				"TimeOfDay",
				backuprecoveryv1.UnmarshalTimeOfDay,
				&StartTime,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetStartTime(StartTime)
			extraFieldPaths, err := r.utils.ValidateJSON(r.StartTime, `{"fields":["hour","timeZone","minute"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "start-time",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "start-time",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "start-time",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "end-time-usecs" {
			OptionsModel.SetEndTimeUsecs(r.EndTimeUsecs)
		}
		if flag.Name == "last-modified-timestamp-usecs" {
			OptionsModel.SetLastModifiedTimestampUsecs(r.LastModifiedTimestampUsecs)
		}
		if flag.Name == "alert-policy" {
			var AlertPolicy *backuprecoveryv1.ProtectionGroupAlertingPolicy
			err, msg := deserialize.Model(
				r.AlertPolicy,
				"alert-policy",
				"ProtectionGroupAlertingPolicy",
				backuprecoveryv1.UnmarshalProtectionGroupAlertingPolicy,
				&AlertPolicy,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetAlertPolicy(AlertPolicy)
			extraFieldPaths, err := r.utils.ValidateJSON(r.AlertPolicy, `{"schemas":{"AlertTarget":["emailAddress","language","recipientType"]},"fields":["raiseObjectLevelFailureAlertAfterEachAttempt","raiseObjectLevelFailureAlert","raiseObjectLevelFailureAlertAfterLastAttempt","backupRunStatus","alertTargets#AlertTarget"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "alert-policy",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "alert-policy",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "alert-policy",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "sla" {
			var Sla []backuprecoveryv1.SlaRule
			err, msg := deserialize.ModelSlice(
				r.Sla,
				"sla",
				"SlaRule",
				backuprecoveryv1.UnmarshalSlaRule,
				&Sla,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSla(Sla)
			extraFieldPaths, err := r.utils.ValidateJSON(r.Sla, `{"fields":["backupRunType","slaMinutes"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "sla",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "sla",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "sla",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "qos-policy" {
			OptionsModel.SetQosPolicy(r.QosPolicy)
		}
		if flag.Name == "abort-in-blackouts" {
			OptionsModel.SetAbortInBlackouts(r.AbortInBlackouts)
		}
		if flag.Name == "pause-in-blackouts" {
			OptionsModel.SetPauseInBlackouts(r.PauseInBlackouts)
		}
		if flag.Name == "is-paused" {
			OptionsModel.SetIsPaused(r.IsPaused)
		}
		if flag.Name == "advanced-configs" {
			var AdvancedConfigs []backuprecoveryv1.KeyValuePair
			err, msg := deserialize.ModelSlice(
				r.AdvancedConfigs,
				"advanced-configs",
				"KeyValuePair",
				backuprecoveryv1.UnmarshalKeyValuePair,
				&AdvancedConfigs,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetAdvancedConfigs(AdvancedConfigs)
			extraFieldPaths, err := r.utils.ValidateJSON(r.AdvancedConfigs, `{"fields":["value","key"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "advanced-configs",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "advanced-configs",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "advanced-configs",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "physical-params" {
			var PhysicalParams *backuprecoveryv1.PhysicalProtectionGroupParams
			err, msg := deserialize.Model(
				r.PhysicalParams,
				"physical-params",
				"PhysicalProtectionGroupParams",
				backuprecoveryv1.UnmarshalPhysicalProtectionGroupParams,
				&PhysicalParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetPhysicalParams(PhysicalParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParams, `{"schemas":{"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"CancellationTimeoutParams":["timeoutMins","backupType"],"PhysicalVolumeProtectionGroupParams":["objects#PhysicalVolumeProtectionGroupObjectParams","indexingPolicy#IndexingPolicy","performSourceSideDeduplication","quiesce","continueOnQuiesceFailure","incrementalBackupAfterRestart","prePostScript#PrePostScriptParams","dedupExclusionSourceIds","excludedVssWriters","cobmrBackup"],"PhysicalFileProtectionGroupObjectParams":["excludedVssWriters","id","filePaths#PhysicalFileBackupPathParams","usesPathLevelSkipNestedVolumeSetting","nestedVolumeTypesToSkip","followNasSymlinkTarget","metadataFilePath"],"PhysicalFileBackupPathParams":["includedPath","excludedPaths","skipNestedVolumes"],"IndexingPolicy":["enableIndexing","includePaths","excludePaths"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"PhysicalFileProtectionGroupParams":["excludedVssWriters","objects#PhysicalFileProtectionGroupObjectParams","indexingPolicy#IndexingPolicy","performSourceSideDeduplication","performBrickBasedDeduplication","taskTimeouts#CancellationTimeoutParams","quiesce","continueOnQuiesceFailure","cobmrBackup","prePostScript#PrePostScriptParams","dedupExclusionSourceIds","globalExcludePaths","globalExcludeFS","ignorableErrors","allowParallelRuns"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"],"PhysicalVolumeProtectionGroupObjectParams":["id","volumeGuids","enableSystemBackup","excludedVssWriters"]},"fields":["protectionType","volumeProtectionTypeParams#PhysicalVolumeProtectionGroupParams","fileProtectionTypeParams#PhysicalFileProtectionGroupParams"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "mssql-params" {
			var MssqlParams *backuprecoveryv1.MSSQLProtectionGroupParams
			err, msg := deserialize.Model(
				r.MssqlParams,
				"mssql-params",
				"MSSQLProtectionGroupParams",
				backuprecoveryv1.UnmarshalMSSQLProtectionGroupParams,
				&MssqlParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMssqlParams(MssqlParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.MssqlParams, `{"schemas":{"MSSQLFileProtectionGroupHostParams":["disableSourceSideDeduplication","hostId"],"MSSQLNativeProtectionGroupObjectParams":["id"],"MSSQLNativeProtectionGroupParams":["aagBackupPreferenceType","advancedSettings#AdvancedSettings","backupSystemDbs","excludeFilters#Filter","fullBackupsCopyOnly","logBackupNumStreams","logBackupWithClause","prePostScript#PrePostScriptParams","useAagPreferencesFromServer","userDbBackupPreferenceType","numStreams","objects#MSSQLNativeProtectionGroupObjectParams","withClause"],"MSSQLVolumeProtectionGroupParams":["aagBackupPreferenceType","advancedSettings#AdvancedSettings","backupSystemDbs","excludeFilters#Filter","fullBackupsCopyOnly","logBackupNumStreams","logBackupWithClause","prePostScript#PrePostScriptParams","useAagPreferencesFromServer","userDbBackupPreferenceType","additionalHostParams#MSSQLVolumeProtectionGroupHostParams","backupDbVolumesOnly","incrementalBackupAfterRestart","indexingPolicy#IndexingPolicy","objects#MSSQLVolumeProtectionGroupObjectParams"],"MSSQLVolumeProtectionGroupHostParams":["enableSystemBackup","hostId","volumeGuids"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"],"AdvancedSettings":["clonedDbBackupStatus","dbBackupIfNotOnlineStatus","missingDbBackupStatus","offlineRestoringDbBackupStatus","readOnlyDbBackupStatus","reportAllNonAutoprotectDbErrors"],"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"Filter":["filterString","isRegularExpression"],"MSSQLFileProtectionGroupParams":["aagBackupPreferenceType","advancedSettings#AdvancedSettings","backupSystemDbs","excludeFilters#Filter","fullBackupsCopyOnly","logBackupNumStreams","logBackupWithClause","prePostScript#PrePostScriptParams","useAagPreferencesFromServer","userDbBackupPreferenceType","additionalHostParams#MSSQLFileProtectionGroupHostParams","objects#MSSQLFileProtectionGroupObjectParams","performSourceSideDeduplication"],"MSSQLFileProtectionGroupObjectParams":["id"],"MSSQLVolumeProtectionGroupObjectParams":["id"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"IndexingPolicy":["enableIndexing","includePaths","excludePaths"]},"fields":["nativeProtectionTypeParams#MSSQLNativeProtectionGroupParams","volumeProtectionTypeParams#MSSQLVolumeProtectionGroupParams","protectionType","fileProtectionTypeParams#MSSQLFileProtectionGroupParams"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "mssql-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "mssql-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "mssql-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "start-time-hour" {
			StartTimeHelper.Hour = core.Int64Ptr(r.StartTimeHour)
		}
		if flag.Name == "start-time-minute" {
			StartTimeHelper.Minute = core.Int64Ptr(r.StartTimeMinute)
		}
		if flag.Name == "start-time-time-zone" {
			StartTimeHelper.TimeZone = core.StringPtr(r.StartTimeTimeZone)
		}
		if flag.Name == "alert-policy-backup-run-status" {
			var AlertPolicyBackupRunStatus []string
			err, msg := deserialize.List(r.AlertPolicyBackupRunStatus, "alert-policy-backup-run-status", "JSON", &AlertPolicyBackupRunStatus)
			r.utils.HandleError(err, msg)
			AlertPolicyHelper.BackupRunStatus = AlertPolicyBackupRunStatus
		}
		if flag.Name == "alert-policy-alert-targets" {
			var AlertPolicyAlertTargets []backuprecoveryv1.AlertTarget
			err, msg := deserialize.ModelSlice(
				r.AlertPolicyAlertTargets,
				"alert-policy-alert-targets",
				"AlertTarget",
				backuprecoveryv1.UnmarshalAlertTarget,
				&AlertPolicyAlertTargets,
			)
			r.utils.HandleError(err, msg)
			AlertPolicyHelper.AlertTargets = AlertPolicyAlertTargets
			extraFieldPaths, err := r.utils.ValidateJSON(r.AlertPolicyAlertTargets, `{"fields":["emailAddress","recipientType","language"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "alert-policy-alert-targets",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "alert-policy-alert-targets",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "alert-policy-alert-targets",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "alert-policy-raise-object-level-failure-alert" {
			AlertPolicyHelper.RaiseObjectLevelFailureAlert = core.BoolPtr(r.AlertPolicyRaiseObjectLevelFailureAlert)
		}
		if flag.Name == "alert-policy-raise-object-level-failure-alert-after-last-attempt" {
			AlertPolicyHelper.RaiseObjectLevelFailureAlertAfterLastAttempt = core.BoolPtr(r.AlertPolicyRaiseObjectLevelFailureAlertAfterLastAttempt)
		}
		if flag.Name == "alert-policy-raise-object-level-failure-alert-after-each-attempt" {
			AlertPolicyHelper.RaiseObjectLevelFailureAlertAfterEachAttempt = core.BoolPtr(r.AlertPolicyRaiseObjectLevelFailureAlertAfterEachAttempt)
		}
		if flag.Name == "physical-params-protection-type" {
			PhysicalParamsHelper.ProtectionType = core.StringPtr(r.PhysicalParamsProtectionType)
		}
		if flag.Name == "physical-params-volume-protection-type-params" {
			var PhysicalParamsVolumeProtectionTypeParams *backuprecoveryv1.PhysicalVolumeProtectionGroupParams
			err, msg := deserialize.Model(
				r.PhysicalParamsVolumeProtectionTypeParams,
				"physical-params-volume-protection-type-params",
				"PhysicalVolumeProtectionGroupParams",
				backuprecoveryv1.UnmarshalPhysicalVolumeProtectionGroupParams,
				&PhysicalParamsVolumeProtectionTypeParams,
			)
			r.utils.HandleError(err, msg)
			PhysicalParamsHelper.VolumeProtectionTypeParams = PhysicalParamsVolumeProtectionTypeParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParamsVolumeProtectionTypeParams, `{"schemas":{"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"IndexingPolicy":["enableIndexing","includePaths","excludePaths"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"],"PhysicalVolumeProtectionGroupObjectParams":["id","volumeGuids","enableSystemBackup","excludedVssWriters"]},"fields":["continueOnQuiesceFailure","excludedVssWriters","incrementalBackupAfterRestart","indexingPolicy#IndexingPolicy","prePostScript#PrePostScriptParams","cobmrBackup","quiesce","objects#PhysicalVolumeProtectionGroupObjectParams","performSourceSideDeduplication","dedupExclusionSourceIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params-volume-protection-type-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params-volume-protection-type-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params-volume-protection-type-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "physical-params-file-protection-type-params" {
			var PhysicalParamsFileProtectionTypeParams *backuprecoveryv1.PhysicalFileProtectionGroupParams
			err, msg := deserialize.Model(
				r.PhysicalParamsFileProtectionTypeParams,
				"physical-params-file-protection-type-params",
				"PhysicalFileProtectionGroupParams",
				backuprecoveryv1.UnmarshalPhysicalFileProtectionGroupParams,
				&PhysicalParamsFileProtectionTypeParams,
			)
			r.utils.HandleError(err, msg)
			PhysicalParamsHelper.FileProtectionTypeParams = PhysicalParamsFileProtectionTypeParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParamsFileProtectionTypeParams, `{"schemas":{"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"CancellationTimeoutParams":["timeoutMins","backupType"],"PhysicalFileProtectionGroupObjectParams":["excludedVssWriters","id","filePaths#PhysicalFileBackupPathParams","usesPathLevelSkipNestedVolumeSetting","nestedVolumeTypesToSkip","followNasSymlinkTarget","metadataFilePath"],"PhysicalFileBackupPathParams":["includedPath","excludedPaths","skipNestedVolumes"],"IndexingPolicy":["enableIndexing","includePaths","excludePaths"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"]},"fields":["excludedVssWriters","continueOnQuiesceFailure","ignorableErrors","taskTimeouts#CancellationTimeoutParams","globalExcludeFS","prePostScript#PrePostScriptParams","performBrickBasedDeduplication","quiesce","performSourceSideDeduplication","allowParallelRuns","indexingPolicy#IndexingPolicy","cobmrBackup","globalExcludePaths","objects#PhysicalFileProtectionGroupObjectParams","dedupExclusionSourceIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params-file-protection-type-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params-file-protection-type-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params-file-protection-type-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "mssql-params-file-protection-type-params" {
			var MssqlParamsFileProtectionTypeParams *backuprecoveryv1.MSSQLFileProtectionGroupParams
			err, msg := deserialize.Model(
				r.MssqlParamsFileProtectionTypeParams,
				"mssql-params-file-protection-type-params",
				"MSSQLFileProtectionGroupParams",
				backuprecoveryv1.UnmarshalMSSQLFileProtectionGroupParams,
				&MssqlParamsFileProtectionTypeParams,
			)
			r.utils.HandleError(err, msg)
			MssqlParamsHelper.FileProtectionTypeParams = MssqlParamsFileProtectionTypeParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.MssqlParamsFileProtectionTypeParams, `{"schemas":{"MSSQLFileProtectionGroupHostParams":["disableSourceSideDeduplication","hostId"],"AdvancedSettings":["clonedDbBackupStatus","dbBackupIfNotOnlineStatus","missingDbBackupStatus","offlineRestoringDbBackupStatus","readOnlyDbBackupStatus","reportAllNonAutoprotectDbErrors"],"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"Filter":["filterString","isRegularExpression"],"MSSQLFileProtectionGroupObjectParams":["id"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"]},"fields":["useAagPreferencesFromServer","advancedSettings#AdvancedSettings","userDbBackupPreferenceType","aagBackupPreferenceType","logBackupNumStreams","prePostScript#PrePostScriptParams","performSourceSideDeduplication","additionalHostParams#MSSQLFileProtectionGroupHostParams","objects#MSSQLFileProtectionGroupObjectParams","excludeFilters#Filter","logBackupWithClause","backupSystemDbs","fullBackupsCopyOnly"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "mssql-params-file-protection-type-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-file-protection-type-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-file-protection-type-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "mssql-params-native-protection-type-params" {
			var MssqlParamsNativeProtectionTypeParams *backuprecoveryv1.MSSQLNativeProtectionGroupParams
			err, msg := deserialize.Model(
				r.MssqlParamsNativeProtectionTypeParams,
				"mssql-params-native-protection-type-params",
				"MSSQLNativeProtectionGroupParams",
				backuprecoveryv1.UnmarshalMSSQLNativeProtectionGroupParams,
				&MssqlParamsNativeProtectionTypeParams,
			)
			r.utils.HandleError(err, msg)
			MssqlParamsHelper.NativeProtectionTypeParams = MssqlParamsNativeProtectionTypeParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.MssqlParamsNativeProtectionTypeParams, `{"schemas":{"AdvancedSettings":["clonedDbBackupStatus","dbBackupIfNotOnlineStatus","missingDbBackupStatus","offlineRestoringDbBackupStatus","readOnlyDbBackupStatus","reportAllNonAutoprotectDbErrors"],"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"MSSQLNativeProtectionGroupObjectParams":["id"],"Filter":["filterString","isRegularExpression"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"]},"fields":["useAagPreferencesFromServer","advancedSettings#AdvancedSettings","userDbBackupPreferenceType","aagBackupPreferenceType","logBackupNumStreams","prePostScript#PrePostScriptParams","withClause","numStreams","excludeFilters#Filter","objects#MSSQLNativeProtectionGroupObjectParams","logBackupWithClause","backupSystemDbs","fullBackupsCopyOnly"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "mssql-params-native-protection-type-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-native-protection-type-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-native-protection-type-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "mssql-params-protection-type" {
			MssqlParamsHelper.ProtectionType = core.StringPtr(r.MssqlParamsProtectionType)
		}
		if flag.Name == "mssql-params-volume-protection-type-params" {
			var MssqlParamsVolumeProtectionTypeParams *backuprecoveryv1.MSSQLVolumeProtectionGroupParams
			err, msg := deserialize.Model(
				r.MssqlParamsVolumeProtectionTypeParams,
				"mssql-params-volume-protection-type-params",
				"MSSQLVolumeProtectionGroupParams",
				backuprecoveryv1.UnmarshalMSSQLVolumeProtectionGroupParams,
				&MssqlParamsVolumeProtectionTypeParams,
			)
			r.utils.HandleError(err, msg)
			MssqlParamsHelper.VolumeProtectionTypeParams = MssqlParamsVolumeProtectionTypeParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.MssqlParamsVolumeProtectionTypeParams, `{"schemas":{"AdvancedSettings":["clonedDbBackupStatus","dbBackupIfNotOnlineStatus","missingDbBackupStatus","offlineRestoringDbBackupStatus","readOnlyDbBackupStatus","reportAllNonAutoprotectDbErrors"],"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"Filter":["filterString","isRegularExpression"],"MSSQLVolumeProtectionGroupHostParams":["enableSystemBackup","hostId","volumeGuids"],"MSSQLVolumeProtectionGroupObjectParams":["id"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"IndexingPolicy":["enableIndexing","includePaths","excludePaths"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"]},"fields":["useAagPreferencesFromServer","advancedSettings#AdvancedSettings","userDbBackupPreferenceType","incrementalBackupAfterRestart","aagBackupPreferenceType","logBackupNumStreams","prePostScript#PrePostScriptParams","objects#MSSQLVolumeProtectionGroupObjectParams","excludeFilters#Filter","backupDbVolumesOnly","logBackupWithClause","indexingPolicy#IndexingPolicy","backupSystemDbs","fullBackupsCopyOnly","additionalHostParams#MSSQLVolumeProtectionGroupHostParams"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "mssql-params-volume-protection-type-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-volume-protection-type-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-volume-protection-type-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
	})

	if !reflect.ValueOf(*StartTimeHelper).IsZero() {
		if OptionsModel.StartTime == nil {
			OptionsModel.SetStartTime(StartTimeHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "StartTime",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*AlertPolicyHelper).IsZero() {
		if OptionsModel.AlertPolicy == nil {
			OptionsModel.SetAlertPolicy(AlertPolicyHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "AlertPolicy",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*PhysicalParamsHelper).IsZero() {
		if OptionsModel.PhysicalParams == nil {
			OptionsModel.SetPhysicalParams(PhysicalParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "PhysicalParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*MssqlParamsHelper).IsZero() {
		if OptionsModel.MssqlParams == nil {
			OptionsModel.SetMssqlParams(MssqlParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "MssqlParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}

	r.MakeRequest(OptionsModel)
}

func (r *CreateProtectionGroupCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.CreateProtectionGroupOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"id",
		"name",
		"clusterId",
		"regionId",
		"policyId",
		"priority",
		"description",
		"startTime",
		"endTimeUsecs",
		"lastModifiedTimestampUsecs",
		"alertPolicy",
		"sla",
		"qosPolicy",
		"abortInBlackouts",
		"pauseInBlackouts",
		"isActive",
		"isDeleted",
		"isPaused",
		"environment",
		"lastRun",
		"permissions",
		"isProtectOnce",
		"missingEntities",
		"invalidEntities",
		"numProtectedObjects",
		"advancedConfigs",
		"physicalParams",
		"mssqlParams",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for GetProtectionGroupByID command
type GetProtectionGroupByIDRequestSender struct{}

func (s GetProtectionGroupByIDRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetProtectionGroupByID(optionsModel.(*backuprecoveryv1.GetProtectionGroupByIdOptions))
}

// Command Runner for GetProtectionGroupByID command
func NewGetProtectionGroupByIDCommandRunner(utils Utilities, sender RequestSender) *GetProtectionGroupByIDCommandRunner {
	return &GetProtectionGroupByIDCommandRunner{utils: utils, sender: sender}
}

type GetProtectionGroupByIDCommandRunner struct {
	ID                     string
	XIBMTenantID           string
	RequestInitiatorType   string
	IncludeLastRunInfo     bool
	PruneExcludedSourceIds bool
	PruneSourceIds         bool
	RequiredFlags          []string
	sender                 RequestSender
	utils                  Utilities
}

// Command mapping: protection-group get, GetGetProtectionGroupByIDCommand
func GetGetProtectionGroupByIDCommand(r *GetProtectionGroupByIDCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "get --id ID --xibm-tenant-id XIBM-TENANT-ID [--request-initiator-type REQUEST-INITIATOR-TYPE] [--include-last-run-info=INCLUDE-LAST-RUN-INFO] [--prune-excluded-source-ids=PRUNE-EXCLUDED-SOURCE-IDS] [--prune-source-ids=PRUNE-SOURCE-IDS]",
		Short:                 translation.T("backup-recovery-protection-group-get-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-group-get-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-group",
			"x-cli-command":       "get",
		},
		Example: `  ibmcloud backup-recovery protection-group get \
    --id exampleString \
    --xibm-tenant-id tenantID \
    --request-initiator-type UIUser \
    --include-last-run-info=true \
    --prune-excluded-source-ids=true \
    --prune-source-ids=true`,
	}

	cmd.Flags().StringVarP(&r.ID, "id", "", "", translation.T("backup-recovery-protection-group-get-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-group-get-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.RequestInitiatorType, "request-initiator-type", "", "", translation.T("backup-recovery-protection-group-get-request-initiator-type-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeLastRunInfo, "include-last-run-info", "", false, translation.T("backup-recovery-protection-group-get-include-last-run-info-flag-description"))
	cmd.Flags().BoolVarP(&r.PruneExcludedSourceIds, "prune-excluded-source-ids", "", false, translation.T("backup-recovery-protection-group-get-prune-excluded-source-ids-flag-description"))
	cmd.Flags().BoolVarP(&r.PruneSourceIds, "prune-source-ids", "", false, translation.T("backup-recovery-protection-group-get-prune-source-ids-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetProtectionGroupByID
func (r *GetProtectionGroupByIDCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetProtectionGroupByIdOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "request-initiator-type" {
			OptionsModel.SetRequestInitiatorType(r.RequestInitiatorType)
		}
		if flag.Name == "include-last-run-info" {
			OptionsModel.SetIncludeLastRunInfo(r.IncludeLastRunInfo)
		}
		if flag.Name == "prune-excluded-source-ids" {
			OptionsModel.SetPruneExcludedSourceIds(r.PruneExcludedSourceIds)
		}
		if flag.Name == "prune-source-ids" {
			OptionsModel.SetPruneSourceIds(r.PruneSourceIds)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetProtectionGroupByIDCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetProtectionGroupByIdOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"id",
		"name",
		"clusterId",
		"regionId",
		"policyId",
		"priority",
		"description",
		"startTime",
		"endTimeUsecs",
		"lastModifiedTimestampUsecs",
		"alertPolicy",
		"sla",
		"qosPolicy",
		"abortInBlackouts",
		"pauseInBlackouts",
		"isActive",
		"isDeleted",
		"isPaused",
		"environment",
		"lastRun",
		"permissions",
		"isProtectOnce",
		"missingEntities",
		"invalidEntities",
		"numProtectedObjects",
		"advancedConfigs",
		"physicalParams",
		"mssqlParams",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for UpdateProtectionGroup command
type UpdateProtectionGroupRequestSender struct{}

func (s UpdateProtectionGroupRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.UpdateProtectionGroup(optionsModel.(*backuprecoveryv1.UpdateProtectionGroupOptions))
}

// Command Runner for UpdateProtectionGroup command
func NewUpdateProtectionGroupCommandRunner(utils Utilities, sender RequestSender) *UpdateProtectionGroupCommandRunner {
	return &UpdateProtectionGroupCommandRunner{utils: utils, sender: sender}
}

type UpdateProtectionGroupCommandRunner struct {
	ID                                                      string
	XIBMTenantID                                            string
	Name                                                    string
	PolicyID                                                string
	Environment                                             string
	Priority                                                string
	Description                                             string
	StartTime                                               string
	EndTimeUsecs                                            int64
	LastModifiedTimestampUsecs                              int64
	AlertPolicy                                             string
	Sla                                                     string
	QosPolicy                                               string
	AbortInBlackouts                                        bool
	PauseInBlackouts                                        bool
	IsPaused                                                bool
	AdvancedConfigs                                         string
	PhysicalParams                                          string
	MssqlParams                                             string
	StartTimeHour                                           int64
	StartTimeMinute                                         int64
	StartTimeTimeZone                                       string
	AlertPolicyBackupRunStatus                              string
	AlertPolicyAlertTargets                                 string
	AlertPolicyRaiseObjectLevelFailureAlert                 bool
	AlertPolicyRaiseObjectLevelFailureAlertAfterLastAttempt bool
	AlertPolicyRaiseObjectLevelFailureAlertAfterEachAttempt bool
	PhysicalParamsProtectionType                            string
	PhysicalParamsVolumeProtectionTypeParams                string
	PhysicalParamsFileProtectionTypeParams                  string
	MssqlParamsFileProtectionTypeParams                     string
	MssqlParamsNativeProtectionTypeParams                   string
	MssqlParamsProtectionType                               string
	MssqlParamsVolumeProtectionTypeParams                   string
	RequiredFlags                                           []string
	sender                                                  RequestSender
	utils                                                   Utilities
}

// Command mapping: protection-group update, GetUpdateProtectionGroupCommand
func GetUpdateProtectionGroupCommand(r *UpdateProtectionGroupCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "update [command options]",
		Short:                 translation.T("backup-recovery-protection-group-update-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-group-update-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-group",
			"x-cli-command":       "update",
		},
		Example: `  ibmcloud backup-recovery protection-group update \
    --id exampleString \
    --xibm-tenant-id tenantId \
    --name update-protection-group \
    --policy-id xxxxxxxxxxxxxxxx:xxxxxxxxxxxxx:xx \
    --environment kPhysical \
    --priority kLow \
    --description 'Protection Group' \
    --start-time '{"hour": 0, "minute": 0, "timeZone": "America/Los_Angeles"}' \
    --end-time-usecs 26 \
    --last-modified-timestamp-usecs 26 \
    --alert-policy '{"backupRunStatus": ["kSuccess","kFailure","kSlaViolation","kWarning"], "alertTargets": [{"emailAddress": "alert1@domain.com", "language": "en-us", "recipientType": "kTo"}], "raiseObjectLevelFailureAlert": true, "raiseObjectLevelFailureAlertAfterLastAttempt": true, "raiseObjectLevelFailureAlertAfterEachAttempt": true}' \
    --sla '[{"backupRunType": "kIncremental", "slaMinutes": 1}]' \
    --qos-policy kBackupHDD \
    --abort-in-blackouts=true \
    --pause-in-blackouts=true \
    --is-paused=true \
    --advanced-configs '[{"key": "configKey", "value": "configValue"}]' \
    --physical-params '{"protectionType": "kFile", "volumeProtectionTypeParams": {"objects": [{"id": 3, "volumeGuids": ["volumeGuid1"], "enableSystemBackup": true, "excludedVssWriters": ["writerName1","writerName2"]}], "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "performSourceSideDeduplication": true, "quiesce": true, "continueOnQuiesceFailure": true, "incrementalBackupAfterRestart": true, "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "dedupExclusionSourceIds": [26,27], "excludedVssWriters": ["writerName1","writerName2"], "cobmrBackup": true}, "fileProtectionTypeParams": {"excludedVssWriters": ["writerName1","writerName2"], "objects": [{"excludedVssWriters": ["writerName1","writerName2"], "id": 2, "filePaths": [{"includedPath": "~/dir1/", "excludedPaths": ["~/dir2"], "skipNestedVolumes": true}], "usesPathLevelSkipNestedVolumeSetting": true, "nestedVolumeTypesToSkip": ["volume1"], "followNasSymlinkTarget": true, "metadataFilePath": "~/dir3"}], "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "performSourceSideDeduplication": true, "performBrickBasedDeduplication": true, "taskTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "quiesce": true, "continueOnQuiesceFailure": true, "cobmrBackup": true, "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "dedupExclusionSourceIds": [26,27], "globalExcludePaths": ["~/dir1"], "globalExcludeFS": ["~/dir2"], "ignorableErrors": ["kEOF","kNonExistent"], "allowParallelRuns": true}}' \
    --mssql-params '{"fileProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "additionalHostParams": [{"disableSourceSideDeduplication": true, "hostId": 26}], "objects": [{"id": 6}], "performSourceSideDeduplication": true}, "nativeProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "numStreams": 38, "objects": [{"id": 6}], "withClause": "withClause"}, "protectionType": "kFile", "volumeProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "additionalHostParams": [{"enableSystemBackup": true, "hostId": 8, "volumeGuids": ["volumeGuid1"]}], "backupDbVolumesOnly": true, "incrementalBackupAfterRestart": true, "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "objects": [{"id": 6}]}}'`,
	}

	cmd.Flags().StringVarP(&r.ID, "id", "", "", translation.T("backup-recovery-protection-group-update-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-group-update-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Name, "name", "", "", translation.T("backup-recovery-protection-group-update-name-flag-description"))
	cmd.Flags().StringVarP(&r.PolicyID, "policy-id", "", "", translation.T("backup-recovery-protection-group-update-policy-id-flag-description"))
	cmd.Flags().StringVarP(&r.Environment, "environment", "", "", translation.T("backup-recovery-protection-group-update-environment-flag-description"))
	cmd.Flags().StringVarP(&r.Priority, "priority", "", "", translation.T("backup-recovery-protection-group-update-priority-flag-description"))
	cmd.Flags().StringVarP(&r.Description, "description", "", "", translation.T("backup-recovery-protection-group-update-description-flag-description"))
	cmd.Flags().StringVarP(&r.StartTime, "start-time", "", "", translation.T("backup-recovery-protection-group-update-start-time-flag-description"))
	cmd.Flags().Int64VarP(&r.EndTimeUsecs, "end-time-usecs", "", 0, translation.T("backup-recovery-protection-group-update-end-time-usecs-flag-description"))
	cmd.Flags().Int64VarP(&r.LastModifiedTimestampUsecs, "last-modified-timestamp-usecs", "", 0, translation.T("backup-recovery-protection-group-update-last-modified-timestamp-usecs-flag-description"))
	cmd.Flags().StringVarP(&r.AlertPolicy, "alert-policy", "", "", translation.T("backup-recovery-protection-group-update-alert-policy-flag-description"))
	cmd.Flags().StringVarP(&r.Sla, "sla", "", "", translation.T("backup-recovery-protection-group-update-sla-flag-description"))
	cmd.Flags().StringVarP(&r.QosPolicy, "qos-policy", "", "", translation.T("backup-recovery-protection-group-update-qos-policy-flag-description"))
	cmd.Flags().BoolVarP(&r.AbortInBlackouts, "abort-in-blackouts", "", false, translation.T("backup-recovery-protection-group-update-abort-in-blackouts-flag-description"))
	cmd.Flags().BoolVarP(&r.PauseInBlackouts, "pause-in-blackouts", "", false, translation.T("backup-recovery-protection-group-update-pause-in-blackouts-flag-description"))
	cmd.Flags().BoolVarP(&r.IsPaused, "is-paused", "", false, translation.T("backup-recovery-protection-group-update-is-paused-flag-description"))
	cmd.Flags().StringVarP(&r.AdvancedConfigs, "advanced-configs", "", "", translation.T("backup-recovery-protection-group-update-advanced-configs-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParams, "physical-params", "", "", translation.T("backup-recovery-protection-group-update-physical-params-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParams, "mssql-params", "", "", translation.T("backup-recovery-protection-group-update-mssql-params-flag-description"))
	cmd.Flags().Int64VarP(&r.StartTimeHour, "start-time-hour", "", 0, translation.T("backup-recovery-protection-group-update-start-time-hour-flag-description"))
	cmd.Flags().Int64VarP(&r.StartTimeMinute, "start-time-minute", "", 0, translation.T("backup-recovery-protection-group-update-start-time-minute-flag-description"))
	cmd.Flags().StringVarP(&r.StartTimeTimeZone, "start-time-time-zone", "", "", translation.T("backup-recovery-protection-group-update-start-time-time-zone-flag-description"))
	cmd.Flags().StringVarP(&r.AlertPolicyBackupRunStatus, "alert-policy-backup-run-status", "", "", translation.T("backup-recovery-protection-group-update-alert-policy-backup-run-status-flag-description"))
	cmd.Flags().StringVarP(&r.AlertPolicyAlertTargets, "alert-policy-alert-targets", "", "", translation.T("backup-recovery-protection-group-update-alert-policy-alert-targets-flag-description"))
	cmd.Flags().BoolVarP(&r.AlertPolicyRaiseObjectLevelFailureAlert, "alert-policy-raise-object-level-failure-alert", "", false, translation.T("backup-recovery-protection-group-update-alert-policy-raise-object-level-failure-alert-flag-description"))
	cmd.Flags().BoolVarP(&r.AlertPolicyRaiseObjectLevelFailureAlertAfterLastAttempt, "alert-policy-raise-object-level-failure-alert-after-last-attempt", "", false, translation.T("backup-recovery-protection-group-update-alert-policy-raise-object-level-failure-alert-after-last-attempt-flag-description"))
	cmd.Flags().BoolVarP(&r.AlertPolicyRaiseObjectLevelFailureAlertAfterEachAttempt, "alert-policy-raise-object-level-failure-alert-after-each-attempt", "", false, translation.T("backup-recovery-protection-group-update-alert-policy-raise-object-level-failure-alert-after-each-attempt-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsProtectionType, "physical-params-protection-type", "", "", translation.T("backup-recovery-protection-group-update-physical-params-protection-type-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsVolumeProtectionTypeParams, "physical-params-volume-protection-type-params", "", "", translation.T("backup-recovery-protection-group-update-physical-params-volume-protection-type-params-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsFileProtectionTypeParams, "physical-params-file-protection-type-params", "", "", translation.T("backup-recovery-protection-group-update-physical-params-file-protection-type-params-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParamsFileProtectionTypeParams, "mssql-params-file-protection-type-params", "", "", translation.T("backup-recovery-protection-group-update-mssql-params-file-protection-type-params-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParamsNativeProtectionTypeParams, "mssql-params-native-protection-type-params", "", "", translation.T("backup-recovery-protection-group-update-mssql-params-native-protection-type-params-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParamsProtectionType, "mssql-params-protection-type", "", "", translation.T("backup-recovery-protection-group-update-mssql-params-protection-type-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParamsVolumeProtectionTypeParams, "mssql-params-volume-protection-type-params", "", "", translation.T("backup-recovery-protection-group-update-mssql-params-volume-protection-type-params-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
		"name",
		"policy-id",
		"environment",
	}

	return cmd
}

// Primary logic for running UpdateProtectionGroup
func (r *UpdateProtectionGroupCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.UpdateProtectionGroupOptions{}
	StartTimeHelper := &backuprecoveryv1.TimeOfDay{}
	AlertPolicyHelper := &backuprecoveryv1.ProtectionGroupAlertingPolicy{}
	PhysicalParamsHelper := &backuprecoveryv1.PhysicalProtectionGroupParams{}
	MssqlParamsHelper := &backuprecoveryv1.MSSQLProtectionGroupParams{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "name" {
			OptionsModel.SetName(r.Name)
		}
		if flag.Name == "policy-id" {
			OptionsModel.SetPolicyID(r.PolicyID)
		}
		if flag.Name == "environment" {
			OptionsModel.SetEnvironment(r.Environment)
		}
		if flag.Name == "priority" {
			OptionsModel.SetPriority(r.Priority)
		}
		if flag.Name == "description" {
			OptionsModel.SetDescription(r.Description)
		}
		if flag.Name == "start-time" {
			var StartTime *backuprecoveryv1.TimeOfDay
			err, msg := deserialize.Model(
				r.StartTime,
				"start-time",
				"TimeOfDay",
				backuprecoveryv1.UnmarshalTimeOfDay,
				&StartTime,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetStartTime(StartTime)
			extraFieldPaths, err := r.utils.ValidateJSON(r.StartTime, `{"fields":["hour","timeZone","minute"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "start-time",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "start-time",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "start-time",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "end-time-usecs" {
			OptionsModel.SetEndTimeUsecs(r.EndTimeUsecs)
		}
		if flag.Name == "last-modified-timestamp-usecs" {
			OptionsModel.SetLastModifiedTimestampUsecs(r.LastModifiedTimestampUsecs)
		}
		if flag.Name == "alert-policy" {
			var AlertPolicy *backuprecoveryv1.ProtectionGroupAlertingPolicy
			err, msg := deserialize.Model(
				r.AlertPolicy,
				"alert-policy",
				"ProtectionGroupAlertingPolicy",
				backuprecoveryv1.UnmarshalProtectionGroupAlertingPolicy,
				&AlertPolicy,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetAlertPolicy(AlertPolicy)
			extraFieldPaths, err := r.utils.ValidateJSON(r.AlertPolicy, `{"schemas":{"AlertTarget":["emailAddress","language","recipientType"]},"fields":["raiseObjectLevelFailureAlertAfterEachAttempt","raiseObjectLevelFailureAlert","raiseObjectLevelFailureAlertAfterLastAttempt","backupRunStatus","alertTargets#AlertTarget"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "alert-policy",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "alert-policy",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "alert-policy",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "sla" {
			var Sla []backuprecoveryv1.SlaRule
			err, msg := deserialize.ModelSlice(
				r.Sla,
				"sla",
				"SlaRule",
				backuprecoveryv1.UnmarshalSlaRule,
				&Sla,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSla(Sla)
			extraFieldPaths, err := r.utils.ValidateJSON(r.Sla, `{"fields":["backupRunType","slaMinutes"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "sla",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "sla",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "sla",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "qos-policy" {
			OptionsModel.SetQosPolicy(r.QosPolicy)
		}
		if flag.Name == "abort-in-blackouts" {
			OptionsModel.SetAbortInBlackouts(r.AbortInBlackouts)
		}
		if flag.Name == "pause-in-blackouts" {
			OptionsModel.SetPauseInBlackouts(r.PauseInBlackouts)
		}
		if flag.Name == "is-paused" {
			OptionsModel.SetIsPaused(r.IsPaused)
		}
		if flag.Name == "advanced-configs" {
			var AdvancedConfigs []backuprecoveryv1.KeyValuePair
			err, msg := deserialize.ModelSlice(
				r.AdvancedConfigs,
				"advanced-configs",
				"KeyValuePair",
				backuprecoveryv1.UnmarshalKeyValuePair,
				&AdvancedConfigs,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetAdvancedConfigs(AdvancedConfigs)
			extraFieldPaths, err := r.utils.ValidateJSON(r.AdvancedConfigs, `{"fields":["value","key"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "advanced-configs",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "advanced-configs",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "advanced-configs",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "physical-params" {
			var PhysicalParams *backuprecoveryv1.PhysicalProtectionGroupParams
			err, msg := deserialize.Model(
				r.PhysicalParams,
				"physical-params",
				"PhysicalProtectionGroupParams",
				backuprecoveryv1.UnmarshalPhysicalProtectionGroupParams,
				&PhysicalParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetPhysicalParams(PhysicalParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParams, `{"schemas":{"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"CancellationTimeoutParams":["timeoutMins","backupType"],"PhysicalVolumeProtectionGroupParams":["objects#PhysicalVolumeProtectionGroupObjectParams","indexingPolicy#IndexingPolicy","performSourceSideDeduplication","quiesce","continueOnQuiesceFailure","incrementalBackupAfterRestart","prePostScript#PrePostScriptParams","dedupExclusionSourceIds","excludedVssWriters","cobmrBackup"],"PhysicalFileProtectionGroupObjectParams":["excludedVssWriters","id","filePaths#PhysicalFileBackupPathParams","usesPathLevelSkipNestedVolumeSetting","nestedVolumeTypesToSkip","followNasSymlinkTarget","metadataFilePath"],"PhysicalFileBackupPathParams":["includedPath","excludedPaths","skipNestedVolumes"],"IndexingPolicy":["enableIndexing","includePaths","excludePaths"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"PhysicalFileProtectionGroupParams":["excludedVssWriters","objects#PhysicalFileProtectionGroupObjectParams","indexingPolicy#IndexingPolicy","performSourceSideDeduplication","performBrickBasedDeduplication","taskTimeouts#CancellationTimeoutParams","quiesce","continueOnQuiesceFailure","cobmrBackup","prePostScript#PrePostScriptParams","dedupExclusionSourceIds","globalExcludePaths","globalExcludeFS","ignorableErrors","allowParallelRuns"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"],"PhysicalVolumeProtectionGroupObjectParams":["id","volumeGuids","enableSystemBackup","excludedVssWriters"]},"fields":["protectionType","volumeProtectionTypeParams#PhysicalVolumeProtectionGroupParams","fileProtectionTypeParams#PhysicalFileProtectionGroupParams"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "mssql-params" {
			var MssqlParams *backuprecoveryv1.MSSQLProtectionGroupParams
			err, msg := deserialize.Model(
				r.MssqlParams,
				"mssql-params",
				"MSSQLProtectionGroupParams",
				backuprecoveryv1.UnmarshalMSSQLProtectionGroupParams,
				&MssqlParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMssqlParams(MssqlParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.MssqlParams, `{"schemas":{"MSSQLFileProtectionGroupHostParams":["disableSourceSideDeduplication","hostId"],"MSSQLNativeProtectionGroupObjectParams":["id"],"MSSQLNativeProtectionGroupParams":["aagBackupPreferenceType","advancedSettings#AdvancedSettings","backupSystemDbs","excludeFilters#Filter","fullBackupsCopyOnly","logBackupNumStreams","logBackupWithClause","prePostScript#PrePostScriptParams","useAagPreferencesFromServer","userDbBackupPreferenceType","numStreams","objects#MSSQLNativeProtectionGroupObjectParams","withClause"],"MSSQLVolumeProtectionGroupParams":["aagBackupPreferenceType","advancedSettings#AdvancedSettings","backupSystemDbs","excludeFilters#Filter","fullBackupsCopyOnly","logBackupNumStreams","logBackupWithClause","prePostScript#PrePostScriptParams","useAagPreferencesFromServer","userDbBackupPreferenceType","additionalHostParams#MSSQLVolumeProtectionGroupHostParams","backupDbVolumesOnly","incrementalBackupAfterRestart","indexingPolicy#IndexingPolicy","objects#MSSQLVolumeProtectionGroupObjectParams"],"MSSQLVolumeProtectionGroupHostParams":["enableSystemBackup","hostId","volumeGuids"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"],"AdvancedSettings":["clonedDbBackupStatus","dbBackupIfNotOnlineStatus","missingDbBackupStatus","offlineRestoringDbBackupStatus","readOnlyDbBackupStatus","reportAllNonAutoprotectDbErrors"],"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"Filter":["filterString","isRegularExpression"],"MSSQLFileProtectionGroupParams":["aagBackupPreferenceType","advancedSettings#AdvancedSettings","backupSystemDbs","excludeFilters#Filter","fullBackupsCopyOnly","logBackupNumStreams","logBackupWithClause","prePostScript#PrePostScriptParams","useAagPreferencesFromServer","userDbBackupPreferenceType","additionalHostParams#MSSQLFileProtectionGroupHostParams","objects#MSSQLFileProtectionGroupObjectParams","performSourceSideDeduplication"],"MSSQLFileProtectionGroupObjectParams":["id"],"MSSQLVolumeProtectionGroupObjectParams":["id"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"IndexingPolicy":["enableIndexing","includePaths","excludePaths"]},"fields":["nativeProtectionTypeParams#MSSQLNativeProtectionGroupParams","volumeProtectionTypeParams#MSSQLVolumeProtectionGroupParams","protectionType","fileProtectionTypeParams#MSSQLFileProtectionGroupParams"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "mssql-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "mssql-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "mssql-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "start-time-hour" {
			StartTimeHelper.Hour = core.Int64Ptr(r.StartTimeHour)
		}
		if flag.Name == "start-time-minute" {
			StartTimeHelper.Minute = core.Int64Ptr(r.StartTimeMinute)
		}
		if flag.Name == "start-time-time-zone" {
			StartTimeHelper.TimeZone = core.StringPtr(r.StartTimeTimeZone)
		}
		if flag.Name == "alert-policy-backup-run-status" {
			var AlertPolicyBackupRunStatus []string
			err, msg := deserialize.List(r.AlertPolicyBackupRunStatus, "alert-policy-backup-run-status", "JSON", &AlertPolicyBackupRunStatus)
			r.utils.HandleError(err, msg)
			AlertPolicyHelper.BackupRunStatus = AlertPolicyBackupRunStatus
		}
		if flag.Name == "alert-policy-alert-targets" {
			var AlertPolicyAlertTargets []backuprecoveryv1.AlertTarget
			err, msg := deserialize.ModelSlice(
				r.AlertPolicyAlertTargets,
				"alert-policy-alert-targets",
				"AlertTarget",
				backuprecoveryv1.UnmarshalAlertTarget,
				&AlertPolicyAlertTargets,
			)
			r.utils.HandleError(err, msg)
			AlertPolicyHelper.AlertTargets = AlertPolicyAlertTargets
			extraFieldPaths, err := r.utils.ValidateJSON(r.AlertPolicyAlertTargets, `{"fields":["emailAddress","recipientType","language"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "alert-policy-alert-targets",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "alert-policy-alert-targets",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "alert-policy-alert-targets",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "alert-policy-raise-object-level-failure-alert" {
			AlertPolicyHelper.RaiseObjectLevelFailureAlert = core.BoolPtr(r.AlertPolicyRaiseObjectLevelFailureAlert)
		}
		if flag.Name == "alert-policy-raise-object-level-failure-alert-after-last-attempt" {
			AlertPolicyHelper.RaiseObjectLevelFailureAlertAfterLastAttempt = core.BoolPtr(r.AlertPolicyRaiseObjectLevelFailureAlertAfterLastAttempt)
		}
		if flag.Name == "alert-policy-raise-object-level-failure-alert-after-each-attempt" {
			AlertPolicyHelper.RaiseObjectLevelFailureAlertAfterEachAttempt = core.BoolPtr(r.AlertPolicyRaiseObjectLevelFailureAlertAfterEachAttempt)
		}
		if flag.Name == "physical-params-protection-type" {
			PhysicalParamsHelper.ProtectionType = core.StringPtr(r.PhysicalParamsProtectionType)
		}
		if flag.Name == "physical-params-volume-protection-type-params" {
			var PhysicalParamsVolumeProtectionTypeParams *backuprecoveryv1.PhysicalVolumeProtectionGroupParams
			err, msg := deserialize.Model(
				r.PhysicalParamsVolumeProtectionTypeParams,
				"physical-params-volume-protection-type-params",
				"PhysicalVolumeProtectionGroupParams",
				backuprecoveryv1.UnmarshalPhysicalVolumeProtectionGroupParams,
				&PhysicalParamsVolumeProtectionTypeParams,
			)
			r.utils.HandleError(err, msg)
			PhysicalParamsHelper.VolumeProtectionTypeParams = PhysicalParamsVolumeProtectionTypeParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParamsVolumeProtectionTypeParams, `{"schemas":{"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"IndexingPolicy":["enableIndexing","includePaths","excludePaths"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"],"PhysicalVolumeProtectionGroupObjectParams":["id","volumeGuids","enableSystemBackup","excludedVssWriters"]},"fields":["continueOnQuiesceFailure","excludedVssWriters","incrementalBackupAfterRestart","indexingPolicy#IndexingPolicy","prePostScript#PrePostScriptParams","cobmrBackup","quiesce","objects#PhysicalVolumeProtectionGroupObjectParams","performSourceSideDeduplication","dedupExclusionSourceIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params-volume-protection-type-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params-volume-protection-type-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params-volume-protection-type-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "physical-params-file-protection-type-params" {
			var PhysicalParamsFileProtectionTypeParams *backuprecoveryv1.PhysicalFileProtectionGroupParams
			err, msg := deserialize.Model(
				r.PhysicalParamsFileProtectionTypeParams,
				"physical-params-file-protection-type-params",
				"PhysicalFileProtectionGroupParams",
				backuprecoveryv1.UnmarshalPhysicalFileProtectionGroupParams,
				&PhysicalParamsFileProtectionTypeParams,
			)
			r.utils.HandleError(err, msg)
			PhysicalParamsHelper.FileProtectionTypeParams = PhysicalParamsFileProtectionTypeParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParamsFileProtectionTypeParams, `{"schemas":{"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"CancellationTimeoutParams":["timeoutMins","backupType"],"PhysicalFileProtectionGroupObjectParams":["excludedVssWriters","id","filePaths#PhysicalFileBackupPathParams","usesPathLevelSkipNestedVolumeSetting","nestedVolumeTypesToSkip","followNasSymlinkTarget","metadataFilePath"],"PhysicalFileBackupPathParams":["includedPath","excludedPaths","skipNestedVolumes"],"IndexingPolicy":["enableIndexing","includePaths","excludePaths"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"]},"fields":["excludedVssWriters","continueOnQuiesceFailure","ignorableErrors","taskTimeouts#CancellationTimeoutParams","globalExcludeFS","prePostScript#PrePostScriptParams","performBrickBasedDeduplication","quiesce","performSourceSideDeduplication","allowParallelRuns","indexingPolicy#IndexingPolicy","cobmrBackup","globalExcludePaths","objects#PhysicalFileProtectionGroupObjectParams","dedupExclusionSourceIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params-file-protection-type-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params-file-protection-type-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params-file-protection-type-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "mssql-params-file-protection-type-params" {
			var MssqlParamsFileProtectionTypeParams *backuprecoveryv1.MSSQLFileProtectionGroupParams
			err, msg := deserialize.Model(
				r.MssqlParamsFileProtectionTypeParams,
				"mssql-params-file-protection-type-params",
				"MSSQLFileProtectionGroupParams",
				backuprecoveryv1.UnmarshalMSSQLFileProtectionGroupParams,
				&MssqlParamsFileProtectionTypeParams,
			)
			r.utils.HandleError(err, msg)
			MssqlParamsHelper.FileProtectionTypeParams = MssqlParamsFileProtectionTypeParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.MssqlParamsFileProtectionTypeParams, `{"schemas":{"MSSQLFileProtectionGroupHostParams":["disableSourceSideDeduplication","hostId"],"AdvancedSettings":["clonedDbBackupStatus","dbBackupIfNotOnlineStatus","missingDbBackupStatus","offlineRestoringDbBackupStatus","readOnlyDbBackupStatus","reportAllNonAutoprotectDbErrors"],"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"Filter":["filterString","isRegularExpression"],"MSSQLFileProtectionGroupObjectParams":["id"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"]},"fields":["useAagPreferencesFromServer","advancedSettings#AdvancedSettings","userDbBackupPreferenceType","aagBackupPreferenceType","logBackupNumStreams","prePostScript#PrePostScriptParams","performSourceSideDeduplication","additionalHostParams#MSSQLFileProtectionGroupHostParams","objects#MSSQLFileProtectionGroupObjectParams","excludeFilters#Filter","logBackupWithClause","backupSystemDbs","fullBackupsCopyOnly"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "mssql-params-file-protection-type-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-file-protection-type-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-file-protection-type-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "mssql-params-native-protection-type-params" {
			var MssqlParamsNativeProtectionTypeParams *backuprecoveryv1.MSSQLNativeProtectionGroupParams
			err, msg := deserialize.Model(
				r.MssqlParamsNativeProtectionTypeParams,
				"mssql-params-native-protection-type-params",
				"MSSQLNativeProtectionGroupParams",
				backuprecoveryv1.UnmarshalMSSQLNativeProtectionGroupParams,
				&MssqlParamsNativeProtectionTypeParams,
			)
			r.utils.HandleError(err, msg)
			MssqlParamsHelper.NativeProtectionTypeParams = MssqlParamsNativeProtectionTypeParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.MssqlParamsNativeProtectionTypeParams, `{"schemas":{"AdvancedSettings":["clonedDbBackupStatus","dbBackupIfNotOnlineStatus","missingDbBackupStatus","offlineRestoringDbBackupStatus","readOnlyDbBackupStatus","reportAllNonAutoprotectDbErrors"],"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"MSSQLNativeProtectionGroupObjectParams":["id"],"Filter":["filterString","isRegularExpression"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"]},"fields":["useAagPreferencesFromServer","advancedSettings#AdvancedSettings","userDbBackupPreferenceType","aagBackupPreferenceType","logBackupNumStreams","prePostScript#PrePostScriptParams","withClause","numStreams","excludeFilters#Filter","objects#MSSQLNativeProtectionGroupObjectParams","logBackupWithClause","backupSystemDbs","fullBackupsCopyOnly"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "mssql-params-native-protection-type-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-native-protection-type-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-native-protection-type-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "mssql-params-protection-type" {
			MssqlParamsHelper.ProtectionType = core.StringPtr(r.MssqlParamsProtectionType)
		}
		if flag.Name == "mssql-params-volume-protection-type-params" {
			var MssqlParamsVolumeProtectionTypeParams *backuprecoveryv1.MSSQLVolumeProtectionGroupParams
			err, msg := deserialize.Model(
				r.MssqlParamsVolumeProtectionTypeParams,
				"mssql-params-volume-protection-type-params",
				"MSSQLVolumeProtectionGroupParams",
				backuprecoveryv1.UnmarshalMSSQLVolumeProtectionGroupParams,
				&MssqlParamsVolumeProtectionTypeParams,
			)
			r.utils.HandleError(err, msg)
			MssqlParamsHelper.VolumeProtectionTypeParams = MssqlParamsVolumeProtectionTypeParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.MssqlParamsVolumeProtectionTypeParams, `{"schemas":{"AdvancedSettings":["clonedDbBackupStatus","dbBackupIfNotOnlineStatus","missingDbBackupStatus","offlineRestoringDbBackupStatus","readOnlyDbBackupStatus","reportAllNonAutoprotectDbErrors"],"CommonPreBackupScriptParams":["path","params","timeoutSecs","isActive","continueOnError"],"Filter":["filterString","isRegularExpression"],"MSSQLVolumeProtectionGroupHostParams":["enableSystemBackup","hostId","volumeGuids"],"MSSQLVolumeProtectionGroupObjectParams":["id"],"PrePostScriptParams":["preScript#CommonPreBackupScriptParams","postScript#CommonPostBackupScriptParams"],"IndexingPolicy":["enableIndexing","includePaths","excludePaths"],"CommonPostBackupScriptParams":["path","params","timeoutSecs","isActive"]},"fields":["useAagPreferencesFromServer","advancedSettings#AdvancedSettings","userDbBackupPreferenceType","incrementalBackupAfterRestart","aagBackupPreferenceType","logBackupNumStreams","prePostScript#PrePostScriptParams","objects#MSSQLVolumeProtectionGroupObjectParams","excludeFilters#Filter","backupDbVolumesOnly","logBackupWithClause","indexingPolicy#IndexingPolicy","backupSystemDbs","fullBackupsCopyOnly","additionalHostParams#MSSQLVolumeProtectionGroupHostParams"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "mssql-params-volume-protection-type-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-volume-protection-type-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-volume-protection-type-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
	})

	if !reflect.ValueOf(*StartTimeHelper).IsZero() {
		if OptionsModel.StartTime == nil {
			OptionsModel.SetStartTime(StartTimeHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "StartTime",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*AlertPolicyHelper).IsZero() {
		if OptionsModel.AlertPolicy == nil {
			OptionsModel.SetAlertPolicy(AlertPolicyHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "AlertPolicy",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*PhysicalParamsHelper).IsZero() {
		if OptionsModel.PhysicalParams == nil {
			OptionsModel.SetPhysicalParams(PhysicalParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "PhysicalParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*MssqlParamsHelper).IsZero() {
		if OptionsModel.MssqlParams == nil {
			OptionsModel.SetMssqlParams(MssqlParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "MssqlParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}

	r.MakeRequest(OptionsModel)
}

func (r *UpdateProtectionGroupCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.UpdateProtectionGroupOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPUpdate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"id",
		"name",
		"clusterId",
		"regionId",
		"policyId",
		"priority",
		"description",
		"startTime",
		"endTimeUsecs",
		"lastModifiedTimestampUsecs",
		"alertPolicy",
		"sla",
		"qosPolicy",
		"abortInBlackouts",
		"pauseInBlackouts",
		"isActive",
		"isDeleted",
		"isPaused",
		"environment",
		"lastRun",
		"permissions",
		"isProtectOnce",
		"missingEntities",
		"invalidEntities",
		"numProtectedObjects",
		"advancedConfigs",
		"physicalParams",
		"mssqlParams",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for DeleteProtectionGroup command
type DeleteProtectionGroupRequestSender struct{}

func (s DeleteProtectionGroupRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	res, err := ServiceInstance.DeleteProtectionGroup(optionsModel.(*backuprecoveryv1.DeleteProtectionGroupOptions))
	// DeleteProtectionGroup returns an empty response body
	return nil, res, err
}

// Command Runner for DeleteProtectionGroup command
func NewDeleteProtectionGroupCommandRunner(utils Utilities, sender RequestSender) *DeleteProtectionGroupCommandRunner {
	return &DeleteProtectionGroupCommandRunner{utils: utils, sender: sender}
}

type DeleteProtectionGroupCommandRunner struct {
	ID                        string
	XIBMTenantID              string
	DeleteSnapshots           bool
	ForceDeleteWithoutConfirm bool
	RequiredFlags             []string
	sender                    RequestSender
	utils                     Utilities
}

// Command mapping: protection-group delete, GetDeleteProtectionGroupCommand
func GetDeleteProtectionGroupCommand(r *DeleteProtectionGroupCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "delete --id ID --xibm-tenant-id XIBM-TENANT-ID [--delete-snapshots=DELETE-SNAPSHOTS]",
		Short:                 translation.T("backup-recovery-protection-group-delete-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-group-delete-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-group",
			"x-cli-command":       "delete",
		},
		Example: `  ibmcloud backup-recovery protection-group delete \
    --id exampleString \
    --xibm-tenant-id tenantId \
    --delete-snapshots=true`,
	}

	cmd.Flags().StringVarP(&r.ID, "id", "", "", translation.T("backup-recovery-protection-group-delete-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-group-delete-xibm-tenant-id-flag-description"))
	cmd.Flags().BoolVarP(&r.DeleteSnapshots, "delete-snapshots", "", false, translation.T("backup-recovery-protection-group-delete-delete-snapshots-flag-description"))
	cmd.Flags().BoolVarP(&r.ForceDeleteWithoutConfirm, "force", "f", false, translation.T("force-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running DeleteProtectionGroup
func (r *DeleteProtectionGroupCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	if !r.utils.ConfirmDelete(r.ForceDeleteWithoutConfirm) {
		// confirm delete, exit otherwise
		return
	}

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.DeleteProtectionGroupOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "delete-snapshots" {
			OptionsModel.SetDeleteSnapshots(r.DeleteSnapshots)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *DeleteProtectionGroupCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.DeleteProtectionGroupOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPDelete,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)
	r.utils.ProcessEmptyResponse(DetailedResponse, ResponseErr)
}

func GetProtectionGroupRunGroup(utils Utilities) *cobra.Command {
	commands := []*cobra.Command{
		GetGetProtectionGroupRunsCommand(NewGetProtectionGroupRunsCommandRunner(utils, GetProtectionGroupRunsRequestSender{})),
		GetUpdateProtectionGroupRunCommand(NewUpdateProtectionGroupRunCommandRunner(utils, UpdateProtectionGroupRunRequestSender{})),
		GetCreateProtectionGroupRunCommand(NewCreateProtectionGroupRunCommandRunner(utils, CreateProtectionGroupRunRequestSender{})),
		GetPerformActionOnProtectionGroupRunCommand(NewPerformActionOnProtectionGroupRunCommandRunner(utils, PerformActionOnProtectionGroupRunRequestSender{})),
	}

	command := &cobra.Command{
		Use:                   "protection-group-run [action]",
		Short:                 translation.T("backup-recovery-protection-group-run-group-short-description"),
		Long:                  translation.T("backup-recovery-protection-group-run-group-long-description"),
		DisableFlagsInUseLine: true,
	}

	command.AddCommand(commands...)

	return command
}

// RequestSender for GetProtectionGroupRuns command
type GetProtectionGroupRunsRequestSender struct{}

func (s GetProtectionGroupRunsRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetProtectionGroupRuns(optionsModel.(*backuprecoveryv1.GetProtectionGroupRunsOptions))
}

// Command Runner for GetProtectionGroupRuns command
func NewGetProtectionGroupRunsCommandRunner(utils Utilities, sender RequestSender) *GetProtectionGroupRunsCommandRunner {
	return &GetProtectionGroupRunsCommandRunner{utils: utils, sender: sender}
}

type GetProtectionGroupRunsCommandRunner struct {
	ID                          string
	XIBMTenantID                string
	RequestInitiatorType        string
	RunID                       string
	StartTimeUsecs              int64
	EndTimeUsecs                int64
	RunTypes                    string
	IncludeObjectDetails        bool
	LocalBackupRunStatus        string
	ReplicationRunStatus        string
	ArchivalRunStatus           string
	CloudSpinRunStatus          string
	NumRuns                     int64
	ExcludeNonRestorableRuns    bool
	RunTags                     string
	UseCachedData               bool
	FilterByEndTime             bool
	SnapshotTargetTypes         string
	OnlyReturnSuccessfulCopyRun bool
	FilterByCopyTaskEndTime     bool
	RequiredFlags               []string
	sender                      RequestSender
	utils                       Utilities
}

// Command mapping: protection-group-run list, GetGetProtectionGroupRunsCommand
func GetGetProtectionGroupRunsCommand(r *GetProtectionGroupRunsCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "list [command options]",
		Short:                 translation.T("backup-recovery-protection-group-run-list-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-group-run-list-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-group-run",
			"x-cli-command":       "list",
		},
		Example: `  ibmcloud backup-recovery protection-group-run list \
    --id exampleString \
    --xibm-tenant-id tenantId \
    --request-initiator-type UIUser \
    --run-id 11:111 \
    --start-time-usecs 26 \
    --end-time-usecs 26 \
    --run-types kAll,kHydrateCDP,kSystem,kStorageArraySnapshot,kIncremental,kFull,kLog \
    --include-object-details=true \
    --local-backup-run-status Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused \
    --replication-run-status Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused \
    --archival-run-status Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused \
    --cloud-spin-run-status Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused \
    --num-runs 26 \
    --exclude-non-restorable-runs=false \
    --run-tags tag1 \
    --use-cached-data=true \
    --filter-by-end-time=true \
    --snapshot-target-types Local,Archival,RpaasArchival,StorageArraySnapshot,Remote \
    --only-return-successful-copy-run=true \
    --filter-by-copy-task-end-time=true`,
	}

	cmd.Flags().StringVarP(&r.ID, "id", "", "", translation.T("backup-recovery-protection-group-run-list-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-group-run-list-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.RequestInitiatorType, "request-initiator-type", "", "", translation.T("backup-recovery-protection-group-run-list-request-initiator-type-flag-description"))
	cmd.Flags().StringVarP(&r.RunID, "run-id", "", "", translation.T("backup-recovery-protection-group-run-list-run-id-flag-description"))
	cmd.Flags().Int64VarP(&r.StartTimeUsecs, "start-time-usecs", "", 0, translation.T("backup-recovery-protection-group-run-list-start-time-usecs-flag-description"))
	cmd.Flags().Int64VarP(&r.EndTimeUsecs, "end-time-usecs", "", 0, translation.T("backup-recovery-protection-group-run-list-end-time-usecs-flag-description"))
	cmd.Flags().StringVarP(&r.RunTypes, "run-types", "", "", translation.T("backup-recovery-protection-group-run-list-run-types-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeObjectDetails, "include-object-details", "", false, translation.T("backup-recovery-protection-group-run-list-include-object-details-flag-description"))
	cmd.Flags().StringVarP(&r.LocalBackupRunStatus, "local-backup-run-status", "", "", translation.T("backup-recovery-protection-group-run-list-local-backup-run-status-flag-description"))
	cmd.Flags().StringVarP(&r.ReplicationRunStatus, "replication-run-status", "", "", translation.T("backup-recovery-protection-group-run-list-replication-run-status-flag-description"))
	cmd.Flags().StringVarP(&r.ArchivalRunStatus, "archival-run-status", "", "", translation.T("backup-recovery-protection-group-run-list-archival-run-status-flag-description"))
	cmd.Flags().StringVarP(&r.CloudSpinRunStatus, "cloud-spin-run-status", "", "", translation.T("backup-recovery-protection-group-run-list-cloud-spin-run-status-flag-description"))
	cmd.Flags().Int64VarP(&r.NumRuns, "num-runs", "", 0, translation.T("backup-recovery-protection-group-run-list-num-runs-flag-description"))
	cmd.Flags().BoolVarP(&r.ExcludeNonRestorableRuns, "exclude-non-restorable-runs", "", false, translation.T("backup-recovery-protection-group-run-list-exclude-non-restorable-runs-flag-description"))
	cmd.Flags().StringVarP(&r.RunTags, "run-tags", "", "", translation.T("backup-recovery-protection-group-run-list-run-tags-flag-description"))
	cmd.Flags().BoolVarP(&r.UseCachedData, "use-cached-data", "", false, translation.T("backup-recovery-protection-group-run-list-use-cached-data-flag-description"))
	cmd.Flags().BoolVarP(&r.FilterByEndTime, "filter-by-end-time", "", false, translation.T("backup-recovery-protection-group-run-list-filter-by-end-time-flag-description"))
	cmd.Flags().StringVarP(&r.SnapshotTargetTypes, "snapshot-target-types", "", "", translation.T("backup-recovery-protection-group-run-list-snapshot-target-types-flag-description"))
	cmd.Flags().BoolVarP(&r.OnlyReturnSuccessfulCopyRun, "only-return-successful-copy-run", "", false, translation.T("backup-recovery-protection-group-run-list-only-return-successful-copy-run-flag-description"))
	cmd.Flags().BoolVarP(&r.FilterByCopyTaskEndTime, "filter-by-copy-task-end-time", "", false, translation.T("backup-recovery-protection-group-run-list-filter-by-copy-task-end-time-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetProtectionGroupRuns
func (r *GetProtectionGroupRunsCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetProtectionGroupRunsOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "request-initiator-type" {
			OptionsModel.SetRequestInitiatorType(r.RequestInitiatorType)
		}
		if flag.Name == "run-id" {
			OptionsModel.SetRunID(r.RunID)
		}
		if flag.Name == "start-time-usecs" {
			OptionsModel.SetStartTimeUsecs(r.StartTimeUsecs)
		}
		if flag.Name == "end-time-usecs" {
			OptionsModel.SetEndTimeUsecs(r.EndTimeUsecs)
		}
		if flag.Name == "run-types" {
			var RunTypes []string
			err, msg := deserialize.List(r.RunTypes, "run-types", "JSON", &RunTypes)
			r.utils.HandleError(err, msg)
			OptionsModel.SetRunTypes(RunTypes)
		}
		if flag.Name == "include-object-details" {
			OptionsModel.SetIncludeObjectDetails(r.IncludeObjectDetails)
		}
		if flag.Name == "local-backup-run-status" {
			var LocalBackupRunStatus []string
			err, msg := deserialize.List(r.LocalBackupRunStatus, "local-backup-run-status", "JSON", &LocalBackupRunStatus)
			r.utils.HandleError(err, msg)
			OptionsModel.SetLocalBackupRunStatus(LocalBackupRunStatus)
		}
		if flag.Name == "replication-run-status" {
			var ReplicationRunStatus []string
			err, msg := deserialize.List(r.ReplicationRunStatus, "replication-run-status", "JSON", &ReplicationRunStatus)
			r.utils.HandleError(err, msg)
			OptionsModel.SetReplicationRunStatus(ReplicationRunStatus)
		}
		if flag.Name == "archival-run-status" {
			var ArchivalRunStatus []string
			err, msg := deserialize.List(r.ArchivalRunStatus, "archival-run-status", "JSON", &ArchivalRunStatus)
			r.utils.HandleError(err, msg)
			OptionsModel.SetArchivalRunStatus(ArchivalRunStatus)
		}
		if flag.Name == "cloud-spin-run-status" {
			var CloudSpinRunStatus []string
			err, msg := deserialize.List(r.CloudSpinRunStatus, "cloud-spin-run-status", "JSON", &CloudSpinRunStatus)
			r.utils.HandleError(err, msg)
			OptionsModel.SetCloudSpinRunStatus(CloudSpinRunStatus)
		}
		if flag.Name == "num-runs" {
			OptionsModel.SetNumRuns(r.NumRuns)
		}
		if flag.Name == "exclude-non-restorable-runs" {
			OptionsModel.SetExcludeNonRestorableRuns(r.ExcludeNonRestorableRuns)
		}
		if flag.Name == "run-tags" {
			var RunTags []string
			err, msg := deserialize.List(r.RunTags, "run-tags", "JSON", &RunTags)
			r.utils.HandleError(err, msg)
			OptionsModel.SetRunTags(RunTags)
		}
		if flag.Name == "use-cached-data" {
			OptionsModel.SetUseCachedData(r.UseCachedData)
		}
		if flag.Name == "filter-by-end-time" {
			OptionsModel.SetFilterByEndTime(r.FilterByEndTime)
		}
		if flag.Name == "snapshot-target-types" {
			var SnapshotTargetTypes []string
			err, msg := deserialize.List(r.SnapshotTargetTypes, "snapshot-target-types", "JSON", &SnapshotTargetTypes)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSnapshotTargetTypes(SnapshotTargetTypes)
		}
		if flag.Name == "only-return-successful-copy-run" {
			OptionsModel.SetOnlyReturnSuccessfulCopyRun(r.OnlyReturnSuccessfulCopyRun)
		}
		if flag.Name == "filter-by-copy-task-end-time" {
			OptionsModel.SetFilterByCopyTaskEndTime(r.FilterByCopyTaskEndTime)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetProtectionGroupRunsCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetProtectionGroupRunsOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"runs",
		"totalRuns",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for UpdateProtectionGroupRun command
type UpdateProtectionGroupRunRequestSender struct{}

func (s UpdateProtectionGroupRunRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.UpdateProtectionGroupRun(optionsModel.(*backuprecoveryv1.UpdateProtectionGroupRunOptions))
}

// Command Runner for UpdateProtectionGroupRun command
func NewUpdateProtectionGroupRunCommandRunner(utils Utilities, sender RequestSender) *UpdateProtectionGroupRunCommandRunner {
	return &UpdateProtectionGroupRunCommandRunner{utils: utils, sender: sender}
}

type UpdateProtectionGroupRunCommandRunner struct {
	ID                             string
	XIBMTenantID                   string
	UpdateProtectionGroupRunParams string
	RequiredFlags                  []string
	sender                         RequestSender
	utils                          Utilities
}

// Command mapping: protection-group-run update, GetUpdateProtectionGroupRunCommand
func GetUpdateProtectionGroupRunCommand(r *UpdateProtectionGroupRunCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "update --id ID --xibm-tenant-id XIBM-TENANT-ID --update-protection-group-run-params UPDATE-PROTECTION-GROUP-RUN-PARAMS | @UPDATE-PROTECTION-GROUP-RUN-PARAMS-FILE",
		Short:                 translation.T("backup-recovery-protection-group-run-update-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-group-run-update-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-group-run",
			"x-cli-command":       "update",
		},
		Example: `  ibmcloud backup-recovery protection-group-run update \
    --id exampleString \
    --xibm-tenant-id tenantId \
    --update-protection-group-run-params '[{"runId": "11:111", "localSnapshotConfig": {"enableLegalHold": true, "deleteSnapshot": true, "dataLock": "Compliance", "daysToKeep": 26}, "replicationSnapshotConfig": {"newSnapshotConfig": [{"id": 26, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}], "updateExistingSnapshotConfig": [{"id": 4, "name": "update-snapshot-config", "enableLegalHold": true, "deleteSnapshot": true, "resync": true, "dataLock": "Compliance", "daysToKeep": 26}]}, "archivalSnapshotConfig": {"newSnapshotConfig": [{"id": 2, "archivalTargetType": "Tape", "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnlyFullySuccessful": true}], "updateExistingSnapshotConfig": [{"id": 3, "name": "update-snapshot-config", "archivalTargetType": "Tape", "enableLegalHold": true, "deleteSnapshot": true, "resync": true, "dataLock": "Compliance", "daysToKeep": 26}]}}]'`,
	}

	cmd.Flags().StringVarP(&r.ID, "id", "", "", translation.T("backup-recovery-protection-group-run-update-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-group-run-update-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.UpdateProtectionGroupRunParams, "update-protection-group-run-params", "", "", translation.T("backup-recovery-protection-group-run-update-update-protection-group-run-params-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
		"update-protection-group-run-params",
	}

	return cmd
}

// Primary logic for running UpdateProtectionGroupRun
func (r *UpdateProtectionGroupRunCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.UpdateProtectionGroupRunOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "update-protection-group-run-params" {
			var UpdateProtectionGroupRunParams []backuprecoveryv1.UpdateProtectionGroupRunParams
			err, msg := deserialize.ModelSlice(
				r.UpdateProtectionGroupRunParams,
				"update-protection-group-run-params",
				"UpdateProtectionGroupRunParams",
				backuprecoveryv1.UnmarshalUpdateProtectionGroupRunParams,
				&UpdateProtectionGroupRunParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetUpdateProtectionGroupRunParams(UpdateProtectionGroupRunParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.UpdateProtectionGroupRunParams, `{"schemas":{"UpdateExistingArchivalSnapshotConfig":["id","name","archivalTargetType","enableLegalHold","deleteSnapshot","resync","dataLock","daysToKeep"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"UpdateLocalSnapshotConfig":["enableLegalHold","deleteSnapshot","dataLock","daysToKeep"],"UpdateArchivalSnapshotConfig":["newSnapshotConfig#RunArchivalConfig","updateExistingSnapshotConfig#UpdateExistingArchivalSnapshotConfig"],"UpdateExistingReplicationSnapshotConfig":["id","name","enableLegalHold","deleteSnapshot","resync","dataLock","daysToKeep"],"RunArchivalConfig":["id","archivalTargetType","retention#Retention","copyOnlyFullySuccessful"],"UpdateReplicationSnapshotConfig":["newSnapshotConfig#RunReplicationConfig","updateExistingSnapshotConfig#UpdateExistingReplicationSnapshotConfig"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"RunReplicationConfig":["id","retention#Retention"]},"fields":["archivalSnapshotConfig#UpdateArchivalSnapshotConfig","runId","localSnapshotConfig#UpdateLocalSnapshotConfig","replicationSnapshotConfig#UpdateReplicationSnapshotConfig"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "update-protection-group-run-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "update-protection-group-run-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "update-protection-group-run-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *UpdateProtectionGroupRunCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.UpdateProtectionGroupRunOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPUpdate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"successfulRunIds",
		"failedRuns",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for CreateProtectionGroupRun command
type CreateProtectionGroupRunRequestSender struct{}

func (s CreateProtectionGroupRunRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.CreateProtectionGroupRun(optionsModel.(*backuprecoveryv1.CreateProtectionGroupRunOptions))
}

// Command Runner for CreateProtectionGroupRun command
func NewCreateProtectionGroupRunCommandRunner(utils Utilities, sender RequestSender) *CreateProtectionGroupRunCommandRunner {
	return &CreateProtectionGroupRunCommandRunner{utils: utils, sender: sender}
}

type CreateProtectionGroupRunCommandRunner struct {
	ID                             string
	XIBMTenantID                   string
	RunType                        string
	Objects                        string
	TargetsConfig                  string
	TargetsConfigUsePolicyDefaults bool
	TargetsConfigReplications      string
	TargetsConfigArchivals         string
	TargetsConfigCloudReplications string
	RequiredFlags                  []string
	sender                         RequestSender
	utils                          Utilities
}

// Command mapping: protection-group-run create, GetCreateProtectionGroupRunCommand
func GetCreateProtectionGroupRunCommand(r *CreateProtectionGroupRunCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "create --id ID --xibm-tenant-id XIBM-TENANT-ID --run-type RUN-TYPE [--objects OBJECTS | @OBJECTS-FILE] [--targets-config (TARGETS-CONFIG | @TARGETS-CONFIG-FILE) | --targets-config-use-policy-defaults=TARGETS-CONFIG-USE-POLICY-DEFAULTS --targets-config-replications TARGETS-CONFIG-REPLICATIONS --targets-config-archivals TARGETS-CONFIG-ARCHIVALS --targets-config-cloud-replications TARGETS-CONFIG-CLOUD-REPLICATIONS]",
		Short:                 translation.T("backup-recovery-protection-group-run-create-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-group-run-create-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-group-run",
			"x-cli-command":       "create",
		},
		Example: `  ibmcloud backup-recovery protection-group-run create \
    --id runId \
    --xibm-tenant-id tenantId \
    --run-type kRegular \
    --objects '[{"id": 4, "appIds": [26,27], "physicalParams": {"metadataFilePath": "~/metadata"}}]' \
    --targets-config '{"usePolicyDefaults": false, "replications": [{"id": 26, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}], "archivals": [{"id": 26, "archivalTargetType": "Tape", "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnlyFullySuccessful": true}], "cloudReplications": [{"awsTarget": {"region": 26, "sourceId": 26}, "azureTarget": {"resourceGroup": 26, "sourceId": 26}, "targetType": "AWS", "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}]}'`,
	}

	cmd.Flags().StringVarP(&r.ID, "id", "", "", translation.T("backup-recovery-protection-group-run-create-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-group-run-create-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.RunType, "run-type", "", "", translation.T("backup-recovery-protection-group-run-create-run-type-flag-description"))
	cmd.Flags().StringVarP(&r.Objects, "objects", "", "", translation.T("backup-recovery-protection-group-run-create-objects-flag-description"))
	cmd.Flags().StringVarP(&r.TargetsConfig, "targets-config", "", "", translation.T("backup-recovery-protection-group-run-create-targets-config-flag-description"))
	cmd.Flags().BoolVarP(&r.TargetsConfigUsePolicyDefaults, "targets-config-use-policy-defaults", "", false, translation.T("backup-recovery-protection-group-run-create-targets-config-use-policy-defaults-flag-description"))
	cmd.Flags().StringVarP(&r.TargetsConfigReplications, "targets-config-replications", "", "", translation.T("backup-recovery-protection-group-run-create-targets-config-replications-flag-description"))
	cmd.Flags().StringVarP(&r.TargetsConfigArchivals, "targets-config-archivals", "", "", translation.T("backup-recovery-protection-group-run-create-targets-config-archivals-flag-description"))
	cmd.Flags().StringVarP(&r.TargetsConfigCloudReplications, "targets-config-cloud-replications", "", "", translation.T("backup-recovery-protection-group-run-create-targets-config-cloud-replications-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
		"run-type",
	}

	return cmd
}

// Primary logic for running CreateProtectionGroupRun
func (r *CreateProtectionGroupRunCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.CreateProtectionGroupRunOptions{}
	TargetsConfigHelper := &backuprecoveryv1.RunTargetsConfiguration{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "run-type" {
			OptionsModel.SetRunType(r.RunType)
		}
		if flag.Name == "objects" {
			var Objects []backuprecoveryv1.RunObject
			err, msg := deserialize.ModelSlice(
				r.Objects,
				"objects",
				"RunObject",
				backuprecoveryv1.UnmarshalRunObject,
				&Objects,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetObjects(Objects)
			extraFieldPaths, err := r.utils.ValidateJSON(r.Objects, `{"schemas":{"RunObjectPhysicalParams":["metadataFilePath"]},"fields":["appIds","id","physicalParams#RunObjectPhysicalParams"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "objects",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "objects",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "objects",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "targets-config" {
			var TargetsConfig *backuprecoveryv1.RunTargetsConfiguration
			err, msg := deserialize.Model(
				r.TargetsConfig,
				"targets-config",
				"RunTargetsConfiguration",
				backuprecoveryv1.UnmarshalRunTargetsConfiguration,
				&TargetsConfig,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetTargetsConfig(TargetsConfig)
			extraFieldPaths, err := r.utils.ValidateJSON(r.TargetsConfig, `{"schemas":{"RunCloudReplicationConfig":["awsTarget#AWSTargetConfig","azureTarget#AzureTargetConfig","targetType","retention#Retention"],"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"RunArchivalConfig":["id","archivalTargetType","retention#Retention","copyOnlyFullySuccessful"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"RunReplicationConfig":["id","retention#Retention"],"AWSTargetConfig":["region","sourceId"],"AzureTargetConfig":["resourceGroup","sourceId"]},"fields":["replications#RunReplicationConfig","usePolicyDefaults","cloudReplications#RunCloudReplicationConfig","archivals#RunArchivalConfig"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "targets-config",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "targets-config",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "targets-config",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "targets-config-use-policy-defaults" {
			TargetsConfigHelper.UsePolicyDefaults = core.BoolPtr(r.TargetsConfigUsePolicyDefaults)
		}
		if flag.Name == "targets-config-replications" {
			var TargetsConfigReplications []backuprecoveryv1.RunReplicationConfig
			err, msg := deserialize.ModelSlice(
				r.TargetsConfigReplications,
				"targets-config-replications",
				"RunReplicationConfig",
				backuprecoveryv1.UnmarshalRunReplicationConfig,
				&TargetsConfigReplications,
			)
			r.utils.HandleError(err, msg)
			TargetsConfigHelper.Replications = TargetsConfigReplications
			extraFieldPaths, err := r.utils.ValidateJSON(r.TargetsConfigReplications, `{"schemas":{"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"]},"fields":["retention#Retention","id"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "targets-config-replications",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "targets-config-replications",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "targets-config-replications",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "targets-config-archivals" {
			var TargetsConfigArchivals []backuprecoveryv1.RunArchivalConfig
			err, msg := deserialize.ModelSlice(
				r.TargetsConfigArchivals,
				"targets-config-archivals",
				"RunArchivalConfig",
				backuprecoveryv1.UnmarshalRunArchivalConfig,
				&TargetsConfigArchivals,
			)
			r.utils.HandleError(err, msg)
			TargetsConfigHelper.Archivals = TargetsConfigArchivals
			extraFieldPaths, err := r.utils.ValidateJSON(r.TargetsConfigArchivals, `{"schemas":{"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"]},"fields":["copyOnlyFullySuccessful","retention#Retention","id","archivalTargetType"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "targets-config-archivals",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "targets-config-archivals",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "targets-config-archivals",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "targets-config-cloud-replications" {
			var TargetsConfigCloudReplications []backuprecoveryv1.RunCloudReplicationConfig
			err, msg := deserialize.ModelSlice(
				r.TargetsConfigCloudReplications,
				"targets-config-cloud-replications",
				"RunCloudReplicationConfig",
				backuprecoveryv1.UnmarshalRunCloudReplicationConfig,
				&TargetsConfigCloudReplications,
			)
			r.utils.HandleError(err, msg)
			TargetsConfigHelper.CloudReplications = TargetsConfigCloudReplications
			extraFieldPaths, err := r.utils.ValidateJSON(r.TargetsConfigCloudReplications, `{"schemas":{"DataLockConfig":["mode","unit","duration","enableWormOnExternalTarget"],"Retention":["unit","duration","dataLockConfig#DataLockConfig"],"AWSTargetConfig":["region","sourceId"],"AzureTargetConfig":["resourceGroup","sourceId"]},"fields":["awsTarget#AWSTargetConfig","azureTarget#AzureTargetConfig","retention#Retention","targetType"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "targets-config-cloud-replications",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "targets-config-cloud-replications",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "targets-config-cloud-replications",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
	})

	if !reflect.ValueOf(*TargetsConfigHelper).IsZero() {
		if OptionsModel.TargetsConfig == nil {
			OptionsModel.SetTargetsConfig(TargetsConfigHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "TargetsConfig",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}

	r.MakeRequest(OptionsModel)
}

func (r *CreateProtectionGroupRunCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.CreateProtectionGroupRunOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"protectionGroupId",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for PerformActionOnProtectionGroupRun command
type PerformActionOnProtectionGroupRunRequestSender struct{}

func (s PerformActionOnProtectionGroupRunRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.PerformActionOnProtectionGroupRun(optionsModel.(*backuprecoveryv1.PerformActionOnProtectionGroupRunOptions))
}

// Command Runner for PerformActionOnProtectionGroupRun command
func NewPerformActionOnProtectionGroupRunCommandRunner(utils Utilities, sender RequestSender) *PerformActionOnProtectionGroupRunCommandRunner {
	return &PerformActionOnProtectionGroupRunCommandRunner{utils: utils, sender: sender}
}

type PerformActionOnProtectionGroupRunCommandRunner struct {
	ID            string
	XIBMTenantID  string
	Action        string
	PauseParams   string
	ResumeParams  string
	CancelParams  string
	RequiredFlags []string
	sender        RequestSender
	utils         Utilities
}

// Command mapping: protection-group-run perform-action, GetPerformActionOnProtectionGroupRunCommand
func GetPerformActionOnProtectionGroupRunCommand(r *PerformActionOnProtectionGroupRunCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "perform-action --id ID --xibm-tenant-id XIBM-TENANT-ID --action ACTION [--pause-params PAUSE-PARAMS | @PAUSE-PARAMS-FILE] [--resume-params RESUME-PARAMS | @RESUME-PARAMS-FILE] [--cancel-params CANCEL-PARAMS | @CANCEL-PARAMS-FILE]",
		Short:                 translation.T("backup-recovery-protection-group-run-perform-action-command-short-description"),
		Long:                  translation.T("backup-recovery-protection-group-run-perform-action-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "protection-group-run",
			"x-cli-description":   "Perform various actions on a Protection Group run.",
			"x-cli-command":       "perform-action",
		},
		Example: `  ibmcloud backup-recovery protection-group-run perform-action \
    --id runId \
    --xibm-tenant-id tenantId \
    --action Pause \
    --pause-params '[{"runId": "11:111"}]' \
    --resume-params '[{"runId": "11:111"}]' \
    --cancel-params '[{"runId": "11:111", "localTaskId": "123:456:789", "objectIds": [26,27], "replicationTaskId": ["123:456:789"], "archivalTaskId": ["123:456:789"], "cloudSpinTaskId": ["123:456:789"]}]'`,
	}

	cmd.Flags().StringVarP(&r.ID, "id", "", "", translation.T("backup-recovery-protection-group-run-perform-action-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protection-group-run-perform-action-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Action, "action", "", "", translation.T("backup-recovery-protection-group-run-perform-action-action-flag-description"))
	cmd.Flags().StringVarP(&r.PauseParams, "pause-params", "", "", translation.T("backup-recovery-protection-group-run-perform-action-pause-params-flag-description"))
	cmd.Flags().StringVarP(&r.ResumeParams, "resume-params", "", "", translation.T("backup-recovery-protection-group-run-perform-action-resume-params-flag-description"))
	cmd.Flags().StringVarP(&r.CancelParams, "cancel-params", "", "", translation.T("backup-recovery-protection-group-run-perform-action-cancel-params-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
		"action",
	}

	return cmd
}

// Primary logic for running PerformActionOnProtectionGroupRun
func (r *PerformActionOnProtectionGroupRunCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.PerformActionOnProtectionGroupRunOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "action" {
			OptionsModel.SetAction(r.Action)
		}
		if flag.Name == "pause-params" {
			var PauseParams []backuprecoveryv1.PauseProtectionRunActionParams
			err, msg := deserialize.ModelSlice(
				r.PauseParams,
				"pause-params",
				"PauseProtectionRunActionParams",
				backuprecoveryv1.UnmarshalPauseProtectionRunActionParams,
				&PauseParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetPauseParams(PauseParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.PauseParams, `{"fields":["runId"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "pause-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "pause-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "pause-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "resume-params" {
			var ResumeParams []backuprecoveryv1.ResumeProtectionRunActionParams
			err, msg := deserialize.ModelSlice(
				r.ResumeParams,
				"resume-params",
				"ResumeProtectionRunActionParams",
				backuprecoveryv1.UnmarshalResumeProtectionRunActionParams,
				&ResumeParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetResumeParams(ResumeParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.ResumeParams, `{"fields":["runId"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "resume-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "resume-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "resume-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "cancel-params" {
			var CancelParams []backuprecoveryv1.CancelProtectionGroupRunRequest
			err, msg := deserialize.ModelSlice(
				r.CancelParams,
				"cancel-params",
				"CancelProtectionGroupRunRequest",
				backuprecoveryv1.UnmarshalCancelProtectionGroupRunRequest,
				&CancelParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetCancelParams(CancelParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.CancelParams, `{"fields":["archivalTaskId","replicationTaskId","cloudSpinTaskId","localTaskId","runId","objectIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "cancel-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "cancel-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "cancel-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *PerformActionOnProtectionGroupRunCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.PerformActionOnProtectionGroupRunOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"action",
		"pauseParams",
		"resumeParams",
		"cancelParams",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

func GetRecoveryGroup(utils Utilities) *cobra.Command {
	commands := []*cobra.Command{
		GetGetRecoveriesCommand(NewGetRecoveriesCommandRunner(utils, GetRecoveriesRequestSender{})),
		GetCreateRecoveryCommand(NewCreateRecoveryCommandRunner(utils, CreateRecoveryRequestSender{})),
		GetGetRecoveryByIDCommand(NewGetRecoveryByIDCommandRunner(utils, GetRecoveryByIDRequestSender{})),
		GetDownloadFilesFromRecoveryCommand(NewDownloadFilesFromRecoveryCommandRunner(utils, DownloadFilesFromRecoveryRequestSender{})),
	}

	command := &cobra.Command{
		Use:                   "recovery [action]",
		Short:                 translation.T("backup-recovery-recovery-group-short-description"),
		Long:                  translation.T("backup-recovery-recovery-group-long-description"),
		DisableFlagsInUseLine: true,
	}

	command.AddCommand(commands...)

	return command
}

// RequestSender for GetRecoveries command
type GetRecoveriesRequestSender struct{}

func (s GetRecoveriesRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetRecoveries(optionsModel.(*backuprecoveryv1.GetRecoveriesOptions))
}

// Command Runner for GetRecoveries command
func NewGetRecoveriesCommandRunner(utils Utilities, sender RequestSender) *GetRecoveriesCommandRunner {
	return &GetRecoveriesCommandRunner{utils: utils, sender: sender}
}

type GetRecoveriesCommandRunner struct {
	XIBMTenantID              string
	Ids                       string
	ReturnOnlyChildRecoveries bool
	StartTimeUsecs            int64
	EndTimeUsecs              int64
	SnapshotTargetType        string
	ArchivalTargetType        string
	SnapshotEnvironments      string
	Status                    string
	RecoveryActions           string
	RequiredFlags             []string
	sender                    RequestSender
	utils                     Utilities
}

// Command mapping: recovery list, GetGetRecoveriesCommand
func GetGetRecoveriesCommand(r *GetRecoveriesCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "list --xibm-tenant-id XIBM-TENANT-ID [--ids IDS] [--return-only-child-recoveries=RETURN-ONLY-CHILD-RECOVERIES] [--start-time-usecs START-TIME-USECS] [--end-time-usecs END-TIME-USECS] [--snapshot-target-type SNAPSHOT-TARGET-TYPE] [--archival-target-type ARCHIVAL-TARGET-TYPE] [--snapshot-environments SNAPSHOT-ENVIRONMENTS] [--status STATUS] [--recovery-actions RECOVERY-ACTIONS]",
		Short:                 translation.T("backup-recovery-recovery-list-command-short-description"),
		Long:                  translation.T("backup-recovery-recovery-list-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "recovery",
			"x-cli-command":       "list",
		},
		Example: `  ibmcloud backup-recovery recovery list \
    --xibm-tenant-id tenantId \
    --ids 11:111:11 \
    --return-only-child-recoveries=true \
    --start-time-usecs 26 \
    --end-time-usecs 26 \
    --snapshot-target-type Local,Archival,RpaasArchival,StorageArraySnapshot,Remote \
    --archival-target-type Tape,Cloud,Nas \
    --snapshot-environments kPhysical,kSQL \
    --status Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,LegalHold \
    --recovery-actions RecoverVMs,RecoverFiles,InstantVolumeMount,RecoverVmDisks,RecoverVApps,RecoverVAppTemplates,UptierSnapshot,RecoverRDS,RecoverAurora,RecoverS3Buckets,RecoverRDSPostgres,RecoverAzureSQL,RecoverApps,CloneApps,RecoverNasVolume,RecoverPhysicalVolumes,RecoverSystem,RecoverExchangeDbs,CloneAppView,RecoverSanVolumes,RecoverSanGroup,RecoverMailbox,RecoverOneDrive,RecoverSharePoint,RecoverPublicFolders,RecoverMsGroup,RecoverMsTeam,ConvertToPst,DownloadChats,RecoverMailboxCSM,RecoverOneDriveCSM,RecoverSharePointCSM,RecoverNamespaces,RecoverObjects,RecoverSfdcObjects,RecoverSfdcOrg,RecoverSfdcRecords,DownloadFilesAndFolders,CloneVMs,CloneView,CloneRefreshApp,CloneVMsToView,ConvertAndDeployVMs,DeployVMs`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-recovery-list-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Ids, "ids", "", "", translation.T("backup-recovery-recovery-list-ids-flag-description"))
	cmd.Flags().BoolVarP(&r.ReturnOnlyChildRecoveries, "return-only-child-recoveries", "", false, translation.T("backup-recovery-recovery-list-return-only-child-recoveries-flag-description"))
	cmd.Flags().Int64VarP(&r.StartTimeUsecs, "start-time-usecs", "", 0, translation.T("backup-recovery-recovery-list-start-time-usecs-flag-description"))
	cmd.Flags().Int64VarP(&r.EndTimeUsecs, "end-time-usecs", "", 0, translation.T("backup-recovery-recovery-list-end-time-usecs-flag-description"))
	cmd.Flags().StringVarP(&r.SnapshotTargetType, "snapshot-target-type", "", "", translation.T("backup-recovery-recovery-list-snapshot-target-type-flag-description"))
	cmd.Flags().StringVarP(&r.ArchivalTargetType, "archival-target-type", "", "", translation.T("backup-recovery-recovery-list-archival-target-type-flag-description"))
	cmd.Flags().StringVarP(&r.SnapshotEnvironments, "snapshot-environments", "", "", translation.T("backup-recovery-recovery-list-snapshot-environments-flag-description"))
	cmd.Flags().StringVarP(&r.Status, "status", "", "", translation.T("backup-recovery-recovery-list-status-flag-description"))
	cmd.Flags().StringVarP(&r.RecoveryActions, "recovery-actions", "", "", translation.T("backup-recovery-recovery-list-recovery-actions-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetRecoveries
func (r *GetRecoveriesCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetRecoveriesOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "ids" {
			var Ids []string
			err, msg := deserialize.List(r.Ids, "ids", "JSON", &Ids)
			r.utils.HandleError(err, msg)
			OptionsModel.SetIds(Ids)
		}
		if flag.Name == "return-only-child-recoveries" {
			OptionsModel.SetReturnOnlyChildRecoveries(r.ReturnOnlyChildRecoveries)
		}
		if flag.Name == "start-time-usecs" {
			OptionsModel.SetStartTimeUsecs(r.StartTimeUsecs)
		}
		if flag.Name == "end-time-usecs" {
			OptionsModel.SetEndTimeUsecs(r.EndTimeUsecs)
		}
		if flag.Name == "snapshot-target-type" {
			var SnapshotTargetType []string
			err, msg := deserialize.List(r.SnapshotTargetType, "snapshot-target-type", "JSON", &SnapshotTargetType)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSnapshotTargetType(SnapshotTargetType)
		}
		if flag.Name == "archival-target-type" {
			var ArchivalTargetType []string
			err, msg := deserialize.List(r.ArchivalTargetType, "archival-target-type", "JSON", &ArchivalTargetType)
			r.utils.HandleError(err, msg)
			OptionsModel.SetArchivalTargetType(ArchivalTargetType)
		}
		if flag.Name == "snapshot-environments" {
			var SnapshotEnvironments []string
			err, msg := deserialize.List(r.SnapshotEnvironments, "snapshot-environments", "JSON", &SnapshotEnvironments)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSnapshotEnvironments(SnapshotEnvironments)
		}
		if flag.Name == "status" {
			var Status []string
			err, msg := deserialize.List(r.Status, "status", "JSON", &Status)
			r.utils.HandleError(err, msg)
			OptionsModel.SetStatus(Status)
		}
		if flag.Name == "recovery-actions" {
			var RecoveryActions []string
			err, msg := deserialize.List(r.RecoveryActions, "recovery-actions", "JSON", &RecoveryActions)
			r.utils.HandleError(err, msg)
			OptionsModel.SetRecoveryActions(RecoveryActions)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetRecoveriesCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetRecoveriesOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"recoveries",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for CreateRecovery command
type CreateRecoveryRequestSender struct{}

func (s CreateRecoveryRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.CreateRecovery(optionsModel.(*backuprecoveryv1.CreateRecoveryOptions))
}

// Command Runner for CreateRecovery command
func NewCreateRecoveryCommandRunner(utils Utilities, sender RequestSender) *CreateRecoveryCommandRunner {
	return &CreateRecoveryCommandRunner{utils: utils, sender: sender}
}

type CreateRecoveryCommandRunner struct {
	XIBMTenantID                              string
	Name                                      string
	SnapshotEnvironment                       string
	PhysicalParams                            string
	MssqlParams                               string
	RequestInitiatorType                      string
	PhysicalParamsObjects                     string
	PhysicalParamsRecoveryAction              string
	PhysicalParamsRecoverVolumeParams         string
	PhysicalParamsMountVolumeParams           string
	PhysicalParamsRecoverFileAndFolderParams  string
	PhysicalParamsDownloadFileAndFolderParams string
	PhysicalParamsSystemRecoveryParams        string
	MssqlParamsRecoverAppParams               string
	MssqlParamsRecoveryAction                 string
	MssqlParamsVlanConfig                     string
	RequiredFlags                             []string
	sender                                    RequestSender
	utils                                     Utilities
}

// Command mapping: recovery create, GetCreateRecoveryCommand
func GetCreateRecoveryCommand(r *CreateRecoveryCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "create [command options]",
		Short:                 translation.T("backup-recovery-recovery-create-command-short-description"),
		Long:                  translation.T("backup-recovery-recovery-create-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "recovery",
			"x-cli-command":       "create",
		},
		Example: `  ibmcloud backup-recovery recovery create \
    --xibm-tenant-id tenantId \
    --name create-recovery \
    --snapshot-environment kPhysical \
    --physical-params '{"objects": [{"snapshotId": "snapshotID", "pointInTimeUsecs": 26, "protectionGroupId": "protectionGroupID", "protectionGroupName": "protectionGroupName", "recoverFromStandby": true}], "recoveryAction": "RecoverPhysicalVolumes", "recoverVolumeParams": {"targetEnvironment": "kPhysical", "physicalTargetParams": {"mountTarget": {"id": 26}, "volumeMapping": [{"sourceVolumeGuid": "sourceVolumeGuid", "destinationVolumeGuid": "destinationVolumeGuid"}], "forceUnmountVolume": true, "vlanConfig": {"id": 38, "disableVlan": true}}}, "mountVolumeParams": {"targetEnvironment": "kPhysical", "physicalTargetParams": {"mountToOriginalTarget": true, "originalTargetConfig": {"serverCredentials": {"username": "Username", "password": "Password"}}, "newTargetConfig": {"mountTarget": {"id": 26}, "serverCredentials": {"username": "Username", "password": "Password"}}, "readOnlyMount": true, "volumeNames": ["volume1"], "vlanConfig": {"id": 38, "disableVlan": true}}}, "recoverFileAndFolderParams": {"filesAndFolders": [{"absolutePath": "~/folder1", "isDirectory": true, "isViewFileRecovery": true}], "targetEnvironment": "kPhysical", "physicalTargetParams": {"recoverTarget": {"id": 26}, "restoreToOriginalPaths": true, "overwriteExisting": true, "alternateRestoreDirectory": "~/dirAlt", "preserveAttributes": true, "preserveTimestamps": true, "preserveAcls": true, "continueOnError": true, "saveSuccessFiles": true, "vlanConfig": {"id": 38, "disableVlan": true}, "restoreEntityType": "kRegular"}}, "downloadFileAndFolderParams": {"expiryTimeUsecs": 26, "filesAndFolders": [{"absolutePath": "~/folder1", "isDirectory": true, "isViewFileRecovery": true}], "downloadFilePath": "~/downloadFile"}, "systemRecoveryParams": {"fullNasPath": "~/nas"}}' \
    --mssql-params '{"recoverAppParams": [{"snapshotId": "snapshotId", "pointInTimeUsecs": 26, "protectionGroupId": "protectionGroupId", "protectionGroupName": "protectionGroupName", "recoverFromStandby": true, "aagInfo": {"name": "aagInfoName", "objectId": 26}, "hostInfo": {"id": "hostInfoId", "name": "hostInfoName", "environment": "kPhysical"}, "isEncrypted": true, "sqlTargetParams": {"newSourceConfig": {"keepCdc": true, "multiStageRestoreOptions": {"enableAutoSync": true, "enableMultiStageRestore": true}, "nativeLogRecoveryWithClause": "LogRecoveryWithClause", "nativeRecoveryWithClause": "RecoveryWithClause", "overwritingPolicy": "FailIfExists", "replayEntireLastLog": true, "restoreTimeUsecs": 26, "secondaryDataFilesDirList": [{"directory": "~/dir1", "filenamePattern": ".sql"}], "withNoRecovery": true, "dataFileDirectoryLocation": "~/dir1", "databaseName": "recovery-database-sql", "host": {"id": 26}, "instanceName": "database-instance-1", "logFileDirectoryLocation": "~/dir2"}, "originalSourceConfig": {"keepCdc": true, "multiStageRestoreOptions": {"enableAutoSync": true, "enableMultiStageRestore": true}, "nativeLogRecoveryWithClause": "LogRecoveryWithClause", "nativeRecoveryWithClause": "RecoveryWithClause", "overwritingPolicy": "FailIfExists", "replayEntireLastLog": true, "restoreTimeUsecs": 26, "secondaryDataFilesDirList": [{"directory": "~/dir1", "filenamePattern": ".sql"}], "withNoRecovery": true, "captureTailLogs": true, "dataFileDirectoryLocation": "~/dir1", "logFileDirectoryLocation": "~/dir2", "newDatabaseName": "recovery-database-sql-new"}, "recoverToNewSource": true}, "targetEnvironment": "kSQL"}], "recoveryAction": "RecoverApps", "vlanConfig": {"id": 38, "disableVlan": true}}' \
    --request-initiator-type UIUser`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-recovery-create-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Name, "name", "", "", translation.T("backup-recovery-recovery-create-name-flag-description"))
	cmd.Flags().StringVarP(&r.SnapshotEnvironment, "snapshot-environment", "", "", translation.T("backup-recovery-recovery-create-snapshot-environment-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParams, "physical-params", "", "", translation.T("backup-recovery-recovery-create-physical-params-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParams, "mssql-params", "", "", translation.T("backup-recovery-recovery-create-mssql-params-flag-description"))
	cmd.Flags().StringVarP(&r.RequestInitiatorType, "request-initiator-type", "", "", translation.T("backup-recovery-recovery-create-request-initiator-type-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsObjects, "physical-params-objects", "", "", translation.T("backup-recovery-recovery-create-physical-params-objects-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsRecoveryAction, "physical-params-recovery-action", "", "", translation.T("backup-recovery-recovery-create-physical-params-recovery-action-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsRecoverVolumeParams, "physical-params-recover-volume-params", "", "", translation.T("backup-recovery-recovery-create-physical-params-recover-volume-params-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsMountVolumeParams, "physical-params-mount-volume-params", "", "", translation.T("backup-recovery-recovery-create-physical-params-mount-volume-params-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsRecoverFileAndFolderParams, "physical-params-recover-file-and-folder-params", "", "", translation.T("backup-recovery-recovery-create-physical-params-recover-file-and-folder-params-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsDownloadFileAndFolderParams, "physical-params-download-file-and-folder-params", "", "", translation.T("backup-recovery-recovery-create-physical-params-download-file-and-folder-params-flag-description"))
	cmd.Flags().StringVarP(&r.PhysicalParamsSystemRecoveryParams, "physical-params-system-recovery-params", "", "", translation.T("backup-recovery-recovery-create-physical-params-system-recovery-params-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParamsRecoverAppParams, "mssql-params-recover-app-params", "", "", translation.T("backup-recovery-recovery-create-mssql-params-recover-app-params-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParamsRecoveryAction, "mssql-params-recovery-action", "", "", translation.T("backup-recovery-recovery-create-mssql-params-recovery-action-flag-description"))
	cmd.Flags().StringVarP(&r.MssqlParamsVlanConfig, "mssql-params-vlan-config", "", "", translation.T("backup-recovery-recovery-create-mssql-params-vlan-config-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
		"name",
		"snapshot-environment",
	}

	return cmd
}

// Primary logic for running CreateRecovery
func (r *CreateRecoveryCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.CreateRecoveryOptions{}
	PhysicalParamsHelper := &backuprecoveryv1.RecoverPhysicalParams{}
	MssqlParamsHelper := &backuprecoveryv1.RecoverSqlParams{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "name" {
			OptionsModel.SetName(r.Name)
		}
		if flag.Name == "snapshot-environment" {
			OptionsModel.SetSnapshotEnvironment(r.SnapshotEnvironment)
		}
		if flag.Name == "physical-params" {
			var PhysicalParams *backuprecoveryv1.RecoverPhysicalParams
			err, msg := deserialize.Model(
				r.PhysicalParams,
				"physical-params",
				"RecoverPhysicalParams",
				backuprecoveryv1.UnmarshalRecoverPhysicalParams,
				&PhysicalParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetPhysicalParams(PhysicalParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParams, `{"schemas":{"PhysicalTargetParamsForRecoverVolumeMountTarget":["id"],"RecoverPhysicalVolumeParamsPhysicalTargetParams":["mountTarget#PhysicalTargetParamsForRecoverVolumeMountTarget","volumeMapping#RecoverVolumeMapping","forceUnmountVolume","vlanConfig#PhysicalTargetParamsForRecoverVolumeVlanConfig"],"PhysicalTargetParamsForRecoverFileAndFolderVlanConfig":["id","disableVlan"],"RecoverPhysicalFileAndFolderParamsPhysicalTargetParams":["recoverTarget#PhysicalTargetParamsForRecoverFileAndFolderRecoverTarget","restoreToOriginalPaths","overwriteExisting","alternateRestoreDirectory","preserveAttributes","preserveTimestamps","preserveAcls","continueOnError","saveSuccessFiles","vlanConfig#PhysicalTargetParamsForRecoverFileAndFolderVlanConfig","restoreEntityType"],"PhysicalMountVolumesOriginalTargetConfigServerCredentials":["username","password"],"MountPhysicalVolumeParamsPhysicalTargetParams":["mountToOriginalTarget","originalTargetConfig#PhysicalTargetParamsForMountVolumeOriginalTargetConfig","newTargetConfig#PhysicalTargetParamsForMountVolumeNewTargetConfig","readOnlyMount","volumeNames","vlanConfig#PhysicalTargetParamsForMountVolumeVlanConfig"],"RecoverPhysicalParamsMountVolumeParams":["targetEnvironment","physicalTargetParams#MountPhysicalVolumeParamsPhysicalTargetParams"],"RecoverPhysicalParamsRecoverFileAndFolderParams":["filesAndFolders#CommonRecoverFileAndFolderInfo","targetEnvironment","physicalTargetParams#RecoverPhysicalFileAndFolderParamsPhysicalTargetParams"],"RecoverPhysicalParamsSystemRecoveryParams":["fullNasPath"],"PhysicalTargetParamsForMountVolumeNewTargetConfig":["mountTarget#RecoverTarget","serverCredentials#PhysicalMountVolumesNewTargetConfigServerCredentials"],"RecoverPhysicalParamsRecoverVolumeParams":["targetEnvironment","physicalTargetParams#RecoverPhysicalVolumeParamsPhysicalTargetParams"],"CommonRecoverFileAndFolderInfo":["absolutePath","isDirectory","isViewFileRecovery"],"PhysicalTargetParamsForMountVolumeVlanConfig":["id","disableVlan"],"PhysicalTargetParamsForMountVolumeOriginalTargetConfig":["serverCredentials#PhysicalMountVolumesOriginalTargetConfigServerCredentials"],"CommonRecoverObjectSnapshotParams":["snapshotId","pointInTimeUsecs","protectionGroupId","protectionGroupName","recoverFromStandby"],"PhysicalTargetParamsForRecoverVolumeVlanConfig":["id","disableVlan"],"RecoverTarget":["id"],"RecoverVolumeMapping":["sourceVolumeGuid","destinationVolumeGuid"],"RecoverPhysicalParamsDownloadFileAndFolderParams":["expiryTimeUsecs","filesAndFolders#CommonRecoverFileAndFolderInfo","downloadFilePath"],"PhysicalTargetParamsForRecoverFileAndFolderRecoverTarget":["id"],"PhysicalMountVolumesNewTargetConfigServerCredentials":["username","password"]},"fields":["downloadFileAndFolderParams#RecoverPhysicalParamsDownloadFileAndFolderParams","recoveryAction","systemRecoveryParams#RecoverPhysicalParamsSystemRecoveryParams","recoverVolumeParams#RecoverPhysicalParamsRecoverVolumeParams","mountVolumeParams#RecoverPhysicalParamsMountVolumeParams","recoverFileAndFolderParams#RecoverPhysicalParamsRecoverFileAndFolderParams","objects#CommonRecoverObjectSnapshotParams"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "mssql-params" {
			var MssqlParams *backuprecoveryv1.RecoverSqlParams
			err, msg := deserialize.Model(
				r.MssqlParams,
				"mssql-params",
				"RecoverSqlParams",
				backuprecoveryv1.UnmarshalRecoverSqlParams,
				&MssqlParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMssqlParams(MssqlParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.MssqlParams, `{"schemas":{"RecoveryVlanConfig":["id","disableVlan"],"SqlTargetParamsForRecoverSqlApp":["newSourceConfig#RecoverSqlAppNewSourceConfig","originalSourceConfig#RecoverSqlAppOriginalSourceConfig","recoverToNewSource"],"MultiStageRestoreOptions":["enableAutoSync","enableMultiStageRestore"],"RecoverSqlAppNewSourceConfig":["keepCdc","multiStageRestoreOptions#MultiStageRestoreOptions","nativeLogRecoveryWithClause","nativeRecoveryWithClause","overwritingPolicy","replayEntireLastLog","restoreTimeUsecs","secondaryDataFilesDirList#FilenamePatternToDirectory","withNoRecovery","dataFileDirectoryLocation","databaseName","host#RecoveryObjectIdentifier","instanceName","logFileDirectoryLocation"],"RecoverSqlAppOriginalSourceConfig":["keepCdc","multiStageRestoreOptions#MultiStageRestoreOptions","nativeLogRecoveryWithClause","nativeRecoveryWithClause","overwritingPolicy","replayEntireLastLog","restoreTimeUsecs","secondaryDataFilesDirList#FilenamePatternToDirectory","withNoRecovery","captureTailLogs","dataFileDirectoryLocation","logFileDirectoryLocation","newDatabaseName"],"FilenamePatternToDirectory":["directory","filenamePattern"],"RecoveryObjectIdentifier":["id"],"AAGInfo":["name","objectId"],"HostInformation":["id","name","environment"],"RecoverSqlAppParams":["snapshotId","pointInTimeUsecs","protectionGroupId","protectionGroupName","recoverFromStandby","aagInfo#AAGInfo","hostInfo#HostInformation","isEncrypted","sqlTargetParams#SqlTargetParamsForRecoverSqlApp","targetEnvironment"]},"fields":["recoveryAction","recoverAppParams#RecoverSqlAppParams","vlanConfig#RecoveryVlanConfig"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "mssql-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "mssql-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "mssql-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "request-initiator-type" {
			OptionsModel.SetRequestInitiatorType(r.RequestInitiatorType)
		}
		if flag.Name == "physical-params-objects" {
			var PhysicalParamsObjects []backuprecoveryv1.CommonRecoverObjectSnapshotParams
			err, msg := deserialize.ModelSlice(
				r.PhysicalParamsObjects,
				"physical-params-objects",
				"CommonRecoverObjectSnapshotParams",
				backuprecoveryv1.UnmarshalCommonRecoverObjectSnapshotParams,
				&PhysicalParamsObjects,
			)
			r.utils.HandleError(err, msg)
			PhysicalParamsHelper.Objects = PhysicalParamsObjects
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParamsObjects, `{"fields":["protectionGroupId","snapshotId","pointInTimeUsecs","protectionGroupName","recoverFromStandby"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params-objects",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params-objects",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params-objects",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "physical-params-recovery-action" {
			PhysicalParamsHelper.RecoveryAction = core.StringPtr(r.PhysicalParamsRecoveryAction)
		}
		if flag.Name == "physical-params-recover-volume-params" {
			var PhysicalParamsRecoverVolumeParams *backuprecoveryv1.RecoverPhysicalParamsRecoverVolumeParams
			err, msg := deserialize.Model(
				r.PhysicalParamsRecoverVolumeParams,
				"physical-params-recover-volume-params",
				"RecoverPhysicalParamsRecoverVolumeParams",
				backuprecoveryv1.UnmarshalRecoverPhysicalParamsRecoverVolumeParams,
				&PhysicalParamsRecoverVolumeParams,
			)
			r.utils.HandleError(err, msg)
			PhysicalParamsHelper.RecoverVolumeParams = PhysicalParamsRecoverVolumeParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParamsRecoverVolumeParams, `{"schemas":{"PhysicalTargetParamsForRecoverVolumeMountTarget":["id"],"RecoverPhysicalVolumeParamsPhysicalTargetParams":["mountTarget#PhysicalTargetParamsForRecoverVolumeMountTarget","volumeMapping#RecoverVolumeMapping","forceUnmountVolume","vlanConfig#PhysicalTargetParamsForRecoverVolumeVlanConfig"],"PhysicalTargetParamsForRecoverVolumeVlanConfig":["id","disableVlan"],"RecoverVolumeMapping":["sourceVolumeGuid","destinationVolumeGuid"]},"fields":["targetEnvironment","physicalTargetParams#RecoverPhysicalVolumeParamsPhysicalTargetParams"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params-recover-volume-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params-recover-volume-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params-recover-volume-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "physical-params-mount-volume-params" {
			var PhysicalParamsMountVolumeParams *backuprecoveryv1.RecoverPhysicalParamsMountVolumeParams
			err, msg := deserialize.Model(
				r.PhysicalParamsMountVolumeParams,
				"physical-params-mount-volume-params",
				"RecoverPhysicalParamsMountVolumeParams",
				backuprecoveryv1.UnmarshalRecoverPhysicalParamsMountVolumeParams,
				&PhysicalParamsMountVolumeParams,
			)
			r.utils.HandleError(err, msg)
			PhysicalParamsHelper.MountVolumeParams = PhysicalParamsMountVolumeParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParamsMountVolumeParams, `{"schemas":{"PhysicalTargetParamsForMountVolumeVlanConfig":["id","disableVlan"],"PhysicalMountVolumesOriginalTargetConfigServerCredentials":["username","password"],"PhysicalTargetParamsForMountVolumeOriginalTargetConfig":["serverCredentials#PhysicalMountVolumesOriginalTargetConfigServerCredentials"],"MountPhysicalVolumeParamsPhysicalTargetParams":["mountToOriginalTarget","originalTargetConfig#PhysicalTargetParamsForMountVolumeOriginalTargetConfig","newTargetConfig#PhysicalTargetParamsForMountVolumeNewTargetConfig","readOnlyMount","volumeNames","vlanConfig#PhysicalTargetParamsForMountVolumeVlanConfig"],"RecoverTarget":["id"],"PhysicalMountVolumesNewTargetConfigServerCredentials":["username","password"],"PhysicalTargetParamsForMountVolumeNewTargetConfig":["mountTarget#RecoverTarget","serverCredentials#PhysicalMountVolumesNewTargetConfigServerCredentials"]},"fields":["targetEnvironment","physicalTargetParams#MountPhysicalVolumeParamsPhysicalTargetParams"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params-mount-volume-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params-mount-volume-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params-mount-volume-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "physical-params-recover-file-and-folder-params" {
			var PhysicalParamsRecoverFileAndFolderParams *backuprecoveryv1.RecoverPhysicalParamsRecoverFileAndFolderParams
			err, msg := deserialize.Model(
				r.PhysicalParamsRecoverFileAndFolderParams,
				"physical-params-recover-file-and-folder-params",
				"RecoverPhysicalParamsRecoverFileAndFolderParams",
				backuprecoveryv1.UnmarshalRecoverPhysicalParamsRecoverFileAndFolderParams,
				&PhysicalParamsRecoverFileAndFolderParams,
			)
			r.utils.HandleError(err, msg)
			PhysicalParamsHelper.RecoverFileAndFolderParams = PhysicalParamsRecoverFileAndFolderParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParamsRecoverFileAndFolderParams, `{"schemas":{"PhysicalTargetParamsForRecoverFileAndFolderVlanConfig":["id","disableVlan"],"RecoverPhysicalFileAndFolderParamsPhysicalTargetParams":["recoverTarget#PhysicalTargetParamsForRecoverFileAndFolderRecoverTarget","restoreToOriginalPaths","overwriteExisting","alternateRestoreDirectory","preserveAttributes","preserveTimestamps","preserveAcls","continueOnError","saveSuccessFiles","vlanConfig#PhysicalTargetParamsForRecoverFileAndFolderVlanConfig","restoreEntityType"],"PhysicalTargetParamsForRecoverFileAndFolderRecoverTarget":["id"],"CommonRecoverFileAndFolderInfo":["absolutePath","isDirectory","isViewFileRecovery"]},"fields":["filesAndFolders#CommonRecoverFileAndFolderInfo","physicalTargetParams#RecoverPhysicalFileAndFolderParamsPhysicalTargetParams","targetEnvironment"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params-recover-file-and-folder-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params-recover-file-and-folder-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params-recover-file-and-folder-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "physical-params-download-file-and-folder-params" {
			var PhysicalParamsDownloadFileAndFolderParams *backuprecoveryv1.RecoverPhysicalParamsDownloadFileAndFolderParams
			err, msg := deserialize.Model(
				r.PhysicalParamsDownloadFileAndFolderParams,
				"physical-params-download-file-and-folder-params",
				"RecoverPhysicalParamsDownloadFileAndFolderParams",
				backuprecoveryv1.UnmarshalRecoverPhysicalParamsDownloadFileAndFolderParams,
				&PhysicalParamsDownloadFileAndFolderParams,
			)
			r.utils.HandleError(err, msg)
			PhysicalParamsHelper.DownloadFileAndFolderParams = PhysicalParamsDownloadFileAndFolderParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParamsDownloadFileAndFolderParams, `{"schemas":{"CommonRecoverFileAndFolderInfo":["absolutePath","isDirectory","isViewFileRecovery"]},"fields":["filesAndFolders#CommonRecoverFileAndFolderInfo","downloadFilePath","expiryTimeUsecs"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params-download-file-and-folder-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params-download-file-and-folder-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params-download-file-and-folder-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "physical-params-system-recovery-params" {
			var PhysicalParamsSystemRecoveryParams *backuprecoveryv1.RecoverPhysicalParamsSystemRecoveryParams
			err, msg := deserialize.Model(
				r.PhysicalParamsSystemRecoveryParams,
				"physical-params-system-recovery-params",
				"RecoverPhysicalParamsSystemRecoveryParams",
				backuprecoveryv1.UnmarshalRecoverPhysicalParamsSystemRecoveryParams,
				&PhysicalParamsSystemRecoveryParams,
			)
			r.utils.HandleError(err, msg)
			PhysicalParamsHelper.SystemRecoveryParams = PhysicalParamsSystemRecoveryParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.PhysicalParamsSystemRecoveryParams, `{"fields":["fullNasPath"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "physical-params-system-recovery-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "physical-params-system-recovery-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "physical-params-system-recovery-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "mssql-params-recover-app-params" {
			var MssqlParamsRecoverAppParams []backuprecoveryv1.RecoverSqlAppParams
			err, msg := deserialize.ModelSlice(
				r.MssqlParamsRecoverAppParams,
				"mssql-params-recover-app-params",
				"RecoverSqlAppParams",
				backuprecoveryv1.UnmarshalRecoverSqlAppParams,
				&MssqlParamsRecoverAppParams,
			)
			r.utils.HandleError(err, msg)
			MssqlParamsHelper.RecoverAppParams = MssqlParamsRecoverAppParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.MssqlParamsRecoverAppParams, `{"schemas":{"SqlTargetParamsForRecoverSqlApp":["newSourceConfig#RecoverSqlAppNewSourceConfig","originalSourceConfig#RecoverSqlAppOriginalSourceConfig","recoverToNewSource"],"MultiStageRestoreOptions":["enableAutoSync","enableMultiStageRestore"],"RecoverSqlAppNewSourceConfig":["keepCdc","multiStageRestoreOptions#MultiStageRestoreOptions","nativeLogRecoveryWithClause","nativeRecoveryWithClause","overwritingPolicy","replayEntireLastLog","restoreTimeUsecs","secondaryDataFilesDirList#FilenamePatternToDirectory","withNoRecovery","dataFileDirectoryLocation","databaseName","host#RecoveryObjectIdentifier","instanceName","logFileDirectoryLocation"],"RecoverSqlAppOriginalSourceConfig":["keepCdc","multiStageRestoreOptions#MultiStageRestoreOptions","nativeLogRecoveryWithClause","nativeRecoveryWithClause","overwritingPolicy","replayEntireLastLog","restoreTimeUsecs","secondaryDataFilesDirList#FilenamePatternToDirectory","withNoRecovery","captureTailLogs","dataFileDirectoryLocation","logFileDirectoryLocation","newDatabaseName"],"FilenamePatternToDirectory":["directory","filenamePattern"],"RecoveryObjectIdentifier":["id"],"AAGInfo":["name","objectId"],"HostInformation":["id","name","environment"]},"fields":["protectionGroupId","hostInfo#HostInformation","snapshotId","aagInfo#AAGInfo","pointInTimeUsecs","protectionGroupName","sqlTargetParams#SqlTargetParamsForRecoverSqlApp","recoverFromStandby","isEncrypted","targetEnvironment"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "mssql-params-recover-app-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-recover-app-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-recover-app-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "mssql-params-recovery-action" {
			MssqlParamsHelper.RecoveryAction = core.StringPtr(r.MssqlParamsRecoveryAction)
		}
		if flag.Name == "mssql-params-vlan-config" {
			var MssqlParamsVlanConfig *backuprecoveryv1.RecoveryVlanConfig
			err, msg := deserialize.Model(
				r.MssqlParamsVlanConfig,
				"mssql-params-vlan-config",
				"RecoveryVlanConfig",
				backuprecoveryv1.UnmarshalRecoveryVlanConfig,
				&MssqlParamsVlanConfig,
			)
			r.utils.HandleError(err, msg)
			MssqlParamsHelper.VlanConfig = MssqlParamsVlanConfig
			extraFieldPaths, err := r.utils.ValidateJSON(r.MssqlParamsVlanConfig, `{"fields":["disableVlan","id"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "mssql-params-vlan-config",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-vlan-config",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "mssql-params-vlan-config",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
	})

	if !reflect.ValueOf(*PhysicalParamsHelper).IsZero() {
		if OptionsModel.PhysicalParams == nil {
			OptionsModel.SetPhysicalParams(PhysicalParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "PhysicalParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*MssqlParamsHelper).IsZero() {
		if OptionsModel.MssqlParams == nil {
			OptionsModel.SetMssqlParams(MssqlParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "MssqlParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}

	r.MakeRequest(OptionsModel)
}

func (r *CreateRecoveryCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.CreateRecoveryOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"id",
		"name",
		"startTimeUsecs",
		"endTimeUsecs",
		"status",
		"progressTaskId",
		"snapshotEnvironment",
		"recoveryAction",
		"permissions",
		"creationInfo",
		"canTearDown",
		"tearDownStatus",
		"tearDownMessage",
		"messages",
		"isParentRecovery",
		"parentRecoveryId",
		"retrieveArchiveTasks",
		"isMultiStageRestore",
		"physicalParams",
		"mssqlParams",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for GetRecoveryByID command
type GetRecoveryByIDRequestSender struct{}

func (s GetRecoveryByIDRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetRecoveryByID(optionsModel.(*backuprecoveryv1.GetRecoveryByIdOptions))
}

// Command Runner for GetRecoveryByID command
func NewGetRecoveryByIDCommandRunner(utils Utilities, sender RequestSender) *GetRecoveryByIDCommandRunner {
	return &GetRecoveryByIDCommandRunner{utils: utils, sender: sender}
}

type GetRecoveryByIDCommandRunner struct {
	ID            string
	XIBMTenantID  string
	RequiredFlags []string
	sender        RequestSender
	utils         Utilities
}

// Command mapping: recovery get, GetGetRecoveryByIDCommand
func GetGetRecoveryByIDCommand(r *GetRecoveryByIDCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "get --id ID --xibm-tenant-id XIBM-TENANT-ID",
		Short:                 translation.T("backup-recovery-recovery-get-command-short-description"),
		Long:                  translation.T("backup-recovery-recovery-get-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "recovery",
			"x-cli-description":   "Get Recovery for a given id.",
			"x-cli-command":       "get",
		},
		Example: `  ibmcloud backup-recovery recovery get \
    --id exampleString \
    --xibm-tenant-id tenantId`,
	}

	cmd.Flags().StringVarP(&r.ID, "id", "", "", translation.T("backup-recovery-recovery-get-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-recovery-get-xibm-tenant-id-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetRecoveryByID
func (r *GetRecoveryByIDCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetRecoveryByIdOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetRecoveryByIDCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetRecoveryByIdOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"id",
		"name",
		"startTimeUsecs",
		"endTimeUsecs",
		"status",
		"progressTaskId",
		"snapshotEnvironment",
		"recoveryAction",
		"permissions",
		"creationInfo",
		"canTearDown",
		"tearDownStatus",
		"tearDownMessage",
		"messages",
		"isParentRecovery",
		"parentRecoveryId",
		"retrieveArchiveTasks",
		"isMultiStageRestore",
		"physicalParams",
		"mssqlParams",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for DownloadFilesFromRecovery command
type DownloadFilesFromRecoveryRequestSender struct{}

func (s DownloadFilesFromRecoveryRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	res, err := ServiceInstance.DownloadFilesFromRecovery(optionsModel.(*backuprecoveryv1.DownloadFilesFromRecoveryOptions))
	// DownloadFilesFromRecovery returns an empty response body
	return nil, res, err
}

// Command Runner for DownloadFilesFromRecovery command
func NewDownloadFilesFromRecoveryCommandRunner(utils Utilities, sender RequestSender) *DownloadFilesFromRecoveryCommandRunner {
	return &DownloadFilesFromRecoveryCommandRunner{utils: utils, sender: sender}
}

type DownloadFilesFromRecoveryCommandRunner struct {
	ID             string
	XIBMTenantID   string
	StartOffset    int64
	Length         int64
	FileType       string
	SourceName     string
	StartTime      string
	IncludeTenants bool
	RequiredFlags  []string
	sender         RequestSender
	utils          Utilities
}

// Command mapping: recovery files-download, GetDownloadFilesFromRecoveryCommand
func GetDownloadFilesFromRecoveryCommand(r *DownloadFilesFromRecoveryCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "files-download --id ID --xibm-tenant-id XIBM-TENANT-ID [--start-offset START-OFFSET] [--length LENGTH] [--file-type FILE-TYPE] [--source-name SOURCE-NAME] [--start-time START-TIME] [--include-tenants=INCLUDE-TENANTS]",
		Short:                 translation.T("backup-recovery-recovery-files-download-command-short-description"),
		Long:                  translation.T("backup-recovery-recovery-files-download-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "recovery",
			"x-cli-description":   "Download files from the given download file recovery.",
			"x-cli-command":       "files-download",
		},
		Example: `  ibmcloud backup-recovery recovery files-download \
    --id exampleString \
    --xibm-tenant-id tenantId \
    --start-offset 26 \
    --length 26 \
    --file-type fileType \
    --source-name sourceName \
    --start-time startTime \
    --include-tenants=true`,
	}

	cmd.Flags().StringVarP(&r.ID, "id", "", "", translation.T("backup-recovery-recovery-files-download-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-recovery-files-download-xibm-tenant-id-flag-description"))
	cmd.Flags().Int64VarP(&r.StartOffset, "start-offset", "", 0, translation.T("backup-recovery-recovery-files-download-start-offset-flag-description"))
	cmd.Flags().Int64VarP(&r.Length, "length", "", 0, translation.T("backup-recovery-recovery-files-download-length-flag-description"))
	cmd.Flags().StringVarP(&r.FileType, "file-type", "", "", translation.T("backup-recovery-recovery-files-download-file-type-flag-description"))
	cmd.Flags().StringVarP(&r.SourceName, "source-name", "", "", translation.T("backup-recovery-recovery-files-download-source-name-flag-description"))
	cmd.Flags().StringVarP(&r.StartTime, "start-time", "", "", translation.T("backup-recovery-recovery-files-download-start-time-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeTenants, "include-tenants", "", false, translation.T("backup-recovery-recovery-files-download-include-tenants-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running DownloadFilesFromRecovery
func (r *DownloadFilesFromRecoveryCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.DownloadFilesFromRecoveryOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "start-offset" {
			OptionsModel.SetStartOffset(r.StartOffset)
		}
		if flag.Name == "length" {
			OptionsModel.SetLength(r.Length)
		}
		if flag.Name == "file-type" {
			OptionsModel.SetFileType(r.FileType)
		}
		if flag.Name == "source-name" {
			OptionsModel.SetSourceName(r.SourceName)
		}
		if flag.Name == "start-time" {
			OptionsModel.SetStartTime(r.StartTime)
		}
		if flag.Name == "include-tenants" {
			OptionsModel.SetIncludeTenants(r.IncludeTenants)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *DownloadFilesFromRecoveryCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.DownloadFilesFromRecoveryOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)
	r.utils.ProcessEmptyResponse(DetailedResponse, ResponseErr)
}

func GetDataSourceConnectionGroup(utils Utilities) *cobra.Command {
	commands := []*cobra.Command{
		GetGetDataSourceConnectionsCommand(NewGetDataSourceConnectionsCommandRunner(utils, GetDataSourceConnectionsRequestSender{})),
		GetCreateDataSourceConnectionCommand(NewCreateDataSourceConnectionCommandRunner(utils, CreateDataSourceConnectionRequestSender{})),
		GetDeleteDataSourceConnectionCommand(NewDeleteDataSourceConnectionCommandRunner(utils, DeleteDataSourceConnectionRequestSender{})),
		GetPatchDataSourceConnectionCommand(NewPatchDataSourceConnectionCommandRunner(utils, PatchDataSourceConnectionRequestSender{})),
		GetGenerateDataSourceConnectionRegistrationTokenCommand(NewGenerateDataSourceConnectionRegistrationTokenCommandRunner(utils, GenerateDataSourceConnectionRegistrationTokenRequestSender{})),
	}

	command := &cobra.Command{
		Use:                   "data-source-connection [action]",
		Short:                 translation.T("backup-recovery-data-source-connection-group-short-description"),
		Long:                  translation.T("backup-recovery-data-source-connection-group-long-description"),
		DisableFlagsInUseLine: true,
	}

	command.AddCommand(commands...)

	return command
}

// RequestSender for GetDataSourceConnections command
type GetDataSourceConnectionsRequestSender struct{}

func (s GetDataSourceConnectionsRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetDataSourceConnections(optionsModel.(*backuprecoveryv1.GetDataSourceConnectionsOptions))
}

// Command Runner for GetDataSourceConnections command
func NewGetDataSourceConnectionsCommandRunner(utils Utilities, sender RequestSender) *GetDataSourceConnectionsCommandRunner {
	return &GetDataSourceConnectionsCommandRunner{utils: utils, sender: sender}
}

type GetDataSourceConnectionsCommandRunner struct {
	XIBMTenantID    string
	ConnectionIds   string
	ConnectionNames string
	RequiredFlags   []string
	sender          RequestSender
	utils           Utilities
}

// Command mapping: data-source-connection list, GetGetDataSourceConnectionsCommand
func GetGetDataSourceConnectionsCommand(r *GetDataSourceConnectionsCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "list --xibm-tenant-id XIBM-TENANT-ID [--connection-ids CONNECTION-IDS] [--connection-names CONNECTION-NAMES]",
		Short:                 translation.T("backup-recovery-data-source-connection-list-command-short-description"),
		Long:                  translation.T("backup-recovery-data-source-connection-list-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "data-source-connection",
			"x-cli-command":       "list",
		},
		Example: `  ibmcloud backup-recovery data-source-connection list \
    --xibm-tenant-id tenantId \
    --connection-ids connectionId1,connectionId2 \
    --connection-names connectionName1,connectionName2`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-data-source-connection-list-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.ConnectionIds, "connection-ids", "", "", translation.T("backup-recovery-data-source-connection-list-connection-ids-flag-description"))
	cmd.Flags().StringVarP(&r.ConnectionNames, "connection-names", "", "", translation.T("backup-recovery-data-source-connection-list-connection-names-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetDataSourceConnections
func (r *GetDataSourceConnectionsCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetDataSourceConnectionsOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "connection-ids" {
			var ConnectionIds []string
			err, msg := deserialize.List(r.ConnectionIds, "connection-ids", "JSON", &ConnectionIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetConnectionIds(ConnectionIds)
		}
		if flag.Name == "connection-names" {
			var ConnectionNames []string
			err, msg := deserialize.List(r.ConnectionNames, "connection-names", "JSON", &ConnectionNames)
			r.utils.HandleError(err, msg)
			OptionsModel.SetConnectionNames(ConnectionNames)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetDataSourceConnectionsCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetDataSourceConnectionsOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"connections",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for CreateDataSourceConnection command
type CreateDataSourceConnectionRequestSender struct{}

func (s CreateDataSourceConnectionRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.CreateDataSourceConnection(optionsModel.(*backuprecoveryv1.CreateDataSourceConnectionOptions))
}

// Command Runner for CreateDataSourceConnection command
func NewCreateDataSourceConnectionCommandRunner(utils Utilities, sender RequestSender) *CreateDataSourceConnectionCommandRunner {
	return &CreateDataSourceConnectionCommandRunner{utils: utils, sender: sender}
}

type CreateDataSourceConnectionCommandRunner struct {
	ConnectionName string
	XIBMTenantID   string
	RequiredFlags  []string
	sender         RequestSender
	utils          Utilities
}

// Command mapping: data-source-connection create, GetCreateDataSourceConnectionCommand
func GetCreateDataSourceConnectionCommand(r *CreateDataSourceConnectionCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "create --connection-name CONNECTION-NAME [--xibm-tenant-id XIBM-TENANT-ID]",
		Short:                 translation.T("backup-recovery-data-source-connection-create-command-short-description"),
		Long:                  translation.T("backup-recovery-data-source-connection-create-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "data-source-connection",
			"x-cli-command":       "create",
		},
		Example: `  ibmcloud backup-recovery data-source-connection create \
    --connection-name data-source-connection \
    --xibm-tenant-id tenantId`,
	}

	cmd.Flags().StringVarP(&r.ConnectionName, "connection-name", "", "", translation.T("backup-recovery-data-source-connection-create-connection-name-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-data-source-connection-create-xibm-tenant-id-flag-description"))
	r.RequiredFlags = []string{
		"connection-name",
	}

	return cmd
}

// Primary logic for running CreateDataSourceConnection
func (r *CreateDataSourceConnectionCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.CreateDataSourceConnectionOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "connection-name" {
			OptionsModel.SetConnectionName(r.ConnectionName)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *CreateDataSourceConnectionCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.CreateDataSourceConnectionOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"connectionId",
		"connectionName",
		"connectorIds",
		"registrationToken",
		"tenantId",
		"upgradingConnectorId",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for DeleteDataSourceConnection command
type DeleteDataSourceConnectionRequestSender struct{}

func (s DeleteDataSourceConnectionRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	res, err := ServiceInstance.DeleteDataSourceConnection(optionsModel.(*backuprecoveryv1.DeleteDataSourceConnectionOptions))
	// DeleteDataSourceConnection returns an empty response body
	return nil, res, err
}

// Command Runner for DeleteDataSourceConnection command
func NewDeleteDataSourceConnectionCommandRunner(utils Utilities, sender RequestSender) *DeleteDataSourceConnectionCommandRunner {
	return &DeleteDataSourceConnectionCommandRunner{utils: utils, sender: sender}
}

type DeleteDataSourceConnectionCommandRunner struct {
	ConnectionID              string
	XIBMTenantID              string
	ForceDeleteWithoutConfirm bool
	RequiredFlags             []string
	sender                    RequestSender
	utils                     Utilities
}

// Command mapping: data-source-connection delete, GetDeleteDataSourceConnectionCommand
func GetDeleteDataSourceConnectionCommand(r *DeleteDataSourceConnectionCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "delete --connection-id CONNECTION-ID --xibm-tenant-id XIBM-TENANT-ID",
		Short:                 translation.T("backup-recovery-data-source-connection-delete-command-short-description"),
		Long:                  translation.T("backup-recovery-data-source-connection-delete-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "data-source-connection",
			"x-cli-command":       "delete",
		},
		Example: `  ibmcloud backup-recovery data-source-connection delete \
    --connection-id exampleString \
    --xibm-tenant-id tenantId`,
	}

	cmd.Flags().StringVarP(&r.ConnectionID, "connection-id", "", "", translation.T("backup-recovery-data-source-connection-delete-connection-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-data-source-connection-delete-xibm-tenant-id-flag-description"))
	cmd.Flags().BoolVarP(&r.ForceDeleteWithoutConfirm, "force", "f", false, translation.T("force-flag-description"))
	r.RequiredFlags = []string{
		"connection-id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running DeleteDataSourceConnection
func (r *DeleteDataSourceConnectionCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	if !r.utils.ConfirmDelete(r.ForceDeleteWithoutConfirm) {
		// confirm delete, exit otherwise
		return
	}

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.DeleteDataSourceConnectionOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "connection-id" {
			OptionsModel.SetConnectionID(r.ConnectionID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *DeleteDataSourceConnectionCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.DeleteDataSourceConnectionOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPDelete,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)
	r.utils.ProcessEmptyResponse(DetailedResponse, ResponseErr)
}

// RequestSender for PatchDataSourceConnection command
type PatchDataSourceConnectionRequestSender struct{}

func (s PatchDataSourceConnectionRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.PatchDataSourceConnection(optionsModel.(*backuprecoveryv1.PatchDataSourceConnectionOptions))
}

// Command Runner for PatchDataSourceConnection command
func NewPatchDataSourceConnectionCommandRunner(utils Utilities, sender RequestSender) *PatchDataSourceConnectionCommandRunner {
	return &PatchDataSourceConnectionCommandRunner{utils: utils, sender: sender}
}

type PatchDataSourceConnectionCommandRunner struct {
	ConnectionID   string
	XIBMTenantID   string
	ConnectionName string
	RequiredFlags  []string
	sender         RequestSender
	utils          Utilities
}

// Command mapping: data-source-connection patch, GetPatchDataSourceConnectionCommand
func GetPatchDataSourceConnectionCommand(r *PatchDataSourceConnectionCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "patch --connection-id CONNECTION-ID --xibm-tenant-id XIBM-TENANT-ID --connection-name CONNECTION-NAME",
		Short:                 translation.T("backup-recovery-data-source-connection-patch-command-short-description"),
		Long:                  translation.T("backup-recovery-data-source-connection-patch-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "data-source-connection",
			"x-cli-command":       "patch",
		},
		Example: `  ibmcloud backup-recovery data-source-connection patch \
    --connection-id connectionId \
    --xibm-tenant-id tenantId \
    --connection-name connectionName`,
	}

	cmd.Flags().StringVarP(&r.ConnectionID, "connection-id", "", "", translation.T("backup-recovery-data-source-connection-patch-connection-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-data-source-connection-patch-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.ConnectionName, "connection-name", "", "", translation.T("backup-recovery-data-source-connection-patch-connection-name-flag-description"))
	r.RequiredFlags = []string{
		"connection-id",
		"xibm-tenant-id",
		"connection-name",
	}

	return cmd
}

// Primary logic for running PatchDataSourceConnection
func (r *PatchDataSourceConnectionCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.PatchDataSourceConnectionOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "connection-id" {
			OptionsModel.SetConnectionID(r.ConnectionID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "connection-name" {
			OptionsModel.SetConnectionName(r.ConnectionName)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *PatchDataSourceConnectionCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.PatchDataSourceConnectionOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPUpdate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"connectionId",
		"connectionName",
		"connectorIds",
		"registrationToken",
		"tenantId",
		"upgradingConnectorId",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for GenerateDataSourceConnectionRegistrationToken command
type GenerateDataSourceConnectionRegistrationTokenRequestSender struct{}

func (s GenerateDataSourceConnectionRegistrationTokenRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GenerateDataSourceConnectionRegistrationToken(optionsModel.(*backuprecoveryv1.GenerateDataSourceConnectionRegistrationTokenOptions))
}

// Command Runner for GenerateDataSourceConnectionRegistrationToken command
func NewGenerateDataSourceConnectionRegistrationTokenCommandRunner(utils Utilities, sender RequestSender) *GenerateDataSourceConnectionRegistrationTokenCommandRunner {
	return &GenerateDataSourceConnectionRegistrationTokenCommandRunner{utils: utils, sender: sender}
}

type GenerateDataSourceConnectionRegistrationTokenCommandRunner struct {
	ConnectionID  string
	XIBMTenantID  string
	RequiredFlags []string
	sender        RequestSender
	utils         Utilities
}

// Command mapping: data-source-connection registration-token-generate, GetGenerateDataSourceConnectionRegistrationTokenCommand
func GetGenerateDataSourceConnectionRegistrationTokenCommand(r *GenerateDataSourceConnectionRegistrationTokenCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "registration-token-generate --connection-id CONNECTION-ID --xibm-tenant-id XIBM-TENANT-ID",
		Short:                 translation.T("backup-recovery-data-source-connection-registration-token-generate-command-short-description"),
		Long:                  translation.T("backup-recovery-data-source-connection-registration-token-generate-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "data-source-connection",
			"x-cli-command":       "registration-token-generate",
		},
		Example: `  ibmcloud backup-recovery data-source-connection registration-token-generate \
    --connection-id exampleString \
    --xibm-tenant-id tenantId`,
	}

	cmd.Flags().StringVarP(&r.ConnectionID, "connection-id", "", "", translation.T("backup-recovery-data-source-connection-registration-token-generate-connection-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-data-source-connection-registration-token-generate-xibm-tenant-id-flag-description"))
	r.RequiredFlags = []string{
		"connection-id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GenerateDataSourceConnectionRegistrationToken
func (r *GenerateDataSourceConnectionRegistrationTokenCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GenerateDataSourceConnectionRegistrationTokenOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "connection-id" {
			OptionsModel.SetConnectionID(r.ConnectionID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GenerateDataSourceConnectionRegistrationTokenCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GenerateDataSourceConnectionRegistrationTokenOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)
	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

func GetDataSourceConnectorGroup(utils Utilities) *cobra.Command {
	commands := []*cobra.Command{
		GetGetDataSourceConnectorsCommand(NewGetDataSourceConnectorsCommandRunner(utils, GetDataSourceConnectorsRequestSender{})),
		GetDeleteDataSourceConnectorCommand(NewDeleteDataSourceConnectorCommandRunner(utils, DeleteDataSourceConnectorRequestSender{})),
		GetPatchDataSourceConnectorCommand(NewPatchDataSourceConnectorCommandRunner(utils, PatchDataSourceConnectorRequestSender{})),
	}

	command := &cobra.Command{
		Use:                   "data-source-connector [action]",
		Short:                 translation.T("backup-recovery-data-source-connector-group-short-description"),
		Long:                  translation.T("backup-recovery-data-source-connector-group-long-description"),
		DisableFlagsInUseLine: true,
	}

	command.AddCommand(commands...)

	return command
}

// RequestSender for GetDataSourceConnectors command
type GetDataSourceConnectorsRequestSender struct{}

func (s GetDataSourceConnectorsRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetDataSourceConnectors(optionsModel.(*backuprecoveryv1.GetDataSourceConnectorsOptions))
}

// Command Runner for GetDataSourceConnectors command
func NewGetDataSourceConnectorsCommandRunner(utils Utilities, sender RequestSender) *GetDataSourceConnectorsCommandRunner {
	return &GetDataSourceConnectorsCommandRunner{utils: utils, sender: sender}
}

type GetDataSourceConnectorsCommandRunner struct {
	XIBMTenantID   string
	ConnectorIds   string
	ConnectorNames string
	ConnectionID   string
	RequiredFlags  []string
	sender         RequestSender
	utils          Utilities
}

// Command mapping: data-source-connector list, GetGetDataSourceConnectorsCommand
func GetGetDataSourceConnectorsCommand(r *GetDataSourceConnectorsCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "list --xibm-tenant-id XIBM-TENANT-ID [--connector-ids CONNECTOR-IDS] [--connector-names CONNECTOR-NAMES] [--connection-id CONNECTION-ID]",
		Short:                 translation.T("backup-recovery-data-source-connector-list-command-short-description"),
		Long:                  translation.T("backup-recovery-data-source-connector-list-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "data-source-connector",
			"x-cli-command":       "list",
		},
		Example: `  ibmcloud backup-recovery data-source-connector list \
    --xibm-tenant-id tenantId \
    --connector-ids connectorId1,connectorId2 \
    --connector-names connectionName1,connectionName2 \
    --connection-id exampleString`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-data-source-connector-list-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.ConnectorIds, "connector-ids", "", "", translation.T("backup-recovery-data-source-connector-list-connector-ids-flag-description"))
	cmd.Flags().StringVarP(&r.ConnectorNames, "connector-names", "", "", translation.T("backup-recovery-data-source-connector-list-connector-names-flag-description"))
	cmd.Flags().StringVarP(&r.ConnectionID, "connection-id", "", "", translation.T("backup-recovery-data-source-connector-list-connection-id-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetDataSourceConnectors
func (r *GetDataSourceConnectorsCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetDataSourceConnectorsOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "connector-ids" {
			var ConnectorIds []string
			err, msg := deserialize.List(r.ConnectorIds, "connector-ids", "JSON", &ConnectorIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetConnectorIds(ConnectorIds)
		}
		if flag.Name == "connector-names" {
			var ConnectorNames []string
			err, msg := deserialize.List(r.ConnectorNames, "connector-names", "JSON", &ConnectorNames)
			r.utils.HandleError(err, msg)
			OptionsModel.SetConnectorNames(ConnectorNames)
		}
		if flag.Name == "connection-id" {
			OptionsModel.SetConnectionID(r.ConnectionID)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetDataSourceConnectorsCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetDataSourceConnectorsOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"connectors",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for DeleteDataSourceConnector command
type DeleteDataSourceConnectorRequestSender struct{}

func (s DeleteDataSourceConnectorRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	res, err := ServiceInstance.DeleteDataSourceConnector(optionsModel.(*backuprecoveryv1.DeleteDataSourceConnectorOptions))
	// DeleteDataSourceConnector returns an empty response body
	return nil, res, err
}

// Command Runner for DeleteDataSourceConnector command
func NewDeleteDataSourceConnectorCommandRunner(utils Utilities, sender RequestSender) *DeleteDataSourceConnectorCommandRunner {
	return &DeleteDataSourceConnectorCommandRunner{utils: utils, sender: sender}
}

type DeleteDataSourceConnectorCommandRunner struct {
	ConnectorID               string
	XIBMTenantID              string
	ForceDeleteWithoutConfirm bool
	RequiredFlags             []string
	sender                    RequestSender
	utils                     Utilities
}

// Command mapping: data-source-connector delete, GetDeleteDataSourceConnectorCommand
func GetDeleteDataSourceConnectorCommand(r *DeleteDataSourceConnectorCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "delete --connector-id CONNECTOR-ID --xibm-tenant-id XIBM-TENANT-ID",
		Short:                 translation.T("backup-recovery-data-source-connector-delete-command-short-description"),
		Long:                  translation.T("backup-recovery-data-source-connector-delete-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "data-source-connector",
			"x-cli-command":       "delete",
		},
		Example: `  ibmcloud backup-recovery data-source-connector delete \
    --connector-id connectorId \
    --xibm-tenant-id tenantId`,
	}

	cmd.Flags().StringVarP(&r.ConnectorID, "connector-id", "", "", translation.T("backup-recovery-data-source-connector-delete-connector-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-data-source-connector-delete-xibm-tenant-id-flag-description"))
	cmd.Flags().BoolVarP(&r.ForceDeleteWithoutConfirm, "force", "f", false, translation.T("force-flag-description"))
	r.RequiredFlags = []string{
		"connector-id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running DeleteDataSourceConnector
func (r *DeleteDataSourceConnectorCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	if !r.utils.ConfirmDelete(r.ForceDeleteWithoutConfirm) {
		// confirm delete, exit otherwise
		return
	}

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.DeleteDataSourceConnectorOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "connector-id" {
			OptionsModel.SetConnectorID(r.ConnectorID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *DeleteDataSourceConnectorCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.DeleteDataSourceConnectorOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPDelete,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)
	r.utils.ProcessEmptyResponse(DetailedResponse, ResponseErr)
}

// RequestSender for PatchDataSourceConnector command
type PatchDataSourceConnectorRequestSender struct{}

func (s PatchDataSourceConnectorRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.PatchDataSourceConnector(optionsModel.(*backuprecoveryv1.PatchDataSourceConnectorOptions))
}

// Command Runner for PatchDataSourceConnector command
func NewPatchDataSourceConnectorCommandRunner(utils Utilities, sender RequestSender) *PatchDataSourceConnectorCommandRunner {
	return &PatchDataSourceConnectorCommandRunner{utils: utils, sender: sender}
}

type PatchDataSourceConnectorCommandRunner struct {
	ConnectorID   string
	XIBMTenantID  string
	ConnectorName string
	RequiredFlags []string
	sender        RequestSender
	utils         Utilities
}

// Command mapping: data-source-connector patch, GetPatchDataSourceConnectorCommand
func GetPatchDataSourceConnectorCommand(r *PatchDataSourceConnectorCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "patch --connector-id CONNECTOR-ID --xibm-tenant-id XIBM-TENANT-ID [--connector-name CONNECTOR-NAME]",
		Short:                 translation.T("backup-recovery-data-source-connector-patch-command-short-description"),
		Long:                  translation.T("backup-recovery-data-source-connector-patch-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command-group": "data-source-connector",
			"x-cli-command":       "patch",
		},
		Example: `  ibmcloud backup-recovery data-source-connector patch \
    --connector-id connectorID \
    --xibm-tenant-id tenantId \
    --connector-name connectorName`,
	}

	cmd.Flags().StringVarP(&r.ConnectorID, "connector-id", "", "", translation.T("backup-recovery-data-source-connector-patch-connector-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-data-source-connector-patch-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.ConnectorName, "connector-name", "", "", translation.T("backup-recovery-data-source-connector-patch-connector-name-flag-description"))
	r.RequiredFlags = []string{
		"connector-id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running PatchDataSourceConnector
func (r *PatchDataSourceConnectorCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.PatchDataSourceConnectorOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "connector-id" {
			OptionsModel.SetConnectorID(r.ConnectorID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "connector-name" {
			OptionsModel.SetConnectorName(r.ConnectorName)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *PatchDataSourceConnectorCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.PatchDataSourceConnectorOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPUpdate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"clusterSideIp",
		"connectionId",
		"connectorId",
		"connectorName",
		"connectivityStatus",
		"softwareVersion",
		"tenantSideIp",
		"upgradeStatus",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for DownloadAgent command
type DownloadAgentRequestSender struct{}

func (s DownloadAgentRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.DownloadAgent(optionsModel.(*backuprecoveryv1.DownloadAgentOptions))
}

// Command Runner for DownloadAgent command
func NewDownloadAgentCommandRunner(utils Utilities, sender RequestSender) *DownloadAgentCommandRunner {
	return &DownloadAgentCommandRunner{utils: utils, sender: sender}
}

type DownloadAgentCommandRunner struct {
	XIBMTenantID           string
	Platform               string
	LinuxParams            string
	LinuxParamsPackageType string
	OutputFilename         string
	RequiredFlags          []string
	sender                 RequestSender
	utils                  Utilities
}

// Command mapping: agent-download, GetDownloadAgentCommand
func GetDownloadAgentCommand(r *DownloadAgentCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "agent-download --xibm-tenant-id XIBM-TENANT-ID --platform PLATFORM [--linux-params (LINUX-PARAMS | @LINUX-PARAMS-FILE) | --linux-params-package-type LINUX-PARAMS-PACKAGE-TYPE]",
		Short:                 translation.T("backup-recovery-agent-download-command-short-description"),
		Long:                  translation.T("backup-recovery-agent-download-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command": "agent-download",
		},
		Example: `  ibmcloud backup-recovery agent-download \
    --xibm-tenant-id tenantId \
    --platform kWindows \
    --linux-params '{"packageType": "kScript"}' \
    --output-file tempdir/example-output.txt`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-agent-download-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Platform, "platform", "", "", translation.T("backup-recovery-agent-download-platform-flag-description"))
	cmd.Flags().StringVarP(&r.LinuxParams, "linux-params", "", "", translation.T("backup-recovery-agent-download-linux-params-flag-description"))
	cmd.Flags().StringVarP(&r.LinuxParamsPackageType, "linux-params-package-type", "", "", translation.T("backup-recovery-agent-download-linux-params-package-type-flag-description"))
	cmd.Flags().StringVarP(&r.OutputFilename, "output-file", "", "", translation.T("output-file-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
		"platform",
		"output-file",
	}

	return cmd
}

// Primary logic for running DownloadAgent
func (r *DownloadAgentCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.DownloadAgentOptions{}
	LinuxParamsHelper := &backuprecoveryv1.LinuxAgentParams{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "platform" {
			OptionsModel.SetPlatform(r.Platform)
		}
		if flag.Name == "linux-params" {
			var LinuxParams *backuprecoveryv1.LinuxAgentParams
			err, msg := deserialize.Model(
				r.LinuxParams,
				"linux-params",
				"LinuxAgentParams",
				backuprecoveryv1.UnmarshalLinuxAgentParams,
				&LinuxParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetLinuxParams(LinuxParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.LinuxParams, `{"fields":["packageType"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "linux-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "linux-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "linux-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "linux-params-package-type" {
			LinuxParamsHelper.PackageType = core.StringPtr(r.LinuxParamsPackageType)
		}
	})

	if !reflect.ValueOf(*LinuxParamsHelper).IsZero() {
		if OptionsModel.LinuxParams == nil {
			OptionsModel.SetLinuxParams(LinuxParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "LinuxParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}

	r.MakeRequest(OptionsModel)
}

func (r *DownloadAgentCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.DownloadAgentOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)
	r.utils.ProcessBinaryResponse(DetailedResponse, ResponseErr, r.OutputFilename)
}

// RequestSender for GetConnectorMetadata command
type GetConnectorMetadataRequestSender struct{}

func (s GetConnectorMetadataRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetConnectorMetadata(optionsModel.(*backuprecoveryv1.GetConnectorMetadataOptions))
}

// Command Runner for GetConnectorMetadata command
func NewGetConnectorMetadataCommandRunner(utils Utilities, sender RequestSender) *GetConnectorMetadataCommandRunner {
	return &GetConnectorMetadataCommandRunner{utils: utils, sender: sender}
}

type GetConnectorMetadataCommandRunner struct {
	XIBMTenantID  string
	RequiredFlags []string
	sender        RequestSender
	utils         Utilities
}

// Command mapping: connector-metadata-get, GetGetConnectorMetadataCommand
func GetGetConnectorMetadataCommand(r *GetConnectorMetadataCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "connector-metadata-get --xibm-tenant-id XIBM-TENANT-ID",
		Short:                 translation.T("backup-recovery-connector-metadata-get-command-short-description"),
		Long:                  translation.T("backup-recovery-connector-metadata-get-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command": "connector-metadata-get",
		},
		Example: `  ibmcloud backup-recovery connector-metadata-get \
    --xibm-tenant-id tenantId`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-connector-metadata-get-xibm-tenant-id-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetConnectorMetadata
func (r *GetConnectorMetadataCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetConnectorMetadataOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetConnectorMetadataCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetConnectorMetadataOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"connectorImageMetadata",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for GetObjectSnapshots command
type GetObjectSnapshotsRequestSender struct{}

func (s GetObjectSnapshotsRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetObjectSnapshots(optionsModel.(*backuprecoveryv1.GetObjectSnapshotsOptions))
}

// Command Runner for GetObjectSnapshots command
func NewGetObjectSnapshotsCommandRunner(utils Utilities, sender RequestSender) *GetObjectSnapshotsCommandRunner {
	return &GetObjectSnapshotsCommandRunner{utils: utils, sender: sender}
}

type GetObjectSnapshotsCommandRunner struct {
	ID                    int64
	XIBMTenantID          string
	FromTimeUsecs         int64
	ToTimeUsecs           int64
	RunStartFromTimeUsecs int64
	RunStartToTimeUsecs   int64
	SnapshotActions       string
	RunTypes              string
	ProtectionGroupIds    string
	RunInstanceIds        string
	RegionIds             string
	ObjectActionKeys      string
	RequiredFlags         []string
	sender                RequestSender
	utils                 Utilities
}

// Command mapping: object-snapshots-list, GetGetObjectSnapshotsCommand
func GetGetObjectSnapshotsCommand(r *GetObjectSnapshotsCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "object-snapshots-list --id ID --xibm-tenant-id XIBM-TENANT-ID [--from-time-usecs FROM-TIME-USECS] [--to-time-usecs TO-TIME-USECS] [--run-start-from-time-usecs RUN-START-FROM-TIME-USECS] [--run-start-to-time-usecs RUN-START-TO-TIME-USECS] [--snapshot-actions SNAPSHOT-ACTIONS] [--run-types RUN-TYPES] [--protection-group-ids PROTECTION-GROUP-IDS] [--run-instance-ids RUN-INSTANCE-IDS] [--region-ids REGION-IDS] [--object-action-keys OBJECT-ACTION-KEYS]",
		Short:                 translation.T("backup-recovery-object-snapshots-list-command-short-description"),
		Long:                  translation.T("backup-recovery-object-snapshots-list-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command": "object-snapshots-list",
		},
		Example: `  ibmcloud backup-recovery object-snapshots-list \
    --id 26 \
    --xibm-tenant-id tenantId \
    --from-time-usecs 26 \
    --to-time-usecs 26 \
    --run-start-from-time-usecs 26 \
    --run-start-to-time-usecs 26 \
    --snapshot-actions RecoverVMs,RecoverFiles,InstantVolumeMount,RecoverVmDisks,MountVolumes,RecoverVApps,RecoverRDS,RecoverAurora,RecoverS3Buckets,RecoverApps,RecoverNasVolume,RecoverPhysicalVolumes,RecoverSystem,RecoverSanVolumes,RecoverNamespaces,RecoverObjects,DownloadFilesAndFolders,RecoverPublicFolders,RecoverVAppTemplates,RecoverMailbox,RecoverOneDrive,RecoverMsTeam,RecoverMsGroup,RecoverSharePoint,ConvertToPst,RecoverSfdcRecords,RecoverAzureSQL,DownloadChats,RecoverRDSPostgres,RecoverMailboxCSM,RecoverOneDriveCSM,RecoverSharePointCSM \
    --run-types kRegular,kFull,kLog,kSystem,kHydrateCDP,kStorageArraySnapshot \
    --protection-group-ids protectionGroupId1 \
    --run-instance-ids 26,27 \
    --region-ids regionId1 \
    --object-action-keys kVMware,kHyperV,kVCD,kAzure,kGCP,kKVM,kAcropolis,kAWS,kAWSNative,kAwsS3,kAWSSnapshotManager,kRDSSnapshotManager,kAuroraSnapshotManager,kAwsRDSPostgresBackup,kAwsRDSPostgres,kAwsAuroraPostgres,kAzureNative,kAzureSQL,kAzureSnapshotManager,kPhysical,kPhysicalFiles,kGPFS,kElastifile,kNetapp,kGenericNas,kIsilon,kFlashBlade,kPure,kIbmFlashSystem,kSQL,kExchange,kAD,kOracle,kView,kRemoteAdapter,kO365,kO365PublicFolders,kO365Teams,kO365Group,kO365Exchange,kO365OneDrive,kO365Sharepoint,kKubernetes,kCassandra,kMongoDB,kCouchbase,kHdfs,kHive,kHBase,kSAPHANA,kUDA,kSfdc,kO365ExchangeCSM,kO365OneDriveCSM,kO365SharepointCSM`,
	}

	cmd.Flags().Int64VarP(&r.ID, "id", "", 0, translation.T("backup-recovery-object-snapshots-list-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-object-snapshots-list-xibm-tenant-id-flag-description"))
	cmd.Flags().Int64VarP(&r.FromTimeUsecs, "from-time-usecs", "", 0, translation.T("backup-recovery-object-snapshots-list-from-time-usecs-flag-description"))
	cmd.Flags().Int64VarP(&r.ToTimeUsecs, "to-time-usecs", "", 0, translation.T("backup-recovery-object-snapshots-list-to-time-usecs-flag-description"))
	cmd.Flags().Int64VarP(&r.RunStartFromTimeUsecs, "run-start-from-time-usecs", "", 0, translation.T("backup-recovery-object-snapshots-list-run-start-from-time-usecs-flag-description"))
	cmd.Flags().Int64VarP(&r.RunStartToTimeUsecs, "run-start-to-time-usecs", "", 0, translation.T("backup-recovery-object-snapshots-list-run-start-to-time-usecs-flag-description"))
	cmd.Flags().StringVarP(&r.SnapshotActions, "snapshot-actions", "", "", translation.T("backup-recovery-object-snapshots-list-snapshot-actions-flag-description"))
	cmd.Flags().StringVarP(&r.RunTypes, "run-types", "", "", translation.T("backup-recovery-object-snapshots-list-run-types-flag-description"))
	cmd.Flags().StringVarP(&r.ProtectionGroupIds, "protection-group-ids", "", "", translation.T("backup-recovery-object-snapshots-list-protection-group-ids-flag-description"))
	cmd.Flags().StringVarP(&r.RunInstanceIds, "run-instance-ids", "", "", translation.T("backup-recovery-object-snapshots-list-run-instance-ids-flag-description"))
	cmd.Flags().StringVarP(&r.RegionIds, "region-ids", "", "", translation.T("backup-recovery-object-snapshots-list-region-ids-flag-description"))
	cmd.Flags().StringVarP(&r.ObjectActionKeys, "object-action-keys", "", "", translation.T("backup-recovery-object-snapshots-list-object-action-keys-flag-description"))
	r.RequiredFlags = []string{
		"id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running GetObjectSnapshots
func (r *GetObjectSnapshotsCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetObjectSnapshotsOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "id" {
			OptionsModel.SetID(r.ID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "from-time-usecs" {
			OptionsModel.SetFromTimeUsecs(r.FromTimeUsecs)
		}
		if flag.Name == "to-time-usecs" {
			OptionsModel.SetToTimeUsecs(r.ToTimeUsecs)
		}
		if flag.Name == "run-start-from-time-usecs" {
			OptionsModel.SetRunStartFromTimeUsecs(r.RunStartFromTimeUsecs)
		}
		if flag.Name == "run-start-to-time-usecs" {
			OptionsModel.SetRunStartToTimeUsecs(r.RunStartToTimeUsecs)
		}
		if flag.Name == "snapshot-actions" {
			var SnapshotActions []string
			err, msg := deserialize.List(r.SnapshotActions, "snapshot-actions", "JSON", &SnapshotActions)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSnapshotActions(SnapshotActions)
		}
		if flag.Name == "run-types" {
			var RunTypes []string
			err, msg := deserialize.List(r.RunTypes, "run-types", "JSON", &RunTypes)
			r.utils.HandleError(err, msg)
			OptionsModel.SetRunTypes(RunTypes)
		}
		if flag.Name == "protection-group-ids" {
			var ProtectionGroupIds []string
			err, msg := deserialize.List(r.ProtectionGroupIds, "protection-group-ids", "JSON", &ProtectionGroupIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetProtectionGroupIds(ProtectionGroupIds)
		}
		if flag.Name == "run-instance-ids" {
			var RunInstanceIds []int64
			err, msg := deserialize.List(r.RunInstanceIds, "run-instance-ids", "JSON", &RunInstanceIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetRunInstanceIds(RunInstanceIds)
		}
		if flag.Name == "region-ids" {
			var RegionIds []string
			err, msg := deserialize.List(r.RegionIds, "region-ids", "JSON", &RegionIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetRegionIds(RegionIds)
		}
		if flag.Name == "object-action-keys" {
			var ObjectActionKeys []string
			err, msg := deserialize.List(r.ObjectActionKeys, "object-action-keys", "JSON", &ObjectActionKeys)
			r.utils.HandleError(err, msg)
			OptionsModel.SetObjectActionKeys(ObjectActionKeys)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetObjectSnapshotsCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetObjectSnapshotsOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"snapshots",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for CreateDownloadFilesAndFoldersRecovery command
type CreateDownloadFilesAndFoldersRecoveryRequestSender struct{}

func (s CreateDownloadFilesAndFoldersRecoveryRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.CreateDownloadFilesAndFoldersRecovery(optionsModel.(*backuprecoveryv1.CreateDownloadFilesAndFoldersRecoveryOptions))
}

// Command Runner for CreateDownloadFilesAndFoldersRecovery command
func NewCreateDownloadFilesAndFoldersRecoveryCommandRunner(utils Utilities, sender RequestSender) *CreateDownloadFilesAndFoldersRecoveryCommandRunner {
	return &CreateDownloadFilesAndFoldersRecoveryCommandRunner{utils: utils, sender: sender}
}

type CreateDownloadFilesAndFoldersRecoveryCommandRunner struct {
	XIBMTenantID              string
	Name                      string
	Object                    string
	FilesAndFolders           string
	Documents                 string
	ParentRecoveryID          string
	GlacierRetrievalType      string
	ObjectSnapshotID          string
	ObjectPointInTimeUsecs    int64
	ObjectProtectionGroupID   string
	ObjectProtectionGroupName string
	ObjectRecoverFromStandby  bool
	RequiredFlags             []string
	sender                    RequestSender
	utils                     Utilities
}

// Command mapping: download-recovery-create, GetCreateDownloadFilesAndFoldersRecoveryCommand
func GetCreateDownloadFilesAndFoldersRecoveryCommand(r *CreateDownloadFilesAndFoldersRecoveryCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "download-recovery-create --xibm-tenant-id XIBM-TENANT-ID --name NAME --files-and-folders FILES-AND-FOLDERS | @FILES-AND-FOLDERS-FILE [--object (OBJECT | @OBJECT-FILE) | --object-snapshot-id OBJECT-SNAPSHOT-ID --object-point-in-time-usecs OBJECT-POINT-IN-TIME-USECS --object-protection-group-id OBJECT-PROTECTION-GROUP-ID --object-protection-group-name OBJECT-PROTECTION-GROUP-NAME --object-recover-from-standby=OBJECT-RECOVER-FROM-STANDBY] [--documents DOCUMENTS | @DOCUMENTS-FILE] [--parent-recovery-id PARENT-RECOVERY-ID] [--glacier-retrieval-type GLACIER-RETRIEVAL-TYPE]",
		Short:                 translation.T("backup-recovery-download-recovery-create-command-short-description"),
		Long:                  translation.T("backup-recovery-download-recovery-create-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-description": "Creates a download files and folders recovery.",
			"x-cli-command":     "download-recovery-create",
		},
		Example: `  ibmcloud backup-recovery download-recovery-create \
    --xibm-tenant-id tenantId \
    --name create-download-files-and-folders-recovery \
    --object '{"snapshotId": "snapshotId", "pointInTimeUsecs": 26, "protectionGroupId": "protectionGroupId", "protectionGroupName": "protectionGroupName", "recoverFromStandby": true}' \
    --files-and-folders '[{"absolutePath": "~/home/dir1", "isDirectory": true}]' \
    --documents '[{"isDirectory": true, "itemId": "item1"}]' \
    --parent-recovery-id parentRecoveryId \
    --glacier-retrieval-type kStandard`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-download-recovery-create-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.Name, "name", "", "", translation.T("backup-recovery-download-recovery-create-name-flag-description"))
	cmd.Flags().StringVarP(&r.Object, "object", "", "", translation.T("backup-recovery-download-recovery-create-object-flag-description"))
	cmd.Flags().StringVarP(&r.FilesAndFolders, "files-and-folders", "", "", translation.T("backup-recovery-download-recovery-create-files-and-folders-flag-description"))
	cmd.Flags().StringVarP(&r.Documents, "documents", "", "", translation.T("backup-recovery-download-recovery-create-documents-flag-description"))
	cmd.Flags().StringVarP(&r.ParentRecoveryID, "parent-recovery-id", "", "", translation.T("backup-recovery-download-recovery-create-parent-recovery-id-flag-description"))
	cmd.Flags().StringVarP(&r.GlacierRetrievalType, "glacier-retrieval-type", "", "", translation.T("backup-recovery-download-recovery-create-glacier-retrieval-type-flag-description"))
	cmd.Flags().StringVarP(&r.ObjectSnapshotID, "object-snapshot-id", "", "", translation.T("backup-recovery-download-recovery-create-object-snapshot-id-flag-description"))
	cmd.Flags().Int64VarP(&r.ObjectPointInTimeUsecs, "object-point-in-time-usecs", "", 0, translation.T("backup-recovery-download-recovery-create-object-point-in-time-usecs-flag-description"))
	cmd.Flags().StringVarP(&r.ObjectProtectionGroupID, "object-protection-group-id", "", "", translation.T("backup-recovery-download-recovery-create-object-protection-group-id-flag-description"))
	cmd.Flags().StringVarP(&r.ObjectProtectionGroupName, "object-protection-group-name", "", "", translation.T("backup-recovery-download-recovery-create-object-protection-group-name-flag-description"))
	cmd.Flags().BoolVarP(&r.ObjectRecoverFromStandby, "object-recover-from-standby", "", false, translation.T("backup-recovery-download-recovery-create-object-recover-from-standby-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
		"name",
		"files-and-folders",
	}

	return cmd
}

// Primary logic for running CreateDownloadFilesAndFoldersRecovery
func (r *CreateDownloadFilesAndFoldersRecoveryCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.CreateDownloadFilesAndFoldersRecoveryOptions{}
	ObjectHelper := &backuprecoveryv1.CommonRecoverObjectSnapshotParams{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "name" {
			OptionsModel.SetName(r.Name)
		}
		if flag.Name == "object" {
			var Object *backuprecoveryv1.CommonRecoverObjectSnapshotParams
			err, msg := deserialize.Model(
				r.Object,
				"object",
				"CommonRecoverObjectSnapshotParams",
				backuprecoveryv1.UnmarshalCommonRecoverObjectSnapshotParams,
				&Object,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetObject(Object)
			extraFieldPaths, err := r.utils.ValidateJSON(r.Object, `{"fields":["protectionGroupId","snapshotId","pointInTimeUsecs","protectionGroupName","recoverFromStandby"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "object",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "object",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "object",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "files-and-folders" {
			var FilesAndFolders []backuprecoveryv1.FilesAndFoldersObject
			err, msg := deserialize.ModelSlice(
				r.FilesAndFolders,
				"files-and-folders",
				"FilesAndFoldersObject",
				backuprecoveryv1.UnmarshalFilesAndFoldersObject,
				&FilesAndFolders,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetFilesAndFolders(FilesAndFolders)
			extraFieldPaths, err := r.utils.ValidateJSON(r.FilesAndFolders, `{"fields":["absolutePath","isDirectory"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "files-and-folders",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "files-and-folders",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "files-and-folders",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "documents" {
			var Documents []backuprecoveryv1.DocumentObject
			err, msg := deserialize.ModelSlice(
				r.Documents,
				"documents",
				"DocumentObject",
				backuprecoveryv1.UnmarshalDocumentObject,
				&Documents,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetDocuments(Documents)
			extraFieldPaths, err := r.utils.ValidateJSON(r.Documents, `{"fields":["itemId","isDirectory"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "documents",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "documents",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "documents",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "parent-recovery-id" {
			OptionsModel.SetParentRecoveryID(r.ParentRecoveryID)
		}
		if flag.Name == "glacier-retrieval-type" {
			OptionsModel.SetGlacierRetrievalType(r.GlacierRetrievalType)
		}
		if flag.Name == "object-snapshot-id" {
			ObjectHelper.SnapshotID = core.StringPtr(r.ObjectSnapshotID)
		}
		if flag.Name == "object-point-in-time-usecs" {
			ObjectHelper.PointInTimeUsecs = core.Int64Ptr(r.ObjectPointInTimeUsecs)
		}
		if flag.Name == "object-protection-group-id" {
			ObjectHelper.ProtectionGroupID = core.StringPtr(r.ObjectProtectionGroupID)
		}
		if flag.Name == "object-protection-group-name" {
			ObjectHelper.ProtectionGroupName = core.StringPtr(r.ObjectProtectionGroupName)
		}
		if flag.Name == "object-recover-from-standby" {
			ObjectHelper.RecoverFromStandby = core.BoolPtr(r.ObjectRecoverFromStandby)
		}
	})

	if !reflect.ValueOf(*ObjectHelper).IsZero() {
		if OptionsModel.Object == nil {
			OptionsModel.SetObject(ObjectHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "Object",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}

	r.MakeRequest(OptionsModel)
}

func (r *CreateDownloadFilesAndFoldersRecoveryCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.CreateDownloadFilesAndFoldersRecoveryOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"id",
		"name",
		"startTimeUsecs",
		"endTimeUsecs",
		"status",
		"progressTaskId",
		"snapshotEnvironment",
		"recoveryAction",
		"permissions",
		"creationInfo",
		"canTearDown",
		"tearDownStatus",
		"tearDownMessage",
		"messages",
		"isParentRecovery",
		"parentRecoveryId",
		"retrieveArchiveTasks",
		"isMultiStageRestore",
		"physicalParams",
		"mssqlParams",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for GetRestorePointsInTimeRange command
type GetRestorePointsInTimeRangeRequestSender struct{}

func (s GetRestorePointsInTimeRangeRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.GetRestorePointsInTimeRange(optionsModel.(*backuprecoveryv1.GetRestorePointsInTimeRangeOptions))
}

// Command Runner for GetRestorePointsInTimeRange command
func NewGetRestorePointsInTimeRangeCommandRunner(utils Utilities, sender RequestSender) *GetRestorePointsInTimeRangeCommandRunner {
	return &GetRestorePointsInTimeRangeCommandRunner{utils: utils, sender: sender}
}

type GetRestorePointsInTimeRangeCommandRunner struct {
	XIBMTenantID       string
	EndTimeUsecs       int64
	Environment        string
	ProtectionGroupIds string
	StartTimeUsecs     int64
	SourceID           int64
	RequiredFlags      []string
	sender             RequestSender
	utils              Utilities
}

// Command mapping: restore-points, GetGetRestorePointsInTimeRangeCommand
func GetGetRestorePointsInTimeRangeCommand(r *GetRestorePointsInTimeRangeCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "restore-points --xibm-tenant-id XIBM-TENANT-ID --end-time-usecs END-TIME-USECS --environment ENVIRONMENT --protection-group-ids PROTECTION-GROUP-IDS --start-time-usecs START-TIME-USECS [--source-id SOURCE-ID]",
		Short:                 translation.T("backup-recovery-restore-points-command-short-description"),
		Long:                  translation.T("backup-recovery-restore-points-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command": "restore-points",
		},
		Example: `  ibmcloud backup-recovery restore-points \
    --xibm-tenant-id tenantId \
    --end-time-usecs 45 \
    --environment kVMware \
    --protection-group-ids protectionGroupId1 \
    --start-time-usecs 15 \
    --source-id 26`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-restore-points-xibm-tenant-id-flag-description"))
	cmd.Flags().Int64VarP(&r.EndTimeUsecs, "end-time-usecs", "", 0, translation.T("backup-recovery-restore-points-end-time-usecs-flag-description"))
	cmd.Flags().StringVarP(&r.Environment, "environment", "", "", translation.T("backup-recovery-restore-points-environment-flag-description"))
	cmd.Flags().StringVarP(&r.ProtectionGroupIds, "protection-group-ids", "", "", translation.T("backup-recovery-restore-points-protection-group-ids-flag-description"))
	cmd.Flags().Int64VarP(&r.StartTimeUsecs, "start-time-usecs", "", 0, translation.T("backup-recovery-restore-points-start-time-usecs-flag-description"))
	cmd.Flags().Int64VarP(&r.SourceID, "source-id", "", 0, translation.T("backup-recovery-restore-points-source-id-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
		"end-time-usecs",
		"environment",
		"protection-group-ids",
		"start-time-usecs",
	}

	return cmd
}

// Primary logic for running GetRestorePointsInTimeRange
func (r *GetRestorePointsInTimeRangeCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.GetRestorePointsInTimeRangeOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "end-time-usecs" {
			OptionsModel.SetEndTimeUsecs(r.EndTimeUsecs)
		}
		if flag.Name == "environment" {
			OptionsModel.SetEnvironment(r.Environment)
		}
		if flag.Name == "protection-group-ids" {
			var ProtectionGroupIds []string
			err, msg := deserialize.List(r.ProtectionGroupIds, "protection-group-ids", "JSON", &ProtectionGroupIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetProtectionGroupIds(ProtectionGroupIds)
		}
		if flag.Name == "start-time-usecs" {
			OptionsModel.SetStartTimeUsecs(r.StartTimeUsecs)
		}
		if flag.Name == "source-id" {
			OptionsModel.SetSourceID(r.SourceID)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *GetRestorePointsInTimeRangeCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.GetRestorePointsInTimeRangeOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"fullSnapshotInfo",
		"timeRangeInfo",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for DownloadIndexedFile command
type DownloadIndexedFileRequestSender struct{}

func (s DownloadIndexedFileRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	res, err := ServiceInstance.DownloadIndexedFile(optionsModel.(*backuprecoveryv1.DownloadIndexedFileOptions))
	// DownloadIndexedFile returns an empty response body
	return nil, res, err
}

// Command Runner for DownloadIndexedFile command
func NewDownloadIndexedFileCommandRunner(utils Utilities, sender RequestSender) *DownloadIndexedFileCommandRunner {
	return &DownloadIndexedFileCommandRunner{utils: utils, sender: sender}
}

type DownloadIndexedFileCommandRunner struct {
	SnapshotsID   string
	XIBMTenantID  string
	FilePath      string
	NvramFile     bool
	RetryAttempt  int64
	StartOffset   int64
	Length        int64
	RequiredFlags []string
	sender        RequestSender
	utils         Utilities
}

// Command mapping: indexed-file-download, GetDownloadIndexedFileCommand
func GetDownloadIndexedFileCommand(r *DownloadIndexedFileCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "indexed-file-download --snapshots-id SNAPSHOTS-ID --xibm-tenant-id XIBM-TENANT-ID [--file-path FILE-PATH] [--nvram-file=NVRAM-FILE] [--retry-attempt RETRY-ATTEMPT] [--start-offset START-OFFSET] [--length LENGTH]",
		Short:                 translation.T("backup-recovery-indexed-file-download-command-short-description"),
		Long:                  translation.T("backup-recovery-indexed-file-download-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command": "indexed-file-download",
		},
		Example: `  ibmcloud backup-recovery indexed-file-download \
    --snapshots-id snapshotId1 \
    --xibm-tenant-id tenantId \
    --file-path ~/home/downloadFile \
    --nvram-file=true \
    --retry-attempt 26 \
    --start-offset 26 \
    --length 26`,
	}

	cmd.Flags().StringVarP(&r.SnapshotsID, "snapshots-id", "", "", translation.T("backup-recovery-indexed-file-download-snapshots-id-flag-description"))
	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-indexed-file-download-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.FilePath, "file-path", "", "", translation.T("backup-recovery-indexed-file-download-file-path-flag-description"))
	cmd.Flags().BoolVarP(&r.NvramFile, "nvram-file", "", false, translation.T("backup-recovery-indexed-file-download-nvram-file-flag-description"))
	cmd.Flags().Int64VarP(&r.RetryAttempt, "retry-attempt", "", 0, translation.T("backup-recovery-indexed-file-download-retry-attempt-flag-description"))
	cmd.Flags().Int64VarP(&r.StartOffset, "start-offset", "", 0, translation.T("backup-recovery-indexed-file-download-start-offset-flag-description"))
	cmd.Flags().Int64VarP(&r.Length, "length", "", 0, translation.T("backup-recovery-indexed-file-download-length-flag-description"))
	r.RequiredFlags = []string{
		"snapshots-id",
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running DownloadIndexedFile
func (r *DownloadIndexedFileCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.DownloadIndexedFileOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "snapshots-id" {
			OptionsModel.SetSnapshotsID(r.SnapshotsID)
		}
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "file-path" {
			OptionsModel.SetFilePath(r.FilePath)
		}
		if flag.Name == "nvram-file" {
			OptionsModel.SetNvramFile(r.NvramFile)
		}
		if flag.Name == "retry-attempt" {
			OptionsModel.SetRetryAttempt(r.RetryAttempt)
		}
		if flag.Name == "start-offset" {
			OptionsModel.SetStartOffset(r.StartOffset)
		}
		if flag.Name == "length" {
			OptionsModel.SetLength(r.Length)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *DownloadIndexedFileCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.DownloadIndexedFileOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)
	r.utils.ProcessEmptyResponse(DetailedResponse, ResponseErr)
}

// RequestSender for SearchIndexedObjects command
type SearchIndexedObjectsRequestSender struct{}

func (s SearchIndexedObjectsRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.SearchIndexedObjects(optionsModel.(*backuprecoveryv1.SearchIndexedObjectsOptions))
}

// Command Runner for SearchIndexedObjects command
func NewSearchIndexedObjectsCommandRunner(utils Utilities, sender RequestSender) *SearchIndexedObjectsCommandRunner {
	return &SearchIndexedObjectsCommandRunner{utils: utils, sender: sender}
}

type SearchIndexedObjectsCommandRunner struct {
	XIBMTenantID                            string
	ObjectType                              string
	ProtectionGroupIds                      string
	StorageDomainIds                        string
	TenantID                                string
	IncludeTenants                          bool
	Tags                                    string
	SnapshotTags                            string
	MustHaveTagIds                          string
	MightHaveTagIds                         string
	MustHaveSnapshotTagIds                  string
	MightHaveSnapshotTagIds                 string
	PaginationCookie                        string
	Count                                   int64
	UseCachedData                           bool
	CassandraParams                         string
	CouchbaseParams                         string
	EmailParams                             string
	ExchangeParams                          string
	FileParams                              string
	HbaseParams                             string
	HdfsParams                              string
	HiveParams                              string
	MongodbParams                           string
	MsGroupsParams                          string
	MsTeamsParams                           string
	OneDriveParams                          string
	PublicFolderParams                      string
	SfdcParams                              string
	SharepointParams                        string
	UdaParams                               string
	CassandraParamsCassandraObjectTypes     string
	CassandraParamsSearchString             string
	CassandraParamsSourceIds                string
	CouchbaseParamsCouchbaseObjectTypes     string
	CouchbaseParamsSearchString             string
	CouchbaseParamsSourceIds                string
	EmailParamsAttendeesAddresses           string
	EmailParamsBccRecipientAddresses        string
	EmailParamsCcRecipientAddresses         string
	EmailParamsCreatedEndTimeSecs           int64
	EmailParamsCreatedStartTimeSecs         int64
	EmailParamsDueDateEndTimeSecs           int64
	EmailParamsDueDateStartTimeSecs         int64
	EmailParamsEmailAddress                 string
	EmailParamsEmailSubject                 string
	EmailParamsFirstName                    string
	EmailParamsFolderNames                  string
	EmailParamsHasAttachment                bool
	EmailParamsLastModifiedEndTimeSecs      int64
	EmailParamsLastModifiedStartTimeSecs    int64
	EmailParamsLastName                     string
	EmailParamsMiddleName                   string
	EmailParamsOrganizerAddress             string
	EmailParamsReceivedEndTimeSecs          int64
	EmailParamsReceivedStartTimeSecs        int64
	EmailParamsRecipientAddresses           string
	EmailParamsSenderAddress                string
	EmailParamsSourceEnvironment            string
	EmailParamsTaskStatusTypes              string
	EmailParamsTypes                        string
	EmailParamsO365Params                   string
	ExchangeParamsSearchString              string
	FileParamsSearchString                  string
	FileParamsTypes                         string
	FileParamsSourceEnvironments            string
	FileParamsSourceIds                     string
	FileParamsObjectIds                     string
	HbaseParamsHbaseObjectTypes             string
	HbaseParamsSearchString                 string
	HbaseParamsSourceIds                    string
	HdfsParamsHdfsTypes                     string
	HdfsParamsSearchString                  string
	HdfsParamsSourceIds                     string
	HiveParamsHiveObjectTypes               string
	HiveParamsSearchString                  string
	HiveParamsSourceIds                     string
	MongodbParamsMongoDBObjectTypes         string
	MongodbParamsSearchString               string
	MongodbParamsSourceIds                  string
	MsGroupsParamsMailboxParams             string
	MsGroupsParamsO365Params                string
	MsGroupsParamsSiteParams                string
	MsTeamsParamsCategoryTypes              string
	MsTeamsParamsChannelNames               string
	MsTeamsParamsChannelParams              string
	MsTeamsParamsCreationEndTimeSecs        int64
	MsTeamsParamsCreationStartTimeSecs      int64
	MsTeamsParamsO365Params                 string
	MsTeamsParamsOwnerNames                 string
	MsTeamsParamsSearchString               string
	MsTeamsParamsSizeBytesLowerLimit        int64
	MsTeamsParamsSizeBytesUpperLimit        int64
	MsTeamsParamsTypes                      string
	OneDriveParamsCategoryTypes             string
	OneDriveParamsCreationEndTimeSecs       int64
	OneDriveParamsCreationStartTimeSecs     int64
	OneDriveParamsIncludeFiles              bool
	OneDriveParamsIncludeFolders            bool
	OneDriveParamsO365Params                string
	OneDriveParamsOwnerNames                string
	OneDriveParamsSearchString              string
	OneDriveParamsSizeBytesLowerLimit       int64
	OneDriveParamsSizeBytesUpperLimit       int64
	PublicFolderParamsSearchString          string
	PublicFolderParamsTypes                 string
	PublicFolderParamsHasAttachment         bool
	PublicFolderParamsSenderAddress         string
	PublicFolderParamsRecipientAddresses    string
	PublicFolderParamsCcRecipientAddresses  string
	PublicFolderParamsBccRecipientAddresses string
	PublicFolderParamsReceivedStartTimeSecs int64
	PublicFolderParamsReceivedEndTimeSecs   int64
	SfdcParamsMutationTypes                 string
	SfdcParamsObjectName                    string
	SfdcParamsQueryString                   string
	SfdcParamsSnapshotID                    string
	SharepointParamsCategoryTypes           string
	SharepointParamsCreationEndTimeSecs     int64
	SharepointParamsCreationStartTimeSecs   int64
	SharepointParamsIncludeFiles            bool
	SharepointParamsIncludeFolders          bool
	SharepointParamsO365Params              string
	SharepointParamsOwnerNames              string
	SharepointParamsSearchString            string
	SharepointParamsSizeBytesLowerLimit     int64
	SharepointParamsSizeBytesUpperLimit     int64
	UdaParamsSearchString                   string
	UdaParamsSourceIds                      string
	RequiredFlags                           []string
	sender                                  RequestSender
	utils                                   Utilities
}

// Command mapping: indexed-objects-search, GetSearchIndexedObjectsCommand
func GetSearchIndexedObjectsCommand(r *SearchIndexedObjectsCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "indexed-objects-search [command options]",
		Short:                 translation.T("backup-recovery-indexed-objects-search-command-short-description"),
		Long:                  translation.T("backup-recovery-indexed-objects-search-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command": "indexed-objects-search",
		},
		Example: `  ibmcloud backup-recovery indexed-objects-search \
    --xibm-tenant-id tenantId \
    --object-type Emails \
    --protection-group-ids protectionGroupId1 \
    --storage-domain-ids 26,27 \
    --tenant-id tenantId \
    --include-tenants=false \
    --tags 123:456:ABC-123,123:456:ABC-456 \
    --snapshot-tags 123:456:DEF-123,123:456:DEF-456 \
    --must-have-tag-ids 123:456:ABC-123 \
    --might-have-tag-ids 123:456:ABC-456 \
    --must-have-snapshot-tag-ids 123:456:DEF-123 \
    --might-have-snapshot-tag-ids 123:456:DEF-456 \
    --pagination-cookie paginationCookie \
    --count 38 \
    --use-cached-data=true \
    --cassandra-params '{"cassandraObjectTypes": ["CassandraKeyspaces","CassandraTables"], "searchString": "searchString", "sourceIds": [26,27]}' \
    --couchbase-params '{"couchbaseObjectTypes": ["CouchbaseBuckets"], "searchString": "searchString", "sourceIds": [26,27]}' \
    --email-params '{"attendeesAddresses": ["attendee1@domain.com"], "bccRecipientAddresses": ["bccrecipient@domain.com"], "ccRecipientAddresses": ["ccrecipient@domain.com"], "createdEndTimeSecs": 26, "createdStartTimeSecs": 26, "dueDateEndTimeSecs": 26, "dueDateStartTimeSecs": 26, "emailAddress": "email@domain.com", "emailSubject": "Email Subject", "firstName": "First Name", "folderNames": ["folder1"], "hasAttachment": true, "lastModifiedEndTimeSecs": 26, "lastModifiedStartTimeSecs": 26, "lastName": "Last Name", "middleName": "Middle Name", "organizerAddress": "organizer@domain.com", "receivedEndTimeSecs": 26, "receivedStartTimeSecs": 26, "recipientAddresses": ["recipient@domain.com"], "senderAddress": "sender@domain.com", "sourceEnvironment": "kO365", "taskStatusTypes": ["NotStarted","InProgress","Completed","WaitingOnOthers","Deferred"], "types": ["Email","Folder","Calendar","Contact","Task","Note"], "o365Params": {"domainIds": [26,27], "mailboxIds": [26,27]}}' \
    --exchange-params '{"searchString": "searchString"}' \
    --file-params '{"searchString": "searchString", "types": ["File","Directory","Symlink"], "sourceEnvironments": ["kVMware","kHyperV","kSQL","kView","kRemoteAdapter","kPhysical","kPhysicalFiles","kPure","kIbmFlashSystem","kAzure","kNetapp","kGenericNas","kAcropolis","kIsilon","kGPFS","kKVM","kAWS","kExchange","kOracle","kGCP","kFlashBlade","kO365","kHyperFlex","kKubernetes","kElastifile","kSAPHANA","kUDA","kSfdc"], "sourceIds": [26,27], "objectIds": [26,27]}' \
    --hbase-params '{"hbaseObjectTypes": ["HbaseNamespaces","HbaseTables"], "searchString": "searchString", "sourceIds": [26,27]}' \
    --hdfs-params '{"hdfsTypes": ["HDFSFolders","HDFSFiles"], "searchString": "searchString", "sourceIds": [26,27]}' \
    --hive-params '{"hiveObjectTypes": ["HiveDatabases","HiveTables","HivePartitions"], "searchString": "searchString", "sourceIds": [26,27]}' \
    --mongodb-params '{"mongoDBObjectTypes": ["MongoDatabases","MongoCollections"], "searchString": "searchString", "sourceIds": [26,27]}' \
    --ms-groups-params '{"mailboxParams": {"attendeesAddresses": ["attendee1@domain.com"], "bccRecipientAddresses": ["bccrecipient@domain.com"], "ccRecipientAddresses": ["ccrecipient@domain.com"], "createdEndTimeSecs": 26, "createdStartTimeSecs": 26, "dueDateEndTimeSecs": 26, "dueDateStartTimeSecs": 26, "emailAddress": "email@domain.com", "emailSubject": "Email Subject", "firstName": "First Name", "folderNames": ["folder1"], "hasAttachment": true, "lastModifiedEndTimeSecs": 26, "lastModifiedStartTimeSecs": 26, "lastName": "Last Name", "middleName": "Middle Name", "organizerAddress": "organizer@domain.com", "receivedEndTimeSecs": 26, "receivedStartTimeSecs": 26, "recipientAddresses": ["recipient@domain.com"], "senderAddress": "sender@domain.com", "sourceEnvironment": "kO365", "taskStatusTypes": ["NotStarted","InProgress","Completed","WaitingOnOthers","Deferred"], "types": ["Email","Folder","Calendar","Contact","Task","Note"]}, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "siteParams": {"categoryTypes": ["Document","Excel","Powerpoint","Image","OneNote"], "creationEndTimeSecs": 26, "creationStartTimeSecs": 26, "includeFiles": true, "includeFolders": true, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "ownerNames": ["ownerName1"], "searchString": "searchString", "sizeBytesLowerLimit": 26, "sizeBytesUpperLimit": 26}}' \
    --ms-teams-params '{"categoryTypes": ["Document","Excel","Powerpoint","Image","OneNote"], "channelNames": ["channelName1"], "channelParams": {"channelEmail": "channel@domain.com", "channelId": "channelId", "channelName": "channelName", "includePrivateChannels": true, "includePublicChannels": true}, "creationEndTimeSecs": 26, "creationStartTimeSecs": 26, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "ownerNames": ["ownerName1"], "searchString": "searchString", "sizeBytesLowerLimit": 26, "sizeBytesUpperLimit": 26, "types": ["Channel","Chat","Conversation","File","Folder"]}' \
    --one-drive-params '{"categoryTypes": ["Document","Excel","Powerpoint","Image","OneNote"], "creationEndTimeSecs": 26, "creationStartTimeSecs": 26, "includeFiles": true, "includeFolders": true, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "ownerNames": ["ownerName1"], "searchString": "searchString", "sizeBytesLowerLimit": 26, "sizeBytesUpperLimit": 26}' \
    --public-folder-params '{"searchString": "searchString", "types": ["Calendar","Contact","Post","Folder","Task","Journal","Note"], "hasAttachment": true, "senderAddress": "sender@domain.com", "recipientAddresses": ["recipient@domain.com"], "ccRecipientAddresses": ["ccrecipient@domain.com"], "bccRecipientAddresses": ["bccrecipient@domain.com"], "receivedStartTimeSecs": 26, "receivedEndTimeSecs": 26}' \
    --sfdc-params '{"mutationTypes": ["All","Added","Removed","Changed"], "objectName": "objectName", "queryString": "queryString", "snapshotId": "snapshotId"}' \
    --sharepoint-params '{"categoryTypes": ["Document","Excel","Powerpoint","Image","OneNote"], "creationEndTimeSecs": 26, "creationStartTimeSecs": 26, "includeFiles": true, "includeFolders": true, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "ownerNames": ["ownerName1"], "searchString": "searchString", "sizeBytesLowerLimit": 26, "sizeBytesUpperLimit": 26}' \
    --uda-params '{"searchString": "searchString", "sourceIds": [26,27]}'`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-indexed-objects-search-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.ObjectType, "object-type", "", "", translation.T("backup-recovery-indexed-objects-search-object-type-flag-description"))
	cmd.Flags().StringVarP(&r.ProtectionGroupIds, "protection-group-ids", "", "", translation.T("backup-recovery-indexed-objects-search-protection-group-ids-flag-description"))
	cmd.Flags().StringVarP(&r.StorageDomainIds, "storage-domain-ids", "", "", translation.T("backup-recovery-indexed-objects-search-storage-domain-ids-flag-description"))
	cmd.Flags().StringVarP(&r.TenantID, "tenant-id", "", "", translation.T("backup-recovery-indexed-objects-search-tenant-id-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeTenants, "include-tenants", "", false, translation.T("backup-recovery-indexed-objects-search-include-tenants-flag-description"))
	cmd.Flags().StringVarP(&r.Tags, "tags", "", "", translation.T("backup-recovery-indexed-objects-search-tags-flag-description"))
	cmd.Flags().StringVarP(&r.SnapshotTags, "snapshot-tags", "", "", translation.T("backup-recovery-indexed-objects-search-snapshot-tags-flag-description"))
	cmd.Flags().StringVarP(&r.MustHaveTagIds, "must-have-tag-ids", "", "", translation.T("backup-recovery-indexed-objects-search-must-have-tag-ids-flag-description"))
	cmd.Flags().StringVarP(&r.MightHaveTagIds, "might-have-tag-ids", "", "", translation.T("backup-recovery-indexed-objects-search-might-have-tag-ids-flag-description"))
	cmd.Flags().StringVarP(&r.MustHaveSnapshotTagIds, "must-have-snapshot-tag-ids", "", "", translation.T("backup-recovery-indexed-objects-search-must-have-snapshot-tag-ids-flag-description"))
	cmd.Flags().StringVarP(&r.MightHaveSnapshotTagIds, "might-have-snapshot-tag-ids", "", "", translation.T("backup-recovery-indexed-objects-search-might-have-snapshot-tag-ids-flag-description"))
	cmd.Flags().StringVarP(&r.PaginationCookie, "pagination-cookie", "", "", translation.T("backup-recovery-indexed-objects-search-pagination-cookie-flag-description"))
	cmd.Flags().Int64VarP(&r.Count, "count", "", 0, translation.T("backup-recovery-indexed-objects-search-count-flag-description"))
	cmd.Flags().BoolVarP(&r.UseCachedData, "use-cached-data", "", false, translation.T("backup-recovery-indexed-objects-search-use-cached-data-flag-description"))
	cmd.Flags().StringVarP(&r.CassandraParams, "cassandra-params", "", "", translation.T("backup-recovery-indexed-objects-search-cassandra-params-flag-description"))
	cmd.Flags().StringVarP(&r.CouchbaseParams, "couchbase-params", "", "", translation.T("backup-recovery-indexed-objects-search-couchbase-params-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParams, "email-params", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-flag-description"))
	cmd.Flags().StringVarP(&r.ExchangeParams, "exchange-params", "", "", translation.T("backup-recovery-indexed-objects-search-exchange-params-flag-description"))
	cmd.Flags().StringVarP(&r.FileParams, "file-params", "", "", translation.T("backup-recovery-indexed-objects-search-file-params-flag-description"))
	cmd.Flags().StringVarP(&r.HbaseParams, "hbase-params", "", "", translation.T("backup-recovery-indexed-objects-search-hbase-params-flag-description"))
	cmd.Flags().StringVarP(&r.HdfsParams, "hdfs-params", "", "", translation.T("backup-recovery-indexed-objects-search-hdfs-params-flag-description"))
	cmd.Flags().StringVarP(&r.HiveParams, "hive-params", "", "", translation.T("backup-recovery-indexed-objects-search-hive-params-flag-description"))
	cmd.Flags().StringVarP(&r.MongodbParams, "mongodb-params", "", "", translation.T("backup-recovery-indexed-objects-search-mongodb-params-flag-description"))
	cmd.Flags().StringVarP(&r.MsGroupsParams, "ms-groups-params", "", "", translation.T("backup-recovery-indexed-objects-search-ms-groups-params-flag-description"))
	cmd.Flags().StringVarP(&r.MsTeamsParams, "ms-teams-params", "", "", translation.T("backup-recovery-indexed-objects-search-ms-teams-params-flag-description"))
	cmd.Flags().StringVarP(&r.OneDriveParams, "one-drive-params", "", "", translation.T("backup-recovery-indexed-objects-search-one-drive-params-flag-description"))
	cmd.Flags().StringVarP(&r.PublicFolderParams, "public-folder-params", "", "", translation.T("backup-recovery-indexed-objects-search-public-folder-params-flag-description"))
	cmd.Flags().StringVarP(&r.SfdcParams, "sfdc-params", "", "", translation.T("backup-recovery-indexed-objects-search-sfdc-params-flag-description"))
	cmd.Flags().StringVarP(&r.SharepointParams, "sharepoint-params", "", "", translation.T("backup-recovery-indexed-objects-search-sharepoint-params-flag-description"))
	cmd.Flags().StringVarP(&r.UdaParams, "uda-params", "", "", translation.T("backup-recovery-indexed-objects-search-uda-params-flag-description"))
	cmd.Flags().StringVarP(&r.CassandraParamsCassandraObjectTypes, "cassandra-params-cassandra-object-types", "", "", translation.T("backup-recovery-indexed-objects-search-cassandra-params-cassandra-object-types-flag-description"))
	cmd.Flags().StringVarP(&r.CassandraParamsSearchString, "cassandra-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-cassandra-params-search-string-flag-description"))
	cmd.Flags().StringVarP(&r.CassandraParamsSourceIds, "cassandra-params-source-ids", "", "", translation.T("backup-recovery-indexed-objects-search-cassandra-params-source-ids-flag-description"))
	cmd.Flags().StringVarP(&r.CouchbaseParamsCouchbaseObjectTypes, "couchbase-params-couchbase-object-types", "", "", translation.T("backup-recovery-indexed-objects-search-couchbase-params-couchbase-object-types-flag-description"))
	cmd.Flags().StringVarP(&r.CouchbaseParamsSearchString, "couchbase-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-couchbase-params-search-string-flag-description"))
	cmd.Flags().StringVarP(&r.CouchbaseParamsSourceIds, "couchbase-params-source-ids", "", "", translation.T("backup-recovery-indexed-objects-search-couchbase-params-source-ids-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsAttendeesAddresses, "email-params-attendees-addresses", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-attendees-addresses-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsBccRecipientAddresses, "email-params-bcc-recipient-addresses", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-bcc-recipient-addresses-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsCcRecipientAddresses, "email-params-cc-recipient-addresses", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-cc-recipient-addresses-flag-description"))
	cmd.Flags().Int64VarP(&r.EmailParamsCreatedEndTimeSecs, "email-params-created-end-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-email-params-created-end-time-secs-flag-description"))
	cmd.Flags().Int64VarP(&r.EmailParamsCreatedStartTimeSecs, "email-params-created-start-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-email-params-created-start-time-secs-flag-description"))
	cmd.Flags().Int64VarP(&r.EmailParamsDueDateEndTimeSecs, "email-params-due-date-end-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-email-params-due-date-end-time-secs-flag-description"))
	cmd.Flags().Int64VarP(&r.EmailParamsDueDateStartTimeSecs, "email-params-due-date-start-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-email-params-due-date-start-time-secs-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsEmailAddress, "email-params-email-address", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-email-address-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsEmailSubject, "email-params-email-subject", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-email-subject-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsFirstName, "email-params-first-name", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-first-name-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsFolderNames, "email-params-folder-names", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-folder-names-flag-description"))
	cmd.Flags().BoolVarP(&r.EmailParamsHasAttachment, "email-params-has-attachment", "", false, translation.T("backup-recovery-indexed-objects-search-email-params-has-attachment-flag-description"))
	cmd.Flags().Int64VarP(&r.EmailParamsLastModifiedEndTimeSecs, "email-params-last-modified-end-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-email-params-last-modified-end-time-secs-flag-description"))
	cmd.Flags().Int64VarP(&r.EmailParamsLastModifiedStartTimeSecs, "email-params-last-modified-start-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-email-params-last-modified-start-time-secs-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsLastName, "email-params-last-name", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-last-name-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsMiddleName, "email-params-middle-name", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-middle-name-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsOrganizerAddress, "email-params-organizer-address", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-organizer-address-flag-description"))
	cmd.Flags().Int64VarP(&r.EmailParamsReceivedEndTimeSecs, "email-params-received-end-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-email-params-received-end-time-secs-flag-description"))
	cmd.Flags().Int64VarP(&r.EmailParamsReceivedStartTimeSecs, "email-params-received-start-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-email-params-received-start-time-secs-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsRecipientAddresses, "email-params-recipient-addresses", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-recipient-addresses-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsSenderAddress, "email-params-sender-address", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-sender-address-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsSourceEnvironment, "email-params-source-environment", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-source-environment-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsTaskStatusTypes, "email-params-task-status-types", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-task-status-types-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsTypes, "email-params-types", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-types-flag-description"))
	cmd.Flags().StringVarP(&r.EmailParamsO365Params, "email-params-o365-params", "", "", translation.T("backup-recovery-indexed-objects-search-email-params-o365-params-flag-description"))
	cmd.Flags().StringVarP(&r.ExchangeParamsSearchString, "exchange-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-exchange-params-search-string-flag-description"))
	cmd.Flags().StringVarP(&r.FileParamsSearchString, "file-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-file-params-search-string-flag-description"))
	cmd.Flags().StringVarP(&r.FileParamsTypes, "file-params-types", "", "", translation.T("backup-recovery-indexed-objects-search-file-params-types-flag-description"))
	cmd.Flags().StringVarP(&r.FileParamsSourceEnvironments, "file-params-source-environments", "", "", translation.T("backup-recovery-indexed-objects-search-file-params-source-environments-flag-description"))
	cmd.Flags().StringVarP(&r.FileParamsSourceIds, "file-params-source-ids", "", "", translation.T("backup-recovery-indexed-objects-search-file-params-source-ids-flag-description"))
	cmd.Flags().StringVarP(&r.FileParamsObjectIds, "file-params-object-ids", "", "", translation.T("backup-recovery-indexed-objects-search-file-params-object-ids-flag-description"))
	cmd.Flags().StringVarP(&r.HbaseParamsHbaseObjectTypes, "hbase-params-hbase-object-types", "", "", translation.T("backup-recovery-indexed-objects-search-hbase-params-hbase-object-types-flag-description"))
	cmd.Flags().StringVarP(&r.HbaseParamsSearchString, "hbase-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-hbase-params-search-string-flag-description"))
	cmd.Flags().StringVarP(&r.HbaseParamsSourceIds, "hbase-params-source-ids", "", "", translation.T("backup-recovery-indexed-objects-search-hbase-params-source-ids-flag-description"))
	cmd.Flags().StringVarP(&r.HdfsParamsHdfsTypes, "hdfs-params-hdfs-types", "", "", translation.T("backup-recovery-indexed-objects-search-hdfs-params-hdfs-types-flag-description"))
	cmd.Flags().StringVarP(&r.HdfsParamsSearchString, "hdfs-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-hdfs-params-search-string-flag-description"))
	cmd.Flags().StringVarP(&r.HdfsParamsSourceIds, "hdfs-params-source-ids", "", "", translation.T("backup-recovery-indexed-objects-search-hdfs-params-source-ids-flag-description"))
	cmd.Flags().StringVarP(&r.HiveParamsHiveObjectTypes, "hive-params-hive-object-types", "", "", translation.T("backup-recovery-indexed-objects-search-hive-params-hive-object-types-flag-description"))
	cmd.Flags().StringVarP(&r.HiveParamsSearchString, "hive-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-hive-params-search-string-flag-description"))
	cmd.Flags().StringVarP(&r.HiveParamsSourceIds, "hive-params-source-ids", "", "", translation.T("backup-recovery-indexed-objects-search-hive-params-source-ids-flag-description"))
	cmd.Flags().StringVarP(&r.MongodbParamsMongoDBObjectTypes, "mongodb-params-mongo-db-object-types", "", "", translation.T("backup-recovery-indexed-objects-search-mongodb-params-mongo-db-object-types-flag-description"))
	cmd.Flags().StringVarP(&r.MongodbParamsSearchString, "mongodb-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-mongodb-params-search-string-flag-description"))
	cmd.Flags().StringVarP(&r.MongodbParamsSourceIds, "mongodb-params-source-ids", "", "", translation.T("backup-recovery-indexed-objects-search-mongodb-params-source-ids-flag-description"))
	cmd.Flags().StringVarP(&r.MsGroupsParamsMailboxParams, "ms-groups-params-mailbox-params", "", "", translation.T("backup-recovery-indexed-objects-search-ms-groups-params-mailbox-params-flag-description"))
	cmd.Flags().StringVarP(&r.MsGroupsParamsO365Params, "ms-groups-params-o365-params", "", "", translation.T("backup-recovery-indexed-objects-search-ms-groups-params-o365-params-flag-description"))
	cmd.Flags().StringVarP(&r.MsGroupsParamsSiteParams, "ms-groups-params-site-params", "", "", translation.T("backup-recovery-indexed-objects-search-ms-groups-params-site-params-flag-description"))
	cmd.Flags().StringVarP(&r.MsTeamsParamsCategoryTypes, "ms-teams-params-category-types", "", "", translation.T("backup-recovery-indexed-objects-search-ms-teams-params-category-types-flag-description"))
	cmd.Flags().StringVarP(&r.MsTeamsParamsChannelNames, "ms-teams-params-channel-names", "", "", translation.T("backup-recovery-indexed-objects-search-ms-teams-params-channel-names-flag-description"))
	cmd.Flags().StringVarP(&r.MsTeamsParamsChannelParams, "ms-teams-params-channel-params", "", "", translation.T("backup-recovery-indexed-objects-search-ms-teams-params-channel-params-flag-description"))
	cmd.Flags().Int64VarP(&r.MsTeamsParamsCreationEndTimeSecs, "ms-teams-params-creation-end-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-ms-teams-params-creation-end-time-secs-flag-description"))
	cmd.Flags().Int64VarP(&r.MsTeamsParamsCreationStartTimeSecs, "ms-teams-params-creation-start-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-ms-teams-params-creation-start-time-secs-flag-description"))
	cmd.Flags().StringVarP(&r.MsTeamsParamsO365Params, "ms-teams-params-o365-params", "", "", translation.T("backup-recovery-indexed-objects-search-ms-teams-params-o365-params-flag-description"))
	cmd.Flags().StringVarP(&r.MsTeamsParamsOwnerNames, "ms-teams-params-owner-names", "", "", translation.T("backup-recovery-indexed-objects-search-ms-teams-params-owner-names-flag-description"))
	cmd.Flags().StringVarP(&r.MsTeamsParamsSearchString, "ms-teams-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-ms-teams-params-search-string-flag-description"))
	cmd.Flags().Int64VarP(&r.MsTeamsParamsSizeBytesLowerLimit, "ms-teams-params-size-bytes-lower-limit", "", 0, translation.T("backup-recovery-indexed-objects-search-ms-teams-params-size-bytes-lower-limit-flag-description"))
	cmd.Flags().Int64VarP(&r.MsTeamsParamsSizeBytesUpperLimit, "ms-teams-params-size-bytes-upper-limit", "", 0, translation.T("backup-recovery-indexed-objects-search-ms-teams-params-size-bytes-upper-limit-flag-description"))
	cmd.Flags().StringVarP(&r.MsTeamsParamsTypes, "ms-teams-params-types", "", "", translation.T("backup-recovery-indexed-objects-search-ms-teams-params-types-flag-description"))
	cmd.Flags().StringVarP(&r.OneDriveParamsCategoryTypes, "one-drive-params-category-types", "", "", translation.T("backup-recovery-indexed-objects-search-one-drive-params-category-types-flag-description"))
	cmd.Flags().Int64VarP(&r.OneDriveParamsCreationEndTimeSecs, "one-drive-params-creation-end-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-one-drive-params-creation-end-time-secs-flag-description"))
	cmd.Flags().Int64VarP(&r.OneDriveParamsCreationStartTimeSecs, "one-drive-params-creation-start-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-one-drive-params-creation-start-time-secs-flag-description"))
	cmd.Flags().BoolVarP(&r.OneDriveParamsIncludeFiles, "one-drive-params-include-files", "", false, translation.T("backup-recovery-indexed-objects-search-one-drive-params-include-files-flag-description"))
	cmd.Flags().BoolVarP(&r.OneDriveParamsIncludeFolders, "one-drive-params-include-folders", "", false, translation.T("backup-recovery-indexed-objects-search-one-drive-params-include-folders-flag-description"))
	cmd.Flags().StringVarP(&r.OneDriveParamsO365Params, "one-drive-params-o365-params", "", "", translation.T("backup-recovery-indexed-objects-search-one-drive-params-o365-params-flag-description"))
	cmd.Flags().StringVarP(&r.OneDriveParamsOwnerNames, "one-drive-params-owner-names", "", "", translation.T("backup-recovery-indexed-objects-search-one-drive-params-owner-names-flag-description"))
	cmd.Flags().StringVarP(&r.OneDriveParamsSearchString, "one-drive-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-one-drive-params-search-string-flag-description"))
	cmd.Flags().Int64VarP(&r.OneDriveParamsSizeBytesLowerLimit, "one-drive-params-size-bytes-lower-limit", "", 0, translation.T("backup-recovery-indexed-objects-search-one-drive-params-size-bytes-lower-limit-flag-description"))
	cmd.Flags().Int64VarP(&r.OneDriveParamsSizeBytesUpperLimit, "one-drive-params-size-bytes-upper-limit", "", 0, translation.T("backup-recovery-indexed-objects-search-one-drive-params-size-bytes-upper-limit-flag-description"))
	cmd.Flags().StringVarP(&r.PublicFolderParamsSearchString, "public-folder-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-public-folder-params-search-string-flag-description"))
	cmd.Flags().StringVarP(&r.PublicFolderParamsTypes, "public-folder-params-types", "", "", translation.T("backup-recovery-indexed-objects-search-public-folder-params-types-flag-description"))
	cmd.Flags().BoolVarP(&r.PublicFolderParamsHasAttachment, "public-folder-params-has-attachment", "", false, translation.T("backup-recovery-indexed-objects-search-public-folder-params-has-attachment-flag-description"))
	cmd.Flags().StringVarP(&r.PublicFolderParamsSenderAddress, "public-folder-params-sender-address", "", "", translation.T("backup-recovery-indexed-objects-search-public-folder-params-sender-address-flag-description"))
	cmd.Flags().StringVarP(&r.PublicFolderParamsRecipientAddresses, "public-folder-params-recipient-addresses", "", "", translation.T("backup-recovery-indexed-objects-search-public-folder-params-recipient-addresses-flag-description"))
	cmd.Flags().StringVarP(&r.PublicFolderParamsCcRecipientAddresses, "public-folder-params-cc-recipient-addresses", "", "", translation.T("backup-recovery-indexed-objects-search-public-folder-params-cc-recipient-addresses-flag-description"))
	cmd.Flags().StringVarP(&r.PublicFolderParamsBccRecipientAddresses, "public-folder-params-bcc-recipient-addresses", "", "", translation.T("backup-recovery-indexed-objects-search-public-folder-params-bcc-recipient-addresses-flag-description"))
	cmd.Flags().Int64VarP(&r.PublicFolderParamsReceivedStartTimeSecs, "public-folder-params-received-start-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-public-folder-params-received-start-time-secs-flag-description"))
	cmd.Flags().Int64VarP(&r.PublicFolderParamsReceivedEndTimeSecs, "public-folder-params-received-end-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-public-folder-params-received-end-time-secs-flag-description"))
	cmd.Flags().StringVarP(&r.SfdcParamsMutationTypes, "sfdc-params-mutation-types", "", "", translation.T("backup-recovery-indexed-objects-search-sfdc-params-mutation-types-flag-description"))
	cmd.Flags().StringVarP(&r.SfdcParamsObjectName, "sfdc-params-object-name", "", "", translation.T("backup-recovery-indexed-objects-search-sfdc-params-object-name-flag-description"))
	cmd.Flags().StringVarP(&r.SfdcParamsQueryString, "sfdc-params-query-string", "", "", translation.T("backup-recovery-indexed-objects-search-sfdc-params-query-string-flag-description"))
	cmd.Flags().StringVarP(&r.SfdcParamsSnapshotID, "sfdc-params-snapshot-id", "", "", translation.T("backup-recovery-indexed-objects-search-sfdc-params-snapshot-id-flag-description"))
	cmd.Flags().StringVarP(&r.SharepointParamsCategoryTypes, "sharepoint-params-category-types", "", "", translation.T("backup-recovery-indexed-objects-search-sharepoint-params-category-types-flag-description"))
	cmd.Flags().Int64VarP(&r.SharepointParamsCreationEndTimeSecs, "sharepoint-params-creation-end-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-sharepoint-params-creation-end-time-secs-flag-description"))
	cmd.Flags().Int64VarP(&r.SharepointParamsCreationStartTimeSecs, "sharepoint-params-creation-start-time-secs", "", 0, translation.T("backup-recovery-indexed-objects-search-sharepoint-params-creation-start-time-secs-flag-description"))
	cmd.Flags().BoolVarP(&r.SharepointParamsIncludeFiles, "sharepoint-params-include-files", "", false, translation.T("backup-recovery-indexed-objects-search-sharepoint-params-include-files-flag-description"))
	cmd.Flags().BoolVarP(&r.SharepointParamsIncludeFolders, "sharepoint-params-include-folders", "", false, translation.T("backup-recovery-indexed-objects-search-sharepoint-params-include-folders-flag-description"))
	cmd.Flags().StringVarP(&r.SharepointParamsO365Params, "sharepoint-params-o365-params", "", "", translation.T("backup-recovery-indexed-objects-search-sharepoint-params-o365-params-flag-description"))
	cmd.Flags().StringVarP(&r.SharepointParamsOwnerNames, "sharepoint-params-owner-names", "", "", translation.T("backup-recovery-indexed-objects-search-sharepoint-params-owner-names-flag-description"))
	cmd.Flags().StringVarP(&r.SharepointParamsSearchString, "sharepoint-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-sharepoint-params-search-string-flag-description"))
	cmd.Flags().Int64VarP(&r.SharepointParamsSizeBytesLowerLimit, "sharepoint-params-size-bytes-lower-limit", "", 0, translation.T("backup-recovery-indexed-objects-search-sharepoint-params-size-bytes-lower-limit-flag-description"))
	cmd.Flags().Int64VarP(&r.SharepointParamsSizeBytesUpperLimit, "sharepoint-params-size-bytes-upper-limit", "", 0, translation.T("backup-recovery-indexed-objects-search-sharepoint-params-size-bytes-upper-limit-flag-description"))
	cmd.Flags().StringVarP(&r.UdaParamsSearchString, "uda-params-search-string", "", "", translation.T("backup-recovery-indexed-objects-search-uda-params-search-string-flag-description"))
	cmd.Flags().StringVarP(&r.UdaParamsSourceIds, "uda-params-source-ids", "", "", translation.T("backup-recovery-indexed-objects-search-uda-params-source-ids-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
		"object-type",
	}

	return cmd
}

// Primary logic for running SearchIndexedObjects
func (r *SearchIndexedObjectsCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.SearchIndexedObjectsOptions{}
	CassandraParamsHelper := &backuprecoveryv1.CassandraOnPremSearchParams{}
	CouchbaseParamsHelper := &backuprecoveryv1.CouchBaseOnPremSearchParams{}
	EmailParamsHelper := &backuprecoveryv1.SearchEmailRequestParams{}
	ExchangeParamsHelper := &backuprecoveryv1.SearchExchangeObjectsRequestParams{}
	FileParamsHelper := &backuprecoveryv1.SearchFileRequestParams{}
	HbaseParamsHelper := &backuprecoveryv1.HbaseOnPremSearchParams{}
	HdfsParamsHelper := &backuprecoveryv1.HDFSOnPremSearchParams{}
	HiveParamsHelper := &backuprecoveryv1.HiveOnPremSearchParams{}
	MongodbParamsHelper := &backuprecoveryv1.MongoDbOnPremSearchParams{}
	MsGroupsParamsHelper := &backuprecoveryv1.SearchMsGroupsRequestParams{}
	MsTeamsParamsHelper := &backuprecoveryv1.SearchMsTeamsRequestParams{}
	OneDriveParamsHelper := &backuprecoveryv1.SearchDocumentLibraryRequestParams{}
	PublicFolderParamsHelper := &backuprecoveryv1.SearchPublicFolderRequestParams{}
	SfdcParamsHelper := &backuprecoveryv1.SearchSfdcRecordsRequestParams{}
	SharepointParamsHelper := &backuprecoveryv1.SearchDocumentLibraryRequestParams{}
	UdaParamsHelper := &backuprecoveryv1.UdaOnPremSearchParams{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "object-type" {
			OptionsModel.SetObjectType(r.ObjectType)
		}
		if flag.Name == "protection-group-ids" {
			var ProtectionGroupIds []string
			err, msg := deserialize.List(r.ProtectionGroupIds, "protection-group-ids", "JSON", &ProtectionGroupIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetProtectionGroupIds(ProtectionGroupIds)
		}
		if flag.Name == "storage-domain-ids" {
			var StorageDomainIds []int64
			err, msg := deserialize.List(r.StorageDomainIds, "storage-domain-ids", "JSON", &StorageDomainIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetStorageDomainIds(StorageDomainIds)
		}
		if flag.Name == "tenant-id" {
			OptionsModel.SetTenantID(r.TenantID)
		}
		if flag.Name == "include-tenants" {
			OptionsModel.SetIncludeTenants(r.IncludeTenants)
		}
		if flag.Name == "tags" {
			var Tags []string
			err, msg := deserialize.List(r.Tags, "tags", "JSON", &Tags)
			r.utils.HandleError(err, msg)
			OptionsModel.SetTags(Tags)
		}
		if flag.Name == "snapshot-tags" {
			var SnapshotTags []string
			err, msg := deserialize.List(r.SnapshotTags, "snapshot-tags", "JSON", &SnapshotTags)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSnapshotTags(SnapshotTags)
		}
		if flag.Name == "must-have-tag-ids" {
			var MustHaveTagIds []string
			err, msg := deserialize.List(r.MustHaveTagIds, "must-have-tag-ids", "JSON", &MustHaveTagIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMustHaveTagIds(MustHaveTagIds)
		}
		if flag.Name == "might-have-tag-ids" {
			var MightHaveTagIds []string
			err, msg := deserialize.List(r.MightHaveTagIds, "might-have-tag-ids", "JSON", &MightHaveTagIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMightHaveTagIds(MightHaveTagIds)
		}
		if flag.Name == "must-have-snapshot-tag-ids" {
			var MustHaveSnapshotTagIds []string
			err, msg := deserialize.List(r.MustHaveSnapshotTagIds, "must-have-snapshot-tag-ids", "JSON", &MustHaveSnapshotTagIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMustHaveSnapshotTagIds(MustHaveSnapshotTagIds)
		}
		if flag.Name == "might-have-snapshot-tag-ids" {
			var MightHaveSnapshotTagIds []string
			err, msg := deserialize.List(r.MightHaveSnapshotTagIds, "might-have-snapshot-tag-ids", "JSON", &MightHaveSnapshotTagIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMightHaveSnapshotTagIds(MightHaveSnapshotTagIds)
		}
		if flag.Name == "pagination-cookie" {
			OptionsModel.SetPaginationCookie(r.PaginationCookie)
		}
		if flag.Name == "count" {
			OptionsModel.SetCount(r.Count)
		}
		if flag.Name == "use-cached-data" {
			OptionsModel.SetUseCachedData(r.UseCachedData)
		}
		if flag.Name == "cassandra-params" {
			var CassandraParams *backuprecoveryv1.CassandraOnPremSearchParams
			err, msg := deserialize.Model(
				r.CassandraParams,
				"cassandra-params",
				"CassandraOnPremSearchParams",
				backuprecoveryv1.UnmarshalCassandraOnPremSearchParams,
				&CassandraParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetCassandraParams(CassandraParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.CassandraParams, `{"fields":["searchString","cassandraObjectTypes","sourceIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "cassandra-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "cassandra-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "cassandra-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "couchbase-params" {
			var CouchbaseParams *backuprecoveryv1.CouchBaseOnPremSearchParams
			err, msg := deserialize.Model(
				r.CouchbaseParams,
				"couchbase-params",
				"CouchBaseOnPremSearchParams",
				backuprecoveryv1.UnmarshalCouchBaseOnPremSearchParams,
				&CouchbaseParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetCouchbaseParams(CouchbaseParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.CouchbaseParams, `{"fields":["searchString","couchbaseObjectTypes","sourceIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "couchbase-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "couchbase-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "couchbase-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "email-params" {
			var EmailParams *backuprecoveryv1.SearchEmailRequestParams
			err, msg := deserialize.Model(
				r.EmailParams,
				"email-params",
				"SearchEmailRequestParams",
				backuprecoveryv1.UnmarshalSearchEmailRequestParams,
				&EmailParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetEmailParams(EmailParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.EmailParams, `{"schemas":{"O365SearchEmailsRequestParams":["domainIds","mailboxIds"]},"fields":["lastName","senderAddress","bccRecipientAddresses","organizerAddress","emailSubject","o365Params#O365SearchEmailsRequestParams","emailAddress","hasAttachment","ccRecipientAddresses","recipientAddresses","folderNames","dueDateStartTimeSecs","sourceEnvironment","dueDateEndTimeSecs","taskStatusTypes","types","createdStartTimeSecs","createdEndTimeSecs","lastModifiedEndTimeSecs","attendeesAddresses","firstName","lastModifiedStartTimeSecs","receivedStartTimeSecs","receivedEndTimeSecs","middleName"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "email-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "email-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "email-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "exchange-params" {
			var ExchangeParams *backuprecoveryv1.SearchExchangeObjectsRequestParams
			err, msg := deserialize.Model(
				r.ExchangeParams,
				"exchange-params",
				"SearchExchangeObjectsRequestParams",
				backuprecoveryv1.UnmarshalSearchExchangeObjectsRequestParams,
				&ExchangeParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetExchangeParams(ExchangeParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.ExchangeParams, `{"fields":["searchString"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "exchange-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "exchange-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "exchange-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "file-params" {
			var FileParams *backuprecoveryv1.SearchFileRequestParams
			err, msg := deserialize.Model(
				r.FileParams,
				"file-params",
				"SearchFileRequestParams",
				backuprecoveryv1.UnmarshalSearchFileRequestParams,
				&FileParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetFileParams(FileParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.FileParams, `{"fields":["searchString","types","sourceEnvironments","sourceIds","objectIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "file-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "file-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "file-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "hbase-params" {
			var HbaseParams *backuprecoveryv1.HbaseOnPremSearchParams
			err, msg := deserialize.Model(
				r.HbaseParams,
				"hbase-params",
				"HbaseOnPremSearchParams",
				backuprecoveryv1.UnmarshalHbaseOnPremSearchParams,
				&HbaseParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetHbaseParams(HbaseParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.HbaseParams, `{"fields":["searchString","hbaseObjectTypes","sourceIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "hbase-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "hbase-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "hbase-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "hdfs-params" {
			var HdfsParams *backuprecoveryv1.HDFSOnPremSearchParams
			err, msg := deserialize.Model(
				r.HdfsParams,
				"hdfs-params",
				"HDFSOnPremSearchParams",
				backuprecoveryv1.UnmarshalHDFSOnPremSearchParams,
				&HdfsParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetHdfsParams(HdfsParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.HdfsParams, `{"fields":["searchString","hdfsTypes","sourceIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "hdfs-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "hdfs-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "hdfs-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "hive-params" {
			var HiveParams *backuprecoveryv1.HiveOnPremSearchParams
			err, msg := deserialize.Model(
				r.HiveParams,
				"hive-params",
				"HiveOnPremSearchParams",
				backuprecoveryv1.UnmarshalHiveOnPremSearchParams,
				&HiveParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetHiveParams(HiveParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.HiveParams, `{"fields":["searchString","hiveObjectTypes","sourceIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "hive-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "hive-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "hive-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "mongodb-params" {
			var MongodbParams *backuprecoveryv1.MongoDbOnPremSearchParams
			err, msg := deserialize.Model(
				r.MongodbParams,
				"mongodb-params",
				"MongoDbOnPremSearchParams",
				backuprecoveryv1.UnmarshalMongoDbOnPremSearchParams,
				&MongodbParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMongodbParams(MongodbParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.MongodbParams, `{"fields":["searchString","mongoDBObjectTypes","sourceIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "mongodb-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "mongodb-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "mongodb-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "ms-groups-params" {
			var MsGroupsParams *backuprecoveryv1.SearchMsGroupsRequestParams
			err, msg := deserialize.Model(
				r.MsGroupsParams,
				"ms-groups-params",
				"SearchMsGroupsRequestParams",
				backuprecoveryv1.UnmarshalSearchMsGroupsRequestParams,
				&MsGroupsParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMsGroupsParams(MsGroupsParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.MsGroupsParams, `{"schemas":{"SearchDocumentLibraryRequestParams":["categoryTypes","creationEndTimeSecs","creationStartTimeSecs","includeFiles","includeFolders","o365Params#O365SearchRequestParams","ownerNames","searchString","sizeBytesLowerLimit","sizeBytesUpperLimit"],"SearchEmailRequestParamsBase":["attendeesAddresses","bccRecipientAddresses","ccRecipientAddresses","createdEndTimeSecs","createdStartTimeSecs","dueDateEndTimeSecs","dueDateStartTimeSecs","emailAddress","emailSubject","firstName","folderNames","hasAttachment","lastModifiedEndTimeSecs","lastModifiedStartTimeSecs","lastName","middleName","organizerAddress","receivedEndTimeSecs","receivedStartTimeSecs","recipientAddresses","senderAddress","sourceEnvironment","taskStatusTypes","types"],"O365SearchRequestParams":["domainIds","groupIds","siteIds","teamsIds","userIds"]},"fields":["siteParams#SearchDocumentLibraryRequestParams","o365Params#O365SearchRequestParams","mailboxParams#SearchEmailRequestParamsBase"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "ms-groups-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "ms-groups-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "ms-groups-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "ms-teams-params" {
			var MsTeamsParams *backuprecoveryv1.SearchMsTeamsRequestParams
			err, msg := deserialize.Model(
				r.MsTeamsParams,
				"ms-teams-params",
				"SearchMsTeamsRequestParams",
				backuprecoveryv1.UnmarshalSearchMsTeamsRequestParams,
				&MsTeamsParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMsTeamsParams(MsTeamsParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.MsTeamsParams, `{"schemas":{"O365TeamsChannelsSearchRequestParams":["channelEmail","channelId","channelName","includePrivateChannels","includePublicChannels"],"O365SearchRequestParams":["domainIds","groupIds","siteIds","teamsIds","userIds"]},"fields":["categoryTypes","searchString","types","channelParams#O365TeamsChannelsSearchRequestParams","creationStartTimeSecs","channelNames","creationEndTimeSecs","ownerNames","o365Params#O365SearchRequestParams","sizeBytesLowerLimit","sizeBytesUpperLimit"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "ms-teams-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "ms-teams-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "ms-teams-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "one-drive-params" {
			var OneDriveParams *backuprecoveryv1.SearchDocumentLibraryRequestParams
			err, msg := deserialize.Model(
				r.OneDriveParams,
				"one-drive-params",
				"SearchDocumentLibraryRequestParams",
				backuprecoveryv1.UnmarshalSearchDocumentLibraryRequestParams,
				&OneDriveParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetOneDriveParams(OneDriveParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.OneDriveParams, `{"schemas":{"O365SearchRequestParams":["domainIds","groupIds","siteIds","teamsIds","userIds"]},"fields":["categoryTypes","searchString","creationStartTimeSecs","creationEndTimeSecs","includeFolders","includeFiles","ownerNames","o365Params#O365SearchRequestParams","sizeBytesLowerLimit","sizeBytesUpperLimit"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "one-drive-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "one-drive-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "one-drive-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "public-folder-params" {
			var PublicFolderParams *backuprecoveryv1.SearchPublicFolderRequestParams
			err, msg := deserialize.Model(
				r.PublicFolderParams,
				"public-folder-params",
				"SearchPublicFolderRequestParams",
				backuprecoveryv1.UnmarshalSearchPublicFolderRequestParams,
				&PublicFolderParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetPublicFolderParams(PublicFolderParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.PublicFolderParams, `{"fields":["searchString","types","hasAttachment","senderAddress","ccRecipientAddresses","bccRecipientAddresses","recipientAddresses","receivedStartTimeSecs","receivedEndTimeSecs"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "public-folder-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "public-folder-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "public-folder-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "sfdc-params" {
			var SfdcParams *backuprecoveryv1.SearchSfdcRecordsRequestParams
			err, msg := deserialize.Model(
				r.SfdcParams,
				"sfdc-params",
				"SearchSfdcRecordsRequestParams",
				backuprecoveryv1.UnmarshalSearchSfdcRecordsRequestParams,
				&SfdcParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSfdcParams(SfdcParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.SfdcParams, `{"fields":["snapshotId","objectName","queryString","mutationTypes"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "sfdc-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "sfdc-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "sfdc-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "sharepoint-params" {
			var SharepointParams *backuprecoveryv1.SearchDocumentLibraryRequestParams
			err, msg := deserialize.Model(
				r.SharepointParams,
				"sharepoint-params",
				"SearchDocumentLibraryRequestParams",
				backuprecoveryv1.UnmarshalSearchDocumentLibraryRequestParams,
				&SharepointParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSharepointParams(SharepointParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.SharepointParams, `{"schemas":{"O365SearchRequestParams":["domainIds","groupIds","siteIds","teamsIds","userIds"]},"fields":["categoryTypes","searchString","creationStartTimeSecs","creationEndTimeSecs","includeFolders","includeFiles","ownerNames","o365Params#O365SearchRequestParams","sizeBytesLowerLimit","sizeBytesUpperLimit"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "sharepoint-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "sharepoint-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "sharepoint-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "uda-params" {
			var UdaParams *backuprecoveryv1.UdaOnPremSearchParams
			err, msg := deserialize.Model(
				r.UdaParams,
				"uda-params",
				"UdaOnPremSearchParams",
				backuprecoveryv1.UnmarshalUdaOnPremSearchParams,
				&UdaParams,
			)
			r.utils.HandleError(err, msg)
			OptionsModel.SetUdaParams(UdaParams)
			extraFieldPaths, err := r.utils.ValidateJSON(r.UdaParams, `{"fields":["searchString","sourceIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "uda-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "uda-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "uda-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "cassandra-params-cassandra-object-types" {
			var CassandraParamsCassandraObjectTypes []string
			err, msg := deserialize.List(r.CassandraParamsCassandraObjectTypes, "cassandra-params-cassandra-object-types", "JSON", &CassandraParamsCassandraObjectTypes)
			r.utils.HandleError(err, msg)
			CassandraParamsHelper.CassandraObjectTypes = CassandraParamsCassandraObjectTypes
		}
		if flag.Name == "cassandra-params-search-string" {
			CassandraParamsHelper.SearchString = core.StringPtr(r.CassandraParamsSearchString)
		}
		if flag.Name == "cassandra-params-source-ids" {
			var CassandraParamsSourceIds []int64
			err, msg := deserialize.List(r.CassandraParamsSourceIds, "cassandra-params-source-ids", "JSON", &CassandraParamsSourceIds)
			r.utils.HandleError(err, msg)
			CassandraParamsHelper.SourceIds = CassandraParamsSourceIds
		}
		if flag.Name == "couchbase-params-couchbase-object-types" {
			var CouchbaseParamsCouchbaseObjectTypes []string
			err, msg := deserialize.List(r.CouchbaseParamsCouchbaseObjectTypes, "couchbase-params-couchbase-object-types", "JSON", &CouchbaseParamsCouchbaseObjectTypes)
			r.utils.HandleError(err, msg)
			CouchbaseParamsHelper.CouchbaseObjectTypes = CouchbaseParamsCouchbaseObjectTypes
		}
		if flag.Name == "couchbase-params-search-string" {
			CouchbaseParamsHelper.SearchString = core.StringPtr(r.CouchbaseParamsSearchString)
		}
		if flag.Name == "couchbase-params-source-ids" {
			var CouchbaseParamsSourceIds []int64
			err, msg := deserialize.List(r.CouchbaseParamsSourceIds, "couchbase-params-source-ids", "JSON", &CouchbaseParamsSourceIds)
			r.utils.HandleError(err, msg)
			CouchbaseParamsHelper.SourceIds = CouchbaseParamsSourceIds
		}
		if flag.Name == "email-params-attendees-addresses" {
			var EmailParamsAttendeesAddresses []string
			err, msg := deserialize.List(r.EmailParamsAttendeesAddresses, "email-params-attendees-addresses", "JSON", &EmailParamsAttendeesAddresses)
			r.utils.HandleError(err, msg)
			EmailParamsHelper.AttendeesAddresses = EmailParamsAttendeesAddresses
		}
		if flag.Name == "email-params-bcc-recipient-addresses" {
			var EmailParamsBccRecipientAddresses []string
			err, msg := deserialize.List(r.EmailParamsBccRecipientAddresses, "email-params-bcc-recipient-addresses", "JSON", &EmailParamsBccRecipientAddresses)
			r.utils.HandleError(err, msg)
			EmailParamsHelper.BccRecipientAddresses = EmailParamsBccRecipientAddresses
		}
		if flag.Name == "email-params-cc-recipient-addresses" {
			var EmailParamsCcRecipientAddresses []string
			err, msg := deserialize.List(r.EmailParamsCcRecipientAddresses, "email-params-cc-recipient-addresses", "JSON", &EmailParamsCcRecipientAddresses)
			r.utils.HandleError(err, msg)
			EmailParamsHelper.CcRecipientAddresses = EmailParamsCcRecipientAddresses
		}
		if flag.Name == "email-params-created-end-time-secs" {
			EmailParamsHelper.CreatedEndTimeSecs = core.Int64Ptr(r.EmailParamsCreatedEndTimeSecs)
		}
		if flag.Name == "email-params-created-start-time-secs" {
			EmailParamsHelper.CreatedStartTimeSecs = core.Int64Ptr(r.EmailParamsCreatedStartTimeSecs)
		}
		if flag.Name == "email-params-due-date-end-time-secs" {
			EmailParamsHelper.DueDateEndTimeSecs = core.Int64Ptr(r.EmailParamsDueDateEndTimeSecs)
		}
		if flag.Name == "email-params-due-date-start-time-secs" {
			EmailParamsHelper.DueDateStartTimeSecs = core.Int64Ptr(r.EmailParamsDueDateStartTimeSecs)
		}
		if flag.Name == "email-params-email-address" {
			EmailParamsHelper.EmailAddress = core.StringPtr(r.EmailParamsEmailAddress)
		}
		if flag.Name == "email-params-email-subject" {
			EmailParamsHelper.EmailSubject = core.StringPtr(r.EmailParamsEmailSubject)
		}
		if flag.Name == "email-params-first-name" {
			EmailParamsHelper.FirstName = core.StringPtr(r.EmailParamsFirstName)
		}
		if flag.Name == "email-params-folder-names" {
			var EmailParamsFolderNames []string
			err, msg := deserialize.List(r.EmailParamsFolderNames, "email-params-folder-names", "JSON", &EmailParamsFolderNames)
			r.utils.HandleError(err, msg)
			EmailParamsHelper.FolderNames = EmailParamsFolderNames
		}
		if flag.Name == "email-params-has-attachment" {
			EmailParamsHelper.HasAttachment = core.BoolPtr(r.EmailParamsHasAttachment)
		}
		if flag.Name == "email-params-last-modified-end-time-secs" {
			EmailParamsHelper.LastModifiedEndTimeSecs = core.Int64Ptr(r.EmailParamsLastModifiedEndTimeSecs)
		}
		if flag.Name == "email-params-last-modified-start-time-secs" {
			EmailParamsHelper.LastModifiedStartTimeSecs = core.Int64Ptr(r.EmailParamsLastModifiedStartTimeSecs)
		}
		if flag.Name == "email-params-last-name" {
			EmailParamsHelper.LastName = core.StringPtr(r.EmailParamsLastName)
		}
		if flag.Name == "email-params-middle-name" {
			EmailParamsHelper.MiddleName = core.StringPtr(r.EmailParamsMiddleName)
		}
		if flag.Name == "email-params-organizer-address" {
			EmailParamsHelper.OrganizerAddress = core.StringPtr(r.EmailParamsOrganizerAddress)
		}
		if flag.Name == "email-params-received-end-time-secs" {
			EmailParamsHelper.ReceivedEndTimeSecs = core.Int64Ptr(r.EmailParamsReceivedEndTimeSecs)
		}
		if flag.Name == "email-params-received-start-time-secs" {
			EmailParamsHelper.ReceivedStartTimeSecs = core.Int64Ptr(r.EmailParamsReceivedStartTimeSecs)
		}
		if flag.Name == "email-params-recipient-addresses" {
			var EmailParamsRecipientAddresses []string
			err, msg := deserialize.List(r.EmailParamsRecipientAddresses, "email-params-recipient-addresses", "JSON", &EmailParamsRecipientAddresses)
			r.utils.HandleError(err, msg)
			EmailParamsHelper.RecipientAddresses = EmailParamsRecipientAddresses
		}
		if flag.Name == "email-params-sender-address" {
			EmailParamsHelper.SenderAddress = core.StringPtr(r.EmailParamsSenderAddress)
		}
		if flag.Name == "email-params-source-environment" {
			EmailParamsHelper.SourceEnvironment = core.StringPtr(r.EmailParamsSourceEnvironment)
		}
		if flag.Name == "email-params-task-status-types" {
			var EmailParamsTaskStatusTypes []string
			err, msg := deserialize.List(r.EmailParamsTaskStatusTypes, "email-params-task-status-types", "JSON", &EmailParamsTaskStatusTypes)
			r.utils.HandleError(err, msg)
			EmailParamsHelper.TaskStatusTypes = EmailParamsTaskStatusTypes
		}
		if flag.Name == "email-params-types" {
			var EmailParamsTypes []string
			err, msg := deserialize.List(r.EmailParamsTypes, "email-params-types", "JSON", &EmailParamsTypes)
			r.utils.HandleError(err, msg)
			EmailParamsHelper.Types = EmailParamsTypes
		}
		if flag.Name == "email-params-o365-params" {
			var EmailParamsO365Params *backuprecoveryv1.O365SearchEmailsRequestParams
			err, msg := deserialize.Model(
				r.EmailParamsO365Params,
				"email-params-o365-params",
				"O365SearchEmailsRequestParams",
				backuprecoveryv1.UnmarshalO365SearchEmailsRequestParams,
				&EmailParamsO365Params,
			)
			r.utils.HandleError(err, msg)
			EmailParamsHelper.O365Params = EmailParamsO365Params
			extraFieldPaths, err := r.utils.ValidateJSON(r.EmailParamsO365Params, `{"fields":["domainIds","mailboxIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "email-params-o365-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "email-params-o365-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "email-params-o365-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "exchange-params-search-string" {
			ExchangeParamsHelper.SearchString = core.StringPtr(r.ExchangeParamsSearchString)
		}
		if flag.Name == "file-params-search-string" {
			FileParamsHelper.SearchString = core.StringPtr(r.FileParamsSearchString)
		}
		if flag.Name == "file-params-types" {
			var FileParamsTypes []string
			err, msg := deserialize.List(r.FileParamsTypes, "file-params-types", "JSON", &FileParamsTypes)
			r.utils.HandleError(err, msg)
			FileParamsHelper.Types = FileParamsTypes
		}
		if flag.Name == "file-params-source-environments" {
			var FileParamsSourceEnvironments []string
			err, msg := deserialize.List(r.FileParamsSourceEnvironments, "file-params-source-environments", "JSON", &FileParamsSourceEnvironments)
			r.utils.HandleError(err, msg)
			FileParamsHelper.SourceEnvironments = FileParamsSourceEnvironments
		}
		if flag.Name == "file-params-source-ids" {
			var FileParamsSourceIds []int64
			err, msg := deserialize.List(r.FileParamsSourceIds, "file-params-source-ids", "JSON", &FileParamsSourceIds)
			r.utils.HandleError(err, msg)
			FileParamsHelper.SourceIds = FileParamsSourceIds
		}
		if flag.Name == "file-params-object-ids" {
			var FileParamsObjectIds []int64
			err, msg := deserialize.List(r.FileParamsObjectIds, "file-params-object-ids", "JSON", &FileParamsObjectIds)
			r.utils.HandleError(err, msg)
			FileParamsHelper.ObjectIds = FileParamsObjectIds
		}
		if flag.Name == "hbase-params-hbase-object-types" {
			var HbaseParamsHbaseObjectTypes []string
			err, msg := deserialize.List(r.HbaseParamsHbaseObjectTypes, "hbase-params-hbase-object-types", "JSON", &HbaseParamsHbaseObjectTypes)
			r.utils.HandleError(err, msg)
			HbaseParamsHelper.HbaseObjectTypes = HbaseParamsHbaseObjectTypes
		}
		if flag.Name == "hbase-params-search-string" {
			HbaseParamsHelper.SearchString = core.StringPtr(r.HbaseParamsSearchString)
		}
		if flag.Name == "hbase-params-source-ids" {
			var HbaseParamsSourceIds []int64
			err, msg := deserialize.List(r.HbaseParamsSourceIds, "hbase-params-source-ids", "JSON", &HbaseParamsSourceIds)
			r.utils.HandleError(err, msg)
			HbaseParamsHelper.SourceIds = HbaseParamsSourceIds
		}
		if flag.Name == "hdfs-params-hdfs-types" {
			var HdfsParamsHdfsTypes []string
			err, msg := deserialize.List(r.HdfsParamsHdfsTypes, "hdfs-params-hdfs-types", "JSON", &HdfsParamsHdfsTypes)
			r.utils.HandleError(err, msg)
			HdfsParamsHelper.HdfsTypes = HdfsParamsHdfsTypes
		}
		if flag.Name == "hdfs-params-search-string" {
			HdfsParamsHelper.SearchString = core.StringPtr(r.HdfsParamsSearchString)
		}
		if flag.Name == "hdfs-params-source-ids" {
			var HdfsParamsSourceIds []int64
			err, msg := deserialize.List(r.HdfsParamsSourceIds, "hdfs-params-source-ids", "JSON", &HdfsParamsSourceIds)
			r.utils.HandleError(err, msg)
			HdfsParamsHelper.SourceIds = HdfsParamsSourceIds
		}
		if flag.Name == "hive-params-hive-object-types" {
			var HiveParamsHiveObjectTypes []string
			err, msg := deserialize.List(r.HiveParamsHiveObjectTypes, "hive-params-hive-object-types", "JSON", &HiveParamsHiveObjectTypes)
			r.utils.HandleError(err, msg)
			HiveParamsHelper.HiveObjectTypes = HiveParamsHiveObjectTypes
		}
		if flag.Name == "hive-params-search-string" {
			HiveParamsHelper.SearchString = core.StringPtr(r.HiveParamsSearchString)
		}
		if flag.Name == "hive-params-source-ids" {
			var HiveParamsSourceIds []int64
			err, msg := deserialize.List(r.HiveParamsSourceIds, "hive-params-source-ids", "JSON", &HiveParamsSourceIds)
			r.utils.HandleError(err, msg)
			HiveParamsHelper.SourceIds = HiveParamsSourceIds
		}
		if flag.Name == "mongodb-params-mongo-db-object-types" {
			var MongodbParamsMongoDBObjectTypes []string
			err, msg := deserialize.List(r.MongodbParamsMongoDBObjectTypes, "mongodb-params-mongo-db-object-types", "JSON", &MongodbParamsMongoDBObjectTypes)
			r.utils.HandleError(err, msg)
			MongodbParamsHelper.MongoDBObjectTypes = MongodbParamsMongoDBObjectTypes
		}
		if flag.Name == "mongodb-params-search-string" {
			MongodbParamsHelper.SearchString = core.StringPtr(r.MongodbParamsSearchString)
		}
		if flag.Name == "mongodb-params-source-ids" {
			var MongodbParamsSourceIds []int64
			err, msg := deserialize.List(r.MongodbParamsSourceIds, "mongodb-params-source-ids", "JSON", &MongodbParamsSourceIds)
			r.utils.HandleError(err, msg)
			MongodbParamsHelper.SourceIds = MongodbParamsSourceIds
		}
		if flag.Name == "ms-groups-params-mailbox-params" {
			var MsGroupsParamsMailboxParams *backuprecoveryv1.SearchEmailRequestParamsBase
			err, msg := deserialize.Model(
				r.MsGroupsParamsMailboxParams,
				"ms-groups-params-mailbox-params",
				"SearchEmailRequestParamsBase",
				backuprecoveryv1.UnmarshalSearchEmailRequestParamsBase,
				&MsGroupsParamsMailboxParams,
			)
			r.utils.HandleError(err, msg)
			MsGroupsParamsHelper.MailboxParams = MsGroupsParamsMailboxParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.MsGroupsParamsMailboxParams, `{"fields":["dueDateEndTimeSecs","lastName","taskStatusTypes","senderAddress","types","bccRecipientAddresses","createdStartTimeSecs","createdEndTimeSecs","lastModifiedEndTimeSecs","organizerAddress","attendeesAddresses","emailSubject","firstName","emailAddress","hasAttachment","lastModifiedStartTimeSecs","ccRecipientAddresses","recipientAddresses","receivedStartTimeSecs","folderNames","receivedEndTimeSecs","dueDateStartTimeSecs","middleName","sourceEnvironment"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "ms-groups-params-mailbox-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "ms-groups-params-mailbox-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "ms-groups-params-mailbox-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "ms-groups-params-o365-params" {
			var MsGroupsParamsO365Params *backuprecoveryv1.O365SearchRequestParams
			err, msg := deserialize.Model(
				r.MsGroupsParamsO365Params,
				"ms-groups-params-o365-params",
				"O365SearchRequestParams",
				backuprecoveryv1.UnmarshalO365SearchRequestParams,
				&MsGroupsParamsO365Params,
			)
			r.utils.HandleError(err, msg)
			MsGroupsParamsHelper.O365Params = MsGroupsParamsO365Params
			extraFieldPaths, err := r.utils.ValidateJSON(r.MsGroupsParamsO365Params, `{"fields":["domainIds","groupIds","userIds","siteIds","teamsIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "ms-groups-params-o365-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "ms-groups-params-o365-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "ms-groups-params-o365-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "ms-groups-params-site-params" {
			var MsGroupsParamsSiteParams *backuprecoveryv1.SearchDocumentLibraryRequestParams
			err, msg := deserialize.Model(
				r.MsGroupsParamsSiteParams,
				"ms-groups-params-site-params",
				"SearchDocumentLibraryRequestParams",
				backuprecoveryv1.UnmarshalSearchDocumentLibraryRequestParams,
				&MsGroupsParamsSiteParams,
			)
			r.utils.HandleError(err, msg)
			MsGroupsParamsHelper.SiteParams = MsGroupsParamsSiteParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.MsGroupsParamsSiteParams, `{"schemas":{"O365SearchRequestParams":["domainIds","groupIds","siteIds","teamsIds","userIds"]},"fields":["categoryTypes","searchString","creationStartTimeSecs","creationEndTimeSecs","includeFolders","includeFiles","ownerNames","o365Params#O365SearchRequestParams","sizeBytesLowerLimit","sizeBytesUpperLimit"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "ms-groups-params-site-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "ms-groups-params-site-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "ms-groups-params-site-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "ms-teams-params-category-types" {
			var MsTeamsParamsCategoryTypes []string
			err, msg := deserialize.List(r.MsTeamsParamsCategoryTypes, "ms-teams-params-category-types", "JSON", &MsTeamsParamsCategoryTypes)
			r.utils.HandleError(err, msg)
			MsTeamsParamsHelper.CategoryTypes = MsTeamsParamsCategoryTypes
		}
		if flag.Name == "ms-teams-params-channel-names" {
			var MsTeamsParamsChannelNames []string
			err, msg := deserialize.List(r.MsTeamsParamsChannelNames, "ms-teams-params-channel-names", "JSON", &MsTeamsParamsChannelNames)
			r.utils.HandleError(err, msg)
			MsTeamsParamsHelper.ChannelNames = MsTeamsParamsChannelNames
		}
		if flag.Name == "ms-teams-params-channel-params" {
			var MsTeamsParamsChannelParams *backuprecoveryv1.O365TeamsChannelsSearchRequestParams
			err, msg := deserialize.Model(
				r.MsTeamsParamsChannelParams,
				"ms-teams-params-channel-params",
				"O365TeamsChannelsSearchRequestParams",
				backuprecoveryv1.UnmarshalO365TeamsChannelsSearchRequestParams,
				&MsTeamsParamsChannelParams,
			)
			r.utils.HandleError(err, msg)
			MsTeamsParamsHelper.ChannelParams = MsTeamsParamsChannelParams
			extraFieldPaths, err := r.utils.ValidateJSON(r.MsTeamsParamsChannelParams, `{"fields":["channelEmail","includePrivateChannels","includePublicChannels","channelName","channelId"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "ms-teams-params-channel-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "ms-teams-params-channel-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "ms-teams-params-channel-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "ms-teams-params-creation-end-time-secs" {
			MsTeamsParamsHelper.CreationEndTimeSecs = core.Int64Ptr(r.MsTeamsParamsCreationEndTimeSecs)
		}
		if flag.Name == "ms-teams-params-creation-start-time-secs" {
			MsTeamsParamsHelper.CreationStartTimeSecs = core.Int64Ptr(r.MsTeamsParamsCreationStartTimeSecs)
		}
		if flag.Name == "ms-teams-params-o365-params" {
			var MsTeamsParamsO365Params *backuprecoveryv1.O365SearchRequestParams
			err, msg := deserialize.Model(
				r.MsTeamsParamsO365Params,
				"ms-teams-params-o365-params",
				"O365SearchRequestParams",
				backuprecoveryv1.UnmarshalO365SearchRequestParams,
				&MsTeamsParamsO365Params,
			)
			r.utils.HandleError(err, msg)
			MsTeamsParamsHelper.O365Params = MsTeamsParamsO365Params
			extraFieldPaths, err := r.utils.ValidateJSON(r.MsTeamsParamsO365Params, `{"fields":["domainIds","groupIds","userIds","siteIds","teamsIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "ms-teams-params-o365-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "ms-teams-params-o365-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "ms-teams-params-o365-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "ms-teams-params-owner-names" {
			var MsTeamsParamsOwnerNames []string
			err, msg := deserialize.List(r.MsTeamsParamsOwnerNames, "ms-teams-params-owner-names", "JSON", &MsTeamsParamsOwnerNames)
			r.utils.HandleError(err, msg)
			MsTeamsParamsHelper.OwnerNames = MsTeamsParamsOwnerNames
		}
		if flag.Name == "ms-teams-params-search-string" {
			MsTeamsParamsHelper.SearchString = core.StringPtr(r.MsTeamsParamsSearchString)
		}
		if flag.Name == "ms-teams-params-size-bytes-lower-limit" {
			MsTeamsParamsHelper.SizeBytesLowerLimit = core.Int64Ptr(r.MsTeamsParamsSizeBytesLowerLimit)
		}
		if flag.Name == "ms-teams-params-size-bytes-upper-limit" {
			MsTeamsParamsHelper.SizeBytesUpperLimit = core.Int64Ptr(r.MsTeamsParamsSizeBytesUpperLimit)
		}
		if flag.Name == "ms-teams-params-types" {
			var MsTeamsParamsTypes []string
			err, msg := deserialize.List(r.MsTeamsParamsTypes, "ms-teams-params-types", "JSON", &MsTeamsParamsTypes)
			r.utils.HandleError(err, msg)
			MsTeamsParamsHelper.Types = MsTeamsParamsTypes
		}
		if flag.Name == "one-drive-params-category-types" {
			var OneDriveParamsCategoryTypes []string
			err, msg := deserialize.List(r.OneDriveParamsCategoryTypes, "one-drive-params-category-types", "JSON", &OneDriveParamsCategoryTypes)
			r.utils.HandleError(err, msg)
			OneDriveParamsHelper.CategoryTypes = OneDriveParamsCategoryTypes
		}
		if flag.Name == "one-drive-params-creation-end-time-secs" {
			OneDriveParamsHelper.CreationEndTimeSecs = core.Int64Ptr(r.OneDriveParamsCreationEndTimeSecs)
		}
		if flag.Name == "one-drive-params-creation-start-time-secs" {
			OneDriveParamsHelper.CreationStartTimeSecs = core.Int64Ptr(r.OneDriveParamsCreationStartTimeSecs)
		}
		if flag.Name == "one-drive-params-include-files" {
			OneDriveParamsHelper.IncludeFiles = core.BoolPtr(r.OneDriveParamsIncludeFiles)
		}
		if flag.Name == "one-drive-params-include-folders" {
			OneDriveParamsHelper.IncludeFolders = core.BoolPtr(r.OneDriveParamsIncludeFolders)
		}
		if flag.Name == "one-drive-params-o365-params" {
			var OneDriveParamsO365Params *backuprecoveryv1.O365SearchRequestParams
			err, msg := deserialize.Model(
				r.OneDriveParamsO365Params,
				"one-drive-params-o365-params",
				"O365SearchRequestParams",
				backuprecoveryv1.UnmarshalO365SearchRequestParams,
				&OneDriveParamsO365Params,
			)
			r.utils.HandleError(err, msg)
			OneDriveParamsHelper.O365Params = OneDriveParamsO365Params
			extraFieldPaths, err := r.utils.ValidateJSON(r.OneDriveParamsO365Params, `{"fields":["domainIds","groupIds","userIds","siteIds","teamsIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "one-drive-params-o365-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "one-drive-params-o365-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "one-drive-params-o365-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "one-drive-params-owner-names" {
			var OneDriveParamsOwnerNames []string
			err, msg := deserialize.List(r.OneDriveParamsOwnerNames, "one-drive-params-owner-names", "JSON", &OneDriveParamsOwnerNames)
			r.utils.HandleError(err, msg)
			OneDriveParamsHelper.OwnerNames = OneDriveParamsOwnerNames
		}
		if flag.Name == "one-drive-params-search-string" {
			OneDriveParamsHelper.SearchString = core.StringPtr(r.OneDriveParamsSearchString)
		}
		if flag.Name == "one-drive-params-size-bytes-lower-limit" {
			OneDriveParamsHelper.SizeBytesLowerLimit = core.Int64Ptr(r.OneDriveParamsSizeBytesLowerLimit)
		}
		if flag.Name == "one-drive-params-size-bytes-upper-limit" {
			OneDriveParamsHelper.SizeBytesUpperLimit = core.Int64Ptr(r.OneDriveParamsSizeBytesUpperLimit)
		}
		if flag.Name == "public-folder-params-search-string" {
			PublicFolderParamsHelper.SearchString = core.StringPtr(r.PublicFolderParamsSearchString)
		}
		if flag.Name == "public-folder-params-types" {
			var PublicFolderParamsTypes []string
			err, msg := deserialize.List(r.PublicFolderParamsTypes, "public-folder-params-types", "JSON", &PublicFolderParamsTypes)
			r.utils.HandleError(err, msg)
			PublicFolderParamsHelper.Types = PublicFolderParamsTypes
		}
		if flag.Name == "public-folder-params-has-attachment" {
			PublicFolderParamsHelper.HasAttachment = core.BoolPtr(r.PublicFolderParamsHasAttachment)
		}
		if flag.Name == "public-folder-params-sender-address" {
			PublicFolderParamsHelper.SenderAddress = core.StringPtr(r.PublicFolderParamsSenderAddress)
		}
		if flag.Name == "public-folder-params-recipient-addresses" {
			var PublicFolderParamsRecipientAddresses []string
			err, msg := deserialize.List(r.PublicFolderParamsRecipientAddresses, "public-folder-params-recipient-addresses", "JSON", &PublicFolderParamsRecipientAddresses)
			r.utils.HandleError(err, msg)
			PublicFolderParamsHelper.RecipientAddresses = PublicFolderParamsRecipientAddresses
		}
		if flag.Name == "public-folder-params-cc-recipient-addresses" {
			var PublicFolderParamsCcRecipientAddresses []string
			err, msg := deserialize.List(r.PublicFolderParamsCcRecipientAddresses, "public-folder-params-cc-recipient-addresses", "JSON", &PublicFolderParamsCcRecipientAddresses)
			r.utils.HandleError(err, msg)
			PublicFolderParamsHelper.CcRecipientAddresses = PublicFolderParamsCcRecipientAddresses
		}
		if flag.Name == "public-folder-params-bcc-recipient-addresses" {
			var PublicFolderParamsBccRecipientAddresses []string
			err, msg := deserialize.List(r.PublicFolderParamsBccRecipientAddresses, "public-folder-params-bcc-recipient-addresses", "JSON", &PublicFolderParamsBccRecipientAddresses)
			r.utils.HandleError(err, msg)
			PublicFolderParamsHelper.BccRecipientAddresses = PublicFolderParamsBccRecipientAddresses
		}
		if flag.Name == "public-folder-params-received-start-time-secs" {
			PublicFolderParamsHelper.ReceivedStartTimeSecs = core.Int64Ptr(r.PublicFolderParamsReceivedStartTimeSecs)
		}
		if flag.Name == "public-folder-params-received-end-time-secs" {
			PublicFolderParamsHelper.ReceivedEndTimeSecs = core.Int64Ptr(r.PublicFolderParamsReceivedEndTimeSecs)
		}
		if flag.Name == "sfdc-params-mutation-types" {
			var SfdcParamsMutationTypes []string
			err, msg := deserialize.List(r.SfdcParamsMutationTypes, "sfdc-params-mutation-types", "JSON", &SfdcParamsMutationTypes)
			r.utils.HandleError(err, msg)
			SfdcParamsHelper.MutationTypes = SfdcParamsMutationTypes
		}
		if flag.Name == "sfdc-params-object-name" {
			SfdcParamsHelper.ObjectName = core.StringPtr(r.SfdcParamsObjectName)
		}
		if flag.Name == "sfdc-params-query-string" {
			SfdcParamsHelper.QueryString = core.StringPtr(r.SfdcParamsQueryString)
		}
		if flag.Name == "sfdc-params-snapshot-id" {
			SfdcParamsHelper.SnapshotID = core.StringPtr(r.SfdcParamsSnapshotID)
		}
		if flag.Name == "sharepoint-params-category-types" {
			var SharepointParamsCategoryTypes []string
			err, msg := deserialize.List(r.SharepointParamsCategoryTypes, "sharepoint-params-category-types", "JSON", &SharepointParamsCategoryTypes)
			r.utils.HandleError(err, msg)
			SharepointParamsHelper.CategoryTypes = SharepointParamsCategoryTypes
		}
		if flag.Name == "sharepoint-params-creation-end-time-secs" {
			SharepointParamsHelper.CreationEndTimeSecs = core.Int64Ptr(r.SharepointParamsCreationEndTimeSecs)
		}
		if flag.Name == "sharepoint-params-creation-start-time-secs" {
			SharepointParamsHelper.CreationStartTimeSecs = core.Int64Ptr(r.SharepointParamsCreationStartTimeSecs)
		}
		if flag.Name == "sharepoint-params-include-files" {
			SharepointParamsHelper.IncludeFiles = core.BoolPtr(r.SharepointParamsIncludeFiles)
		}
		if flag.Name == "sharepoint-params-include-folders" {
			SharepointParamsHelper.IncludeFolders = core.BoolPtr(r.SharepointParamsIncludeFolders)
		}
		if flag.Name == "sharepoint-params-o365-params" {
			var SharepointParamsO365Params *backuprecoveryv1.O365SearchRequestParams
			err, msg := deserialize.Model(
				r.SharepointParamsO365Params,
				"sharepoint-params-o365-params",
				"O365SearchRequestParams",
				backuprecoveryv1.UnmarshalO365SearchRequestParams,
				&SharepointParamsO365Params,
			)
			r.utils.HandleError(err, msg)
			SharepointParamsHelper.O365Params = SharepointParamsO365Params
			extraFieldPaths, err := r.utils.ValidateJSON(r.SharepointParamsO365Params, `{"fields":["domainIds","groupIds","userIds","siteIds","teamsIds"]}`)
			if err != nil {
				r.utils.HandleError(err, translation.T("json-parsing-error", map[string]interface{}{
					"FLAG_NAME": "sharepoint-params-o365-params",
				}))
			} else if len(extraFieldPaths) == 1 {
				r.utils.Warn(translation.T("extraneous-json-field", map[string]interface{}{
					"FLAG_NAME":  "sharepoint-params-o365-params",
					"FIELD_PATH": extraFieldPaths[0],
				}))
			} else if len(extraFieldPaths) > 1 {
				r.utils.Warn(translation.T("extraneous-json-fields", map[string]interface{}{
					"FLAG_NAME":  "sharepoint-params-o365-params",
					"FIELD_PATH": strings.Join(extraFieldPaths, ", "),
				}))
			}
		}
		if flag.Name == "sharepoint-params-owner-names" {
			var SharepointParamsOwnerNames []string
			err, msg := deserialize.List(r.SharepointParamsOwnerNames, "sharepoint-params-owner-names", "JSON", &SharepointParamsOwnerNames)
			r.utils.HandleError(err, msg)
			SharepointParamsHelper.OwnerNames = SharepointParamsOwnerNames
		}
		if flag.Name == "sharepoint-params-search-string" {
			SharepointParamsHelper.SearchString = core.StringPtr(r.SharepointParamsSearchString)
		}
		if flag.Name == "sharepoint-params-size-bytes-lower-limit" {
			SharepointParamsHelper.SizeBytesLowerLimit = core.Int64Ptr(r.SharepointParamsSizeBytesLowerLimit)
		}
		if flag.Name == "sharepoint-params-size-bytes-upper-limit" {
			SharepointParamsHelper.SizeBytesUpperLimit = core.Int64Ptr(r.SharepointParamsSizeBytesUpperLimit)
		}
		if flag.Name == "uda-params-search-string" {
			UdaParamsHelper.SearchString = core.StringPtr(r.UdaParamsSearchString)
		}
		if flag.Name == "uda-params-source-ids" {
			var UdaParamsSourceIds []int64
			err, msg := deserialize.List(r.UdaParamsSourceIds, "uda-params-source-ids", "JSON", &UdaParamsSourceIds)
			r.utils.HandleError(err, msg)
			UdaParamsHelper.SourceIds = UdaParamsSourceIds
		}
	})

	if !reflect.ValueOf(*CassandraParamsHelper).IsZero() {
		if OptionsModel.CassandraParams == nil {
			OptionsModel.SetCassandraParams(CassandraParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "CassandraParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*CouchbaseParamsHelper).IsZero() {
		if OptionsModel.CouchbaseParams == nil {
			OptionsModel.SetCouchbaseParams(CouchbaseParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "CouchbaseParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*EmailParamsHelper).IsZero() {
		if OptionsModel.EmailParams == nil {
			OptionsModel.SetEmailParams(EmailParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "EmailParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*ExchangeParamsHelper).IsZero() {
		if OptionsModel.ExchangeParams == nil {
			OptionsModel.SetExchangeParams(ExchangeParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "ExchangeParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*FileParamsHelper).IsZero() {
		if OptionsModel.FileParams == nil {
			OptionsModel.SetFileParams(FileParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "FileParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*HbaseParamsHelper).IsZero() {
		if OptionsModel.HbaseParams == nil {
			OptionsModel.SetHbaseParams(HbaseParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "HbaseParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*HdfsParamsHelper).IsZero() {
		if OptionsModel.HdfsParams == nil {
			OptionsModel.SetHdfsParams(HdfsParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "HdfsParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*HiveParamsHelper).IsZero() {
		if OptionsModel.HiveParams == nil {
			OptionsModel.SetHiveParams(HiveParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "HiveParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*MongodbParamsHelper).IsZero() {
		if OptionsModel.MongodbParams == nil {
			OptionsModel.SetMongodbParams(MongodbParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "MongodbParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*MsGroupsParamsHelper).IsZero() {
		if OptionsModel.MsGroupsParams == nil {
			OptionsModel.SetMsGroupsParams(MsGroupsParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "MsGroupsParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*MsTeamsParamsHelper).IsZero() {
		if OptionsModel.MsTeamsParams == nil {
			OptionsModel.SetMsTeamsParams(MsTeamsParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "MsTeamsParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*OneDriveParamsHelper).IsZero() {
		if OptionsModel.OneDriveParams == nil {
			OptionsModel.SetOneDriveParams(OneDriveParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "OneDriveParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*PublicFolderParamsHelper).IsZero() {
		if OptionsModel.PublicFolderParams == nil {
			OptionsModel.SetPublicFolderParams(PublicFolderParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "PublicFolderParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*SfdcParamsHelper).IsZero() {
		if OptionsModel.SfdcParams == nil {
			OptionsModel.SetSfdcParams(SfdcParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "SfdcParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*SharepointParamsHelper).IsZero() {
		if OptionsModel.SharepointParams == nil {
			OptionsModel.SetSharepointParams(SharepointParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "SharepointParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}
	if !reflect.ValueOf(*UdaParamsHelper).IsZero() {
		if OptionsModel.UdaParams == nil {
			OptionsModel.SetUdaParams(UdaParamsHelper)
		} else {
			flagErr := errors.New(translation.T("mutually-exclusive-fields", map[string]interface{}{
				"FLAG_NAME": "UdaParams",
			}))
			r.utils.HandleError(flagErr, "")
		}
	}

	r.MakeRequest(OptionsModel)
}

func (r *SearchIndexedObjectsCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.SearchIndexedObjectsOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPCreate,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"objectType",
		"count",
		"paginationCookie",
		"cassandraObjects",
		"couchbaseObjects",
		"emails",
		"exchangeObjects",
		"files",
		"hbaseObjects",
		"hdfsObjects",
		"hiveObjects",
		"mongoObjects",
		"msGroupItems",
		"oneDriveItems",
		"publicFolderItems",
		"sfdcRecords",
		"sharepointItems",
		"teamsItems",
		"udaObjects",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for SearchObjects command
type SearchObjectsRequestSender struct{}

func (s SearchObjectsRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.SearchObjects(optionsModel.(*backuprecoveryv1.SearchObjectsOptions))
}

// Command Runner for SearchObjects command
func NewSearchObjectsCommandRunner(utils Utilities, sender RequestSender) *SearchObjectsCommandRunner {
	return &SearchObjectsCommandRunner{utils: utils, sender: sender}
}

type SearchObjectsCommandRunner struct {
	XIBMTenantID                   string
	RequestInitiatorType           string
	SearchString                   string
	Environments                   string
	ProtectionTypes                string
	ProtectionGroupIds             string
	ObjectIds                      string
	OsTypes                        string
	SourceIds                      string
	SourceUUIDs                    string
	IsProtected                    bool
	IsDeleted                      bool
	LastRunStatusList              string
	ClusterIdentifiers             string
	IncludeDeletedObjects          bool
	PaginationCookie               string
	Count                          int64
	MustHaveTagIds                 string
	MightHaveTagIds                string
	MustHaveSnapshotTagIds         string
	MightHaveSnapshotTagIds        string
	TagSearchName                  string
	TagNames                       string
	TagTypes                       string
	TagCategories                  string
	TagSubCategories               string
	IncludeHeliosTagInfoForObjects bool
	ExternalFilters                string
	RequiredFlags                  []string
	sender                         RequestSender
	utils                          Utilities
}

// Command mapping: objects-search, GetSearchObjectsCommand
func GetSearchObjectsCommand(r *SearchObjectsCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "objects-search [command options]",
		Short:                 translation.T("backup-recovery-objects-search-command-short-description"),
		Long:                  translation.T("backup-recovery-objects-search-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command": "objects-search",
		},
		Example: `  ibmcloud backup-recovery objects-search \
    --xibm-tenant-id tenantId \
    --request-initiator-type UIUser \
    --search-string searchString \
    --environments kPhysical,kSQL \
    --protection-types kAgent,kNative,kSnapshotManager,kRDSSnapshotManager,kAuroraSnapshotManager,kAwsS3,kAwsRDSPostgresBackup,kAwsAuroraPostgres,kAwsRDSPostgres,kAzureSQL,kFile,kVolume \
    --protection-group-ids protectionGroupId1 \
    --object-ids 26,27 \
    --os-types kLinux,kWindows \
    --source-ids 26,27 \
    --source-uuids sourceUuid1 \
    --is-protected=true \
    --is-deleted=true \
    --last-run-status-list Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,LegalHold \
    --cluster-identifiers clusterIdentifier1 \
    --include-deleted-objects=true \
    --pagination-cookie paginationCookie \
    --count 38 \
    --must-have-tag-ids 123:456:ABC-123 \
    --might-have-tag-ids 123:456:ABC-456 \
    --must-have-snapshot-tag-ids 123:456:DEF-123 \
    --might-have-snapshot-tag-ids 123:456:DEF-456 \
    --tag-search-name tagName \
    --tag-names tag1 \
    --tag-types System,Custom,ThirdParty \
    --tag-categories Security \
    --tag-sub-categories Classification,Threats,Anomalies,Dspm \
    --include-helios-tag-info-for-objects=true \
    --external-filters filter1`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-objects-search-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.RequestInitiatorType, "request-initiator-type", "", "", translation.T("backup-recovery-objects-search-request-initiator-type-flag-description"))
	cmd.Flags().StringVarP(&r.SearchString, "search-string", "", "", translation.T("backup-recovery-objects-search-search-string-flag-description"))
	cmd.Flags().StringVarP(&r.Environments, "environments", "", "", translation.T("backup-recovery-objects-search-environments-flag-description"))
	cmd.Flags().StringVarP(&r.ProtectionTypes, "protection-types", "", "", translation.T("backup-recovery-objects-search-protection-types-flag-description"))
	cmd.Flags().StringVarP(&r.ProtectionGroupIds, "protection-group-ids", "", "", translation.T("backup-recovery-objects-search-protection-group-ids-flag-description"))
	cmd.Flags().StringVarP(&r.ObjectIds, "object-ids", "", "", translation.T("backup-recovery-objects-search-object-ids-flag-description"))
	cmd.Flags().StringVarP(&r.OsTypes, "os-types", "", "", translation.T("backup-recovery-objects-search-os-types-flag-description"))
	cmd.Flags().StringVarP(&r.SourceIds, "source-ids", "", "", translation.T("backup-recovery-objects-search-source-ids-flag-description"))
	cmd.Flags().StringVarP(&r.SourceUUIDs, "source-uuids", "", "", translation.T("backup-recovery-objects-search-source-uuids-flag-description"))
	cmd.Flags().BoolVarP(&r.IsProtected, "is-protected", "", false, translation.T("backup-recovery-objects-search-is-protected-flag-description"))
	cmd.Flags().BoolVarP(&r.IsDeleted, "is-deleted", "", false, translation.T("backup-recovery-objects-search-is-deleted-flag-description"))
	cmd.Flags().StringVarP(&r.LastRunStatusList, "last-run-status-list", "", "", translation.T("backup-recovery-objects-search-last-run-status-list-flag-description"))
	cmd.Flags().StringVarP(&r.ClusterIdentifiers, "cluster-identifiers", "", "", translation.T("backup-recovery-objects-search-cluster-identifiers-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeDeletedObjects, "include-deleted-objects", "", false, translation.T("backup-recovery-objects-search-include-deleted-objects-flag-description"))
	cmd.Flags().StringVarP(&r.PaginationCookie, "pagination-cookie", "", "", translation.T("backup-recovery-objects-search-pagination-cookie-flag-description"))
	cmd.Flags().Int64VarP(&r.Count, "count", "", 0, translation.T("backup-recovery-objects-search-count-flag-description"))
	cmd.Flags().StringVarP(&r.MustHaveTagIds, "must-have-tag-ids", "", "", translation.T("backup-recovery-objects-search-must-have-tag-ids-flag-description"))
	cmd.Flags().StringVarP(&r.MightHaveTagIds, "might-have-tag-ids", "", "", translation.T("backup-recovery-objects-search-might-have-tag-ids-flag-description"))
	cmd.Flags().StringVarP(&r.MustHaveSnapshotTagIds, "must-have-snapshot-tag-ids", "", "", translation.T("backup-recovery-objects-search-must-have-snapshot-tag-ids-flag-description"))
	cmd.Flags().StringVarP(&r.MightHaveSnapshotTagIds, "might-have-snapshot-tag-ids", "", "", translation.T("backup-recovery-objects-search-might-have-snapshot-tag-ids-flag-description"))
	cmd.Flags().StringVarP(&r.TagSearchName, "tag-search-name", "", "", translation.T("backup-recovery-objects-search-tag-search-name-flag-description"))
	cmd.Flags().StringVarP(&r.TagNames, "tag-names", "", "", translation.T("backup-recovery-objects-search-tag-names-flag-description"))
	cmd.Flags().StringVarP(&r.TagTypes, "tag-types", "", "", translation.T("backup-recovery-objects-search-tag-types-flag-description"))
	cmd.Flags().StringVarP(&r.TagCategories, "tag-categories", "", "", translation.T("backup-recovery-objects-search-tag-categories-flag-description"))
	cmd.Flags().StringVarP(&r.TagSubCategories, "tag-sub-categories", "", "", translation.T("backup-recovery-objects-search-tag-sub-categories-flag-description"))
	cmd.Flags().BoolVarP(&r.IncludeHeliosTagInfoForObjects, "include-helios-tag-info-for-objects", "", false, translation.T("backup-recovery-objects-search-include-helios-tag-info-for-objects-flag-description"))
	cmd.Flags().StringVarP(&r.ExternalFilters, "external-filters", "", "", translation.T("backup-recovery-objects-search-external-filters-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running SearchObjects
func (r *SearchObjectsCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.SearchObjectsOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "request-initiator-type" {
			OptionsModel.SetRequestInitiatorType(r.RequestInitiatorType)
		}
		if flag.Name == "search-string" {
			OptionsModel.SetSearchString(r.SearchString)
		}
		if flag.Name == "environments" {
			var Environments []string
			err, msg := deserialize.List(r.Environments, "environments", "JSON", &Environments)
			r.utils.HandleError(err, msg)
			OptionsModel.SetEnvironments(Environments)
		}
		if flag.Name == "protection-types" {
			var ProtectionTypes []string
			err, msg := deserialize.List(r.ProtectionTypes, "protection-types", "JSON", &ProtectionTypes)
			r.utils.HandleError(err, msg)
			OptionsModel.SetProtectionTypes(ProtectionTypes)
		}
		if flag.Name == "protection-group-ids" {
			var ProtectionGroupIds []string
			err, msg := deserialize.List(r.ProtectionGroupIds, "protection-group-ids", "JSON", &ProtectionGroupIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetProtectionGroupIds(ProtectionGroupIds)
		}
		if flag.Name == "object-ids" {
			var ObjectIds []int64
			err, msg := deserialize.List(r.ObjectIds, "object-ids", "JSON", &ObjectIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetObjectIds(ObjectIds)
		}
		if flag.Name == "os-types" {
			var OsTypes []string
			err, msg := deserialize.List(r.OsTypes, "os-types", "JSON", &OsTypes)
			r.utils.HandleError(err, msg)
			OptionsModel.SetOsTypes(OsTypes)
		}
		if flag.Name == "source-ids" {
			var SourceIds []int64
			err, msg := deserialize.List(r.SourceIds, "source-ids", "JSON", &SourceIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSourceIds(SourceIds)
		}
		if flag.Name == "source-uuids" {
			var SourceUUIDs []string
			err, msg := deserialize.List(r.SourceUUIDs, "source-uuids", "JSON", &SourceUUIDs)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSourceUUIDs(SourceUUIDs)
		}
		if flag.Name == "is-protected" {
			OptionsModel.SetIsProtected(r.IsProtected)
		}
		if flag.Name == "is-deleted" {
			OptionsModel.SetIsDeleted(r.IsDeleted)
		}
		if flag.Name == "last-run-status-list" {
			var LastRunStatusList []string
			err, msg := deserialize.List(r.LastRunStatusList, "last-run-status-list", "JSON", &LastRunStatusList)
			r.utils.HandleError(err, msg)
			OptionsModel.SetLastRunStatusList(LastRunStatusList)
		}
		if flag.Name == "cluster-identifiers" {
			var ClusterIdentifiers []string
			err, msg := deserialize.List(r.ClusterIdentifiers, "cluster-identifiers", "JSON", &ClusterIdentifiers)
			r.utils.HandleError(err, msg)
			OptionsModel.SetClusterIdentifiers(ClusterIdentifiers)
		}
		if flag.Name == "include-deleted-objects" {
			OptionsModel.SetIncludeDeletedObjects(r.IncludeDeletedObjects)
		}
		if flag.Name == "pagination-cookie" {
			OptionsModel.SetPaginationCookie(r.PaginationCookie)
		}
		if flag.Name == "count" {
			OptionsModel.SetCount(r.Count)
		}
		if flag.Name == "must-have-tag-ids" {
			var MustHaveTagIds []string
			err, msg := deserialize.List(r.MustHaveTagIds, "must-have-tag-ids", "JSON", &MustHaveTagIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMustHaveTagIds(MustHaveTagIds)
		}
		if flag.Name == "might-have-tag-ids" {
			var MightHaveTagIds []string
			err, msg := deserialize.List(r.MightHaveTagIds, "might-have-tag-ids", "JSON", &MightHaveTagIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMightHaveTagIds(MightHaveTagIds)
		}
		if flag.Name == "must-have-snapshot-tag-ids" {
			var MustHaveSnapshotTagIds []string
			err, msg := deserialize.List(r.MustHaveSnapshotTagIds, "must-have-snapshot-tag-ids", "JSON", &MustHaveSnapshotTagIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMustHaveSnapshotTagIds(MustHaveSnapshotTagIds)
		}
		if flag.Name == "might-have-snapshot-tag-ids" {
			var MightHaveSnapshotTagIds []string
			err, msg := deserialize.List(r.MightHaveSnapshotTagIds, "might-have-snapshot-tag-ids", "JSON", &MightHaveSnapshotTagIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetMightHaveSnapshotTagIds(MightHaveSnapshotTagIds)
		}
		if flag.Name == "tag-search-name" {
			OptionsModel.SetTagSearchName(r.TagSearchName)
		}
		if flag.Name == "tag-names" {
			var TagNames []string
			err, msg := deserialize.List(r.TagNames, "tag-names", "JSON", &TagNames)
			r.utils.HandleError(err, msg)
			OptionsModel.SetTagNames(TagNames)
		}
		if flag.Name == "tag-types" {
			var TagTypes []string
			err, msg := deserialize.List(r.TagTypes, "tag-types", "JSON", &TagTypes)
			r.utils.HandleError(err, msg)
			OptionsModel.SetTagTypes(TagTypes)
		}
		if flag.Name == "tag-categories" {
			var TagCategories []string
			err, msg := deserialize.List(r.TagCategories, "tag-categories", "JSON", &TagCategories)
			r.utils.HandleError(err, msg)
			OptionsModel.SetTagCategories(TagCategories)
		}
		if flag.Name == "tag-sub-categories" {
			var TagSubCategories []string
			err, msg := deserialize.List(r.TagSubCategories, "tag-sub-categories", "JSON", &TagSubCategories)
			r.utils.HandleError(err, msg)
			OptionsModel.SetTagSubCategories(TagSubCategories)
		}
		if flag.Name == "include-helios-tag-info-for-objects" {
			OptionsModel.SetIncludeHeliosTagInfoForObjects(r.IncludeHeliosTagInfoForObjects)
		}
		if flag.Name == "external-filters" {
			var ExternalFilters []string
			err, msg := deserialize.List(r.ExternalFilters, "external-filters", "JSON", &ExternalFilters)
			r.utils.HandleError(err, msg)
			OptionsModel.SetExternalFilters(ExternalFilters)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *SearchObjectsCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.SearchObjectsOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"objects",
		"paginationCookie",
		"count",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}

// RequestSender for SearchProtectedObjects command
type SearchProtectedObjectsRequestSender struct{}

func (s SearchProtectedObjectsRequestSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return ServiceInstance.SearchProtectedObjects(optionsModel.(*backuprecoveryv1.SearchProtectedObjectsOptions))
}

// Command Runner for SearchProtectedObjects command
func NewSearchProtectedObjectsCommandRunner(utils Utilities, sender RequestSender) *SearchProtectedObjectsCommandRunner {
	return &SearchProtectedObjectsCommandRunner{utils: utils, sender: sender}
}

type SearchProtectedObjectsCommandRunner struct {
	XIBMTenantID            string
	RequestInitiatorType    string
	SearchString            string
	Environments            string
	SnapshotActions         string
	ObjectActionKey         string
	ProtectionGroupIds      string
	ObjectIds               string
	SubResultSize           int64
	FilterSnapshotFromUsecs int64
	FilterSnapshotToUsecs   int64
	OsTypes                 string
	SourceIds               string
	RunInstanceIds          string
	CdpProtectedOnly        bool
	UseCachedData           bool
	RequiredFlags           []string
	sender                  RequestSender
	utils                   Utilities
}

// Command mapping: protected-objects-search, GetSearchProtectedObjectsCommand
func GetSearchProtectedObjectsCommand(r *SearchProtectedObjectsCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "protected-objects-search [command options]",
		Short:                 translation.T("backup-recovery-protected-objects-search-command-short-description"),
		Long:                  translation.T("backup-recovery-protected-objects-search-command-long-description"),
		Run:                   r.Run,
		DisableFlagsInUseLine: true,
		Annotations: map[string]string{
			"x-cli-command": "protected-objects-search",
		},
		Example: `  ibmcloud backup-recovery protected-objects-search \
    --xibm-tenant-id tenantId \
    --request-initiator-type UIUser \
    --search-string searchString \
    --environments kPhysical,kSQL \
    --snapshot-actions RecoverVMs,RecoverFiles,InstantVolumeMount,RecoverVmDisks,MountVolumes,RecoverVApps,RecoverRDS,RecoverAurora,RecoverS3Buckets,RecoverApps,RecoverNasVolume,RecoverPhysicalVolumes,RecoverSystem,RecoverSanVolumes,RecoverNamespaces,RecoverObjects,DownloadFilesAndFolders,RecoverPublicFolders,RecoverVAppTemplates,RecoverMailbox,RecoverOneDrive,RecoverMsTeam,RecoverMsGroup,RecoverSharePoint,ConvertToPst,RecoverSfdcRecords,RecoverAzureSQL,DownloadChats,RecoverRDSPostgres,RecoverMailboxCSM,RecoverOneDriveCSM,RecoverSharePointCSM \
    --object-action-key kPhysical \
    --protection-group-ids protectionGroupId1 \
    --object-ids 26,27 \
    --sub-result-size 38 \
    --filter-snapshot-from-usecs 26 \
    --filter-snapshot-to-usecs 26 \
    --os-types kLinux,kWindows \
    --source-ids 26,27 \
    --run-instance-ids 26,27 \
    --cdp-protected-only=true \
    --use-cached-data=true`,
	}

	cmd.Flags().StringVarP(&r.XIBMTenantID, "xibm-tenant-id", "", "", translation.T("backup-recovery-protected-objects-search-xibm-tenant-id-flag-description"))
	cmd.Flags().StringVarP(&r.RequestInitiatorType, "request-initiator-type", "", "", translation.T("backup-recovery-protected-objects-search-request-initiator-type-flag-description"))
	cmd.Flags().StringVarP(&r.SearchString, "search-string", "", "", translation.T("backup-recovery-protected-objects-search-search-string-flag-description"))
	cmd.Flags().StringVarP(&r.Environments, "environments", "", "", translation.T("backup-recovery-protected-objects-search-environments-flag-description"))
	cmd.Flags().StringVarP(&r.SnapshotActions, "snapshot-actions", "", "", translation.T("backup-recovery-protected-objects-search-snapshot-actions-flag-description"))
	cmd.Flags().StringVarP(&r.ObjectActionKey, "object-action-key", "", "", translation.T("backup-recovery-protected-objects-search-object-action-key-flag-description"))
	cmd.Flags().StringVarP(&r.ProtectionGroupIds, "protection-group-ids", "", "", translation.T("backup-recovery-protected-objects-search-protection-group-ids-flag-description"))
	cmd.Flags().StringVarP(&r.ObjectIds, "object-ids", "", "", translation.T("backup-recovery-protected-objects-search-object-ids-flag-description"))
	cmd.Flags().Int64VarP(&r.SubResultSize, "sub-result-size", "", 0, translation.T("backup-recovery-protected-objects-search-sub-result-size-flag-description"))
	cmd.Flags().Int64VarP(&r.FilterSnapshotFromUsecs, "filter-snapshot-from-usecs", "", 0, translation.T("backup-recovery-protected-objects-search-filter-snapshot-from-usecs-flag-description"))
	cmd.Flags().Int64VarP(&r.FilterSnapshotToUsecs, "filter-snapshot-to-usecs", "", 0, translation.T("backup-recovery-protected-objects-search-filter-snapshot-to-usecs-flag-description"))
	cmd.Flags().StringVarP(&r.OsTypes, "os-types", "", "", translation.T("backup-recovery-protected-objects-search-os-types-flag-description"))
	cmd.Flags().StringVarP(&r.SourceIds, "source-ids", "", "", translation.T("backup-recovery-protected-objects-search-source-ids-flag-description"))
	cmd.Flags().StringVarP(&r.RunInstanceIds, "run-instance-ids", "", "", translation.T("backup-recovery-protected-objects-search-run-instance-ids-flag-description"))
	cmd.Flags().BoolVarP(&r.CdpProtectedOnly, "cdp-protected-only", "", false, translation.T("backup-recovery-protected-objects-search-cdp-protected-only-flag-description"))
	cmd.Flags().BoolVarP(&r.UseCachedData, "use-cached-data", "", false, translation.T("backup-recovery-protected-objects-search-use-cached-data-flag-description"))
	r.RequiredFlags = []string{
		"xibm-tenant-id",
	}

	return cmd
}

// Primary logic for running SearchProtectedObjects
func (r *SearchProtectedObjectsCommandRunner) Run(cmd *cobra.Command, args []string) {
	Service.InitializeServiceInstance(cmd.Flags())

	err := r.utils.ValidateRequiredFlags(r.RequiredFlags, cmd.Flags(), serviceName)
	r.utils.HandleError(err, translation.T("root-command-error"))

	r.utils.ConfirmRunningCommand()
	OptionsModel := backuprecoveryv1.SearchProtectedObjectsOptions{}

	// optional params should only be set when they are explicitly passed by the user
	// otherwise, the default type values will be sent to the service
	flagSet := cmd.Flags()
	flagSet.Visit(func(flag *pflag.Flag) {
		if flag.Name == "xibm-tenant-id" {
			OptionsModel.SetXIBMTenantID(r.XIBMTenantID)
		}
		if flag.Name == "request-initiator-type" {
			OptionsModel.SetRequestInitiatorType(r.RequestInitiatorType)
		}
		if flag.Name == "search-string" {
			OptionsModel.SetSearchString(r.SearchString)
		}
		if flag.Name == "environments" {
			var Environments []string
			err, msg := deserialize.List(r.Environments, "environments", "JSON", &Environments)
			r.utils.HandleError(err, msg)
			OptionsModel.SetEnvironments(Environments)
		}
		if flag.Name == "snapshot-actions" {
			var SnapshotActions []string
			err, msg := deserialize.List(r.SnapshotActions, "snapshot-actions", "JSON", &SnapshotActions)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSnapshotActions(SnapshotActions)
		}
		if flag.Name == "object-action-key" {
			OptionsModel.SetObjectActionKey(r.ObjectActionKey)
		}
		if flag.Name == "protection-group-ids" {
			var ProtectionGroupIds []string
			err, msg := deserialize.List(r.ProtectionGroupIds, "protection-group-ids", "JSON", &ProtectionGroupIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetProtectionGroupIds(ProtectionGroupIds)
		}
		if flag.Name == "object-ids" {
			var ObjectIds []int64
			err, msg := deserialize.List(r.ObjectIds, "object-ids", "JSON", &ObjectIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetObjectIds(ObjectIds)
		}
		if flag.Name == "sub-result-size" {
			OptionsModel.SetSubResultSize(r.SubResultSize)
		}
		if flag.Name == "filter-snapshot-from-usecs" {
			OptionsModel.SetFilterSnapshotFromUsecs(r.FilterSnapshotFromUsecs)
		}
		if flag.Name == "filter-snapshot-to-usecs" {
			OptionsModel.SetFilterSnapshotToUsecs(r.FilterSnapshotToUsecs)
		}
		if flag.Name == "os-types" {
			var OsTypes []string
			err, msg := deserialize.List(r.OsTypes, "os-types", "JSON", &OsTypes)
			r.utils.HandleError(err, msg)
			OptionsModel.SetOsTypes(OsTypes)
		}
		if flag.Name == "source-ids" {
			var SourceIds []int64
			err, msg := deserialize.List(r.SourceIds, "source-ids", "JSON", &SourceIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetSourceIds(SourceIds)
		}
		if flag.Name == "run-instance-ids" {
			var RunInstanceIds []int64
			err, msg := deserialize.List(r.RunInstanceIds, "run-instance-ids", "JSON", &RunInstanceIds)
			r.utils.HandleError(err, msg)
			OptionsModel.SetRunInstanceIds(RunInstanceIds)
		}
		if flag.Name == "cdp-protected-only" {
			OptionsModel.SetCdpProtectedOnly(r.CdpProtectedOnly)
		}
		if flag.Name == "use-cached-data" {
			OptionsModel.SetUseCachedData(r.UseCachedData)
		}
	})

	r.MakeRequest(OptionsModel)
}

func (r *SearchProtectedObjectsCommandRunner) MakeRequest(OptionsModel backuprecoveryv1.SearchProtectedObjectsOptions) {

	// Set the operation metadata that will be passed to the utils package to help handling the response more correctly.
	err := r.utils.SetOperationMetadata(utils.OperationMetadata{
		OperationType: utils.OPRead,
	})
	r.utils.HandleError(err, "")

	_, DetailedResponse, ResponseErr := r.sender.Send(&OptionsModel)

	r.utils.SetTableHeaderOrder([]string{
		"objects",
		"metadata",
		"numResults",
	})

	r.utils.ProcessResponse(DetailedResponse, ResponseErr)
}
