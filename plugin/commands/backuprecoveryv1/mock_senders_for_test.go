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

package backuprecoveryv1_test

import (
	"encoding/base64"
	"encoding/json"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/ibm-backup-recovery-sdk-go/backuprecoveryv1"
	"github.com/go-openapi/strfmt"
	. "github.com/onsi/gomega"
	"ibmcloud-backup-recovery-cli/plugin/version"
	"ibmcloud-backup-recovery-cli/testing_utilities"
)

// Fake senders for ListProtectionSources
type ListProtectionSourcesMockSender struct{}

func (f ListProtectionSourcesMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.ListProtectionSourcesOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.ExcludeOffice365Types).To(Equal([]string{"kDomain","kOutlook","kMailbox","kUsers","kUser","kGroups","kGroup","kSites","kSite"}))
	Expect(createdOptions.GetTeamsChannels).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.AfterCursorEntityID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.BeforeCursorEntityID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.NodeID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.PageSize).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.HasValidMailbox).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.HasValidOnedrive).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IsSecurityGroup).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.ID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.NumLevels).To(Equal(core.Float64Ptr(float64(72.5))))
	Expect(createdOptions.ExcludeTypes).To(Equal([]string{"kVCenter","kFolder","kDatacenter","kComputeResource","kClusterComputeResource","kResourcePool","kDatastore","kHostSystem","kVirtualMachine","kVirtualApp","kStandaloneHost","kStoragePod","kNetwork","kDistributedVirtualPortgroup","kTagCategory","kTag"}))
	Expect(createdOptions.ExcludeAwsTypes).To(Equal([]string{"kEC2Instance","kRDSInstance","kAuroraCluster","kS3Bucket","kTag","kRDSTag","kAuroraTag","kS3Tag"}))
	Expect(createdOptions.ExcludeKubernetesTypes).To(Equal([]string{"kService"}))
	Expect(createdOptions.IncludeDatastores).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IncludeNetworks).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IncludeVMFolders).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IncludeSfdcFields).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IncludeSystemVApps).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.Environments).To(Equal([]string{"kVMware","kHyperV","kSQL","kView","kPuppeteer","kPhysical","kPure","kNimble","kAzure","kNetapp","kAgent","kGenericNas","kAcropolis","kPhysicalFiles","kIsilon","kGPFS","kKVM","kAWS","kExchange","kHyperVVSS","kOracle","kGCP","kFlashBlade","kAWSNative","kO365","kO365Outlook","kHyperFlex","kGCPNative","kAzureNative","kKubernetes","kElastifile","kAD","kRDSSnapshotManager","kCassandra","kMongoDB","kCouchbase","kHdfs","kHBase","kUDA","KSfdc","kAwsS3"}))
	Expect(createdOptions.Environment).To(Equal(core.StringPtr("kPhysical")))
	Expect(createdOptions.IncludeEntityPermissionInfo).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.Sids).To(Equal([]string{"sid1"}))
	Expect(createdOptions.IncludeSourceCredentials).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.EncryptionKey).To(Equal(core.StringPtr("encryptionKey")))
	Expect(createdOptions.IncludeObjectProtectionInfo).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.PruneNonCriticalInfo).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.PruneAggregationInfo).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.RequestInitiatorType).To(Equal(core.StringPtr("requestInitiatorType")))
	Expect(createdOptions.UseCachedData).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.AllUnderHierarchy).To(Equal(core.BoolPtr(true)))
	return testing_utilities.GetMockSuccessResponse()
}

type ListProtectionSourcesErrorSender struct{}

func (f ListProtectionSourcesErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetSourceRegistrations
type GetSourceRegistrationsMockSender struct{}

func (f GetSourceRegistrationsMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetSourceRegistrationsOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Ids).To(Equal([]int64{int64(38),int64(39)}))
	Expect(createdOptions.IncludeSourceCredentials).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.EncryptionKey).To(Equal(core.StringPtr("encryptionKey")))
	Expect(createdOptions.UseCachedData).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IncludeExternalMetadata).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IgnoreTenantMigrationInProgressCheck).To(Equal(core.BoolPtr(true)))
	return testing_utilities.GetMockSuccessResponse()
}

type GetSourceRegistrationsErrorSender struct{}

func (f GetSourceRegistrationsErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for RegisterProtectionSource
type RegisterProtectionSourceMockSender struct{}

func (f RegisterProtectionSourceMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the ConnectionConfig model
	connectionConfigModel := new(backuprecoveryv1.ConnectionConfig)
	connectionConfigModel.ConnectionID = core.Int64Ptr(int64(26))
	connectionConfigModel.EntityID = core.Int64Ptr(int64(26))
	connectionConfigModel.ConnectorGroupID = core.Int64Ptr(int64(26))
	connectionConfigModel.DataSourceConnectionID = core.StringPtr("DatasourceConnectionId")

	// Construct an instance of the KeyValuePair model
	keyValuePairModel := new(backuprecoveryv1.KeyValuePair)
	keyValuePairModel.Key = core.StringPtr("configKey")
	keyValuePairModel.Value = core.StringPtr("configValue")

	// Construct an instance of the PhysicalSourceRegistrationParams model
	physicalSourceRegistrationParamsModel := new(backuprecoveryv1.PhysicalSourceRegistrationParams)
	physicalSourceRegistrationParamsModel.Endpoint = core.StringPtr("xxx.xx.xx.xx")
	physicalSourceRegistrationParamsModel.ForceRegister = core.BoolPtr(true)
	physicalSourceRegistrationParamsModel.HostType = core.StringPtr("kLinux")
	physicalSourceRegistrationParamsModel.PhysicalType = core.StringPtr("kGroup")
	physicalSourceRegistrationParamsModel.Applications = []string{"kSQL","kOracle"}

	createdOptions, ok := optionsModel.(*backuprecoveryv1.RegisterProtectionSourceOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Environment).To(Equal(core.StringPtr("kPhysical")))
	Expect(createdOptions.Name).To(Equal(core.StringPtr("register-protection-source")))
	Expect(createdOptions.IsInternalEncrypted).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.EncryptionKey).To(Equal(core.StringPtr("encryptionKey")))
	Expect(createdOptions.ConnectionID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(ResolveModel(createdOptions.Connections)).To(Equal(ResolveModel([]backuprecoveryv1.ConnectionConfig{*connectionConfigModel})))
	Expect(createdOptions.ConnectorGroupID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(ResolveModel(createdOptions.AdvancedConfigs)).To(Equal(ResolveModel([]backuprecoveryv1.KeyValuePair{*keyValuePairModel})))
	Expect(createdOptions.DataSourceConnectionID).To(Equal(core.StringPtr("DatasourceConnectionId")))
	Expect(ResolveModel(createdOptions.PhysicalParams)).To(Equal(ResolveModel(physicalSourceRegistrationParamsModel)))
	return testing_utilities.GetMockSuccessResponse()
}

type RegisterProtectionSourceErrorSender struct{}

func (f RegisterProtectionSourceErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetProtectionSourceRegistration
type GetProtectionSourceRegistrationMockSender struct{}

func (f GetProtectionSourceRegistrationMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetProtectionSourceRegistrationOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.RequestInitiatorType).To(Equal(core.StringPtr("UIUser")))
	return testing_utilities.GetMockSuccessResponse()
}

type GetProtectionSourceRegistrationErrorSender struct{}

func (f GetProtectionSourceRegistrationErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for UpdateProtectionSourceRegistration
type UpdateProtectionSourceRegistrationMockSender struct{}

func (f UpdateProtectionSourceRegistrationMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the ConnectionConfig model
	connectionConfigModel := new(backuprecoveryv1.ConnectionConfig)
	connectionConfigModel.ConnectionID = core.Int64Ptr(int64(26))
	connectionConfigModel.EntityID = core.Int64Ptr(int64(26))
	connectionConfigModel.ConnectorGroupID = core.Int64Ptr(int64(26))
	connectionConfigModel.DataSourceConnectionID = core.StringPtr("DatasourceConnectionId")

	// Construct an instance of the KeyValuePair model
	keyValuePairModel := new(backuprecoveryv1.KeyValuePair)
	keyValuePairModel.Key = core.StringPtr("configKey")
	keyValuePairModel.Value = core.StringPtr("configValue")

	// Construct an instance of the PhysicalSourceRegistrationParams model
	physicalSourceRegistrationParamsModel := new(backuprecoveryv1.PhysicalSourceRegistrationParams)
	physicalSourceRegistrationParamsModel.Endpoint = core.StringPtr("xxx.xx.xx.xx")
	physicalSourceRegistrationParamsModel.ForceRegister = core.BoolPtr(true)
	physicalSourceRegistrationParamsModel.HostType = core.StringPtr("kLinux")
	physicalSourceRegistrationParamsModel.PhysicalType = core.StringPtr("kGroup")
	physicalSourceRegistrationParamsModel.Applications = []string{"kSQL","kOracle"}

	createdOptions, ok := optionsModel.(*backuprecoveryv1.UpdateProtectionSourceRegistrationOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Environment).To(Equal(core.StringPtr("kPhysical")))
	Expect(createdOptions.Name).To(Equal(core.StringPtr("update-protection-source")))
	Expect(createdOptions.IsInternalEncrypted).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.EncryptionKey).To(Equal(core.StringPtr("encryptionKey")))
	Expect(createdOptions.ConnectionID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(ResolveModel(createdOptions.Connections)).To(Equal(ResolveModel([]backuprecoveryv1.ConnectionConfig{*connectionConfigModel})))
	Expect(createdOptions.ConnectorGroupID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(ResolveModel(createdOptions.AdvancedConfigs)).To(Equal(ResolveModel([]backuprecoveryv1.KeyValuePair{*keyValuePairModel})))
	Expect(createdOptions.DataSourceConnectionID).To(Equal(core.StringPtr("DatasourceConnectionId")))
	Expect(createdOptions.LastModifiedTimestampUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(ResolveModel(createdOptions.PhysicalParams)).To(Equal(ResolveModel(physicalSourceRegistrationParamsModel)))
	return testing_utilities.GetMockSuccessResponse()
}

type UpdateProtectionSourceRegistrationErrorSender struct{}

func (f UpdateProtectionSourceRegistrationErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for PatchProtectionSourceRegistration
type PatchProtectionSourceRegistrationMockSender struct{}

func (f PatchProtectionSourceRegistrationMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.PatchProtectionSourceRegistrationOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Environment).To(Equal(core.StringPtr("kPhysical")))
	return testing_utilities.GetMockSuccessResponse()
}

type PatchProtectionSourceRegistrationErrorSender struct{}

func (f PatchProtectionSourceRegistrationErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for DeleteProtectionSourceRegistration
type DeleteProtectionSourceRegistrationMockSender struct{}

func (f DeleteProtectionSourceRegistrationMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.DeleteProtectionSourceRegistrationOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	return testing_utilities.GetMockSuccessResponse()
}

type DeleteProtectionSourceRegistrationErrorSender struct{}

func (f DeleteProtectionSourceRegistrationErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for RefreshProtectionSourceByID
type RefreshProtectionSourceByIDMockSender struct{}

func (f RefreshProtectionSourceByIDMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.RefreshProtectionSourceByIdOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	return testing_utilities.GetMockSuccessResponse()
}

type RefreshProtectionSourceByIDErrorSender struct{}

func (f RefreshProtectionSourceByIDErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetUpgradeTasks
type GetUpgradeTasksMockSender struct{}

func (f GetUpgradeTasksMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetUpgradeTasksOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Ids).To(Equal([]int64{int64(26),int64(27)}))
	return testing_utilities.GetMockSuccessResponse()
}

type GetUpgradeTasksErrorSender struct{}

func (f GetUpgradeTasksErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for CreateUpgradeTask
type CreateUpgradeTaskMockSender struct{}

func (f CreateUpgradeTaskMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.CreateUpgradeTaskOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.AgentIDs).To(Equal([]int64{int64(26),int64(27)}))
	Expect(createdOptions.Description).To(Equal(core.StringPtr("Upgrade task")))
	Expect(createdOptions.Name).To(Equal(core.StringPtr("create-upgrade-task")))
	Expect(createdOptions.RetryTaskID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.ScheduleEndTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.ScheduleTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	return testing_utilities.GetMockSuccessResponse()
}

type CreateUpgradeTaskErrorSender struct{}

func (f CreateUpgradeTaskErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetProtectionPolicies
type GetProtectionPoliciesMockSender struct{}

func (f GetProtectionPoliciesMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetProtectionPoliciesOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.RequestInitiatorType).To(Equal(core.StringPtr("UIUser")))
	Expect(createdOptions.Ids).To(Equal([]string{"policyId1"}))
	Expect(createdOptions.PolicyNames).To(Equal([]string{"policyName1"}))
	Expect(createdOptions.Types).To(Equal([]string{"Regular","Internal"}))
	Expect(createdOptions.ExcludeLinkedPolicies).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IncludeReplicatedPolicies).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IncludeStats).To(Equal(core.BoolPtr(true)))
	return testing_utilities.GetMockSuccessResponse()
}

type GetProtectionPoliciesErrorSender struct{}

func (f GetProtectionPoliciesErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for CreateProtectionPolicy
type CreateProtectionPolicyMockSender struct{}

func (f CreateProtectionPolicyMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the MinuteSchedule model
	minuteScheduleModel := new(backuprecoveryv1.MinuteSchedule)
	minuteScheduleModel.Frequency = core.Int64Ptr(int64(1))

	// Construct an instance of the HourSchedule model
	hourScheduleModel := new(backuprecoveryv1.HourSchedule)
	hourScheduleModel.Frequency = core.Int64Ptr(int64(1))

	// Construct an instance of the DaySchedule model
	dayScheduleModel := new(backuprecoveryv1.DaySchedule)
	dayScheduleModel.Frequency = core.Int64Ptr(int64(1))

	// Construct an instance of the WeekSchedule model
	weekScheduleModel := new(backuprecoveryv1.WeekSchedule)
	weekScheduleModel.DayOfWeek = []string{"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"}

	// Construct an instance of the MonthSchedule model
	monthScheduleModel := new(backuprecoveryv1.MonthSchedule)
	monthScheduleModel.DayOfWeek = []string{"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"}
	monthScheduleModel.WeekOfMonth = core.StringPtr("First")
	monthScheduleModel.DayOfMonth = core.Int64Ptr(int64(10))

	// Construct an instance of the YearSchedule model
	yearScheduleModel := new(backuprecoveryv1.YearSchedule)
	yearScheduleModel.DayOfYear = core.StringPtr("First")

	// Construct an instance of the IncrementalSchedule model
	incrementalScheduleModel := new(backuprecoveryv1.IncrementalSchedule)
	incrementalScheduleModel.Unit = core.StringPtr("Minutes")
	incrementalScheduleModel.MinuteSchedule = minuteScheduleModel
	incrementalScheduleModel.HourSchedule = hourScheduleModel
	incrementalScheduleModel.DaySchedule = dayScheduleModel
	incrementalScheduleModel.WeekSchedule = weekScheduleModel
	incrementalScheduleModel.MonthSchedule = monthScheduleModel
	incrementalScheduleModel.YearSchedule = yearScheduleModel

	// Construct an instance of the IncrementalBackupPolicy model
	incrementalBackupPolicyModel := new(backuprecoveryv1.IncrementalBackupPolicy)
	incrementalBackupPolicyModel.Schedule = incrementalScheduleModel

	// Construct an instance of the FullSchedule model
	fullScheduleModel := new(backuprecoveryv1.FullSchedule)
	fullScheduleModel.Unit = core.StringPtr("Days")
	fullScheduleModel.DaySchedule = dayScheduleModel
	fullScheduleModel.WeekSchedule = weekScheduleModel
	fullScheduleModel.MonthSchedule = monthScheduleModel
	fullScheduleModel.YearSchedule = yearScheduleModel

	// Construct an instance of the FullBackupPolicy model
	fullBackupPolicyModel := new(backuprecoveryv1.FullBackupPolicy)
	fullBackupPolicyModel.Schedule = fullScheduleModel

	// Construct an instance of the DataLockConfig model
	dataLockConfigModel := new(backuprecoveryv1.DataLockConfig)
	dataLockConfigModel.Mode = core.StringPtr("Compliance")
	dataLockConfigModel.Unit = core.StringPtr("Days")
	dataLockConfigModel.Duration = core.Int64Ptr(int64(1))
	dataLockConfigModel.EnableWormOnExternalTarget = core.BoolPtr(true)

	// Construct an instance of the Retention model
	retentionModel := new(backuprecoveryv1.Retention)
	retentionModel.Unit = core.StringPtr("Days")
	retentionModel.Duration = core.Int64Ptr(int64(1))
	retentionModel.DataLockConfig = dataLockConfigModel

	// Construct an instance of the FullScheduleAndRetention model
	fullScheduleAndRetentionModel := new(backuprecoveryv1.FullScheduleAndRetention)
	fullScheduleAndRetentionModel.Schedule = fullScheduleModel
	fullScheduleAndRetentionModel.Retention = retentionModel

	// Construct an instance of the AWSTier model
	awsTierModel := new(backuprecoveryv1.AWSTier)
	awsTierModel.MoveAfterUnit = core.StringPtr("Days")
	awsTierModel.MoveAfter = core.Int64Ptr(int64(26))
	awsTierModel.TierType = core.StringPtr("kAmazonS3Standard")

	// Construct an instance of the AWSTiers model
	awsTiersModel := new(backuprecoveryv1.AWSTiers)
	awsTiersModel.Tiers = []backuprecoveryv1.AWSTier{*awsTierModel}

	// Construct an instance of the AzureTier model
	azureTierModel := new(backuprecoveryv1.AzureTier)
	azureTierModel.MoveAfterUnit = core.StringPtr("Days")
	azureTierModel.MoveAfter = core.Int64Ptr(int64(26))
	azureTierModel.TierType = core.StringPtr("kAzureTierHot")

	// Construct an instance of the AzureTiers model
	azureTiersModel := new(backuprecoveryv1.AzureTiers)
	azureTiersModel.Tiers = []backuprecoveryv1.AzureTier{*azureTierModel}

	// Construct an instance of the GoogleTier model
	googleTierModel := new(backuprecoveryv1.GoogleTier)
	googleTierModel.MoveAfterUnit = core.StringPtr("Days")
	googleTierModel.MoveAfter = core.Int64Ptr(int64(26))
	googleTierModel.TierType = core.StringPtr("kGoogleStandard")

	// Construct an instance of the GoogleTiers model
	googleTiersModel := new(backuprecoveryv1.GoogleTiers)
	googleTiersModel.Tiers = []backuprecoveryv1.GoogleTier{*googleTierModel}

	// Construct an instance of the OracleTier model
	oracleTierModel := new(backuprecoveryv1.OracleTier)
	oracleTierModel.MoveAfterUnit = core.StringPtr("Days")
	oracleTierModel.MoveAfter = core.Int64Ptr(int64(26))
	oracleTierModel.TierType = core.StringPtr("kOracleTierStandard")

	// Construct an instance of the OracleTiers model
	oracleTiersModel := new(backuprecoveryv1.OracleTiers)
	oracleTiersModel.Tiers = []backuprecoveryv1.OracleTier{*oracleTierModel}

	// Construct an instance of the TierLevelSettings model
	tierLevelSettingsModel := new(backuprecoveryv1.TierLevelSettings)
	tierLevelSettingsModel.AwsTiering = awsTiersModel
	tierLevelSettingsModel.AzureTiering = azureTiersModel
	tierLevelSettingsModel.CloudPlatform = core.StringPtr("AWS")
	tierLevelSettingsModel.GoogleTiering = googleTiersModel
	tierLevelSettingsModel.OracleTiering = oracleTiersModel

	// Construct an instance of the PrimaryArchivalTarget model
	primaryArchivalTargetModel := new(backuprecoveryv1.PrimaryArchivalTarget)
	primaryArchivalTargetModel.TargetID = core.Int64Ptr(int64(26))
	primaryArchivalTargetModel.TierSettings = tierLevelSettingsModel

	// Construct an instance of the PrimaryBackupTarget model
	primaryBackupTargetModel := new(backuprecoveryv1.PrimaryBackupTarget)
	primaryBackupTargetModel.TargetType = core.StringPtr("Local")
	primaryBackupTargetModel.ArchivalTargetSettings = primaryArchivalTargetModel
	primaryBackupTargetModel.UseDefaultBackupTarget = core.BoolPtr(true)

	// Construct an instance of the RegularBackupPolicy model
	regularBackupPolicyModel := new(backuprecoveryv1.RegularBackupPolicy)
	regularBackupPolicyModel.Incremental = incrementalBackupPolicyModel
	regularBackupPolicyModel.Full = fullBackupPolicyModel
	regularBackupPolicyModel.FullBackups = []backuprecoveryv1.FullScheduleAndRetention{*fullScheduleAndRetentionModel}
	regularBackupPolicyModel.Retention = retentionModel
	regularBackupPolicyModel.PrimaryBackupTarget = primaryBackupTargetModel

	// Construct an instance of the LogSchedule model
	logScheduleModel := new(backuprecoveryv1.LogSchedule)
	logScheduleModel.Unit = core.StringPtr("Minutes")
	logScheduleModel.MinuteSchedule = minuteScheduleModel
	logScheduleModel.HourSchedule = hourScheduleModel

	// Construct an instance of the LogBackupPolicy model
	logBackupPolicyModel := new(backuprecoveryv1.LogBackupPolicy)
	logBackupPolicyModel.Schedule = logScheduleModel
	logBackupPolicyModel.Retention = retentionModel

	// Construct an instance of the BmrSchedule model
	bmrScheduleModel := new(backuprecoveryv1.BmrSchedule)
	bmrScheduleModel.Unit = core.StringPtr("Days")
	bmrScheduleModel.DaySchedule = dayScheduleModel
	bmrScheduleModel.WeekSchedule = weekScheduleModel
	bmrScheduleModel.MonthSchedule = monthScheduleModel
	bmrScheduleModel.YearSchedule = yearScheduleModel

	// Construct an instance of the BmrBackupPolicy model
	bmrBackupPolicyModel := new(backuprecoveryv1.BmrBackupPolicy)
	bmrBackupPolicyModel.Schedule = bmrScheduleModel
	bmrBackupPolicyModel.Retention = retentionModel

	// Construct an instance of the CdpRetention model
	cdpRetentionModel := new(backuprecoveryv1.CdpRetention)
	cdpRetentionModel.Unit = core.StringPtr("Minutes")
	cdpRetentionModel.Duration = core.Int64Ptr(int64(1))
	cdpRetentionModel.DataLockConfig = dataLockConfigModel

	// Construct an instance of the CdpBackupPolicy model
	cdpBackupPolicyModel := new(backuprecoveryv1.CdpBackupPolicy)
	cdpBackupPolicyModel.Retention = cdpRetentionModel

	// Construct an instance of the StorageArraySnapshotSchedule model
	storageArraySnapshotScheduleModel := new(backuprecoveryv1.StorageArraySnapshotSchedule)
	storageArraySnapshotScheduleModel.Unit = core.StringPtr("Minutes")
	storageArraySnapshotScheduleModel.MinuteSchedule = minuteScheduleModel
	storageArraySnapshotScheduleModel.HourSchedule = hourScheduleModel
	storageArraySnapshotScheduleModel.DaySchedule = dayScheduleModel
	storageArraySnapshotScheduleModel.WeekSchedule = weekScheduleModel
	storageArraySnapshotScheduleModel.MonthSchedule = monthScheduleModel
	storageArraySnapshotScheduleModel.YearSchedule = yearScheduleModel

	// Construct an instance of the StorageArraySnapshotBackupPolicy model
	storageArraySnapshotBackupPolicyModel := new(backuprecoveryv1.StorageArraySnapshotBackupPolicy)
	storageArraySnapshotBackupPolicyModel.Schedule = storageArraySnapshotScheduleModel
	storageArraySnapshotBackupPolicyModel.Retention = retentionModel

	// Construct an instance of the CancellationTimeoutParams model
	cancellationTimeoutParamsModel := new(backuprecoveryv1.CancellationTimeoutParams)
	cancellationTimeoutParamsModel.TimeoutMins = core.Int64Ptr(int64(26))
	cancellationTimeoutParamsModel.BackupType = core.StringPtr("kRegular")

	// Construct an instance of the BackupPolicy model
	backupPolicyModel := new(backuprecoveryv1.BackupPolicy)
	backupPolicyModel.Regular = regularBackupPolicyModel
	backupPolicyModel.Log = logBackupPolicyModel
	backupPolicyModel.Bmr = bmrBackupPolicyModel
	backupPolicyModel.Cdp = cdpBackupPolicyModel
	backupPolicyModel.StorageArraySnapshot = storageArraySnapshotBackupPolicyModel
	backupPolicyModel.RunTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}

	// Construct an instance of the TimeOfDay model
	timeOfDayModel := new(backuprecoveryv1.TimeOfDay)
	timeOfDayModel.Hour = core.Int64Ptr(int64(1))
	timeOfDayModel.Minute = core.Int64Ptr(int64(15))
	timeOfDayModel.TimeZone = core.StringPtr("America/Los_Angeles")

	// Construct an instance of the BlackoutWindow model
	blackoutWindowModel := new(backuprecoveryv1.BlackoutWindow)
	blackoutWindowModel.Day = core.StringPtr("Sunday")
	blackoutWindowModel.StartTime = timeOfDayModel
	blackoutWindowModel.EndTime = timeOfDayModel
	blackoutWindowModel.ConfigID = core.StringPtr("Config-Id")

	// Construct an instance of the ExtendedRetentionSchedule model
	extendedRetentionScheduleModel := new(backuprecoveryv1.ExtendedRetentionSchedule)
	extendedRetentionScheduleModel.Unit = core.StringPtr("Runs")
	extendedRetentionScheduleModel.Frequency = core.Int64Ptr(int64(3))

	// Construct an instance of the ExtendedRetentionPolicy model
	extendedRetentionPolicyModel := new(backuprecoveryv1.ExtendedRetentionPolicy)
	extendedRetentionPolicyModel.Schedule = extendedRetentionScheduleModel
	extendedRetentionPolicyModel.Retention = retentionModel
	extendedRetentionPolicyModel.RunType = core.StringPtr("Regular")
	extendedRetentionPolicyModel.ConfigID = core.StringPtr("Config-Id")

	// Construct an instance of the TargetSchedule model
	targetScheduleModel := new(backuprecoveryv1.TargetSchedule)
	targetScheduleModel.Unit = core.StringPtr("Runs")
	targetScheduleModel.Frequency = core.Int64Ptr(int64(3))

	// Construct an instance of the LogRetention model
	logRetentionModel := new(backuprecoveryv1.LogRetention)
	logRetentionModel.Unit = core.StringPtr("Days")
	logRetentionModel.Duration = core.Int64Ptr(int64(0))
	logRetentionModel.DataLockConfig = dataLockConfigModel

	// Construct an instance of the AWSTargetConfig model
	awsTargetConfigModel := new(backuprecoveryv1.AWSTargetConfig)
	awsTargetConfigModel.Region = core.Int64Ptr(int64(26))
	awsTargetConfigModel.SourceID = core.Int64Ptr(int64(26))

	// Construct an instance of the AzureTargetConfig model
	azureTargetConfigModel := new(backuprecoveryv1.AzureTargetConfig)
	azureTargetConfigModel.ResourceGroup = core.Int64Ptr(int64(26))
	azureTargetConfigModel.SourceID = core.Int64Ptr(int64(26))

	// Construct an instance of the RemoteTargetConfig model
	remoteTargetConfigModel := new(backuprecoveryv1.RemoteTargetConfig)
	remoteTargetConfigModel.ClusterID = core.Int64Ptr(int64(26))

	// Construct an instance of the ReplicationTargetConfiguration model
	replicationTargetConfigurationModel := new(backuprecoveryv1.ReplicationTargetConfiguration)
	replicationTargetConfigurationModel.Schedule = targetScheduleModel
	replicationTargetConfigurationModel.Retention = retentionModel
	replicationTargetConfigurationModel.CopyOnRunSuccess = core.BoolPtr(true)
	replicationTargetConfigurationModel.ConfigID = core.StringPtr("Config-Id")
	replicationTargetConfigurationModel.BackupRunType = core.StringPtr("Regular")
	replicationTargetConfigurationModel.RunTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}
	replicationTargetConfigurationModel.LogRetention = logRetentionModel
	replicationTargetConfigurationModel.AwsTargetConfig = awsTargetConfigModel
	replicationTargetConfigurationModel.AzureTargetConfig = azureTargetConfigModel
	replicationTargetConfigurationModel.TargetType = core.StringPtr("RemoteCluster")
	replicationTargetConfigurationModel.RemoteTargetConfig = remoteTargetConfigModel

	// Construct an instance of the ArchivalTargetConfiguration model
	archivalTargetConfigurationModel := new(backuprecoveryv1.ArchivalTargetConfiguration)
	archivalTargetConfigurationModel.Schedule = targetScheduleModel
	archivalTargetConfigurationModel.Retention = retentionModel
	archivalTargetConfigurationModel.CopyOnRunSuccess = core.BoolPtr(true)
	archivalTargetConfigurationModel.ConfigID = core.StringPtr("Config-Id")
	archivalTargetConfigurationModel.BackupRunType = core.StringPtr("Regular")
	archivalTargetConfigurationModel.RunTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}
	archivalTargetConfigurationModel.LogRetention = logRetentionModel
	archivalTargetConfigurationModel.TargetID = core.Int64Ptr(int64(5))
	archivalTargetConfigurationModel.TierSettings = tierLevelSettingsModel
	archivalTargetConfigurationModel.ExtendedRetention = []backuprecoveryv1.ExtendedRetentionPolicy{*extendedRetentionPolicyModel}

	// Construct an instance of the CustomTagParams model
	customTagParamsModel := new(backuprecoveryv1.CustomTagParams)
	customTagParamsModel.Key = core.StringPtr("custom-tag-key")
	customTagParamsModel.Value = core.StringPtr("custom-tag-value")

	// Construct an instance of the AwsCloudSpinParams model
	awsCloudSpinParamsModel := new(backuprecoveryv1.AwsCloudSpinParams)
	awsCloudSpinParamsModel.CustomTagList = []backuprecoveryv1.CustomTagParams{*customTagParamsModel}
	awsCloudSpinParamsModel.Region = core.Int64Ptr(int64(3))
	awsCloudSpinParamsModel.SubnetID = core.Int64Ptr(int64(26))
	awsCloudSpinParamsModel.VpcID = core.Int64Ptr(int64(26))

	// Construct an instance of the AzureCloudSpinParams model
	azureCloudSpinParamsModel := new(backuprecoveryv1.AzureCloudSpinParams)
	azureCloudSpinParamsModel.AvailabilitySetID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.NetworkResourceGroupID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.ResourceGroupID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.StorageAccountID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.StorageContainerID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.StorageResourceGroupID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.TempVmResourceGroupID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.TempVmStorageAccountID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.TempVmStorageContainerID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.TempVmSubnetID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.TempVmVirtualNetworkID = core.Int64Ptr(int64(26))

	// Construct an instance of the CloudSpinTarget model
	cloudSpinTargetModel := new(backuprecoveryv1.CloudSpinTarget)
	cloudSpinTargetModel.AwsParams = awsCloudSpinParamsModel
	cloudSpinTargetModel.AzureParams = azureCloudSpinParamsModel
	cloudSpinTargetModel.ID = core.Int64Ptr(int64(2))

	// Construct an instance of the CloudSpinTargetConfiguration model
	cloudSpinTargetConfigurationModel := new(backuprecoveryv1.CloudSpinTargetConfiguration)
	cloudSpinTargetConfigurationModel.Schedule = targetScheduleModel
	cloudSpinTargetConfigurationModel.Retention = retentionModel
	cloudSpinTargetConfigurationModel.CopyOnRunSuccess = core.BoolPtr(true)
	cloudSpinTargetConfigurationModel.ConfigID = core.StringPtr("Config-Id")
	cloudSpinTargetConfigurationModel.BackupRunType = core.StringPtr("Regular")
	cloudSpinTargetConfigurationModel.RunTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}
	cloudSpinTargetConfigurationModel.LogRetention = logRetentionModel
	cloudSpinTargetConfigurationModel.Target = cloudSpinTargetModel

	// Construct an instance of the OnpremDeployParams model
	onpremDeployParamsModel := new(backuprecoveryv1.OnpremDeployParams)
	onpremDeployParamsModel.ID = core.Int64Ptr(int64(4))

	// Construct an instance of the OnpremDeployTargetConfiguration model
	onpremDeployTargetConfigurationModel := new(backuprecoveryv1.OnpremDeployTargetConfiguration)
	onpremDeployTargetConfigurationModel.Schedule = targetScheduleModel
	onpremDeployTargetConfigurationModel.Retention = retentionModel
	onpremDeployTargetConfigurationModel.CopyOnRunSuccess = core.BoolPtr(true)
	onpremDeployTargetConfigurationModel.ConfigID = core.StringPtr("Config-Id")
	onpremDeployTargetConfigurationModel.BackupRunType = core.StringPtr("Regular")
	onpremDeployTargetConfigurationModel.RunTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}
	onpremDeployTargetConfigurationModel.LogRetention = logRetentionModel
	onpremDeployTargetConfigurationModel.Params = onpremDeployParamsModel

	// Construct an instance of the RpaasTargetConfiguration model
	rpaasTargetConfigurationModel := new(backuprecoveryv1.RpaasTargetConfiguration)
	rpaasTargetConfigurationModel.Schedule = targetScheduleModel
	rpaasTargetConfigurationModel.Retention = retentionModel
	rpaasTargetConfigurationModel.CopyOnRunSuccess = core.BoolPtr(true)
	rpaasTargetConfigurationModel.ConfigID = core.StringPtr("Config-Id")
	rpaasTargetConfigurationModel.BackupRunType = core.StringPtr("Regular")
	rpaasTargetConfigurationModel.RunTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}
	rpaasTargetConfigurationModel.LogRetention = logRetentionModel
	rpaasTargetConfigurationModel.TargetID = core.Int64Ptr(int64(5))
	rpaasTargetConfigurationModel.TargetType = core.StringPtr("Tape")

	// Construct an instance of the TargetsConfiguration model
	targetsConfigurationModel := new(backuprecoveryv1.TargetsConfiguration)
	targetsConfigurationModel.ReplicationTargets = []backuprecoveryv1.ReplicationTargetConfiguration{*replicationTargetConfigurationModel}
	targetsConfigurationModel.ArchivalTargets = []backuprecoveryv1.ArchivalTargetConfiguration{*archivalTargetConfigurationModel}
	targetsConfigurationModel.CloudSpinTargets = []backuprecoveryv1.CloudSpinTargetConfiguration{*cloudSpinTargetConfigurationModel}
	targetsConfigurationModel.OnpremDeployTargets = []backuprecoveryv1.OnpremDeployTargetConfiguration{*onpremDeployTargetConfigurationModel}
	targetsConfigurationModel.RpaasTargets = []backuprecoveryv1.RpaasTargetConfiguration{*rpaasTargetConfigurationModel}

	// Construct an instance of the CascadedTargetConfiguration model
	cascadedTargetConfigurationModel := new(backuprecoveryv1.CascadedTargetConfiguration)
	cascadedTargetConfigurationModel.SourceClusterID = core.Int64Ptr(int64(26))
	cascadedTargetConfigurationModel.RemoteTargets = targetsConfigurationModel

	// Construct an instance of the RetryOptions model
	retryOptionsModel := new(backuprecoveryv1.RetryOptions)
	retryOptionsModel.Retries = core.Int64Ptr(int64(0))
	retryOptionsModel.RetryIntervalMins = core.Int64Ptr(int64(1))

	createdOptions, ok := optionsModel.(*backuprecoveryv1.CreateProtectionPolicyOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Name).To(Equal(core.StringPtr("create-protection-policy")))
	Expect(ResolveModel(createdOptions.BackupPolicy)).To(Equal(ResolveModel(backupPolicyModel)))
	Expect(createdOptions.Description).To(Equal(core.StringPtr("Protection Policy")))
	Expect(ResolveModel(createdOptions.BlackoutWindow)).To(Equal(ResolveModel([]backuprecoveryv1.BlackoutWindow{*blackoutWindowModel})))
	Expect(ResolveModel(createdOptions.ExtendedRetention)).To(Equal(ResolveModel([]backuprecoveryv1.ExtendedRetentionPolicy{*extendedRetentionPolicyModel})))
	Expect(ResolveModel(createdOptions.RemoteTargetPolicy)).To(Equal(ResolveModel(targetsConfigurationModel)))
	Expect(ResolveModel(createdOptions.CascadedTargetsConfig)).To(Equal(ResolveModel([]backuprecoveryv1.CascadedTargetConfiguration{*cascadedTargetConfigurationModel})))
	Expect(ResolveModel(createdOptions.RetryOptions)).To(Equal(ResolveModel(retryOptionsModel)))
	Expect(createdOptions.DataLock).To(Equal(core.StringPtr("Compliance")))
	Expect(createdOptions.Version).To(Equal(core.Int64Ptr(int64(38))))
	Expect(createdOptions.IsCBSEnabled).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.LastModificationTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.TemplateID).To(Equal(core.StringPtr("protection-policy-template")))
	return testing_utilities.GetMockSuccessResponse()
}

type CreateProtectionPolicyErrorSender struct{}

func (f CreateProtectionPolicyErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetProtectionPolicyByID
type GetProtectionPolicyByIDMockSender struct{}

func (f GetProtectionPolicyByIDMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetProtectionPolicyByIdOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.StringPtr("testString")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.RequestInitiatorType).To(Equal(core.StringPtr("UIUser")))
	return testing_utilities.GetMockSuccessResponse()
}

type GetProtectionPolicyByIDErrorSender struct{}

func (f GetProtectionPolicyByIDErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for UpdateProtectionPolicy
type UpdateProtectionPolicyMockSender struct{}

func (f UpdateProtectionPolicyMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the MinuteSchedule model
	minuteScheduleModel := new(backuprecoveryv1.MinuteSchedule)
	minuteScheduleModel.Frequency = core.Int64Ptr(int64(1))

	// Construct an instance of the HourSchedule model
	hourScheduleModel := new(backuprecoveryv1.HourSchedule)
	hourScheduleModel.Frequency = core.Int64Ptr(int64(1))

	// Construct an instance of the DaySchedule model
	dayScheduleModel := new(backuprecoveryv1.DaySchedule)
	dayScheduleModel.Frequency = core.Int64Ptr(int64(1))

	// Construct an instance of the WeekSchedule model
	weekScheduleModel := new(backuprecoveryv1.WeekSchedule)
	weekScheduleModel.DayOfWeek = []string{"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"}

	// Construct an instance of the MonthSchedule model
	monthScheduleModel := new(backuprecoveryv1.MonthSchedule)
	monthScheduleModel.DayOfWeek = []string{"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"}
	monthScheduleModel.WeekOfMonth = core.StringPtr("First")
	monthScheduleModel.DayOfMonth = core.Int64Ptr(int64(10))

	// Construct an instance of the YearSchedule model
	yearScheduleModel := new(backuprecoveryv1.YearSchedule)
	yearScheduleModel.DayOfYear = core.StringPtr("First")

	// Construct an instance of the IncrementalSchedule model
	incrementalScheduleModel := new(backuprecoveryv1.IncrementalSchedule)
	incrementalScheduleModel.Unit = core.StringPtr("Minutes")
	incrementalScheduleModel.MinuteSchedule = minuteScheduleModel
	incrementalScheduleModel.HourSchedule = hourScheduleModel
	incrementalScheduleModel.DaySchedule = dayScheduleModel
	incrementalScheduleModel.WeekSchedule = weekScheduleModel
	incrementalScheduleModel.MonthSchedule = monthScheduleModel
	incrementalScheduleModel.YearSchedule = yearScheduleModel

	// Construct an instance of the IncrementalBackupPolicy model
	incrementalBackupPolicyModel := new(backuprecoveryv1.IncrementalBackupPolicy)
	incrementalBackupPolicyModel.Schedule = incrementalScheduleModel

	// Construct an instance of the FullSchedule model
	fullScheduleModel := new(backuprecoveryv1.FullSchedule)
	fullScheduleModel.Unit = core.StringPtr("Days")
	fullScheduleModel.DaySchedule = dayScheduleModel
	fullScheduleModel.WeekSchedule = weekScheduleModel
	fullScheduleModel.MonthSchedule = monthScheduleModel
	fullScheduleModel.YearSchedule = yearScheduleModel

	// Construct an instance of the FullBackupPolicy model
	fullBackupPolicyModel := new(backuprecoveryv1.FullBackupPolicy)
	fullBackupPolicyModel.Schedule = fullScheduleModel

	// Construct an instance of the DataLockConfig model
	dataLockConfigModel := new(backuprecoveryv1.DataLockConfig)
	dataLockConfigModel.Mode = core.StringPtr("Compliance")
	dataLockConfigModel.Unit = core.StringPtr("Days")
	dataLockConfigModel.Duration = core.Int64Ptr(int64(1))
	dataLockConfigModel.EnableWormOnExternalTarget = core.BoolPtr(true)

	// Construct an instance of the Retention model
	retentionModel := new(backuprecoveryv1.Retention)
	retentionModel.Unit = core.StringPtr("Days")
	retentionModel.Duration = core.Int64Ptr(int64(1))
	retentionModel.DataLockConfig = dataLockConfigModel

	// Construct an instance of the FullScheduleAndRetention model
	fullScheduleAndRetentionModel := new(backuprecoveryv1.FullScheduleAndRetention)
	fullScheduleAndRetentionModel.Schedule = fullScheduleModel
	fullScheduleAndRetentionModel.Retention = retentionModel

	// Construct an instance of the AWSTier model
	awsTierModel := new(backuprecoveryv1.AWSTier)
	awsTierModel.MoveAfterUnit = core.StringPtr("Days")
	awsTierModel.MoveAfter = core.Int64Ptr(int64(26))
	awsTierModel.TierType = core.StringPtr("kAmazonS3Standard")

	// Construct an instance of the AWSTiers model
	awsTiersModel := new(backuprecoveryv1.AWSTiers)
	awsTiersModel.Tiers = []backuprecoveryv1.AWSTier{*awsTierModel}

	// Construct an instance of the AzureTier model
	azureTierModel := new(backuprecoveryv1.AzureTier)
	azureTierModel.MoveAfterUnit = core.StringPtr("Days")
	azureTierModel.MoveAfter = core.Int64Ptr(int64(26))
	azureTierModel.TierType = core.StringPtr("kAzureTierHot")

	// Construct an instance of the AzureTiers model
	azureTiersModel := new(backuprecoveryv1.AzureTiers)
	azureTiersModel.Tiers = []backuprecoveryv1.AzureTier{*azureTierModel}

	// Construct an instance of the GoogleTier model
	googleTierModel := new(backuprecoveryv1.GoogleTier)
	googleTierModel.MoveAfterUnit = core.StringPtr("Days")
	googleTierModel.MoveAfter = core.Int64Ptr(int64(26))
	googleTierModel.TierType = core.StringPtr("kGoogleStandard")

	// Construct an instance of the GoogleTiers model
	googleTiersModel := new(backuprecoveryv1.GoogleTiers)
	googleTiersModel.Tiers = []backuprecoveryv1.GoogleTier{*googleTierModel}

	// Construct an instance of the OracleTier model
	oracleTierModel := new(backuprecoveryv1.OracleTier)
	oracleTierModel.MoveAfterUnit = core.StringPtr("Days")
	oracleTierModel.MoveAfter = core.Int64Ptr(int64(26))
	oracleTierModel.TierType = core.StringPtr("kOracleTierStandard")

	// Construct an instance of the OracleTiers model
	oracleTiersModel := new(backuprecoveryv1.OracleTiers)
	oracleTiersModel.Tiers = []backuprecoveryv1.OracleTier{*oracleTierModel}

	// Construct an instance of the TierLevelSettings model
	tierLevelSettingsModel := new(backuprecoveryv1.TierLevelSettings)
	tierLevelSettingsModel.AwsTiering = awsTiersModel
	tierLevelSettingsModel.AzureTiering = azureTiersModel
	tierLevelSettingsModel.CloudPlatform = core.StringPtr("AWS")
	tierLevelSettingsModel.GoogleTiering = googleTiersModel
	tierLevelSettingsModel.OracleTiering = oracleTiersModel

	// Construct an instance of the PrimaryArchivalTarget model
	primaryArchivalTargetModel := new(backuprecoveryv1.PrimaryArchivalTarget)
	primaryArchivalTargetModel.TargetID = core.Int64Ptr(int64(26))
	primaryArchivalTargetModel.TierSettings = tierLevelSettingsModel

	// Construct an instance of the PrimaryBackupTarget model
	primaryBackupTargetModel := new(backuprecoveryv1.PrimaryBackupTarget)
	primaryBackupTargetModel.TargetType = core.StringPtr("Local")
	primaryBackupTargetModel.ArchivalTargetSettings = primaryArchivalTargetModel
	primaryBackupTargetModel.UseDefaultBackupTarget = core.BoolPtr(true)

	// Construct an instance of the RegularBackupPolicy model
	regularBackupPolicyModel := new(backuprecoveryv1.RegularBackupPolicy)
	regularBackupPolicyModel.Incremental = incrementalBackupPolicyModel
	regularBackupPolicyModel.Full = fullBackupPolicyModel
	regularBackupPolicyModel.FullBackups = []backuprecoveryv1.FullScheduleAndRetention{*fullScheduleAndRetentionModel}
	regularBackupPolicyModel.Retention = retentionModel
	regularBackupPolicyModel.PrimaryBackupTarget = primaryBackupTargetModel

	// Construct an instance of the LogSchedule model
	logScheduleModel := new(backuprecoveryv1.LogSchedule)
	logScheduleModel.Unit = core.StringPtr("Minutes")
	logScheduleModel.MinuteSchedule = minuteScheduleModel
	logScheduleModel.HourSchedule = hourScheduleModel

	// Construct an instance of the LogBackupPolicy model
	logBackupPolicyModel := new(backuprecoveryv1.LogBackupPolicy)
	logBackupPolicyModel.Schedule = logScheduleModel
	logBackupPolicyModel.Retention = retentionModel

	// Construct an instance of the BmrSchedule model
	bmrScheduleModel := new(backuprecoveryv1.BmrSchedule)
	bmrScheduleModel.Unit = core.StringPtr("Days")
	bmrScheduleModel.DaySchedule = dayScheduleModel
	bmrScheduleModel.WeekSchedule = weekScheduleModel
	bmrScheduleModel.MonthSchedule = monthScheduleModel
	bmrScheduleModel.YearSchedule = yearScheduleModel

	// Construct an instance of the BmrBackupPolicy model
	bmrBackupPolicyModel := new(backuprecoveryv1.BmrBackupPolicy)
	bmrBackupPolicyModel.Schedule = bmrScheduleModel
	bmrBackupPolicyModel.Retention = retentionModel

	// Construct an instance of the CdpRetention model
	cdpRetentionModel := new(backuprecoveryv1.CdpRetention)
	cdpRetentionModel.Unit = core.StringPtr("Minutes")
	cdpRetentionModel.Duration = core.Int64Ptr(int64(1))
	cdpRetentionModel.DataLockConfig = dataLockConfigModel

	// Construct an instance of the CdpBackupPolicy model
	cdpBackupPolicyModel := new(backuprecoveryv1.CdpBackupPolicy)
	cdpBackupPolicyModel.Retention = cdpRetentionModel

	// Construct an instance of the StorageArraySnapshotSchedule model
	storageArraySnapshotScheduleModel := new(backuprecoveryv1.StorageArraySnapshotSchedule)
	storageArraySnapshotScheduleModel.Unit = core.StringPtr("Minutes")
	storageArraySnapshotScheduleModel.MinuteSchedule = minuteScheduleModel
	storageArraySnapshotScheduleModel.HourSchedule = hourScheduleModel
	storageArraySnapshotScheduleModel.DaySchedule = dayScheduleModel
	storageArraySnapshotScheduleModel.WeekSchedule = weekScheduleModel
	storageArraySnapshotScheduleModel.MonthSchedule = monthScheduleModel
	storageArraySnapshotScheduleModel.YearSchedule = yearScheduleModel

	// Construct an instance of the StorageArraySnapshotBackupPolicy model
	storageArraySnapshotBackupPolicyModel := new(backuprecoveryv1.StorageArraySnapshotBackupPolicy)
	storageArraySnapshotBackupPolicyModel.Schedule = storageArraySnapshotScheduleModel
	storageArraySnapshotBackupPolicyModel.Retention = retentionModel

	// Construct an instance of the CancellationTimeoutParams model
	cancellationTimeoutParamsModel := new(backuprecoveryv1.CancellationTimeoutParams)
	cancellationTimeoutParamsModel.TimeoutMins = core.Int64Ptr(int64(26))
	cancellationTimeoutParamsModel.BackupType = core.StringPtr("kRegular")

	// Construct an instance of the BackupPolicy model
	backupPolicyModel := new(backuprecoveryv1.BackupPolicy)
	backupPolicyModel.Regular = regularBackupPolicyModel
	backupPolicyModel.Log = logBackupPolicyModel
	backupPolicyModel.Bmr = bmrBackupPolicyModel
	backupPolicyModel.Cdp = cdpBackupPolicyModel
	backupPolicyModel.StorageArraySnapshot = storageArraySnapshotBackupPolicyModel
	backupPolicyModel.RunTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}

	// Construct an instance of the TimeOfDay model
	timeOfDayModel := new(backuprecoveryv1.TimeOfDay)
	timeOfDayModel.Hour = core.Int64Ptr(int64(1))
	timeOfDayModel.Minute = core.Int64Ptr(int64(15))
	timeOfDayModel.TimeZone = core.StringPtr("America/Los_Angeles")

	// Construct an instance of the BlackoutWindow model
	blackoutWindowModel := new(backuprecoveryv1.BlackoutWindow)
	blackoutWindowModel.Day = core.StringPtr("Sunday")
	blackoutWindowModel.StartTime = timeOfDayModel
	blackoutWindowModel.EndTime = timeOfDayModel
	blackoutWindowModel.ConfigID = core.StringPtr("Config-Id")

	// Construct an instance of the ExtendedRetentionSchedule model
	extendedRetentionScheduleModel := new(backuprecoveryv1.ExtendedRetentionSchedule)
	extendedRetentionScheduleModel.Unit = core.StringPtr("Runs")
	extendedRetentionScheduleModel.Frequency = core.Int64Ptr(int64(3))

	// Construct an instance of the ExtendedRetentionPolicy model
	extendedRetentionPolicyModel := new(backuprecoveryv1.ExtendedRetentionPolicy)
	extendedRetentionPolicyModel.Schedule = extendedRetentionScheduleModel
	extendedRetentionPolicyModel.Retention = retentionModel
	extendedRetentionPolicyModel.RunType = core.StringPtr("Regular")
	extendedRetentionPolicyModel.ConfigID = core.StringPtr("Config-Id")

	// Construct an instance of the TargetSchedule model
	targetScheduleModel := new(backuprecoveryv1.TargetSchedule)
	targetScheduleModel.Unit = core.StringPtr("Runs")
	targetScheduleModel.Frequency = core.Int64Ptr(int64(3))

	// Construct an instance of the LogRetention model
	logRetentionModel := new(backuprecoveryv1.LogRetention)
	logRetentionModel.Unit = core.StringPtr("Days")
	logRetentionModel.Duration = core.Int64Ptr(int64(0))
	logRetentionModel.DataLockConfig = dataLockConfigModel

	// Construct an instance of the AWSTargetConfig model
	awsTargetConfigModel := new(backuprecoveryv1.AWSTargetConfig)
	awsTargetConfigModel.Region = core.Int64Ptr(int64(26))
	awsTargetConfigModel.SourceID = core.Int64Ptr(int64(26))

	// Construct an instance of the AzureTargetConfig model
	azureTargetConfigModel := new(backuprecoveryv1.AzureTargetConfig)
	azureTargetConfigModel.ResourceGroup = core.Int64Ptr(int64(26))
	azureTargetConfigModel.SourceID = core.Int64Ptr(int64(26))

	// Construct an instance of the RemoteTargetConfig model
	remoteTargetConfigModel := new(backuprecoveryv1.RemoteTargetConfig)
	remoteTargetConfigModel.ClusterID = core.Int64Ptr(int64(26))

	// Construct an instance of the ReplicationTargetConfiguration model
	replicationTargetConfigurationModel := new(backuprecoveryv1.ReplicationTargetConfiguration)
	replicationTargetConfigurationModel.Schedule = targetScheduleModel
	replicationTargetConfigurationModel.Retention = retentionModel
	replicationTargetConfigurationModel.CopyOnRunSuccess = core.BoolPtr(true)
	replicationTargetConfigurationModel.ConfigID = core.StringPtr("Config-Id")
	replicationTargetConfigurationModel.BackupRunType = core.StringPtr("Regular")
	replicationTargetConfigurationModel.RunTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}
	replicationTargetConfigurationModel.LogRetention = logRetentionModel
	replicationTargetConfigurationModel.AwsTargetConfig = awsTargetConfigModel
	replicationTargetConfigurationModel.AzureTargetConfig = azureTargetConfigModel
	replicationTargetConfigurationModel.TargetType = core.StringPtr("RemoteCluster")
	replicationTargetConfigurationModel.RemoteTargetConfig = remoteTargetConfigModel

	// Construct an instance of the ArchivalTargetConfiguration model
	archivalTargetConfigurationModel := new(backuprecoveryv1.ArchivalTargetConfiguration)
	archivalTargetConfigurationModel.Schedule = targetScheduleModel
	archivalTargetConfigurationModel.Retention = retentionModel
	archivalTargetConfigurationModel.CopyOnRunSuccess = core.BoolPtr(true)
	archivalTargetConfigurationModel.ConfigID = core.StringPtr("Config-Id")
	archivalTargetConfigurationModel.BackupRunType = core.StringPtr("Regular")
	archivalTargetConfigurationModel.RunTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}
	archivalTargetConfigurationModel.LogRetention = logRetentionModel
	archivalTargetConfigurationModel.TargetID = core.Int64Ptr(int64(5))
	archivalTargetConfigurationModel.TierSettings = tierLevelSettingsModel
	archivalTargetConfigurationModel.ExtendedRetention = []backuprecoveryv1.ExtendedRetentionPolicy{*extendedRetentionPolicyModel}

	// Construct an instance of the CustomTagParams model
	customTagParamsModel := new(backuprecoveryv1.CustomTagParams)
	customTagParamsModel.Key = core.StringPtr("custom-tag-key")
	customTagParamsModel.Value = core.StringPtr("custom-tag-value")

	// Construct an instance of the AwsCloudSpinParams model
	awsCloudSpinParamsModel := new(backuprecoveryv1.AwsCloudSpinParams)
	awsCloudSpinParamsModel.CustomTagList = []backuprecoveryv1.CustomTagParams{*customTagParamsModel}
	awsCloudSpinParamsModel.Region = core.Int64Ptr(int64(3))
	awsCloudSpinParamsModel.SubnetID = core.Int64Ptr(int64(26))
	awsCloudSpinParamsModel.VpcID = core.Int64Ptr(int64(26))

	// Construct an instance of the AzureCloudSpinParams model
	azureCloudSpinParamsModel := new(backuprecoveryv1.AzureCloudSpinParams)
	azureCloudSpinParamsModel.AvailabilitySetID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.NetworkResourceGroupID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.ResourceGroupID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.StorageAccountID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.StorageContainerID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.StorageResourceGroupID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.TempVmResourceGroupID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.TempVmStorageAccountID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.TempVmStorageContainerID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.TempVmSubnetID = core.Int64Ptr(int64(26))
	azureCloudSpinParamsModel.TempVmVirtualNetworkID = core.Int64Ptr(int64(26))

	// Construct an instance of the CloudSpinTarget model
	cloudSpinTargetModel := new(backuprecoveryv1.CloudSpinTarget)
	cloudSpinTargetModel.AwsParams = awsCloudSpinParamsModel
	cloudSpinTargetModel.AzureParams = azureCloudSpinParamsModel
	cloudSpinTargetModel.ID = core.Int64Ptr(int64(2))

	// Construct an instance of the CloudSpinTargetConfiguration model
	cloudSpinTargetConfigurationModel := new(backuprecoveryv1.CloudSpinTargetConfiguration)
	cloudSpinTargetConfigurationModel.Schedule = targetScheduleModel
	cloudSpinTargetConfigurationModel.Retention = retentionModel
	cloudSpinTargetConfigurationModel.CopyOnRunSuccess = core.BoolPtr(true)
	cloudSpinTargetConfigurationModel.ConfigID = core.StringPtr("Config-Id")
	cloudSpinTargetConfigurationModel.BackupRunType = core.StringPtr("Regular")
	cloudSpinTargetConfigurationModel.RunTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}
	cloudSpinTargetConfigurationModel.LogRetention = logRetentionModel
	cloudSpinTargetConfigurationModel.Target = cloudSpinTargetModel

	// Construct an instance of the OnpremDeployParams model
	onpremDeployParamsModel := new(backuprecoveryv1.OnpremDeployParams)
	onpremDeployParamsModel.ID = core.Int64Ptr(int64(4))

	// Construct an instance of the OnpremDeployTargetConfiguration model
	onpremDeployTargetConfigurationModel := new(backuprecoveryv1.OnpremDeployTargetConfiguration)
	onpremDeployTargetConfigurationModel.Schedule = targetScheduleModel
	onpremDeployTargetConfigurationModel.Retention = retentionModel
	onpremDeployTargetConfigurationModel.CopyOnRunSuccess = core.BoolPtr(true)
	onpremDeployTargetConfigurationModel.ConfigID = core.StringPtr("Config-Id")
	onpremDeployTargetConfigurationModel.BackupRunType = core.StringPtr("Regular")
	onpremDeployTargetConfigurationModel.RunTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}
	onpremDeployTargetConfigurationModel.LogRetention = logRetentionModel
	onpremDeployTargetConfigurationModel.Params = onpremDeployParamsModel

	// Construct an instance of the RpaasTargetConfiguration model
	rpaasTargetConfigurationModel := new(backuprecoveryv1.RpaasTargetConfiguration)
	rpaasTargetConfigurationModel.Schedule = targetScheduleModel
	rpaasTargetConfigurationModel.Retention = retentionModel
	rpaasTargetConfigurationModel.CopyOnRunSuccess = core.BoolPtr(true)
	rpaasTargetConfigurationModel.ConfigID = core.StringPtr("Config-Id")
	rpaasTargetConfigurationModel.BackupRunType = core.StringPtr("Regular")
	rpaasTargetConfigurationModel.RunTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}
	rpaasTargetConfigurationModel.LogRetention = logRetentionModel
	rpaasTargetConfigurationModel.TargetID = core.Int64Ptr(int64(5))
	rpaasTargetConfigurationModel.TargetType = core.StringPtr("Tape")

	// Construct an instance of the TargetsConfiguration model
	targetsConfigurationModel := new(backuprecoveryv1.TargetsConfiguration)
	targetsConfigurationModel.ReplicationTargets = []backuprecoveryv1.ReplicationTargetConfiguration{*replicationTargetConfigurationModel}
	targetsConfigurationModel.ArchivalTargets = []backuprecoveryv1.ArchivalTargetConfiguration{*archivalTargetConfigurationModel}
	targetsConfigurationModel.CloudSpinTargets = []backuprecoveryv1.CloudSpinTargetConfiguration{*cloudSpinTargetConfigurationModel}
	targetsConfigurationModel.OnpremDeployTargets = []backuprecoveryv1.OnpremDeployTargetConfiguration{*onpremDeployTargetConfigurationModel}
	targetsConfigurationModel.RpaasTargets = []backuprecoveryv1.RpaasTargetConfiguration{*rpaasTargetConfigurationModel}

	// Construct an instance of the CascadedTargetConfiguration model
	cascadedTargetConfigurationModel := new(backuprecoveryv1.CascadedTargetConfiguration)
	cascadedTargetConfigurationModel.SourceClusterID = core.Int64Ptr(int64(26))
	cascadedTargetConfigurationModel.RemoteTargets = targetsConfigurationModel

	// Construct an instance of the RetryOptions model
	retryOptionsModel := new(backuprecoveryv1.RetryOptions)
	retryOptionsModel.Retries = core.Int64Ptr(int64(0))
	retryOptionsModel.RetryIntervalMins = core.Int64Ptr(int64(1))

	createdOptions, ok := optionsModel.(*backuprecoveryv1.UpdateProtectionPolicyOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.StringPtr("testString")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Name).To(Equal(core.StringPtr("update-protection-policy")))
	Expect(ResolveModel(createdOptions.BackupPolicy)).To(Equal(ResolveModel(backupPolicyModel)))
	Expect(createdOptions.Description).To(Equal(core.StringPtr("Protection Policy")))
	Expect(ResolveModel(createdOptions.BlackoutWindow)).To(Equal(ResolveModel([]backuprecoveryv1.BlackoutWindow{*blackoutWindowModel})))
	Expect(ResolveModel(createdOptions.ExtendedRetention)).To(Equal(ResolveModel([]backuprecoveryv1.ExtendedRetentionPolicy{*extendedRetentionPolicyModel})))
	Expect(ResolveModel(createdOptions.RemoteTargetPolicy)).To(Equal(ResolveModel(targetsConfigurationModel)))
	Expect(ResolveModel(createdOptions.CascadedTargetsConfig)).To(Equal(ResolveModel([]backuprecoveryv1.CascadedTargetConfiguration{*cascadedTargetConfigurationModel})))
	Expect(ResolveModel(createdOptions.RetryOptions)).To(Equal(ResolveModel(retryOptionsModel)))
	Expect(createdOptions.DataLock).To(Equal(core.StringPtr("Compliance")))
	Expect(createdOptions.Version).To(Equal(core.Int64Ptr(int64(38))))
	Expect(createdOptions.IsCBSEnabled).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.LastModificationTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.TemplateID).To(Equal(core.StringPtr("protection-policy-template")))
	return testing_utilities.GetMockSuccessResponse()
}

type UpdateProtectionPolicyErrorSender struct{}

func (f UpdateProtectionPolicyErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for DeleteProtectionPolicy
type DeleteProtectionPolicyMockSender struct{}

func (f DeleteProtectionPolicyMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.DeleteProtectionPolicyOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.StringPtr("testString")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	return testing_utilities.GetMockSuccessResponse()
}

type DeleteProtectionPolicyErrorSender struct{}

func (f DeleteProtectionPolicyErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetProtectionGroups
type GetProtectionGroupsMockSender struct{}

func (f GetProtectionGroupsMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetProtectionGroupsOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantID")))
	Expect(createdOptions.RequestInitiatorType).To(Equal(core.StringPtr("UIUser")))
	Expect(createdOptions.Ids).To(Equal([]string{"protectionGroupId1"}))
	Expect(createdOptions.Names).To(Equal([]string{"policyName1"}))
	Expect(createdOptions.PolicyIds).To(Equal([]string{"policyId1"}))
	Expect(createdOptions.IncludeGroupsWithDatalockOnly).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.Environments).To(Equal([]string{"kPhysical","kSQL"}))
	Expect(createdOptions.IsActive).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IsDeleted).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IsPaused).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.LastRunLocalBackupStatus).To(Equal([]string{"Accepted","Running","Canceled","Canceling","Failed","Missed","Succeeded","SucceededWithWarning","OnHold","Finalizing","Skipped","Paused"}))
	Expect(createdOptions.LastRunReplicationStatus).To(Equal([]string{"Accepted","Running","Canceled","Canceling","Failed","Missed","Succeeded","SucceededWithWarning","OnHold","Finalizing","Skipped","Paused"}))
	Expect(createdOptions.LastRunArchivalStatus).To(Equal([]string{"Accepted","Running","Canceled","Canceling","Failed","Missed","Succeeded","SucceededWithWarning","OnHold","Finalizing","Skipped","Paused"}))
	Expect(createdOptions.LastRunCloudSpinStatus).To(Equal([]string{"Accepted","Running","Canceled","Canceling","Failed","Missed","Succeeded","SucceededWithWarning","OnHold","Finalizing","Skipped","Paused"}))
	Expect(createdOptions.LastRunAnyStatus).To(Equal([]string{"Accepted","Running","Canceled","Canceling","Failed","Missed","Succeeded","SucceededWithWarning","OnHold","Finalizing","Skipped","Paused"}))
	Expect(createdOptions.IsLastRunSlaViolated).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IncludeLastRunInfo).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.PruneExcludedSourceIds).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.PruneSourceIds).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.UseCachedData).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.SourceIds).To(Equal([]int64{int64(26),int64(27)}))
	return testing_utilities.GetMockSuccessResponse()
}

type GetProtectionGroupsErrorSender struct{}

func (f GetProtectionGroupsErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for CreateProtectionGroup
type CreateProtectionGroupMockSender struct{}

func (f CreateProtectionGroupMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the TimeOfDay model
	timeOfDayModel := new(backuprecoveryv1.TimeOfDay)
	timeOfDayModel.Hour = core.Int64Ptr(int64(0))
	timeOfDayModel.Minute = core.Int64Ptr(int64(0))
	timeOfDayModel.TimeZone = core.StringPtr("America/Los_Angeles")

	// Construct an instance of the AlertTarget model
	alertTargetModel := new(backuprecoveryv1.AlertTarget)
	alertTargetModel.EmailAddress = core.StringPtr("alert1@domain.com")
	alertTargetModel.Language = core.StringPtr("en-us")
	alertTargetModel.RecipientType = core.StringPtr("kTo")

	// Construct an instance of the ProtectionGroupAlertingPolicy model
	protectionGroupAlertingPolicyModel := new(backuprecoveryv1.ProtectionGroupAlertingPolicy)
	protectionGroupAlertingPolicyModel.BackupRunStatus = []string{"kSuccess","kFailure","kSlaViolation","kWarning"}
	protectionGroupAlertingPolicyModel.AlertTargets = []backuprecoveryv1.AlertTarget{*alertTargetModel}
	protectionGroupAlertingPolicyModel.RaiseObjectLevelFailureAlert = core.BoolPtr(true)
	protectionGroupAlertingPolicyModel.RaiseObjectLevelFailureAlertAfterLastAttempt = core.BoolPtr(true)
	protectionGroupAlertingPolicyModel.RaiseObjectLevelFailureAlertAfterEachAttempt = core.BoolPtr(true)

	// Construct an instance of the SlaRule model
	slaRuleModel := new(backuprecoveryv1.SlaRule)
	slaRuleModel.BackupRunType = core.StringPtr("kIncremental")
	slaRuleModel.SlaMinutes = core.Int64Ptr(int64(1))

	// Construct an instance of the KeyValuePair model
	keyValuePairModel := new(backuprecoveryv1.KeyValuePair)
	keyValuePairModel.Key = core.StringPtr("configKey")
	keyValuePairModel.Value = core.StringPtr("configValue")

	// Construct an instance of the PhysicalVolumeProtectionGroupObjectParams model
	physicalVolumeProtectionGroupObjectParamsModel := new(backuprecoveryv1.PhysicalVolumeProtectionGroupObjectParams)
	physicalVolumeProtectionGroupObjectParamsModel.ID = core.Int64Ptr(int64(3))
	physicalVolumeProtectionGroupObjectParamsModel.VolumeGuids = []string{"volumeGuid1"}
	physicalVolumeProtectionGroupObjectParamsModel.EnableSystemBackup = core.BoolPtr(true)
	physicalVolumeProtectionGroupObjectParamsModel.ExcludedVssWriters = []string{"writerName1","writerName2"}

	// Construct an instance of the IndexingPolicy model
	indexingPolicyModel := new(backuprecoveryv1.IndexingPolicy)
	indexingPolicyModel.EnableIndexing = core.BoolPtr(true)
	indexingPolicyModel.IncludePaths = []string{"~/dir1"}
	indexingPolicyModel.ExcludePaths = []string{"~/dir2"}

	// Construct an instance of the CommonPreBackupScriptParams model
	commonPreBackupScriptParamsModel := new(backuprecoveryv1.CommonPreBackupScriptParams)
	commonPreBackupScriptParamsModel.Path = core.StringPtr("~/script1")
	commonPreBackupScriptParamsModel.Params = core.StringPtr("param1")
	commonPreBackupScriptParamsModel.TimeoutSecs = core.Int64Ptr(int64(1))
	commonPreBackupScriptParamsModel.IsActive = core.BoolPtr(true)
	commonPreBackupScriptParamsModel.ContinueOnError = core.BoolPtr(true)

	// Construct an instance of the CommonPostBackupScriptParams model
	commonPostBackupScriptParamsModel := new(backuprecoveryv1.CommonPostBackupScriptParams)
	commonPostBackupScriptParamsModel.Path = core.StringPtr("~/script2")
	commonPostBackupScriptParamsModel.Params = core.StringPtr("param2")
	commonPostBackupScriptParamsModel.TimeoutSecs = core.Int64Ptr(int64(1))
	commonPostBackupScriptParamsModel.IsActive = core.BoolPtr(true)

	// Construct an instance of the PrePostScriptParams model
	prePostScriptParamsModel := new(backuprecoveryv1.PrePostScriptParams)
	prePostScriptParamsModel.PreScript = commonPreBackupScriptParamsModel
	prePostScriptParamsModel.PostScript = commonPostBackupScriptParamsModel

	// Construct an instance of the PhysicalVolumeProtectionGroupParams model
	physicalVolumeProtectionGroupParamsModel := new(backuprecoveryv1.PhysicalVolumeProtectionGroupParams)
	physicalVolumeProtectionGroupParamsModel.Objects = []backuprecoveryv1.PhysicalVolumeProtectionGroupObjectParams{*physicalVolumeProtectionGroupObjectParamsModel}
	physicalVolumeProtectionGroupParamsModel.IndexingPolicy = indexingPolicyModel
	physicalVolumeProtectionGroupParamsModel.PerformSourceSideDeduplication = core.BoolPtr(true)
	physicalVolumeProtectionGroupParamsModel.Quiesce = core.BoolPtr(true)
	physicalVolumeProtectionGroupParamsModel.ContinueOnQuiesceFailure = core.BoolPtr(true)
	physicalVolumeProtectionGroupParamsModel.IncrementalBackupAfterRestart = core.BoolPtr(true)
	physicalVolumeProtectionGroupParamsModel.PrePostScript = prePostScriptParamsModel
	physicalVolumeProtectionGroupParamsModel.DedupExclusionSourceIds = []int64{int64(26),int64(27)}
	physicalVolumeProtectionGroupParamsModel.ExcludedVssWriters = []string{"writerName1","writerName2"}
	physicalVolumeProtectionGroupParamsModel.CobmrBackup = core.BoolPtr(true)

	// Construct an instance of the PhysicalFileBackupPathParams model
	physicalFileBackupPathParamsModel := new(backuprecoveryv1.PhysicalFileBackupPathParams)
	physicalFileBackupPathParamsModel.IncludedPath = core.StringPtr("~/dir1/")
	physicalFileBackupPathParamsModel.ExcludedPaths = []string{"~/dir2"}
	physicalFileBackupPathParamsModel.SkipNestedVolumes = core.BoolPtr(true)

	// Construct an instance of the PhysicalFileProtectionGroupObjectParams model
	physicalFileProtectionGroupObjectParamsModel := new(backuprecoveryv1.PhysicalFileProtectionGroupObjectParams)
	physicalFileProtectionGroupObjectParamsModel.ExcludedVssWriters = []string{"writerName1","writerName2"}
	physicalFileProtectionGroupObjectParamsModel.ID = core.Int64Ptr(int64(2))
	physicalFileProtectionGroupObjectParamsModel.FilePaths = []backuprecoveryv1.PhysicalFileBackupPathParams{*physicalFileBackupPathParamsModel}
	physicalFileProtectionGroupObjectParamsModel.UsesPathLevelSkipNestedVolumeSetting = core.BoolPtr(true)
	physicalFileProtectionGroupObjectParamsModel.NestedVolumeTypesToSkip = []string{"volume1"}
	physicalFileProtectionGroupObjectParamsModel.FollowNasSymlinkTarget = core.BoolPtr(true)
	physicalFileProtectionGroupObjectParamsModel.MetadataFilePath = core.StringPtr("~/dir3")

	// Construct an instance of the CancellationTimeoutParams model
	cancellationTimeoutParamsModel := new(backuprecoveryv1.CancellationTimeoutParams)
	cancellationTimeoutParamsModel.TimeoutMins = core.Int64Ptr(int64(26))
	cancellationTimeoutParamsModel.BackupType = core.StringPtr("kRegular")

	// Construct an instance of the PhysicalFileProtectionGroupParams model
	physicalFileProtectionGroupParamsModel := new(backuprecoveryv1.PhysicalFileProtectionGroupParams)
	physicalFileProtectionGroupParamsModel.ExcludedVssWriters = []string{"writerName1","writerName2"}
	physicalFileProtectionGroupParamsModel.Objects = []backuprecoveryv1.PhysicalFileProtectionGroupObjectParams{*physicalFileProtectionGroupObjectParamsModel}
	physicalFileProtectionGroupParamsModel.IndexingPolicy = indexingPolicyModel
	physicalFileProtectionGroupParamsModel.PerformSourceSideDeduplication = core.BoolPtr(true)
	physicalFileProtectionGroupParamsModel.PerformBrickBasedDeduplication = core.BoolPtr(true)
	physicalFileProtectionGroupParamsModel.TaskTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}
	physicalFileProtectionGroupParamsModel.Quiesce = core.BoolPtr(true)
	physicalFileProtectionGroupParamsModel.ContinueOnQuiesceFailure = core.BoolPtr(true)
	physicalFileProtectionGroupParamsModel.CobmrBackup = core.BoolPtr(true)
	physicalFileProtectionGroupParamsModel.PrePostScript = prePostScriptParamsModel
	physicalFileProtectionGroupParamsModel.DedupExclusionSourceIds = []int64{int64(26),int64(27)}
	physicalFileProtectionGroupParamsModel.GlobalExcludePaths = []string{"~/dir1"}
	physicalFileProtectionGroupParamsModel.GlobalExcludeFS = []string{"~/dir2"}
	physicalFileProtectionGroupParamsModel.IgnorableErrors = []string{"kEOF","kNonExistent"}
	physicalFileProtectionGroupParamsModel.AllowParallelRuns = core.BoolPtr(true)

	// Construct an instance of the PhysicalProtectionGroupParams model
	physicalProtectionGroupParamsModel := new(backuprecoveryv1.PhysicalProtectionGroupParams)
	physicalProtectionGroupParamsModel.ProtectionType = core.StringPtr("kFile")
	physicalProtectionGroupParamsModel.VolumeProtectionTypeParams = physicalVolumeProtectionGroupParamsModel
	physicalProtectionGroupParamsModel.FileProtectionTypeParams = physicalFileProtectionGroupParamsModel

	// Construct an instance of the AdvancedSettings model
	advancedSettingsModel := new(backuprecoveryv1.AdvancedSettings)
	advancedSettingsModel.ClonedDbBackupStatus = core.StringPtr("kError")
	advancedSettingsModel.DbBackupIfNotOnlineStatus = core.StringPtr("kError")
	advancedSettingsModel.MissingDbBackupStatus = core.StringPtr("kError")
	advancedSettingsModel.OfflineRestoringDbBackupStatus = core.StringPtr("kError")
	advancedSettingsModel.ReadOnlyDbBackupStatus = core.StringPtr("kError")
	advancedSettingsModel.ReportAllNonAutoprotectDbErrors = core.StringPtr("kError")

	// Construct an instance of the Filter model
	filterModel := new(backuprecoveryv1.Filter)
	filterModel.FilterString = core.StringPtr("filterString")
	filterModel.IsRegularExpression = core.BoolPtr(false)

	// Construct an instance of the MSSQLFileProtectionGroupHostParams model
	mssqlFileProtectionGroupHostParamsModel := new(backuprecoveryv1.MSSQLFileProtectionGroupHostParams)
	mssqlFileProtectionGroupHostParamsModel.DisableSourceSideDeduplication = core.BoolPtr(true)
	mssqlFileProtectionGroupHostParamsModel.HostID = core.Int64Ptr(int64(26))

	// Construct an instance of the MSSQLFileProtectionGroupObjectParams model
	mssqlFileProtectionGroupObjectParamsModel := new(backuprecoveryv1.MSSQLFileProtectionGroupObjectParams)
	mssqlFileProtectionGroupObjectParamsModel.ID = core.Int64Ptr(int64(6))

	// Construct an instance of the MSSQLFileProtectionGroupParams model
	mssqlFileProtectionGroupParamsModel := new(backuprecoveryv1.MSSQLFileProtectionGroupParams)
	mssqlFileProtectionGroupParamsModel.AagBackupPreferenceType = core.StringPtr("kPrimaryReplicaOnly")
	mssqlFileProtectionGroupParamsModel.AdvancedSettings = advancedSettingsModel
	mssqlFileProtectionGroupParamsModel.BackupSystemDbs = core.BoolPtr(true)
	mssqlFileProtectionGroupParamsModel.ExcludeFilters = []backuprecoveryv1.Filter{*filterModel}
	mssqlFileProtectionGroupParamsModel.FullBackupsCopyOnly = core.BoolPtr(true)
	mssqlFileProtectionGroupParamsModel.LogBackupNumStreams = core.Int64Ptr(int64(38))
	mssqlFileProtectionGroupParamsModel.LogBackupWithClause = core.StringPtr("backupWithClause")
	mssqlFileProtectionGroupParamsModel.PrePostScript = prePostScriptParamsModel
	mssqlFileProtectionGroupParamsModel.UseAagPreferencesFromServer = core.BoolPtr(true)
	mssqlFileProtectionGroupParamsModel.UserDbBackupPreferenceType = core.StringPtr("kBackupAllDatabases")
	mssqlFileProtectionGroupParamsModel.AdditionalHostParams = []backuprecoveryv1.MSSQLFileProtectionGroupHostParams{*mssqlFileProtectionGroupHostParamsModel}
	mssqlFileProtectionGroupParamsModel.Objects = []backuprecoveryv1.MSSQLFileProtectionGroupObjectParams{*mssqlFileProtectionGroupObjectParamsModel}
	mssqlFileProtectionGroupParamsModel.PerformSourceSideDeduplication = core.BoolPtr(true)

	// Construct an instance of the MSSQLNativeProtectionGroupObjectParams model
	mssqlNativeProtectionGroupObjectParamsModel := new(backuprecoveryv1.MSSQLNativeProtectionGroupObjectParams)
	mssqlNativeProtectionGroupObjectParamsModel.ID = core.Int64Ptr(int64(6))

	// Construct an instance of the MSSQLNativeProtectionGroupParams model
	mssqlNativeProtectionGroupParamsModel := new(backuprecoveryv1.MSSQLNativeProtectionGroupParams)
	mssqlNativeProtectionGroupParamsModel.AagBackupPreferenceType = core.StringPtr("kPrimaryReplicaOnly")
	mssqlNativeProtectionGroupParamsModel.AdvancedSettings = advancedSettingsModel
	mssqlNativeProtectionGroupParamsModel.BackupSystemDbs = core.BoolPtr(true)
	mssqlNativeProtectionGroupParamsModel.ExcludeFilters = []backuprecoveryv1.Filter{*filterModel}
	mssqlNativeProtectionGroupParamsModel.FullBackupsCopyOnly = core.BoolPtr(true)
	mssqlNativeProtectionGroupParamsModel.LogBackupNumStreams = core.Int64Ptr(int64(38))
	mssqlNativeProtectionGroupParamsModel.LogBackupWithClause = core.StringPtr("backupWithClause")
	mssqlNativeProtectionGroupParamsModel.PrePostScript = prePostScriptParamsModel
	mssqlNativeProtectionGroupParamsModel.UseAagPreferencesFromServer = core.BoolPtr(true)
	mssqlNativeProtectionGroupParamsModel.UserDbBackupPreferenceType = core.StringPtr("kBackupAllDatabases")
	mssqlNativeProtectionGroupParamsModel.NumStreams = core.Int64Ptr(int64(38))
	mssqlNativeProtectionGroupParamsModel.Objects = []backuprecoveryv1.MSSQLNativeProtectionGroupObjectParams{*mssqlNativeProtectionGroupObjectParamsModel}
	mssqlNativeProtectionGroupParamsModel.WithClause = core.StringPtr("withClause")

	// Construct an instance of the MSSQLVolumeProtectionGroupHostParams model
	mssqlVolumeProtectionGroupHostParamsModel := new(backuprecoveryv1.MSSQLVolumeProtectionGroupHostParams)
	mssqlVolumeProtectionGroupHostParamsModel.EnableSystemBackup = core.BoolPtr(true)
	mssqlVolumeProtectionGroupHostParamsModel.HostID = core.Int64Ptr(int64(8))
	mssqlVolumeProtectionGroupHostParamsModel.VolumeGuids = []string{"volumeGuid1"}

	// Construct an instance of the MSSQLVolumeProtectionGroupObjectParams model
	mssqlVolumeProtectionGroupObjectParamsModel := new(backuprecoveryv1.MSSQLVolumeProtectionGroupObjectParams)
	mssqlVolumeProtectionGroupObjectParamsModel.ID = core.Int64Ptr(int64(6))

	// Construct an instance of the MSSQLVolumeProtectionGroupParams model
	mssqlVolumeProtectionGroupParamsModel := new(backuprecoveryv1.MSSQLVolumeProtectionGroupParams)
	mssqlVolumeProtectionGroupParamsModel.AagBackupPreferenceType = core.StringPtr("kPrimaryReplicaOnly")
	mssqlVolumeProtectionGroupParamsModel.AdvancedSettings = advancedSettingsModel
	mssqlVolumeProtectionGroupParamsModel.BackupSystemDbs = core.BoolPtr(true)
	mssqlVolumeProtectionGroupParamsModel.ExcludeFilters = []backuprecoveryv1.Filter{*filterModel}
	mssqlVolumeProtectionGroupParamsModel.FullBackupsCopyOnly = core.BoolPtr(true)
	mssqlVolumeProtectionGroupParamsModel.LogBackupNumStreams = core.Int64Ptr(int64(38))
	mssqlVolumeProtectionGroupParamsModel.LogBackupWithClause = core.StringPtr("backupWithClause")
	mssqlVolumeProtectionGroupParamsModel.PrePostScript = prePostScriptParamsModel
	mssqlVolumeProtectionGroupParamsModel.UseAagPreferencesFromServer = core.BoolPtr(true)
	mssqlVolumeProtectionGroupParamsModel.UserDbBackupPreferenceType = core.StringPtr("kBackupAllDatabases")
	mssqlVolumeProtectionGroupParamsModel.AdditionalHostParams = []backuprecoveryv1.MSSQLVolumeProtectionGroupHostParams{*mssqlVolumeProtectionGroupHostParamsModel}
	mssqlVolumeProtectionGroupParamsModel.BackupDbVolumesOnly = core.BoolPtr(true)
	mssqlVolumeProtectionGroupParamsModel.IncrementalBackupAfterRestart = core.BoolPtr(true)
	mssqlVolumeProtectionGroupParamsModel.IndexingPolicy = indexingPolicyModel
	mssqlVolumeProtectionGroupParamsModel.Objects = []backuprecoveryv1.MSSQLVolumeProtectionGroupObjectParams{*mssqlVolumeProtectionGroupObjectParamsModel}

	// Construct an instance of the MSSQLProtectionGroupParams model
	mssqlProtectionGroupParamsModel := new(backuprecoveryv1.MSSQLProtectionGroupParams)
	mssqlProtectionGroupParamsModel.FileProtectionTypeParams = mssqlFileProtectionGroupParamsModel
	mssqlProtectionGroupParamsModel.NativeProtectionTypeParams = mssqlNativeProtectionGroupParamsModel
	mssqlProtectionGroupParamsModel.ProtectionType = core.StringPtr("kFile")
	mssqlProtectionGroupParamsModel.VolumeProtectionTypeParams = mssqlVolumeProtectionGroupParamsModel

	createdOptions, ok := optionsModel.(*backuprecoveryv1.CreateProtectionGroupOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Name).To(Equal(core.StringPtr("create-protection-group")))
	Expect(createdOptions.PolicyID).To(Equal(core.StringPtr("xxxxxxxxxxxxxxxx:xxxxxxxxxxxxx:xx")))
	Expect(createdOptions.Environment).To(Equal(core.StringPtr("kPhysical")))
	Expect(createdOptions.Priority).To(Equal(core.StringPtr("kLow")))
	Expect(createdOptions.Description).To(Equal(core.StringPtr("Protection Group")))
	Expect(ResolveModel(createdOptions.StartTime)).To(Equal(ResolveModel(timeOfDayModel)))
	Expect(createdOptions.EndTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.LastModifiedTimestampUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(ResolveModel(createdOptions.AlertPolicy)).To(Equal(ResolveModel(protectionGroupAlertingPolicyModel)))
	Expect(ResolveModel(createdOptions.Sla)).To(Equal(ResolveModel([]backuprecoveryv1.SlaRule{*slaRuleModel})))
	Expect(createdOptions.QosPolicy).To(Equal(core.StringPtr("kBackupHDD")))
	Expect(createdOptions.AbortInBlackouts).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.PauseInBlackouts).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IsPaused).To(Equal(core.BoolPtr(true)))
	Expect(ResolveModel(createdOptions.AdvancedConfigs)).To(Equal(ResolveModel([]backuprecoveryv1.KeyValuePair{*keyValuePairModel})))
	Expect(ResolveModel(createdOptions.PhysicalParams)).To(Equal(ResolveModel(physicalProtectionGroupParamsModel)))
	Expect(ResolveModel(createdOptions.MssqlParams)).To(Equal(ResolveModel(mssqlProtectionGroupParamsModel)))
	return testing_utilities.GetMockSuccessResponse()
}

type CreateProtectionGroupErrorSender struct{}

func (f CreateProtectionGroupErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetProtectionGroupByID
type GetProtectionGroupByIDMockSender struct{}

func (f GetProtectionGroupByIDMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetProtectionGroupByIdOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.StringPtr("testString")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantID")))
	Expect(createdOptions.RequestInitiatorType).To(Equal(core.StringPtr("UIUser")))
	Expect(createdOptions.IncludeLastRunInfo).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.PruneExcludedSourceIds).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.PruneSourceIds).To(Equal(core.BoolPtr(true)))
	return testing_utilities.GetMockSuccessResponse()
}

type GetProtectionGroupByIDErrorSender struct{}

func (f GetProtectionGroupByIDErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for UpdateProtectionGroup
type UpdateProtectionGroupMockSender struct{}

func (f UpdateProtectionGroupMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the TimeOfDay model
	timeOfDayModel := new(backuprecoveryv1.TimeOfDay)
	timeOfDayModel.Hour = core.Int64Ptr(int64(0))
	timeOfDayModel.Minute = core.Int64Ptr(int64(0))
	timeOfDayModel.TimeZone = core.StringPtr("America/Los_Angeles")

	// Construct an instance of the AlertTarget model
	alertTargetModel := new(backuprecoveryv1.AlertTarget)
	alertTargetModel.EmailAddress = core.StringPtr("alert1@domain.com")
	alertTargetModel.Language = core.StringPtr("en-us")
	alertTargetModel.RecipientType = core.StringPtr("kTo")

	// Construct an instance of the ProtectionGroupAlertingPolicy model
	protectionGroupAlertingPolicyModel := new(backuprecoveryv1.ProtectionGroupAlertingPolicy)
	protectionGroupAlertingPolicyModel.BackupRunStatus = []string{"kSuccess","kFailure","kSlaViolation","kWarning"}
	protectionGroupAlertingPolicyModel.AlertTargets = []backuprecoveryv1.AlertTarget{*alertTargetModel}
	protectionGroupAlertingPolicyModel.RaiseObjectLevelFailureAlert = core.BoolPtr(true)
	protectionGroupAlertingPolicyModel.RaiseObjectLevelFailureAlertAfterLastAttempt = core.BoolPtr(true)
	protectionGroupAlertingPolicyModel.RaiseObjectLevelFailureAlertAfterEachAttempt = core.BoolPtr(true)

	// Construct an instance of the SlaRule model
	slaRuleModel := new(backuprecoveryv1.SlaRule)
	slaRuleModel.BackupRunType = core.StringPtr("kIncremental")
	slaRuleModel.SlaMinutes = core.Int64Ptr(int64(1))

	// Construct an instance of the KeyValuePair model
	keyValuePairModel := new(backuprecoveryv1.KeyValuePair)
	keyValuePairModel.Key = core.StringPtr("configKey")
	keyValuePairModel.Value = core.StringPtr("configValue")

	// Construct an instance of the PhysicalVolumeProtectionGroupObjectParams model
	physicalVolumeProtectionGroupObjectParamsModel := new(backuprecoveryv1.PhysicalVolumeProtectionGroupObjectParams)
	physicalVolumeProtectionGroupObjectParamsModel.ID = core.Int64Ptr(int64(3))
	physicalVolumeProtectionGroupObjectParamsModel.VolumeGuids = []string{"volumeGuid1"}
	physicalVolumeProtectionGroupObjectParamsModel.EnableSystemBackup = core.BoolPtr(true)
	physicalVolumeProtectionGroupObjectParamsModel.ExcludedVssWriters = []string{"writerName1","writerName2"}

	// Construct an instance of the IndexingPolicy model
	indexingPolicyModel := new(backuprecoveryv1.IndexingPolicy)
	indexingPolicyModel.EnableIndexing = core.BoolPtr(true)
	indexingPolicyModel.IncludePaths = []string{"~/dir1"}
	indexingPolicyModel.ExcludePaths = []string{"~/dir2"}

	// Construct an instance of the CommonPreBackupScriptParams model
	commonPreBackupScriptParamsModel := new(backuprecoveryv1.CommonPreBackupScriptParams)
	commonPreBackupScriptParamsModel.Path = core.StringPtr("~/script1")
	commonPreBackupScriptParamsModel.Params = core.StringPtr("param1")
	commonPreBackupScriptParamsModel.TimeoutSecs = core.Int64Ptr(int64(1))
	commonPreBackupScriptParamsModel.IsActive = core.BoolPtr(true)
	commonPreBackupScriptParamsModel.ContinueOnError = core.BoolPtr(true)

	// Construct an instance of the CommonPostBackupScriptParams model
	commonPostBackupScriptParamsModel := new(backuprecoveryv1.CommonPostBackupScriptParams)
	commonPostBackupScriptParamsModel.Path = core.StringPtr("~/script2")
	commonPostBackupScriptParamsModel.Params = core.StringPtr("param2")
	commonPostBackupScriptParamsModel.TimeoutSecs = core.Int64Ptr(int64(1))
	commonPostBackupScriptParamsModel.IsActive = core.BoolPtr(true)

	// Construct an instance of the PrePostScriptParams model
	prePostScriptParamsModel := new(backuprecoveryv1.PrePostScriptParams)
	prePostScriptParamsModel.PreScript = commonPreBackupScriptParamsModel
	prePostScriptParamsModel.PostScript = commonPostBackupScriptParamsModel

	// Construct an instance of the PhysicalVolumeProtectionGroupParams model
	physicalVolumeProtectionGroupParamsModel := new(backuprecoveryv1.PhysicalVolumeProtectionGroupParams)
	physicalVolumeProtectionGroupParamsModel.Objects = []backuprecoveryv1.PhysicalVolumeProtectionGroupObjectParams{*physicalVolumeProtectionGroupObjectParamsModel}
	physicalVolumeProtectionGroupParamsModel.IndexingPolicy = indexingPolicyModel
	physicalVolumeProtectionGroupParamsModel.PerformSourceSideDeduplication = core.BoolPtr(true)
	physicalVolumeProtectionGroupParamsModel.Quiesce = core.BoolPtr(true)
	physicalVolumeProtectionGroupParamsModel.ContinueOnQuiesceFailure = core.BoolPtr(true)
	physicalVolumeProtectionGroupParamsModel.IncrementalBackupAfterRestart = core.BoolPtr(true)
	physicalVolumeProtectionGroupParamsModel.PrePostScript = prePostScriptParamsModel
	physicalVolumeProtectionGroupParamsModel.DedupExclusionSourceIds = []int64{int64(26),int64(27)}
	physicalVolumeProtectionGroupParamsModel.ExcludedVssWriters = []string{"writerName1","writerName2"}
	physicalVolumeProtectionGroupParamsModel.CobmrBackup = core.BoolPtr(true)

	// Construct an instance of the PhysicalFileBackupPathParams model
	physicalFileBackupPathParamsModel := new(backuprecoveryv1.PhysicalFileBackupPathParams)
	physicalFileBackupPathParamsModel.IncludedPath = core.StringPtr("~/dir1/")
	physicalFileBackupPathParamsModel.ExcludedPaths = []string{"~/dir2"}
	physicalFileBackupPathParamsModel.SkipNestedVolumes = core.BoolPtr(true)

	// Construct an instance of the PhysicalFileProtectionGroupObjectParams model
	physicalFileProtectionGroupObjectParamsModel := new(backuprecoveryv1.PhysicalFileProtectionGroupObjectParams)
	physicalFileProtectionGroupObjectParamsModel.ExcludedVssWriters = []string{"writerName1","writerName2"}
	physicalFileProtectionGroupObjectParamsModel.ID = core.Int64Ptr(int64(2))
	physicalFileProtectionGroupObjectParamsModel.FilePaths = []backuprecoveryv1.PhysicalFileBackupPathParams{*physicalFileBackupPathParamsModel}
	physicalFileProtectionGroupObjectParamsModel.UsesPathLevelSkipNestedVolumeSetting = core.BoolPtr(true)
	physicalFileProtectionGroupObjectParamsModel.NestedVolumeTypesToSkip = []string{"volume1"}
	physicalFileProtectionGroupObjectParamsModel.FollowNasSymlinkTarget = core.BoolPtr(true)
	physicalFileProtectionGroupObjectParamsModel.MetadataFilePath = core.StringPtr("~/dir3")

	// Construct an instance of the CancellationTimeoutParams model
	cancellationTimeoutParamsModel := new(backuprecoveryv1.CancellationTimeoutParams)
	cancellationTimeoutParamsModel.TimeoutMins = core.Int64Ptr(int64(26))
	cancellationTimeoutParamsModel.BackupType = core.StringPtr("kRegular")

	// Construct an instance of the PhysicalFileProtectionGroupParams model
	physicalFileProtectionGroupParamsModel := new(backuprecoveryv1.PhysicalFileProtectionGroupParams)
	physicalFileProtectionGroupParamsModel.ExcludedVssWriters = []string{"writerName1","writerName2"}
	physicalFileProtectionGroupParamsModel.Objects = []backuprecoveryv1.PhysicalFileProtectionGroupObjectParams{*physicalFileProtectionGroupObjectParamsModel}
	physicalFileProtectionGroupParamsModel.IndexingPolicy = indexingPolicyModel
	physicalFileProtectionGroupParamsModel.PerformSourceSideDeduplication = core.BoolPtr(true)
	physicalFileProtectionGroupParamsModel.PerformBrickBasedDeduplication = core.BoolPtr(true)
	physicalFileProtectionGroupParamsModel.TaskTimeouts = []backuprecoveryv1.CancellationTimeoutParams{*cancellationTimeoutParamsModel}
	physicalFileProtectionGroupParamsModel.Quiesce = core.BoolPtr(true)
	physicalFileProtectionGroupParamsModel.ContinueOnQuiesceFailure = core.BoolPtr(true)
	physicalFileProtectionGroupParamsModel.CobmrBackup = core.BoolPtr(true)
	physicalFileProtectionGroupParamsModel.PrePostScript = prePostScriptParamsModel
	physicalFileProtectionGroupParamsModel.DedupExclusionSourceIds = []int64{int64(26),int64(27)}
	physicalFileProtectionGroupParamsModel.GlobalExcludePaths = []string{"~/dir1"}
	physicalFileProtectionGroupParamsModel.GlobalExcludeFS = []string{"~/dir2"}
	physicalFileProtectionGroupParamsModel.IgnorableErrors = []string{"kEOF","kNonExistent"}
	physicalFileProtectionGroupParamsModel.AllowParallelRuns = core.BoolPtr(true)

	// Construct an instance of the PhysicalProtectionGroupParams model
	physicalProtectionGroupParamsModel := new(backuprecoveryv1.PhysicalProtectionGroupParams)
	physicalProtectionGroupParamsModel.ProtectionType = core.StringPtr("kFile")
	physicalProtectionGroupParamsModel.VolumeProtectionTypeParams = physicalVolumeProtectionGroupParamsModel
	physicalProtectionGroupParamsModel.FileProtectionTypeParams = physicalFileProtectionGroupParamsModel

	// Construct an instance of the AdvancedSettings model
	advancedSettingsModel := new(backuprecoveryv1.AdvancedSettings)
	advancedSettingsModel.ClonedDbBackupStatus = core.StringPtr("kError")
	advancedSettingsModel.DbBackupIfNotOnlineStatus = core.StringPtr("kError")
	advancedSettingsModel.MissingDbBackupStatus = core.StringPtr("kError")
	advancedSettingsModel.OfflineRestoringDbBackupStatus = core.StringPtr("kError")
	advancedSettingsModel.ReadOnlyDbBackupStatus = core.StringPtr("kError")
	advancedSettingsModel.ReportAllNonAutoprotectDbErrors = core.StringPtr("kError")

	// Construct an instance of the Filter model
	filterModel := new(backuprecoveryv1.Filter)
	filterModel.FilterString = core.StringPtr("filterString")
	filterModel.IsRegularExpression = core.BoolPtr(false)

	// Construct an instance of the MSSQLFileProtectionGroupHostParams model
	mssqlFileProtectionGroupHostParamsModel := new(backuprecoveryv1.MSSQLFileProtectionGroupHostParams)
	mssqlFileProtectionGroupHostParamsModel.DisableSourceSideDeduplication = core.BoolPtr(true)
	mssqlFileProtectionGroupHostParamsModel.HostID = core.Int64Ptr(int64(26))

	// Construct an instance of the MSSQLFileProtectionGroupObjectParams model
	mssqlFileProtectionGroupObjectParamsModel := new(backuprecoveryv1.MSSQLFileProtectionGroupObjectParams)
	mssqlFileProtectionGroupObjectParamsModel.ID = core.Int64Ptr(int64(6))

	// Construct an instance of the MSSQLFileProtectionGroupParams model
	mssqlFileProtectionGroupParamsModel := new(backuprecoveryv1.MSSQLFileProtectionGroupParams)
	mssqlFileProtectionGroupParamsModel.AagBackupPreferenceType = core.StringPtr("kPrimaryReplicaOnly")
	mssqlFileProtectionGroupParamsModel.AdvancedSettings = advancedSettingsModel
	mssqlFileProtectionGroupParamsModel.BackupSystemDbs = core.BoolPtr(true)
	mssqlFileProtectionGroupParamsModel.ExcludeFilters = []backuprecoveryv1.Filter{*filterModel}
	mssqlFileProtectionGroupParamsModel.FullBackupsCopyOnly = core.BoolPtr(true)
	mssqlFileProtectionGroupParamsModel.LogBackupNumStreams = core.Int64Ptr(int64(38))
	mssqlFileProtectionGroupParamsModel.LogBackupWithClause = core.StringPtr("backupWithClause")
	mssqlFileProtectionGroupParamsModel.PrePostScript = prePostScriptParamsModel
	mssqlFileProtectionGroupParamsModel.UseAagPreferencesFromServer = core.BoolPtr(true)
	mssqlFileProtectionGroupParamsModel.UserDbBackupPreferenceType = core.StringPtr("kBackupAllDatabases")
	mssqlFileProtectionGroupParamsModel.AdditionalHostParams = []backuprecoveryv1.MSSQLFileProtectionGroupHostParams{*mssqlFileProtectionGroupHostParamsModel}
	mssqlFileProtectionGroupParamsModel.Objects = []backuprecoveryv1.MSSQLFileProtectionGroupObjectParams{*mssqlFileProtectionGroupObjectParamsModel}
	mssqlFileProtectionGroupParamsModel.PerformSourceSideDeduplication = core.BoolPtr(true)

	// Construct an instance of the MSSQLNativeProtectionGroupObjectParams model
	mssqlNativeProtectionGroupObjectParamsModel := new(backuprecoveryv1.MSSQLNativeProtectionGroupObjectParams)
	mssqlNativeProtectionGroupObjectParamsModel.ID = core.Int64Ptr(int64(6))

	// Construct an instance of the MSSQLNativeProtectionGroupParams model
	mssqlNativeProtectionGroupParamsModel := new(backuprecoveryv1.MSSQLNativeProtectionGroupParams)
	mssqlNativeProtectionGroupParamsModel.AagBackupPreferenceType = core.StringPtr("kPrimaryReplicaOnly")
	mssqlNativeProtectionGroupParamsModel.AdvancedSettings = advancedSettingsModel
	mssqlNativeProtectionGroupParamsModel.BackupSystemDbs = core.BoolPtr(true)
	mssqlNativeProtectionGroupParamsModel.ExcludeFilters = []backuprecoveryv1.Filter{*filterModel}
	mssqlNativeProtectionGroupParamsModel.FullBackupsCopyOnly = core.BoolPtr(true)
	mssqlNativeProtectionGroupParamsModel.LogBackupNumStreams = core.Int64Ptr(int64(38))
	mssqlNativeProtectionGroupParamsModel.LogBackupWithClause = core.StringPtr("backupWithClause")
	mssqlNativeProtectionGroupParamsModel.PrePostScript = prePostScriptParamsModel
	mssqlNativeProtectionGroupParamsModel.UseAagPreferencesFromServer = core.BoolPtr(true)
	mssqlNativeProtectionGroupParamsModel.UserDbBackupPreferenceType = core.StringPtr("kBackupAllDatabases")
	mssqlNativeProtectionGroupParamsModel.NumStreams = core.Int64Ptr(int64(38))
	mssqlNativeProtectionGroupParamsModel.Objects = []backuprecoveryv1.MSSQLNativeProtectionGroupObjectParams{*mssqlNativeProtectionGroupObjectParamsModel}
	mssqlNativeProtectionGroupParamsModel.WithClause = core.StringPtr("withClause")

	// Construct an instance of the MSSQLVolumeProtectionGroupHostParams model
	mssqlVolumeProtectionGroupHostParamsModel := new(backuprecoveryv1.MSSQLVolumeProtectionGroupHostParams)
	mssqlVolumeProtectionGroupHostParamsModel.EnableSystemBackup = core.BoolPtr(true)
	mssqlVolumeProtectionGroupHostParamsModel.HostID = core.Int64Ptr(int64(8))
	mssqlVolumeProtectionGroupHostParamsModel.VolumeGuids = []string{"volumeGuid1"}

	// Construct an instance of the MSSQLVolumeProtectionGroupObjectParams model
	mssqlVolumeProtectionGroupObjectParamsModel := new(backuprecoveryv1.MSSQLVolumeProtectionGroupObjectParams)
	mssqlVolumeProtectionGroupObjectParamsModel.ID = core.Int64Ptr(int64(6))

	// Construct an instance of the MSSQLVolumeProtectionGroupParams model
	mssqlVolumeProtectionGroupParamsModel := new(backuprecoveryv1.MSSQLVolumeProtectionGroupParams)
	mssqlVolumeProtectionGroupParamsModel.AagBackupPreferenceType = core.StringPtr("kPrimaryReplicaOnly")
	mssqlVolumeProtectionGroupParamsModel.AdvancedSettings = advancedSettingsModel
	mssqlVolumeProtectionGroupParamsModel.BackupSystemDbs = core.BoolPtr(true)
	mssqlVolumeProtectionGroupParamsModel.ExcludeFilters = []backuprecoveryv1.Filter{*filterModel}
	mssqlVolumeProtectionGroupParamsModel.FullBackupsCopyOnly = core.BoolPtr(true)
	mssqlVolumeProtectionGroupParamsModel.LogBackupNumStreams = core.Int64Ptr(int64(38))
	mssqlVolumeProtectionGroupParamsModel.LogBackupWithClause = core.StringPtr("backupWithClause")
	mssqlVolumeProtectionGroupParamsModel.PrePostScript = prePostScriptParamsModel
	mssqlVolumeProtectionGroupParamsModel.UseAagPreferencesFromServer = core.BoolPtr(true)
	mssqlVolumeProtectionGroupParamsModel.UserDbBackupPreferenceType = core.StringPtr("kBackupAllDatabases")
	mssqlVolumeProtectionGroupParamsModel.AdditionalHostParams = []backuprecoveryv1.MSSQLVolumeProtectionGroupHostParams{*mssqlVolumeProtectionGroupHostParamsModel}
	mssqlVolumeProtectionGroupParamsModel.BackupDbVolumesOnly = core.BoolPtr(true)
	mssqlVolumeProtectionGroupParamsModel.IncrementalBackupAfterRestart = core.BoolPtr(true)
	mssqlVolumeProtectionGroupParamsModel.IndexingPolicy = indexingPolicyModel
	mssqlVolumeProtectionGroupParamsModel.Objects = []backuprecoveryv1.MSSQLVolumeProtectionGroupObjectParams{*mssqlVolumeProtectionGroupObjectParamsModel}

	// Construct an instance of the MSSQLProtectionGroupParams model
	mssqlProtectionGroupParamsModel := new(backuprecoveryv1.MSSQLProtectionGroupParams)
	mssqlProtectionGroupParamsModel.FileProtectionTypeParams = mssqlFileProtectionGroupParamsModel
	mssqlProtectionGroupParamsModel.NativeProtectionTypeParams = mssqlNativeProtectionGroupParamsModel
	mssqlProtectionGroupParamsModel.ProtectionType = core.StringPtr("kFile")
	mssqlProtectionGroupParamsModel.VolumeProtectionTypeParams = mssqlVolumeProtectionGroupParamsModel

	createdOptions, ok := optionsModel.(*backuprecoveryv1.UpdateProtectionGroupOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.StringPtr("testString")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Name).To(Equal(core.StringPtr("update-protection-group")))
	Expect(createdOptions.PolicyID).To(Equal(core.StringPtr("xxxxxxxxxxxxxxxx:xxxxxxxxxxxxx:xx")))
	Expect(createdOptions.Environment).To(Equal(core.StringPtr("kPhysical")))
	Expect(createdOptions.Priority).To(Equal(core.StringPtr("kLow")))
	Expect(createdOptions.Description).To(Equal(core.StringPtr("Protection Group")))
	Expect(ResolveModel(createdOptions.StartTime)).To(Equal(ResolveModel(timeOfDayModel)))
	Expect(createdOptions.EndTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.LastModifiedTimestampUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(ResolveModel(createdOptions.AlertPolicy)).To(Equal(ResolveModel(protectionGroupAlertingPolicyModel)))
	Expect(ResolveModel(createdOptions.Sla)).To(Equal(ResolveModel([]backuprecoveryv1.SlaRule{*slaRuleModel})))
	Expect(createdOptions.QosPolicy).To(Equal(core.StringPtr("kBackupHDD")))
	Expect(createdOptions.AbortInBlackouts).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.PauseInBlackouts).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IsPaused).To(Equal(core.BoolPtr(true)))
	Expect(ResolveModel(createdOptions.AdvancedConfigs)).To(Equal(ResolveModel([]backuprecoveryv1.KeyValuePair{*keyValuePairModel})))
	Expect(ResolveModel(createdOptions.PhysicalParams)).To(Equal(ResolveModel(physicalProtectionGroupParamsModel)))
	Expect(ResolveModel(createdOptions.MssqlParams)).To(Equal(ResolveModel(mssqlProtectionGroupParamsModel)))
	return testing_utilities.GetMockSuccessResponse()
}

type UpdateProtectionGroupErrorSender struct{}

func (f UpdateProtectionGroupErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for DeleteProtectionGroup
type DeleteProtectionGroupMockSender struct{}

func (f DeleteProtectionGroupMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.DeleteProtectionGroupOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.StringPtr("testString")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.DeleteSnapshots).To(Equal(core.BoolPtr(true)))
	return testing_utilities.GetMockSuccessResponse()
}

type DeleteProtectionGroupErrorSender struct{}

func (f DeleteProtectionGroupErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetProtectionGroupRuns
type GetProtectionGroupRunsMockSender struct{}

func (f GetProtectionGroupRunsMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetProtectionGroupRunsOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.StringPtr("testString")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.RequestInitiatorType).To(Equal(core.StringPtr("UIUser")))
	Expect(createdOptions.RunID).To(Equal(core.StringPtr("11:111")))
	Expect(createdOptions.StartTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.EndTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.RunTypes).To(Equal([]string{"kAll","kHydrateCDP","kSystem","kStorageArraySnapshot","kIncremental","kFull","kLog"}))
	Expect(createdOptions.IncludeObjectDetails).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.LocalBackupRunStatus).To(Equal([]string{"Accepted","Running","Canceled","Canceling","Failed","Missed","Succeeded","SucceededWithWarning","OnHold","Finalizing","Skipped","Paused"}))
	Expect(createdOptions.ReplicationRunStatus).To(Equal([]string{"Accepted","Running","Canceled","Canceling","Failed","Missed","Succeeded","SucceededWithWarning","OnHold","Finalizing","Skipped","Paused"}))
	Expect(createdOptions.ArchivalRunStatus).To(Equal([]string{"Accepted","Running","Canceled","Canceling","Failed","Missed","Succeeded","SucceededWithWarning","OnHold","Finalizing","Skipped","Paused"}))
	Expect(createdOptions.CloudSpinRunStatus).To(Equal([]string{"Accepted","Running","Canceled","Canceling","Failed","Missed","Succeeded","SucceededWithWarning","OnHold","Finalizing","Skipped","Paused"}))
	Expect(createdOptions.NumRuns).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.ExcludeNonRestorableRuns).To(Equal(core.BoolPtr(false)))
	Expect(createdOptions.RunTags).To(Equal([]string{"tag1"}))
	Expect(createdOptions.UseCachedData).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.FilterByEndTime).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.SnapshotTargetTypes).To(Equal([]string{"Local","Archival","RpaasArchival","StorageArraySnapshot","Remote"}))
	Expect(createdOptions.OnlyReturnSuccessfulCopyRun).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.FilterByCopyTaskEndTime).To(Equal(core.BoolPtr(true)))
	return testing_utilities.GetMockSuccessResponse()
}

type GetProtectionGroupRunsErrorSender struct{}

func (f GetProtectionGroupRunsErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for UpdateProtectionGroupRun
type UpdateProtectionGroupRunMockSender struct{}

func (f UpdateProtectionGroupRunMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the UpdateLocalSnapshotConfig model
	updateLocalSnapshotConfigModel := new(backuprecoveryv1.UpdateLocalSnapshotConfig)
	updateLocalSnapshotConfigModel.EnableLegalHold = core.BoolPtr(true)
	updateLocalSnapshotConfigModel.DeleteSnapshot = core.BoolPtr(true)
	updateLocalSnapshotConfigModel.DataLock = core.StringPtr("Compliance")
	updateLocalSnapshotConfigModel.DaysToKeep = core.Int64Ptr(int64(26))

	// Construct an instance of the DataLockConfig model
	dataLockConfigModel := new(backuprecoveryv1.DataLockConfig)
	dataLockConfigModel.Mode = core.StringPtr("Compliance")
	dataLockConfigModel.Unit = core.StringPtr("Days")
	dataLockConfigModel.Duration = core.Int64Ptr(int64(1))
	dataLockConfigModel.EnableWormOnExternalTarget = core.BoolPtr(true)

	// Construct an instance of the Retention model
	retentionModel := new(backuprecoveryv1.Retention)
	retentionModel.Unit = core.StringPtr("Days")
	retentionModel.Duration = core.Int64Ptr(int64(1))
	retentionModel.DataLockConfig = dataLockConfigModel

	// Construct an instance of the RunReplicationConfig model
	runReplicationConfigModel := new(backuprecoveryv1.RunReplicationConfig)
	runReplicationConfigModel.ID = core.Int64Ptr(int64(26))
	runReplicationConfigModel.Retention = retentionModel

	// Construct an instance of the UpdateExistingReplicationSnapshotConfig model
	updateExistingReplicationSnapshotConfigModel := new(backuprecoveryv1.UpdateExistingReplicationSnapshotConfig)
	updateExistingReplicationSnapshotConfigModel.ID = core.Int64Ptr(int64(4))
	updateExistingReplicationSnapshotConfigModel.Name = core.StringPtr("update-snapshot-config")
	updateExistingReplicationSnapshotConfigModel.EnableLegalHold = core.BoolPtr(true)
	updateExistingReplicationSnapshotConfigModel.DeleteSnapshot = core.BoolPtr(true)
	updateExistingReplicationSnapshotConfigModel.Resync = core.BoolPtr(true)
	updateExistingReplicationSnapshotConfigModel.DataLock = core.StringPtr("Compliance")
	updateExistingReplicationSnapshotConfigModel.DaysToKeep = core.Int64Ptr(int64(26))

	// Construct an instance of the UpdateReplicationSnapshotConfig model
	updateReplicationSnapshotConfigModel := new(backuprecoveryv1.UpdateReplicationSnapshotConfig)
	updateReplicationSnapshotConfigModel.NewSnapshotConfig = []backuprecoveryv1.RunReplicationConfig{*runReplicationConfigModel}
	updateReplicationSnapshotConfigModel.UpdateExistingSnapshotConfig = []backuprecoveryv1.UpdateExistingReplicationSnapshotConfig{*updateExistingReplicationSnapshotConfigModel}

	// Construct an instance of the RunArchivalConfig model
	runArchivalConfigModel := new(backuprecoveryv1.RunArchivalConfig)
	runArchivalConfigModel.ID = core.Int64Ptr(int64(2))
	runArchivalConfigModel.ArchivalTargetType = core.StringPtr("Tape")
	runArchivalConfigModel.Retention = retentionModel
	runArchivalConfigModel.CopyOnlyFullySuccessful = core.BoolPtr(true)

	// Construct an instance of the UpdateExistingArchivalSnapshotConfig model
	updateExistingArchivalSnapshotConfigModel := new(backuprecoveryv1.UpdateExistingArchivalSnapshotConfig)
	updateExistingArchivalSnapshotConfigModel.ID = core.Int64Ptr(int64(3))
	updateExistingArchivalSnapshotConfigModel.Name = core.StringPtr("update-snapshot-config")
	updateExistingArchivalSnapshotConfigModel.ArchivalTargetType = core.StringPtr("Tape")
	updateExistingArchivalSnapshotConfigModel.EnableLegalHold = core.BoolPtr(true)
	updateExistingArchivalSnapshotConfigModel.DeleteSnapshot = core.BoolPtr(true)
	updateExistingArchivalSnapshotConfigModel.Resync = core.BoolPtr(true)
	updateExistingArchivalSnapshotConfigModel.DataLock = core.StringPtr("Compliance")
	updateExistingArchivalSnapshotConfigModel.DaysToKeep = core.Int64Ptr(int64(26))

	// Construct an instance of the UpdateArchivalSnapshotConfig model
	updateArchivalSnapshotConfigModel := new(backuprecoveryv1.UpdateArchivalSnapshotConfig)
	updateArchivalSnapshotConfigModel.NewSnapshotConfig = []backuprecoveryv1.RunArchivalConfig{*runArchivalConfigModel}
	updateArchivalSnapshotConfigModel.UpdateExistingSnapshotConfig = []backuprecoveryv1.UpdateExistingArchivalSnapshotConfig{*updateExistingArchivalSnapshotConfigModel}

	// Construct an instance of the UpdateProtectionGroupRunParams model
	updateProtectionGroupRunParamsModel := new(backuprecoveryv1.UpdateProtectionGroupRunParams)
	updateProtectionGroupRunParamsModel.RunID = core.StringPtr("11:111")
	updateProtectionGroupRunParamsModel.LocalSnapshotConfig = updateLocalSnapshotConfigModel
	updateProtectionGroupRunParamsModel.ReplicationSnapshotConfig = updateReplicationSnapshotConfigModel
	updateProtectionGroupRunParamsModel.ArchivalSnapshotConfig = updateArchivalSnapshotConfigModel

	createdOptions, ok := optionsModel.(*backuprecoveryv1.UpdateProtectionGroupRunOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.StringPtr("testString")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(ResolveModel(createdOptions.UpdateProtectionGroupRunParams)).To(Equal(ResolveModel([]backuprecoveryv1.UpdateProtectionGroupRunParams{*updateProtectionGroupRunParamsModel})))
	return testing_utilities.GetMockSuccessResponse()
}

type UpdateProtectionGroupRunErrorSender struct{}

func (f UpdateProtectionGroupRunErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for CreateProtectionGroupRun
type CreateProtectionGroupRunMockSender struct{}

func (f CreateProtectionGroupRunMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the RunObjectPhysicalParams model
	runObjectPhysicalParamsModel := new(backuprecoveryv1.RunObjectPhysicalParams)
	runObjectPhysicalParamsModel.MetadataFilePath = core.StringPtr("~/metadata")

	// Construct an instance of the RunObject model
	runObjectModel := new(backuprecoveryv1.RunObject)
	runObjectModel.ID = core.Int64Ptr(int64(4))
	runObjectModel.AppIds = []int64{int64(26),int64(27)}
	runObjectModel.PhysicalParams = runObjectPhysicalParamsModel

	// Construct an instance of the DataLockConfig model
	dataLockConfigModel := new(backuprecoveryv1.DataLockConfig)
	dataLockConfigModel.Mode = core.StringPtr("Compliance")
	dataLockConfigModel.Unit = core.StringPtr("Days")
	dataLockConfigModel.Duration = core.Int64Ptr(int64(1))
	dataLockConfigModel.EnableWormOnExternalTarget = core.BoolPtr(true)

	// Construct an instance of the Retention model
	retentionModel := new(backuprecoveryv1.Retention)
	retentionModel.Unit = core.StringPtr("Days")
	retentionModel.Duration = core.Int64Ptr(int64(1))
	retentionModel.DataLockConfig = dataLockConfigModel

	// Construct an instance of the RunReplicationConfig model
	runReplicationConfigModel := new(backuprecoveryv1.RunReplicationConfig)
	runReplicationConfigModel.ID = core.Int64Ptr(int64(26))
	runReplicationConfigModel.Retention = retentionModel

	// Construct an instance of the RunArchivalConfig model
	runArchivalConfigModel := new(backuprecoveryv1.RunArchivalConfig)
	runArchivalConfigModel.ID = core.Int64Ptr(int64(26))
	runArchivalConfigModel.ArchivalTargetType = core.StringPtr("Tape")
	runArchivalConfigModel.Retention = retentionModel
	runArchivalConfigModel.CopyOnlyFullySuccessful = core.BoolPtr(true)

	// Construct an instance of the AWSTargetConfig model
	awsTargetConfigModel := new(backuprecoveryv1.AWSTargetConfig)
	awsTargetConfigModel.Region = core.Int64Ptr(int64(26))
	awsTargetConfigModel.SourceID = core.Int64Ptr(int64(26))

	// Construct an instance of the AzureTargetConfig model
	azureTargetConfigModel := new(backuprecoveryv1.AzureTargetConfig)
	azureTargetConfigModel.ResourceGroup = core.Int64Ptr(int64(26))
	azureTargetConfigModel.SourceID = core.Int64Ptr(int64(26))

	// Construct an instance of the RunCloudReplicationConfig model
	runCloudReplicationConfigModel := new(backuprecoveryv1.RunCloudReplicationConfig)
	runCloudReplicationConfigModel.AwsTarget = awsTargetConfigModel
	runCloudReplicationConfigModel.AzureTarget = azureTargetConfigModel
	runCloudReplicationConfigModel.TargetType = core.StringPtr("AWS")
	runCloudReplicationConfigModel.Retention = retentionModel

	// Construct an instance of the RunTargetsConfiguration model
	runTargetsConfigurationModel := new(backuprecoveryv1.RunTargetsConfiguration)
	runTargetsConfigurationModel.UsePolicyDefaults = core.BoolPtr(false)
	runTargetsConfigurationModel.Replications = []backuprecoveryv1.RunReplicationConfig{*runReplicationConfigModel}
	runTargetsConfigurationModel.Archivals = []backuprecoveryv1.RunArchivalConfig{*runArchivalConfigModel}
	runTargetsConfigurationModel.CloudReplications = []backuprecoveryv1.RunCloudReplicationConfig{*runCloudReplicationConfigModel}

	createdOptions, ok := optionsModel.(*backuprecoveryv1.CreateProtectionGroupRunOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.StringPtr("runId")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.RunType).To(Equal(core.StringPtr("kRegular")))
	Expect(ResolveModel(createdOptions.Objects)).To(Equal(ResolveModel([]backuprecoveryv1.RunObject{*runObjectModel})))
	Expect(ResolveModel(createdOptions.TargetsConfig)).To(Equal(ResolveModel(runTargetsConfigurationModel)))
	return testing_utilities.GetMockSuccessResponse()
}

type CreateProtectionGroupRunErrorSender struct{}

func (f CreateProtectionGroupRunErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for PerformActionOnProtectionGroupRun
type PerformActionOnProtectionGroupRunMockSender struct{}

func (f PerformActionOnProtectionGroupRunMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the PauseProtectionRunActionParams model
	pauseProtectionRunActionParamsModel := new(backuprecoveryv1.PauseProtectionRunActionParams)
	pauseProtectionRunActionParamsModel.RunID = core.StringPtr("11:111")

	// Construct an instance of the ResumeProtectionRunActionParams model
	resumeProtectionRunActionParamsModel := new(backuprecoveryv1.ResumeProtectionRunActionParams)
	resumeProtectionRunActionParamsModel.RunID = core.StringPtr("11:111")

	// Construct an instance of the CancelProtectionGroupRunRequest model
	cancelProtectionGroupRunRequestModel := new(backuprecoveryv1.CancelProtectionGroupRunRequest)
	cancelProtectionGroupRunRequestModel.RunID = core.StringPtr("11:111")
	cancelProtectionGroupRunRequestModel.LocalTaskID = core.StringPtr("123:456:789")
	cancelProtectionGroupRunRequestModel.ObjectIds = []int64{int64(26),int64(27)}
	cancelProtectionGroupRunRequestModel.ReplicationTaskID = []string{"123:456:789"}
	cancelProtectionGroupRunRequestModel.ArchivalTaskID = []string{"123:456:789"}
	cancelProtectionGroupRunRequestModel.CloudSpinTaskID = []string{"123:456:789"}

	createdOptions, ok := optionsModel.(*backuprecoveryv1.PerformActionOnProtectionGroupRunOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.StringPtr("runId")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Action).To(Equal(core.StringPtr("Pause")))
	Expect(ResolveModel(createdOptions.PauseParams)).To(Equal(ResolveModel([]backuprecoveryv1.PauseProtectionRunActionParams{*pauseProtectionRunActionParamsModel})))
	Expect(ResolveModel(createdOptions.ResumeParams)).To(Equal(ResolveModel([]backuprecoveryv1.ResumeProtectionRunActionParams{*resumeProtectionRunActionParamsModel})))
	Expect(ResolveModel(createdOptions.CancelParams)).To(Equal(ResolveModel([]backuprecoveryv1.CancelProtectionGroupRunRequest{*cancelProtectionGroupRunRequestModel})))
	return testing_utilities.GetMockSuccessResponse()
}

type PerformActionOnProtectionGroupRunErrorSender struct{}

func (f PerformActionOnProtectionGroupRunErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetRecoveries
type GetRecoveriesMockSender struct{}

func (f GetRecoveriesMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetRecoveriesOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Ids).To(Equal([]string{"11:111:11"}))
	Expect(createdOptions.ReturnOnlyChildRecoveries).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.StartTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.EndTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.SnapshotTargetType).To(Equal([]string{"Local","Archival","RpaasArchival","StorageArraySnapshot","Remote"}))
	Expect(createdOptions.ArchivalTargetType).To(Equal([]string{"Tape","Cloud","Nas"}))
	Expect(createdOptions.SnapshotEnvironments).To(Equal([]string{"kPhysical","kSQL"}))
	Expect(createdOptions.Status).To(Equal([]string{"Accepted","Running","Canceled","Canceling","Failed","Missed","Succeeded","SucceededWithWarning","OnHold","Finalizing","Skipped","LegalHold"}))
	Expect(createdOptions.RecoveryActions).To(Equal([]string{"RecoverVMs","RecoverFiles","InstantVolumeMount","RecoverVmDisks","RecoverVApps","RecoverVAppTemplates","UptierSnapshot","RecoverRDS","RecoverAurora","RecoverS3Buckets","RecoverRDSPostgres","RecoverAzureSQL","RecoverApps","CloneApps","RecoverNasVolume","RecoverPhysicalVolumes","RecoverSystem","RecoverExchangeDbs","CloneAppView","RecoverSanVolumes","RecoverSanGroup","RecoverMailbox","RecoverOneDrive","RecoverSharePoint","RecoverPublicFolders","RecoverMsGroup","RecoverMsTeam","ConvertToPst","DownloadChats","RecoverMailboxCSM","RecoverOneDriveCSM","RecoverSharePointCSM","RecoverNamespaces","RecoverObjects","RecoverSfdcObjects","RecoverSfdcOrg","RecoverSfdcRecords","DownloadFilesAndFolders","CloneVMs","CloneView","CloneRefreshApp","CloneVMsToView","ConvertAndDeployVMs","DeployVMs"}))
	return testing_utilities.GetMockSuccessResponse()
}

type GetRecoveriesErrorSender struct{}

func (f GetRecoveriesErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for CreateRecovery
type CreateRecoveryMockSender struct{}

func (f CreateRecoveryMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the CommonRecoverObjectSnapshotParams model
	commonRecoverObjectSnapshotParamsModel := new(backuprecoveryv1.CommonRecoverObjectSnapshotParams)
	commonRecoverObjectSnapshotParamsModel.SnapshotID = core.StringPtr("snapshotID")
	commonRecoverObjectSnapshotParamsModel.PointInTimeUsecs = core.Int64Ptr(int64(26))
	commonRecoverObjectSnapshotParamsModel.ProtectionGroupID = core.StringPtr("protectionGroupID")
	commonRecoverObjectSnapshotParamsModel.ProtectionGroupName = core.StringPtr("protectionGroupName")
	commonRecoverObjectSnapshotParamsModel.RecoverFromStandby = core.BoolPtr(true)

	// Construct an instance of the PhysicalTargetParamsForRecoverVolumeMountTarget model
	physicalTargetParamsForRecoverVolumeMountTargetModel := new(backuprecoveryv1.PhysicalTargetParamsForRecoverVolumeMountTarget)
	physicalTargetParamsForRecoverVolumeMountTargetModel.ID = core.Int64Ptr(int64(26))

	// Construct an instance of the RecoverVolumeMapping model
	recoverVolumeMappingModel := new(backuprecoveryv1.RecoverVolumeMapping)
	recoverVolumeMappingModel.SourceVolumeGuid = core.StringPtr("sourceVolumeGuid")
	recoverVolumeMappingModel.DestinationVolumeGuid = core.StringPtr("destinationVolumeGuid")

	// Construct an instance of the PhysicalTargetParamsForRecoverVolumeVlanConfig model
	physicalTargetParamsForRecoverVolumeVlanConfigModel := new(backuprecoveryv1.PhysicalTargetParamsForRecoverVolumeVlanConfig)
	physicalTargetParamsForRecoverVolumeVlanConfigModel.ID = core.Int64Ptr(int64(38))
	physicalTargetParamsForRecoverVolumeVlanConfigModel.DisableVlan = core.BoolPtr(true)

	// Construct an instance of the RecoverPhysicalVolumeParamsPhysicalTargetParams model
	recoverPhysicalVolumeParamsPhysicalTargetParamsModel := new(backuprecoveryv1.RecoverPhysicalVolumeParamsPhysicalTargetParams)
	recoverPhysicalVolumeParamsPhysicalTargetParamsModel.MountTarget = physicalTargetParamsForRecoverVolumeMountTargetModel
	recoverPhysicalVolumeParamsPhysicalTargetParamsModel.VolumeMapping = []backuprecoveryv1.RecoverVolumeMapping{*recoverVolumeMappingModel}
	recoverPhysicalVolumeParamsPhysicalTargetParamsModel.ForceUnmountVolume = core.BoolPtr(true)
	recoverPhysicalVolumeParamsPhysicalTargetParamsModel.VlanConfig = physicalTargetParamsForRecoverVolumeVlanConfigModel

	// Construct an instance of the RecoverPhysicalParamsRecoverVolumeParams model
	recoverPhysicalParamsRecoverVolumeParamsModel := new(backuprecoveryv1.RecoverPhysicalParamsRecoverVolumeParams)
	recoverPhysicalParamsRecoverVolumeParamsModel.TargetEnvironment = core.StringPtr("kPhysical")
	recoverPhysicalParamsRecoverVolumeParamsModel.PhysicalTargetParams = recoverPhysicalVolumeParamsPhysicalTargetParamsModel

	// Construct an instance of the PhysicalMountVolumesOriginalTargetConfigServerCredentials model
	physicalMountVolumesOriginalTargetConfigServerCredentialsModel := new(backuprecoveryv1.PhysicalMountVolumesOriginalTargetConfigServerCredentials)
	physicalMountVolumesOriginalTargetConfigServerCredentialsModel.Username = core.StringPtr("Username")
	physicalMountVolumesOriginalTargetConfigServerCredentialsModel.Password = core.StringPtr("Password")

	// Construct an instance of the PhysicalTargetParamsForMountVolumeOriginalTargetConfig model
	physicalTargetParamsForMountVolumeOriginalTargetConfigModel := new(backuprecoveryv1.PhysicalTargetParamsForMountVolumeOriginalTargetConfig)
	physicalTargetParamsForMountVolumeOriginalTargetConfigModel.ServerCredentials = physicalMountVolumesOriginalTargetConfigServerCredentialsModel

	// Construct an instance of the RecoverTarget model
	recoverTargetModel := new(backuprecoveryv1.RecoverTarget)
	recoverTargetModel.ID = core.Int64Ptr(int64(26))

	// Construct an instance of the PhysicalMountVolumesNewTargetConfigServerCredentials model
	physicalMountVolumesNewTargetConfigServerCredentialsModel := new(backuprecoveryv1.PhysicalMountVolumesNewTargetConfigServerCredentials)
	physicalMountVolumesNewTargetConfigServerCredentialsModel.Username = core.StringPtr("Username")
	physicalMountVolumesNewTargetConfigServerCredentialsModel.Password = core.StringPtr("Password")

	// Construct an instance of the PhysicalTargetParamsForMountVolumeNewTargetConfig model
	physicalTargetParamsForMountVolumeNewTargetConfigModel := new(backuprecoveryv1.PhysicalTargetParamsForMountVolumeNewTargetConfig)
	physicalTargetParamsForMountVolumeNewTargetConfigModel.MountTarget = recoverTargetModel
	physicalTargetParamsForMountVolumeNewTargetConfigModel.ServerCredentials = physicalMountVolumesNewTargetConfigServerCredentialsModel

	// Construct an instance of the PhysicalTargetParamsForMountVolumeVlanConfig model
	physicalTargetParamsForMountVolumeVlanConfigModel := new(backuprecoveryv1.PhysicalTargetParamsForMountVolumeVlanConfig)
	physicalTargetParamsForMountVolumeVlanConfigModel.ID = core.Int64Ptr(int64(38))
	physicalTargetParamsForMountVolumeVlanConfigModel.DisableVlan = core.BoolPtr(true)

	// Construct an instance of the MountPhysicalVolumeParamsPhysicalTargetParams model
	mountPhysicalVolumeParamsPhysicalTargetParamsModel := new(backuprecoveryv1.MountPhysicalVolumeParamsPhysicalTargetParams)
	mountPhysicalVolumeParamsPhysicalTargetParamsModel.MountToOriginalTarget = core.BoolPtr(true)
	mountPhysicalVolumeParamsPhysicalTargetParamsModel.OriginalTargetConfig = physicalTargetParamsForMountVolumeOriginalTargetConfigModel
	mountPhysicalVolumeParamsPhysicalTargetParamsModel.NewTargetConfig = physicalTargetParamsForMountVolumeNewTargetConfigModel
	mountPhysicalVolumeParamsPhysicalTargetParamsModel.ReadOnlyMount = core.BoolPtr(true)
	mountPhysicalVolumeParamsPhysicalTargetParamsModel.VolumeNames = []string{"volume1"}
	mountPhysicalVolumeParamsPhysicalTargetParamsModel.VlanConfig = physicalTargetParamsForMountVolumeVlanConfigModel

	// Construct an instance of the RecoverPhysicalParamsMountVolumeParams model
	recoverPhysicalParamsMountVolumeParamsModel := new(backuprecoveryv1.RecoverPhysicalParamsMountVolumeParams)
	recoverPhysicalParamsMountVolumeParamsModel.TargetEnvironment = core.StringPtr("kPhysical")
	recoverPhysicalParamsMountVolumeParamsModel.PhysicalTargetParams = mountPhysicalVolumeParamsPhysicalTargetParamsModel

	// Construct an instance of the CommonRecoverFileAndFolderInfo model
	commonRecoverFileAndFolderInfoModel := new(backuprecoveryv1.CommonRecoverFileAndFolderInfo)
	commonRecoverFileAndFolderInfoModel.AbsolutePath = core.StringPtr("~/folder1")
	commonRecoverFileAndFolderInfoModel.IsDirectory = core.BoolPtr(true)
	commonRecoverFileAndFolderInfoModel.IsViewFileRecovery = core.BoolPtr(true)

	// Construct an instance of the PhysicalTargetParamsForRecoverFileAndFolderRecoverTarget model
	physicalTargetParamsForRecoverFileAndFolderRecoverTargetModel := new(backuprecoveryv1.PhysicalTargetParamsForRecoverFileAndFolderRecoverTarget)
	physicalTargetParamsForRecoverFileAndFolderRecoverTargetModel.ID = core.Int64Ptr(int64(26))

	// Construct an instance of the PhysicalTargetParamsForRecoverFileAndFolderVlanConfig model
	physicalTargetParamsForRecoverFileAndFolderVlanConfigModel := new(backuprecoveryv1.PhysicalTargetParamsForRecoverFileAndFolderVlanConfig)
	physicalTargetParamsForRecoverFileAndFolderVlanConfigModel.ID = core.Int64Ptr(int64(38))
	physicalTargetParamsForRecoverFileAndFolderVlanConfigModel.DisableVlan = core.BoolPtr(true)

	// Construct an instance of the RecoverPhysicalFileAndFolderParamsPhysicalTargetParams model
	recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel := new(backuprecoveryv1.RecoverPhysicalFileAndFolderParamsPhysicalTargetParams)
	recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel.RecoverTarget = physicalTargetParamsForRecoverFileAndFolderRecoverTargetModel
	recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel.RestoreToOriginalPaths = core.BoolPtr(true)
	recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel.OverwriteExisting = core.BoolPtr(true)
	recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel.AlternateRestoreDirectory = core.StringPtr("~/dirAlt")
	recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel.PreserveAttributes = core.BoolPtr(true)
	recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel.PreserveTimestamps = core.BoolPtr(true)
	recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel.PreserveAcls = core.BoolPtr(true)
	recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel.ContinueOnError = core.BoolPtr(true)
	recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel.SaveSuccessFiles = core.BoolPtr(true)
	recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel.VlanConfig = physicalTargetParamsForRecoverFileAndFolderVlanConfigModel
	recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel.RestoreEntityType = core.StringPtr("kRegular")

	// Construct an instance of the RecoverPhysicalParamsRecoverFileAndFolderParams model
	recoverPhysicalParamsRecoverFileAndFolderParamsModel := new(backuprecoveryv1.RecoverPhysicalParamsRecoverFileAndFolderParams)
	recoverPhysicalParamsRecoverFileAndFolderParamsModel.FilesAndFolders = []backuprecoveryv1.CommonRecoverFileAndFolderInfo{*commonRecoverFileAndFolderInfoModel}
	recoverPhysicalParamsRecoverFileAndFolderParamsModel.TargetEnvironment = core.StringPtr("kPhysical")
	recoverPhysicalParamsRecoverFileAndFolderParamsModel.PhysicalTargetParams = recoverPhysicalFileAndFolderParamsPhysicalTargetParamsModel

	// Construct an instance of the RecoverPhysicalParamsDownloadFileAndFolderParams model
	recoverPhysicalParamsDownloadFileAndFolderParamsModel := new(backuprecoveryv1.RecoverPhysicalParamsDownloadFileAndFolderParams)
	recoverPhysicalParamsDownloadFileAndFolderParamsModel.ExpiryTimeUsecs = core.Int64Ptr(int64(26))
	recoverPhysicalParamsDownloadFileAndFolderParamsModel.FilesAndFolders = []backuprecoveryv1.CommonRecoverFileAndFolderInfo{*commonRecoverFileAndFolderInfoModel}
	recoverPhysicalParamsDownloadFileAndFolderParamsModel.DownloadFilePath = core.StringPtr("~/downloadFile")

	// Construct an instance of the RecoverPhysicalParamsSystemRecoveryParams model
	recoverPhysicalParamsSystemRecoveryParamsModel := new(backuprecoveryv1.RecoverPhysicalParamsSystemRecoveryParams)
	recoverPhysicalParamsSystemRecoveryParamsModel.FullNasPath = core.StringPtr("~/nas")

	// Construct an instance of the RecoverPhysicalParams model
	recoverPhysicalParamsModel := new(backuprecoveryv1.RecoverPhysicalParams)
	recoverPhysicalParamsModel.Objects = []backuprecoveryv1.CommonRecoverObjectSnapshotParams{*commonRecoverObjectSnapshotParamsModel}
	recoverPhysicalParamsModel.RecoveryAction = core.StringPtr("RecoverPhysicalVolumes")
	recoverPhysicalParamsModel.RecoverVolumeParams = recoverPhysicalParamsRecoverVolumeParamsModel
	recoverPhysicalParamsModel.MountVolumeParams = recoverPhysicalParamsMountVolumeParamsModel
	recoverPhysicalParamsModel.RecoverFileAndFolderParams = recoverPhysicalParamsRecoverFileAndFolderParamsModel
	recoverPhysicalParamsModel.DownloadFileAndFolderParams = recoverPhysicalParamsDownloadFileAndFolderParamsModel
	recoverPhysicalParamsModel.SystemRecoveryParams = recoverPhysicalParamsSystemRecoveryParamsModel

	// Construct an instance of the AAGInfo model
	aagInfoModel := new(backuprecoveryv1.AAGInfo)
	aagInfoModel.Name = core.StringPtr("aagInfoName")
	aagInfoModel.ObjectID = core.Int64Ptr(int64(26))

	// Construct an instance of the HostInformation model
	hostInformationModel := new(backuprecoveryv1.HostInformation)
	hostInformationModel.ID = core.StringPtr("hostInfoId")
	hostInformationModel.Name = core.StringPtr("hostInfoName")
	hostInformationModel.Environment = core.StringPtr("kPhysical")

	// Construct an instance of the MultiStageRestoreOptions model
	multiStageRestoreOptionsModel := new(backuprecoveryv1.MultiStageRestoreOptions)
	multiStageRestoreOptionsModel.EnableAutoSync = core.BoolPtr(true)
	multiStageRestoreOptionsModel.EnableMultiStageRestore = core.BoolPtr(true)

	// Construct an instance of the FilenamePatternToDirectory model
	filenamePatternToDirectoryModel := new(backuprecoveryv1.FilenamePatternToDirectory)
	filenamePatternToDirectoryModel.Directory = core.StringPtr("~/dir1")
	filenamePatternToDirectoryModel.FilenamePattern = core.StringPtr(".sql")

	// Construct an instance of the RecoveryObjectIdentifier model
	recoveryObjectIdentifierModel := new(backuprecoveryv1.RecoveryObjectIdentifier)
	recoveryObjectIdentifierModel.ID = core.Int64Ptr(int64(26))

	// Construct an instance of the RecoverSqlAppNewSourceConfig model
	recoverSqlAppNewSourceConfigModel := new(backuprecoveryv1.RecoverSqlAppNewSourceConfig)
	recoverSqlAppNewSourceConfigModel.KeepCdc = core.BoolPtr(true)
	recoverSqlAppNewSourceConfigModel.MultiStageRestoreOptions = multiStageRestoreOptionsModel
	recoverSqlAppNewSourceConfigModel.NativeLogRecoveryWithClause = core.StringPtr("LogRecoveryWithClause")
	recoverSqlAppNewSourceConfigModel.NativeRecoveryWithClause = core.StringPtr("RecoveryWithClause")
	recoverSqlAppNewSourceConfigModel.OverwritingPolicy = core.StringPtr("FailIfExists")
	recoverSqlAppNewSourceConfigModel.ReplayEntireLastLog = core.BoolPtr(true)
	recoverSqlAppNewSourceConfigModel.RestoreTimeUsecs = core.Int64Ptr(int64(26))
	recoverSqlAppNewSourceConfigModel.SecondaryDataFilesDirList = []backuprecoveryv1.FilenamePatternToDirectory{*filenamePatternToDirectoryModel}
	recoverSqlAppNewSourceConfigModel.WithNoRecovery = core.BoolPtr(true)
	recoverSqlAppNewSourceConfigModel.DataFileDirectoryLocation = core.StringPtr("~/dir1")
	recoverSqlAppNewSourceConfigModel.DatabaseName = core.StringPtr("recovery-database-sql")
	recoverSqlAppNewSourceConfigModel.Host = recoveryObjectIdentifierModel
	recoverSqlAppNewSourceConfigModel.InstanceName = core.StringPtr("database-instance-1")
	recoverSqlAppNewSourceConfigModel.LogFileDirectoryLocation = core.StringPtr("~/dir2")

	// Construct an instance of the RecoverSqlAppOriginalSourceConfig model
	recoverSqlAppOriginalSourceConfigModel := new(backuprecoveryv1.RecoverSqlAppOriginalSourceConfig)
	recoverSqlAppOriginalSourceConfigModel.KeepCdc = core.BoolPtr(true)
	recoverSqlAppOriginalSourceConfigModel.MultiStageRestoreOptions = multiStageRestoreOptionsModel
	recoverSqlAppOriginalSourceConfigModel.NativeLogRecoveryWithClause = core.StringPtr("LogRecoveryWithClause")
	recoverSqlAppOriginalSourceConfigModel.NativeRecoveryWithClause = core.StringPtr("RecoveryWithClause")
	recoverSqlAppOriginalSourceConfigModel.OverwritingPolicy = core.StringPtr("FailIfExists")
	recoverSqlAppOriginalSourceConfigModel.ReplayEntireLastLog = core.BoolPtr(true)
	recoverSqlAppOriginalSourceConfigModel.RestoreTimeUsecs = core.Int64Ptr(int64(26))
	recoverSqlAppOriginalSourceConfigModel.SecondaryDataFilesDirList = []backuprecoveryv1.FilenamePatternToDirectory{*filenamePatternToDirectoryModel}
	recoverSqlAppOriginalSourceConfigModel.WithNoRecovery = core.BoolPtr(true)
	recoverSqlAppOriginalSourceConfigModel.CaptureTailLogs = core.BoolPtr(true)
	recoverSqlAppOriginalSourceConfigModel.DataFileDirectoryLocation = core.StringPtr("~/dir1")
	recoverSqlAppOriginalSourceConfigModel.LogFileDirectoryLocation = core.StringPtr("~/dir2")
	recoverSqlAppOriginalSourceConfigModel.NewDatabaseName = core.StringPtr("recovery-database-sql-new")

	// Construct an instance of the SqlTargetParamsForRecoverSqlApp model
	sqlTargetParamsForRecoverSqlAppModel := new(backuprecoveryv1.SqlTargetParamsForRecoverSqlApp)
	sqlTargetParamsForRecoverSqlAppModel.NewSourceConfig = recoverSqlAppNewSourceConfigModel
	sqlTargetParamsForRecoverSqlAppModel.OriginalSourceConfig = recoverSqlAppOriginalSourceConfigModel
	sqlTargetParamsForRecoverSqlAppModel.RecoverToNewSource = core.BoolPtr(true)

	// Construct an instance of the RecoverSqlAppParams model
	recoverSqlAppParamsModel := new(backuprecoveryv1.RecoverSqlAppParams)
	recoverSqlAppParamsModel.SnapshotID = core.StringPtr("snapshotId")
	recoverSqlAppParamsModel.PointInTimeUsecs = core.Int64Ptr(int64(26))
	recoverSqlAppParamsModel.ProtectionGroupID = core.StringPtr("protectionGroupId")
	recoverSqlAppParamsModel.ProtectionGroupName = core.StringPtr("protectionGroupName")
	recoverSqlAppParamsModel.RecoverFromStandby = core.BoolPtr(true)
	recoverSqlAppParamsModel.AagInfo = aagInfoModel
	recoverSqlAppParamsModel.HostInfo = hostInformationModel
	recoverSqlAppParamsModel.IsEncrypted = core.BoolPtr(true)
	recoverSqlAppParamsModel.SqlTargetParams = sqlTargetParamsForRecoverSqlAppModel
	recoverSqlAppParamsModel.TargetEnvironment = core.StringPtr("kSQL")

	// Construct an instance of the RecoveryVlanConfig model
	recoveryVlanConfigModel := new(backuprecoveryv1.RecoveryVlanConfig)
	recoveryVlanConfigModel.ID = core.Int64Ptr(int64(38))
	recoveryVlanConfigModel.DisableVlan = core.BoolPtr(true)

	// Construct an instance of the RecoverSqlParams model
	recoverSqlParamsModel := new(backuprecoveryv1.RecoverSqlParams)
	recoverSqlParamsModel.RecoverAppParams = []backuprecoveryv1.RecoverSqlAppParams{*recoverSqlAppParamsModel}
	recoverSqlParamsModel.RecoveryAction = core.StringPtr("RecoverApps")
	recoverSqlParamsModel.VlanConfig = recoveryVlanConfigModel

	createdOptions, ok := optionsModel.(*backuprecoveryv1.CreateRecoveryOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Name).To(Equal(core.StringPtr("create-recovery")))
	Expect(createdOptions.SnapshotEnvironment).To(Equal(core.StringPtr("kPhysical")))
	Expect(ResolveModel(createdOptions.PhysicalParams)).To(Equal(ResolveModel(recoverPhysicalParamsModel)))
	Expect(ResolveModel(createdOptions.MssqlParams)).To(Equal(ResolveModel(recoverSqlParamsModel)))
	Expect(createdOptions.RequestInitiatorType).To(Equal(core.StringPtr("UIUser")))
	return testing_utilities.GetMockSuccessResponse()
}

type CreateRecoveryErrorSender struct{}

func (f CreateRecoveryErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetRecoveryByID
type GetRecoveryByIDMockSender struct{}

func (f GetRecoveryByIDMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetRecoveryByIdOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.StringPtr("testString")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	return testing_utilities.GetMockSuccessResponse()
}

type GetRecoveryByIDErrorSender struct{}

func (f GetRecoveryByIDErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for DownloadFilesFromRecovery
type DownloadFilesFromRecoveryMockSender struct{}

func (f DownloadFilesFromRecoveryMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.DownloadFilesFromRecoveryOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.StringPtr("testString")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.StartOffset).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.Length).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.FileType).To(Equal(core.StringPtr("fileType")))
	Expect(createdOptions.SourceName).To(Equal(core.StringPtr("sourceName")))
	Expect(createdOptions.StartTime).To(Equal(core.StringPtr("startTime")))
	Expect(createdOptions.IncludeTenants).To(Equal(core.BoolPtr(true)))
	return testing_utilities.GetMockSuccessResponse()
}

type DownloadFilesFromRecoveryErrorSender struct{}

func (f DownloadFilesFromRecoveryErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetDataSourceConnections
type GetDataSourceConnectionsMockSender struct{}

func (f GetDataSourceConnectionsMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetDataSourceConnectionsOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.ConnectionIds).To(Equal([]string{"connectionId1","connectionId2"}))
	Expect(createdOptions.ConnectionNames).To(Equal([]string{"connectionName1","connectionName2"}))
	return testing_utilities.GetMockSuccessResponse()
}

type GetDataSourceConnectionsErrorSender struct{}

func (f GetDataSourceConnectionsErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for CreateDataSourceConnection
type CreateDataSourceConnectionMockSender struct{}

func (f CreateDataSourceConnectionMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.CreateDataSourceConnectionOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ConnectionName).To(Equal(core.StringPtr("data-source-connection")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	return testing_utilities.GetMockSuccessResponse()
}

type CreateDataSourceConnectionErrorSender struct{}

func (f CreateDataSourceConnectionErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for DeleteDataSourceConnection
type DeleteDataSourceConnectionMockSender struct{}

func (f DeleteDataSourceConnectionMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.DeleteDataSourceConnectionOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ConnectionID).To(Equal(core.StringPtr("testString")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	return testing_utilities.GetMockSuccessResponse()
}

type DeleteDataSourceConnectionErrorSender struct{}

func (f DeleteDataSourceConnectionErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for PatchDataSourceConnection
type PatchDataSourceConnectionMockSender struct{}

func (f PatchDataSourceConnectionMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.PatchDataSourceConnectionOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ConnectionID).To(Equal(core.StringPtr("connectionId")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.ConnectionName).To(Equal(core.StringPtr("connectionName")))
	return testing_utilities.GetMockSuccessResponse()
}

type PatchDataSourceConnectionErrorSender struct{}

func (f PatchDataSourceConnectionErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GenerateDataSourceConnectionRegistrationToken
type GenerateDataSourceConnectionRegistrationTokenMockSender struct{}

func (f GenerateDataSourceConnectionRegistrationTokenMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GenerateDataSourceConnectionRegistrationTokenOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ConnectionID).To(Equal(core.StringPtr("testString")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	return testing_utilities.GetMockSuccessResponse()
}

type GenerateDataSourceConnectionRegistrationTokenErrorSender struct{}

func (f GenerateDataSourceConnectionRegistrationTokenErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetDataSourceConnectors
type GetDataSourceConnectorsMockSender struct{}

func (f GetDataSourceConnectorsMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetDataSourceConnectorsOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.ConnectorIds).To(Equal([]string{"connectorId1","connectorId2"}))
	Expect(createdOptions.ConnectorNames).To(Equal([]string{"connectionName1","connectionName2"}))
	Expect(createdOptions.ConnectionID).To(Equal(core.StringPtr("testString")))
	return testing_utilities.GetMockSuccessResponse()
}

type GetDataSourceConnectorsErrorSender struct{}

func (f GetDataSourceConnectorsErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for DeleteDataSourceConnector
type DeleteDataSourceConnectorMockSender struct{}

func (f DeleteDataSourceConnectorMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.DeleteDataSourceConnectorOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ConnectorID).To(Equal(core.StringPtr("connectorId")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	return testing_utilities.GetMockSuccessResponse()
}

type DeleteDataSourceConnectorErrorSender struct{}

func (f DeleteDataSourceConnectorErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for PatchDataSourceConnector
type PatchDataSourceConnectorMockSender struct{}

func (f PatchDataSourceConnectorMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.PatchDataSourceConnectorOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ConnectorID).To(Equal(core.StringPtr("connectorID")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.ConnectorName).To(Equal(core.StringPtr("connectorName")))
	return testing_utilities.GetMockSuccessResponse()
}

type PatchDataSourceConnectorErrorSender struct{}

func (f PatchDataSourceConnectorErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for DownloadAgent
type DownloadAgentMockSender struct{}

func (f DownloadAgentMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the LinuxAgentParams model
	linuxAgentParamsModel := new(backuprecoveryv1.LinuxAgentParams)
	linuxAgentParamsModel.PackageType = core.StringPtr("kScript")

	createdOptions, ok := optionsModel.(*backuprecoveryv1.DownloadAgentOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Platform).To(Equal(core.StringPtr("kWindows")))
	Expect(ResolveModel(createdOptions.LinuxParams)).To(Equal(ResolveModel(linuxAgentParamsModel)))
	return testing_utilities.GetMockFileResponse()
}

type DownloadAgentErrorSender struct{}

func (f DownloadAgentErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetConnectorMetadata
type GetConnectorMetadataMockSender struct{}

func (f GetConnectorMetadataMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetConnectorMetadataOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	return testing_utilities.GetMockSuccessResponse()
}

type GetConnectorMetadataErrorSender struct{}

func (f GetConnectorMetadataErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetObjectSnapshots
type GetObjectSnapshotsMockSender struct{}

func (f GetObjectSnapshotsMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetObjectSnapshotsOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.ID).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.FromTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.ToTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.RunStartFromTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.RunStartToTimeUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.SnapshotActions).To(Equal([]string{"RecoverVMs","RecoverFiles","InstantVolumeMount","RecoverVmDisks","MountVolumes","RecoverVApps","RecoverRDS","RecoverAurora","RecoverS3Buckets","RecoverApps","RecoverNasVolume","RecoverPhysicalVolumes","RecoverSystem","RecoverSanVolumes","RecoverNamespaces","RecoverObjects","DownloadFilesAndFolders","RecoverPublicFolders","RecoverVAppTemplates","RecoverMailbox","RecoverOneDrive","RecoverMsTeam","RecoverMsGroup","RecoverSharePoint","ConvertToPst","RecoverSfdcRecords","RecoverAzureSQL","DownloadChats","RecoverRDSPostgres","RecoverMailboxCSM","RecoverOneDriveCSM","RecoverSharePointCSM"}))
	Expect(createdOptions.RunTypes).To(Equal([]string{"kRegular","kFull","kLog","kSystem","kHydrateCDP","kStorageArraySnapshot"}))
	Expect(createdOptions.ProtectionGroupIds).To(Equal([]string{"protectionGroupId1"}))
	Expect(createdOptions.RunInstanceIds).To(Equal([]int64{int64(26),int64(27)}))
	Expect(createdOptions.RegionIds).To(Equal([]string{"regionId1"}))
	Expect(createdOptions.ObjectActionKeys).To(Equal([]string{"kVMware","kHyperV","kVCD","kAzure","kGCP","kKVM","kAcropolis","kAWS","kAWSNative","kAwsS3","kAWSSnapshotManager","kRDSSnapshotManager","kAuroraSnapshotManager","kAwsRDSPostgresBackup","kAwsRDSPostgres","kAwsAuroraPostgres","kAzureNative","kAzureSQL","kAzureSnapshotManager","kPhysical","kPhysicalFiles","kGPFS","kElastifile","kNetapp","kGenericNas","kIsilon","kFlashBlade","kPure","kIbmFlashSystem","kSQL","kExchange","kAD","kOracle","kView","kRemoteAdapter","kO365","kO365PublicFolders","kO365Teams","kO365Group","kO365Exchange","kO365OneDrive","kO365Sharepoint","kKubernetes","kCassandra","kMongoDB","kCouchbase","kHdfs","kHive","kHBase","kSAPHANA","kUDA","kSfdc","kO365ExchangeCSM","kO365OneDriveCSM","kO365SharepointCSM"}))
	return testing_utilities.GetMockSuccessResponse()
}

type GetObjectSnapshotsErrorSender struct{}

func (f GetObjectSnapshotsErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for CreateDownloadFilesAndFoldersRecovery
type CreateDownloadFilesAndFoldersRecoveryMockSender struct{}

func (f CreateDownloadFilesAndFoldersRecoveryMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the CommonRecoverObjectSnapshotParams model
	commonRecoverObjectSnapshotParamsModel := new(backuprecoveryv1.CommonRecoverObjectSnapshotParams)
	commonRecoverObjectSnapshotParamsModel.SnapshotID = core.StringPtr("snapshotId")
	commonRecoverObjectSnapshotParamsModel.PointInTimeUsecs = core.Int64Ptr(int64(26))
	commonRecoverObjectSnapshotParamsModel.ProtectionGroupID = core.StringPtr("protectionGroupId")
	commonRecoverObjectSnapshotParamsModel.ProtectionGroupName = core.StringPtr("protectionGroupName")
	commonRecoverObjectSnapshotParamsModel.RecoverFromStandby = core.BoolPtr(true)

	// Construct an instance of the FilesAndFoldersObject model
	filesAndFoldersObjectModel := new(backuprecoveryv1.FilesAndFoldersObject)
	filesAndFoldersObjectModel.AbsolutePath = core.StringPtr("~/home/dir1")
	filesAndFoldersObjectModel.IsDirectory = core.BoolPtr(true)

	// Construct an instance of the DocumentObject model
	documentObjectModel := new(backuprecoveryv1.DocumentObject)
	documentObjectModel.IsDirectory = core.BoolPtr(true)
	documentObjectModel.ItemID = core.StringPtr("item1")

	createdOptions, ok := optionsModel.(*backuprecoveryv1.CreateDownloadFilesAndFoldersRecoveryOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.Name).To(Equal(core.StringPtr("create-download-files-and-folders-recovery")))
	Expect(ResolveModel(createdOptions.Object)).To(Equal(ResolveModel(commonRecoverObjectSnapshotParamsModel)))
	Expect(ResolveModel(createdOptions.FilesAndFolders)).To(Equal(ResolveModel([]backuprecoveryv1.FilesAndFoldersObject{*filesAndFoldersObjectModel})))
	Expect(ResolveModel(createdOptions.Documents)).To(Equal(ResolveModel([]backuprecoveryv1.DocumentObject{*documentObjectModel})))
	Expect(createdOptions.ParentRecoveryID).To(Equal(core.StringPtr("parentRecoveryId")))
	Expect(createdOptions.GlacierRetrievalType).To(Equal(core.StringPtr("kStandard")))
	return testing_utilities.GetMockSuccessResponse()
}

type CreateDownloadFilesAndFoldersRecoveryErrorSender struct{}

func (f CreateDownloadFilesAndFoldersRecoveryErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for GetRestorePointsInTimeRange
type GetRestorePointsInTimeRangeMockSender struct{}

func (f GetRestorePointsInTimeRangeMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.GetRestorePointsInTimeRangeOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.EndTimeUsecs).To(Equal(core.Int64Ptr(int64(45))))
	Expect(createdOptions.Environment).To(Equal(core.StringPtr("kVMware")))
	Expect(createdOptions.ProtectionGroupIds).To(Equal([]string{"protectionGroupId1"}))
	Expect(createdOptions.StartTimeUsecs).To(Equal(core.Int64Ptr(int64(15))))
	Expect(createdOptions.SourceID).To(Equal(core.Int64Ptr(int64(26))))
	return testing_utilities.GetMockSuccessResponse()
}

type GetRestorePointsInTimeRangeErrorSender struct{}

func (f GetRestorePointsInTimeRangeErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for DownloadIndexedFile
type DownloadIndexedFileMockSender struct{}

func (f DownloadIndexedFileMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.DownloadIndexedFileOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.SnapshotsID).To(Equal(core.StringPtr("snapshotId1")))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.FilePath).To(Equal(core.StringPtr("~/home/downloadFile")))
	Expect(createdOptions.NvramFile).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.RetryAttempt).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.StartOffset).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.Length).To(Equal(core.Int64Ptr(int64(26))))
	return testing_utilities.GetMockSuccessResponse()
}

type DownloadIndexedFileErrorSender struct{}

func (f DownloadIndexedFileErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for SearchIndexedObjects
type SearchIndexedObjectsMockSender struct{}

func (f SearchIndexedObjectsMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	// Construct an instance of the CassandraOnPremSearchParams model
	cassandraOnPremSearchParamsModel := new(backuprecoveryv1.CassandraOnPremSearchParams)
	cassandraOnPremSearchParamsModel.CassandraObjectTypes = []string{"CassandraKeyspaces","CassandraTables"}
	cassandraOnPremSearchParamsModel.SearchString = core.StringPtr("searchString")
	cassandraOnPremSearchParamsModel.SourceIds = []int64{int64(26),int64(27)}

	// Construct an instance of the CouchBaseOnPremSearchParams model
	couchBaseOnPremSearchParamsModel := new(backuprecoveryv1.CouchBaseOnPremSearchParams)
	couchBaseOnPremSearchParamsModel.CouchbaseObjectTypes = []string{"CouchbaseBuckets"}
	couchBaseOnPremSearchParamsModel.SearchString = core.StringPtr("searchString")
	couchBaseOnPremSearchParamsModel.SourceIds = []int64{int64(26),int64(27)}

	// Construct an instance of the O365SearchEmailsRequestParams model
	o365SearchEmailsRequestParamsModel := new(backuprecoveryv1.O365SearchEmailsRequestParams)
	o365SearchEmailsRequestParamsModel.DomainIds = []int64{int64(26),int64(27)}
	o365SearchEmailsRequestParamsModel.MailboxIds = []int64{int64(26),int64(27)}

	// Construct an instance of the SearchEmailRequestParams model
	searchEmailRequestParamsModel := new(backuprecoveryv1.SearchEmailRequestParams)
	searchEmailRequestParamsModel.AttendeesAddresses = []string{"attendee1@domain.com"}
	searchEmailRequestParamsModel.BccRecipientAddresses = []string{"bccrecipient@domain.com"}
	searchEmailRequestParamsModel.CcRecipientAddresses = []string{"ccrecipient@domain.com"}
	searchEmailRequestParamsModel.CreatedEndTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsModel.CreatedStartTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsModel.DueDateEndTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsModel.DueDateStartTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsModel.EmailAddress = core.StringPtr("email@domain.com")
	searchEmailRequestParamsModel.EmailSubject = core.StringPtr("Email Subject")
	searchEmailRequestParamsModel.FirstName = core.StringPtr("First Name")
	searchEmailRequestParamsModel.FolderNames = []string{"folder1"}
	searchEmailRequestParamsModel.HasAttachment = core.BoolPtr(true)
	searchEmailRequestParamsModel.LastModifiedEndTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsModel.LastModifiedStartTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsModel.LastName = core.StringPtr("Last Name")
	searchEmailRequestParamsModel.MiddleName = core.StringPtr("Middle Name")
	searchEmailRequestParamsModel.OrganizerAddress = core.StringPtr("organizer@domain.com")
	searchEmailRequestParamsModel.ReceivedEndTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsModel.ReceivedStartTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsModel.RecipientAddresses = []string{"recipient@domain.com"}
	searchEmailRequestParamsModel.SenderAddress = core.StringPtr("sender@domain.com")
	searchEmailRequestParamsModel.SourceEnvironment = core.StringPtr("kO365")
	searchEmailRequestParamsModel.TaskStatusTypes = []string{"NotStarted","InProgress","Completed","WaitingOnOthers","Deferred"}
	searchEmailRequestParamsModel.Types = []string{"Email","Folder","Calendar","Contact","Task","Note"}
	searchEmailRequestParamsModel.O365Params = o365SearchEmailsRequestParamsModel

	// Construct an instance of the SearchExchangeObjectsRequestParams model
	searchExchangeObjectsRequestParamsModel := new(backuprecoveryv1.SearchExchangeObjectsRequestParams)
	searchExchangeObjectsRequestParamsModel.SearchString = core.StringPtr("searchString")

	// Construct an instance of the SearchFileRequestParams model
	searchFileRequestParamsModel := new(backuprecoveryv1.SearchFileRequestParams)
	searchFileRequestParamsModel.SearchString = core.StringPtr("searchString")
	searchFileRequestParamsModel.Types = []string{"File","Directory","Symlink"}
	searchFileRequestParamsModel.SourceEnvironments = []string{"kVMware","kHyperV","kSQL","kView","kRemoteAdapter","kPhysical","kPhysicalFiles","kPure","kIbmFlashSystem","kAzure","kNetapp","kGenericNas","kAcropolis","kIsilon","kGPFS","kKVM","kAWS","kExchange","kOracle","kGCP","kFlashBlade","kO365","kHyperFlex","kKubernetes","kElastifile","kSAPHANA","kUDA","kSfdc"}
	searchFileRequestParamsModel.SourceIds = []int64{int64(26),int64(27)}
	searchFileRequestParamsModel.ObjectIds = []int64{int64(26),int64(27)}

	// Construct an instance of the HbaseOnPremSearchParams model
	hbaseOnPremSearchParamsModel := new(backuprecoveryv1.HbaseOnPremSearchParams)
	hbaseOnPremSearchParamsModel.HbaseObjectTypes = []string{"HbaseNamespaces","HbaseTables"}
	hbaseOnPremSearchParamsModel.SearchString = core.StringPtr("searchString")
	hbaseOnPremSearchParamsModel.SourceIds = []int64{int64(26),int64(27)}

	// Construct an instance of the HDFSOnPremSearchParams model
	hdfsOnPremSearchParamsModel := new(backuprecoveryv1.HDFSOnPremSearchParams)
	hdfsOnPremSearchParamsModel.HdfsTypes = []string{"HDFSFolders","HDFSFiles"}
	hdfsOnPremSearchParamsModel.SearchString = core.StringPtr("searchString")
	hdfsOnPremSearchParamsModel.SourceIds = []int64{int64(26),int64(27)}

	// Construct an instance of the HiveOnPremSearchParams model
	hiveOnPremSearchParamsModel := new(backuprecoveryv1.HiveOnPremSearchParams)
	hiveOnPremSearchParamsModel.HiveObjectTypes = []string{"HiveDatabases","HiveTables","HivePartitions"}
	hiveOnPremSearchParamsModel.SearchString = core.StringPtr("searchString")
	hiveOnPremSearchParamsModel.SourceIds = []int64{int64(26),int64(27)}

	// Construct an instance of the MongoDbOnPremSearchParams model
	mongoDbOnPremSearchParamsModel := new(backuprecoveryv1.MongoDbOnPremSearchParams)
	mongoDbOnPremSearchParamsModel.MongoDBObjectTypes = []string{"MongoDatabases","MongoCollections"}
	mongoDbOnPremSearchParamsModel.SearchString = core.StringPtr("searchString")
	mongoDbOnPremSearchParamsModel.SourceIds = []int64{int64(26),int64(27)}

	// Construct an instance of the SearchEmailRequestParamsBase model
	searchEmailRequestParamsBaseModel := new(backuprecoveryv1.SearchEmailRequestParamsBase)
	searchEmailRequestParamsBaseModel.AttendeesAddresses = []string{"attendee1@domain.com"}
	searchEmailRequestParamsBaseModel.BccRecipientAddresses = []string{"bccrecipient@domain.com"}
	searchEmailRequestParamsBaseModel.CcRecipientAddresses = []string{"ccrecipient@domain.com"}
	searchEmailRequestParamsBaseModel.CreatedEndTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsBaseModel.CreatedStartTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsBaseModel.DueDateEndTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsBaseModel.DueDateStartTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsBaseModel.EmailAddress = core.StringPtr("email@domain.com")
	searchEmailRequestParamsBaseModel.EmailSubject = core.StringPtr("Email Subject")
	searchEmailRequestParamsBaseModel.FirstName = core.StringPtr("First Name")
	searchEmailRequestParamsBaseModel.FolderNames = []string{"folder1"}
	searchEmailRequestParamsBaseModel.HasAttachment = core.BoolPtr(true)
	searchEmailRequestParamsBaseModel.LastModifiedEndTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsBaseModel.LastModifiedStartTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsBaseModel.LastName = core.StringPtr("Last Name")
	searchEmailRequestParamsBaseModel.MiddleName = core.StringPtr("Middle Name")
	searchEmailRequestParamsBaseModel.OrganizerAddress = core.StringPtr("organizer@domain.com")
	searchEmailRequestParamsBaseModel.ReceivedEndTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsBaseModel.ReceivedStartTimeSecs = core.Int64Ptr(int64(26))
	searchEmailRequestParamsBaseModel.RecipientAddresses = []string{"recipient@domain.com"}
	searchEmailRequestParamsBaseModel.SenderAddress = core.StringPtr("sender@domain.com")
	searchEmailRequestParamsBaseModel.SourceEnvironment = core.StringPtr("kO365")
	searchEmailRequestParamsBaseModel.TaskStatusTypes = []string{"NotStarted","InProgress","Completed","WaitingOnOthers","Deferred"}
	searchEmailRequestParamsBaseModel.Types = []string{"Email","Folder","Calendar","Contact","Task","Note"}

	// Construct an instance of the O365SearchRequestParams model
	o365SearchRequestParamsModel := new(backuprecoveryv1.O365SearchRequestParams)
	o365SearchRequestParamsModel.DomainIds = []int64{int64(26),int64(27)}
	o365SearchRequestParamsModel.GroupIds = []int64{int64(26),int64(27)}
	o365SearchRequestParamsModel.SiteIds = []int64{int64(26),int64(27)}
	o365SearchRequestParamsModel.TeamsIds = []int64{int64(26),int64(27)}
	o365SearchRequestParamsModel.UserIds = []int64{int64(26),int64(27)}

	// Construct an instance of the SearchDocumentLibraryRequestParams model
	searchDocumentLibraryRequestParamsModel := new(backuprecoveryv1.SearchDocumentLibraryRequestParams)
	searchDocumentLibraryRequestParamsModel.CategoryTypes = []string{"Document","Excel","Powerpoint","Image","OneNote"}
	searchDocumentLibraryRequestParamsModel.CreationEndTimeSecs = core.Int64Ptr(int64(26))
	searchDocumentLibraryRequestParamsModel.CreationStartTimeSecs = core.Int64Ptr(int64(26))
	searchDocumentLibraryRequestParamsModel.IncludeFiles = core.BoolPtr(true)
	searchDocumentLibraryRequestParamsModel.IncludeFolders = core.BoolPtr(true)
	searchDocumentLibraryRequestParamsModel.O365Params = o365SearchRequestParamsModel
	searchDocumentLibraryRequestParamsModel.OwnerNames = []string{"ownerName1"}
	searchDocumentLibraryRequestParamsModel.SearchString = core.StringPtr("searchString")
	searchDocumentLibraryRequestParamsModel.SizeBytesLowerLimit = core.Int64Ptr(int64(26))
	searchDocumentLibraryRequestParamsModel.SizeBytesUpperLimit = core.Int64Ptr(int64(26))

	// Construct an instance of the SearchMsGroupsRequestParams model
	searchMsGroupsRequestParamsModel := new(backuprecoveryv1.SearchMsGroupsRequestParams)
	searchMsGroupsRequestParamsModel.MailboxParams = searchEmailRequestParamsBaseModel
	searchMsGroupsRequestParamsModel.O365Params = o365SearchRequestParamsModel
	searchMsGroupsRequestParamsModel.SiteParams = searchDocumentLibraryRequestParamsModel

	// Construct an instance of the O365TeamsChannelsSearchRequestParams model
	o365TeamsChannelsSearchRequestParamsModel := new(backuprecoveryv1.O365TeamsChannelsSearchRequestParams)
	o365TeamsChannelsSearchRequestParamsModel.ChannelEmail = core.StringPtr("channel@domain.com")
	o365TeamsChannelsSearchRequestParamsModel.ChannelID = core.StringPtr("channelId")
	o365TeamsChannelsSearchRequestParamsModel.ChannelName = core.StringPtr("channelName")
	o365TeamsChannelsSearchRequestParamsModel.IncludePrivateChannels = core.BoolPtr(true)
	o365TeamsChannelsSearchRequestParamsModel.IncludePublicChannels = core.BoolPtr(true)

	// Construct an instance of the SearchMsTeamsRequestParams model
	searchMsTeamsRequestParamsModel := new(backuprecoveryv1.SearchMsTeamsRequestParams)
	searchMsTeamsRequestParamsModel.CategoryTypes = []string{"Document","Excel","Powerpoint","Image","OneNote"}
	searchMsTeamsRequestParamsModel.ChannelNames = []string{"channelName1"}
	searchMsTeamsRequestParamsModel.ChannelParams = o365TeamsChannelsSearchRequestParamsModel
	searchMsTeamsRequestParamsModel.CreationEndTimeSecs = core.Int64Ptr(int64(26))
	searchMsTeamsRequestParamsModel.CreationStartTimeSecs = core.Int64Ptr(int64(26))
	searchMsTeamsRequestParamsModel.O365Params = o365SearchRequestParamsModel
	searchMsTeamsRequestParamsModel.OwnerNames = []string{"ownerName1"}
	searchMsTeamsRequestParamsModel.SearchString = core.StringPtr("searchString")
	searchMsTeamsRequestParamsModel.SizeBytesLowerLimit = core.Int64Ptr(int64(26))
	searchMsTeamsRequestParamsModel.SizeBytesUpperLimit = core.Int64Ptr(int64(26))
	searchMsTeamsRequestParamsModel.Types = []string{"Channel","Chat","Conversation","File","Folder"}

	// Construct an instance of the SearchPublicFolderRequestParams model
	searchPublicFolderRequestParamsModel := new(backuprecoveryv1.SearchPublicFolderRequestParams)
	searchPublicFolderRequestParamsModel.SearchString = core.StringPtr("searchString")
	searchPublicFolderRequestParamsModel.Types = []string{"Calendar","Contact","Post","Folder","Task","Journal","Note"}
	searchPublicFolderRequestParamsModel.HasAttachment = core.BoolPtr(true)
	searchPublicFolderRequestParamsModel.SenderAddress = core.StringPtr("sender@domain.com")
	searchPublicFolderRequestParamsModel.RecipientAddresses = []string{"recipient@domain.com"}
	searchPublicFolderRequestParamsModel.CcRecipientAddresses = []string{"ccrecipient@domain.com"}
	searchPublicFolderRequestParamsModel.BccRecipientAddresses = []string{"bccrecipient@domain.com"}
	searchPublicFolderRequestParamsModel.ReceivedStartTimeSecs = core.Int64Ptr(int64(26))
	searchPublicFolderRequestParamsModel.ReceivedEndTimeSecs = core.Int64Ptr(int64(26))

	// Construct an instance of the SearchSfdcRecordsRequestParams model
	searchSfdcRecordsRequestParamsModel := new(backuprecoveryv1.SearchSfdcRecordsRequestParams)
	searchSfdcRecordsRequestParamsModel.MutationTypes = []string{"All","Added","Removed","Changed"}
	searchSfdcRecordsRequestParamsModel.ObjectName = core.StringPtr("objectName")
	searchSfdcRecordsRequestParamsModel.QueryString = core.StringPtr("queryString")
	searchSfdcRecordsRequestParamsModel.SnapshotID = core.StringPtr("snapshotId")

	// Construct an instance of the UdaOnPremSearchParams model
	udaOnPremSearchParamsModel := new(backuprecoveryv1.UdaOnPremSearchParams)
	udaOnPremSearchParamsModel.SearchString = core.StringPtr("searchString")
	udaOnPremSearchParamsModel.SourceIds = []int64{int64(26),int64(27)}

	createdOptions, ok := optionsModel.(*backuprecoveryv1.SearchIndexedObjectsOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.ObjectType).To(Equal(core.StringPtr("Emails")))
	Expect(createdOptions.ProtectionGroupIds).To(Equal([]string{"protectionGroupId1"}))
	Expect(createdOptions.StorageDomainIds).To(Equal([]int64{int64(26),int64(27)}))
	Expect(createdOptions.TenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.IncludeTenants).To(Equal(core.BoolPtr(false)))
	Expect(createdOptions.Tags).To(Equal([]string{"123:456:ABC-123","123:456:ABC-456"}))
	Expect(createdOptions.SnapshotTags).To(Equal([]string{"123:456:DEF-123","123:456:DEF-456"}))
	Expect(createdOptions.MustHaveTagIds).To(Equal([]string{"123:456:ABC-123"}))
	Expect(createdOptions.MightHaveTagIds).To(Equal([]string{"123:456:ABC-456"}))
	Expect(createdOptions.MustHaveSnapshotTagIds).To(Equal([]string{"123:456:DEF-123"}))
	Expect(createdOptions.MightHaveSnapshotTagIds).To(Equal([]string{"123:456:DEF-456"}))
	Expect(createdOptions.PaginationCookie).To(Equal(core.StringPtr("paginationCookie")))
	Expect(createdOptions.Count).To(Equal(core.Int64Ptr(int64(38))))
	Expect(createdOptions.UseCachedData).To(Equal(core.BoolPtr(true)))
	Expect(ResolveModel(createdOptions.CassandraParams)).To(Equal(ResolveModel(cassandraOnPremSearchParamsModel)))
	Expect(ResolveModel(createdOptions.CouchbaseParams)).To(Equal(ResolveModel(couchBaseOnPremSearchParamsModel)))
	Expect(ResolveModel(createdOptions.EmailParams)).To(Equal(ResolveModel(searchEmailRequestParamsModel)))
	Expect(ResolveModel(createdOptions.ExchangeParams)).To(Equal(ResolveModel(searchExchangeObjectsRequestParamsModel)))
	Expect(ResolveModel(createdOptions.FileParams)).To(Equal(ResolveModel(searchFileRequestParamsModel)))
	Expect(ResolveModel(createdOptions.HbaseParams)).To(Equal(ResolveModel(hbaseOnPremSearchParamsModel)))
	Expect(ResolveModel(createdOptions.HdfsParams)).To(Equal(ResolveModel(hdfsOnPremSearchParamsModel)))
	Expect(ResolveModel(createdOptions.HiveParams)).To(Equal(ResolveModel(hiveOnPremSearchParamsModel)))
	Expect(ResolveModel(createdOptions.MongodbParams)).To(Equal(ResolveModel(mongoDbOnPremSearchParamsModel)))
	Expect(ResolveModel(createdOptions.MsGroupsParams)).To(Equal(ResolveModel(searchMsGroupsRequestParamsModel)))
	Expect(ResolveModel(createdOptions.MsTeamsParams)).To(Equal(ResolveModel(searchMsTeamsRequestParamsModel)))
	Expect(ResolveModel(createdOptions.OneDriveParams)).To(Equal(ResolveModel(searchDocumentLibraryRequestParamsModel)))
	Expect(ResolveModel(createdOptions.PublicFolderParams)).To(Equal(ResolveModel(searchPublicFolderRequestParamsModel)))
	Expect(ResolveModel(createdOptions.SfdcParams)).To(Equal(ResolveModel(searchSfdcRecordsRequestParamsModel)))
	Expect(ResolveModel(createdOptions.SharepointParams)).To(Equal(ResolveModel(searchDocumentLibraryRequestParamsModel)))
	Expect(ResolveModel(createdOptions.UdaParams)).To(Equal(ResolveModel(udaOnPremSearchParamsModel)))
	return testing_utilities.GetMockSuccessResponse()
}

type SearchIndexedObjectsErrorSender struct{}

func (f SearchIndexedObjectsErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for SearchObjects
type SearchObjectsMockSender struct{}

func (f SearchObjectsMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.SearchObjectsOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.RequestInitiatorType).To(Equal(core.StringPtr("UIUser")))
	Expect(createdOptions.SearchString).To(Equal(core.StringPtr("searchString")))
	Expect(createdOptions.Environments).To(Equal([]string{"kPhysical","kSQL"}))
	Expect(createdOptions.ProtectionTypes).To(Equal([]string{"kAgent","kNative","kSnapshotManager","kRDSSnapshotManager","kAuroraSnapshotManager","kAwsS3","kAwsRDSPostgresBackup","kAwsAuroraPostgres","kAwsRDSPostgres","kAzureSQL","kFile","kVolume"}))
	Expect(createdOptions.ProtectionGroupIds).To(Equal([]string{"protectionGroupId1"}))
	Expect(createdOptions.ObjectIds).To(Equal([]int64{int64(26),int64(27)}))
	Expect(createdOptions.OsTypes).To(Equal([]string{"kLinux","kWindows"}))
	Expect(createdOptions.SourceIds).To(Equal([]int64{int64(26),int64(27)}))
	Expect(createdOptions.SourceUUIDs).To(Equal([]string{"sourceUuid1"}))
	Expect(createdOptions.IsProtected).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.IsDeleted).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.LastRunStatusList).To(Equal([]string{"Accepted","Running","Canceled","Canceling","Failed","Missed","Succeeded","SucceededWithWarning","OnHold","Finalizing","Skipped","LegalHold"}))
	Expect(createdOptions.ClusterIdentifiers).To(Equal([]string{"clusterIdentifier1"}))
	Expect(createdOptions.IncludeDeletedObjects).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.PaginationCookie).To(Equal(core.StringPtr("paginationCookie")))
	Expect(createdOptions.Count).To(Equal(core.Int64Ptr(int64(38))))
	Expect(createdOptions.MustHaveTagIds).To(Equal([]string{"123:456:ABC-123"}))
	Expect(createdOptions.MightHaveTagIds).To(Equal([]string{"123:456:ABC-456"}))
	Expect(createdOptions.MustHaveSnapshotTagIds).To(Equal([]string{"123:456:DEF-123"}))
	Expect(createdOptions.MightHaveSnapshotTagIds).To(Equal([]string{"123:456:DEF-456"}))
	Expect(createdOptions.TagSearchName).To(Equal(core.StringPtr("tagName")))
	Expect(createdOptions.TagNames).To(Equal([]string{"tag1"}))
	Expect(createdOptions.TagTypes).To(Equal([]string{"System","Custom","ThirdParty"}))
	Expect(createdOptions.TagCategories).To(Equal([]string{"Security"}))
	Expect(createdOptions.TagSubCategories).To(Equal([]string{"Classification","Threats","Anomalies","Dspm"}))
	Expect(createdOptions.IncludeHeliosTagInfoForObjects).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.ExternalFilters).To(Equal([]string{"filter1"}))
	return testing_utilities.GetMockSuccessResponse()
}

type SearchObjectsErrorSender struct{}

func (f SearchObjectsErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}
// Fake senders for SearchProtectedObjects
type SearchProtectedObjectsMockSender struct{}

func (f SearchProtectedObjectsMockSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	createdOptions, ok := optionsModel.(*backuprecoveryv1.SearchProtectedObjectsOptions)
	Expect(ok).To(Equal(true))
	Expect(createdOptions.XIBMTenantID).To(Equal(core.StringPtr("tenantId")))
	Expect(createdOptions.RequestInitiatorType).To(Equal(core.StringPtr("UIUser")))
	Expect(createdOptions.SearchString).To(Equal(core.StringPtr("searchString")))
	Expect(createdOptions.Environments).To(Equal([]string{"kPhysical","kSQL"}))
	Expect(createdOptions.SnapshotActions).To(Equal([]string{"RecoverVMs","RecoverFiles","InstantVolumeMount","RecoverVmDisks","MountVolumes","RecoverVApps","RecoverRDS","RecoverAurora","RecoverS3Buckets","RecoverApps","RecoverNasVolume","RecoverPhysicalVolumes","RecoverSystem","RecoverSanVolumes","RecoverNamespaces","RecoverObjects","DownloadFilesAndFolders","RecoverPublicFolders","RecoverVAppTemplates","RecoverMailbox","RecoverOneDrive","RecoverMsTeam","RecoverMsGroup","RecoverSharePoint","ConvertToPst","RecoverSfdcRecords","RecoverAzureSQL","DownloadChats","RecoverRDSPostgres","RecoverMailboxCSM","RecoverOneDriveCSM","RecoverSharePointCSM"}))
	Expect(createdOptions.ObjectActionKey).To(Equal(core.StringPtr("kPhysical")))
	Expect(createdOptions.ProtectionGroupIds).To(Equal([]string{"protectionGroupId1"}))
	Expect(createdOptions.ObjectIds).To(Equal([]int64{int64(26),int64(27)}))
	Expect(createdOptions.SubResultSize).To(Equal(core.Int64Ptr(int64(38))))
	Expect(createdOptions.FilterSnapshotFromUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.FilterSnapshotToUsecs).To(Equal(core.Int64Ptr(int64(26))))
	Expect(createdOptions.OsTypes).To(Equal([]string{"kLinux","kWindows"}))
	Expect(createdOptions.SourceIds).To(Equal([]int64{int64(26),int64(27)}))
	Expect(createdOptions.RunInstanceIds).To(Equal([]int64{int64(26),int64(27)}))
	Expect(createdOptions.CdpProtectedOnly).To(Equal(core.BoolPtr(true)))
	Expect(createdOptions.UseCachedData).To(Equal(core.BoolPtr(true)))
	return testing_utilities.GetMockSuccessResponse()
}

type SearchProtectedObjectsErrorSender struct{}

func (f SearchProtectedObjectsErrorSender) Send(optionsModel interface{}) (interface{}, *core.DetailedResponse, error) {
	return testing_utilities.GetMockErrorResponse()
}

//
// Utility functions used by the generated test code
//

func CheckServiceURL(serviceInstance *backuprecoveryv1.BackupRecoveryV1) {
	Expect(serviceInstance.GetServiceURL()).To(Equal("https://ibm.cloud.com/my-api"))
}

func CreateMockMap() map[string]interface{} {
	m := make(map[string]interface{})
	return m
}

func CreateMockByteArray(encodedString string) *[]byte {
	ba, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		panic(err)
	}
	return &ba
}

func CreateMockUUID(mockData string) *strfmt.UUID {
	uuid := strfmt.UUID(mockData)
	return &uuid
}

func CreateMockDate(mockData string) *strfmt.Date {
	d, err := core.ParseDate(mockData)
	if err != nil {
		return nil
	}
	return &d
}

func CreateMockDateTime(mockData string) *strfmt.DateTime {
	d, err := core.ParseDateTime(mockData)
	if err != nil {
		return nil
	}
	return &d
}

// convert struct instance to a generic map with resolved pointers, etc. for comparison
func ResolveModel(model interface{}) interface{} {
	buf, e := json.Marshal(model)
	if e != nil {
		panic(e)
	}

	var data interface{}

	e = json.Unmarshal(buf, &data)
	if e != nil {
		panic(e)
	}

	return data
}

func CheckAnalyticsHeader(serviceInstance *backuprecoveryv1.BackupRecoveryV1) {
	header := serviceInstance.Service.DefaultHeaders.Get("X-Original-User-Agent")
	Expect(header).To(Equal("ibmcloud-backup-recovery-cli/"+version.GetPluginVersion().String()))
}
