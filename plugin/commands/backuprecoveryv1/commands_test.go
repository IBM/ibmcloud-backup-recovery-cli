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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/spf13/cobra"
	"ibmcloud-backup-recovery-cli/plugin/commands/backuprecoveryv1"
	"ibmcloud-backup-recovery-cli/testing_utilities"
	"os"
)

var positiveFakeUtils = testing_utilities.NewPositiveTestUtilities()
var negativeFakeUtils = testing_utilities.NewNegativeTestUtilities()

var _ = BeforeSuite(func() {
	// create a temp mock directory
	defer GinkgoRecover()
	dirErr := os.Mkdir("tempdir", 0755)
	if dirErr != nil {
		Fail(dirErr.Error())
	}

	// Create mock files for testing binary parameters.
	message := []byte(testing_utilities.MockFileContents)
	fileErr := os.WriteFile("tempdir/test-file.txt", message, 0644)
	if fileErr != nil {
		Fail(fileErr.Error())
	}

	fileErr = os.WriteFile("tempdir/test-file-2.txt", message, 0644)
	if fileErr != nil {
		Fail(fileErr.Error())
	}
})

// cleanup mock files
var _ = AfterSuite(func() {
	defer GinkgoRecover()
	err := os.RemoveAll("tempdir")
	if err != nil {
		Fail(err.Error())
	}
})

// Test suite
var _ = Describe("BackupRecoveryV1", func() {
	// ensure the service instance is newly created during each test
	BeforeEach(func() {
	  backuprecoveryv1.ServiceInstance = nil
	})

	Describe("ListProtectionSources", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		ExcludeOffice365Types := `--exclude-office365-types=kDomain,kOutlook,kMailbox,kUsers,kUser,kGroups,kGroup,kSites,kSite`
		GetTeamsChannels := `--get-teams-channels=true`
		AfterCursorEntityID := `--after-cursor-entity-id=26`
		BeforeCursorEntityID := `--before-cursor-entity-id=26`
		NodeID := `--node-id=26`
		PageSize := `--page-size=26`
		HasValidMailbox := `--has-valid-mailbox=true`
		HasValidOnedrive := `--has-valid-onedrive=true`
		IsSecurityGroup := `--is-security-group=true`
		ID := `--id=26`
		NumLevels := `--num-levels=72.5`
		ExcludeTypes := `--exclude-types=kVCenter,kFolder,kDatacenter,kComputeResource,kClusterComputeResource,kResourcePool,kDatastore,kHostSystem,kVirtualMachine,kVirtualApp,kStandaloneHost,kStoragePod,kNetwork,kDistributedVirtualPortgroup,kTagCategory,kTag`
		ExcludeAwsTypes := `--exclude-aws-types=kEC2Instance,kRDSInstance,kAuroraCluster,kS3Bucket,kTag,kRDSTag,kAuroraTag,kS3Tag`
		ExcludeKubernetesTypes := `--exclude-kubernetes-types=kService`
		IncludeDatastores := `--include-datastores=true`
		IncludeNetworks := `--include-networks=true`
		IncludeVMFolders := `--include-vm-folders=true`
		IncludeSfdcFields := `--include-sfdc-fields=true`
		IncludeSystemVApps := `--include-system-v-apps=true`
		Environments := `--environments=kVMware,kHyperV,kSQL,kView,kPuppeteer,kPhysical,kPure,kNimble,kAzure,kNetapp,kAgent,kGenericNas,kAcropolis,kPhysicalFiles,kIsilon,kGPFS,kKVM,kAWS,kExchange,kHyperVVSS,kOracle,kGCP,kFlashBlade,kAWSNative,kO365,kO365Outlook,kHyperFlex,kGCPNative,kAzureNative,kKubernetes,kElastifile,kAD,kRDSSnapshotManager,kCassandra,kMongoDB,kCouchbase,kHdfs,kHBase,kUDA,KSfdc,kAwsS3`
		Environment := `--environment=kPhysical`
		IncludeEntityPermissionInfo := `--include-entity-permission-info=true`
		Sids := `--sids=sid1`
		IncludeSourceCredentials := `--include-source-credentials=true`
		EncryptionKey := `--encryption-key=encryptionKey`
		IncludeObjectProtectionInfo := `--include-object-protection-info=true`
		PruneNonCriticalInfo := `--prune-non-critical-info=true`
		PruneAggregationInfo := `--prune-aggregation-info=true`
		RequestInitiatorType := `--request-initiator-type=requestInitiatorType`
		UseCachedData := `--use-cached-data=true`
		AllUnderHierarchy := `--all-under-hierarchy=true`

		args := []string{
			XIBMTenantID,
			ExcludeOffice365Types,
			GetTeamsChannels,
			AfterCursorEntityID,
			BeforeCursorEntityID,
			NodeID,
			PageSize,
			HasValidMailbox,
			HasValidOnedrive,
			IsSecurityGroup,
			ID,
			NumLevels,
			ExcludeTypes,
			ExcludeAwsTypes,
			ExcludeKubernetesTypes,
			IncludeDatastores,
			IncludeNetworks,
			IncludeVMFolders,
			IncludeSfdcFields,
			IncludeSystemVApps,
			Environments,
			Environment,
			IncludeEntityPermissionInfo,
			Sids,
			IncludeSourceCredentials,
			EncryptionKey,
			IncludeObjectProtectionInfo,
			PruneNonCriticalInfo,
			PruneAggregationInfo,
			RequestInitiatorType,
			UseCachedData,
			AllUnderHierarchy,
		}

		It("Puts together ListProtectionSources options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewListProtectionSourcesCommandRunner(positiveFakeUtils, ListProtectionSourcesMockSender{})
			command := backuprecoveryv1.GetListProtectionSourcesCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for ListProtectionSources", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewListProtectionSourcesCommandRunner(negativeFakeUtils, ListProtectionSourcesErrorSender{})
			command := backuprecoveryv1.GetListProtectionSourcesCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetSourceRegistrations", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Ids := `--ids=38,39`
		IncludeSourceCredentials := `--include-source-credentials=true`
		EncryptionKey := `--encryption-key=encryptionKey`
		UseCachedData := `--use-cached-data=true`
		IncludeExternalMetadata := `--include-external-metadata=true`
		IgnoreTenantMigrationInProgressCheck := `--ignore-tenant-migration-in-progress-check=true`

		args := []string{
			XIBMTenantID,
			Ids,
			IncludeSourceCredentials,
			EncryptionKey,
			UseCachedData,
			IncludeExternalMetadata,
			IgnoreTenantMigrationInProgressCheck,
		}

		It("Puts together GetSourceRegistrations options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetSourceRegistrationsCommandRunner(positiveFakeUtils, GetSourceRegistrationsMockSender{})
			command := backuprecoveryv1.GetGetSourceRegistrationsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetSourceRegistrations", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetSourceRegistrationsCommandRunner(negativeFakeUtils, GetSourceRegistrationsErrorSender{})
			command := backuprecoveryv1.GetGetSourceRegistrationsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("RegisterProtectionSource", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Environment := `--environment=kPhysical`
		Name := `--name=register-protection-source`
		IsInternalEncrypted := `--is-internal-encrypted=true`
		EncryptionKey := `--encryption-key=encryptionKey`
		ConnectionID := `--connection-id=26`
		Connections := `--connections=[{"connectionId": 26, "entityId": 26, "connectorGroupId": 26, "dataSourceConnectionId": "DatasourceConnectionId"}]`
		ConnectorGroupID := `--connector-group-id=26`
		AdvancedConfigs := `--advanced-configs=[{"key": "configKey", "value": "configValue"}]`
		DataSourceConnectionID := `--data-source-connection-id=DatasourceConnectionId`
		PhysicalParams := `--physical-params={"endpoint": "xxx.xx.xx.xx", "forceRegister": true, "hostType": "kLinux", "physicalType": "kGroup", "applications": ["kSQL","kOracle"]}`

		args := []string{
			XIBMTenantID,
			Environment,
			Name,
			IsInternalEncrypted,
			EncryptionKey,
			ConnectionID,
			Connections,
			ConnectorGroupID,
			AdvancedConfigs,
			DataSourceConnectionID,
			PhysicalParams,
		}

		It("Puts together RegisterProtectionSource options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewRegisterProtectionSourceCommandRunner(positiveFakeUtils, RegisterProtectionSourceMockSender{})
			command := backuprecoveryv1.GetRegisterProtectionSourceCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewRegisterProtectionSourceCommandRunner(positiveFakeUtils, RegisterProtectionSourceMockSender{})
			command := backuprecoveryv1.GetRegisterProtectionSourceCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			ConnectionsContents := []byte(`[{"connectionId": 26, "entityId": 26, "connectorGroupId": 26, "dataSourceConnectionId": "DatasourceConnectionId"}]`)
			ConnectionsFileErr := os.WriteFile("tempdir/connections.json", ConnectionsContents, 0644)
			if ConnectionsFileErr != nil {
				Fail(ConnectionsFileErr.Error())
			}
			AdvancedConfigsContents := []byte(`[{"key": "configKey", "value": "configValue"}]`)
			AdvancedConfigsFileErr := os.WriteFile("tempdir/advanced-configs.json", AdvancedConfigsContents, 0644)
			if AdvancedConfigsFileErr != nil {
				Fail(AdvancedConfigsFileErr.Error())
			}
			PhysicalParamsContents := []byte(`{"endpoint": "xxx.xx.xx.xx", "forceRegister": true, "hostType": "kLinux", "physicalType": "kGroup", "applications": ["kSQL","kOracle"]}`)
			PhysicalParamsFileErr := os.WriteFile("tempdir/physical-params.json", PhysicalParamsContents, 0644)
			if PhysicalParamsFileErr != nil {
				Fail(PhysicalParamsFileErr.Error())
			}

			XIBMTenantID := `--xibm-tenant-id=tenantId`
			Environment := `--environment=kPhysical`
			Name := `--name=register-protection-source`
			IsInternalEncrypted := `--is-internal-encrypted=true`
			EncryptionKey := `--encryption-key=encryptionKey`
			ConnectionID := `--connection-id=26`
			Connections := `--connections=@tempdir/connections.json`
			ConnectorGroupID := `--connector-group-id=26`
			AdvancedConfigs := `--advanced-configs=@tempdir/advanced-configs.json`
			DataSourceConnectionID := `--data-source-connection-id=DatasourceConnectionId`
			PhysicalParams := `--physical-params=@tempdir/physical-params.json`

			argsWithFiles := []string{
				XIBMTenantID,
				Environment,
				Name,
				IsInternalEncrypted,
				EncryptionKey,
				ConnectionID,
				Connections,
				ConnectorGroupID,
				AdvancedConfigs,
				DataSourceConnectionID,
				PhysicalParams,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for RegisterProtectionSource", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewRegisterProtectionSourceCommandRunner(negativeFakeUtils, RegisterProtectionSourceErrorSender{})
			command := backuprecoveryv1.GetRegisterProtectionSourceCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetProtectionSourceRegistration", func() {
		// put together mock arguments
		ID := `--id=26`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		RequestInitiatorType := `--request-initiator-type=UIUser`

		args := []string{
			ID,
			XIBMTenantID,
			RequestInitiatorType,
		}

		It("Puts together GetProtectionSourceRegistration options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetProtectionSourceRegistrationCommandRunner(positiveFakeUtils, GetProtectionSourceRegistrationMockSender{})
			command := backuprecoveryv1.GetGetProtectionSourceRegistrationCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetProtectionSourceRegistration", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetProtectionSourceRegistrationCommandRunner(negativeFakeUtils, GetProtectionSourceRegistrationErrorSender{})
			command := backuprecoveryv1.GetGetProtectionSourceRegistrationCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("UpdateProtectionSourceRegistration", func() {
		// put together mock arguments
		ID := `--id=26`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Environment := `--environment=kPhysical`
		Name := `--name=update-protection-source`
		IsInternalEncrypted := `--is-internal-encrypted=true`
		EncryptionKey := `--encryption-key=encryptionKey`
		ConnectionID := `--connection-id=26`
		Connections := `--connections=[{"connectionId": 26, "entityId": 26, "connectorGroupId": 26, "dataSourceConnectionId": "DatasourceConnectionId"}]`
		ConnectorGroupID := `--connector-group-id=26`
		AdvancedConfigs := `--advanced-configs=[{"key": "configKey", "value": "configValue"}]`
		DataSourceConnectionID := `--data-source-connection-id=DatasourceConnectionId`
		LastModifiedTimestampUsecs := `--last-modified-timestamp-usecs=26`
		PhysicalParams := `--physical-params={"endpoint": "xxx.xx.xx.xx", "forceRegister": true, "hostType": "kLinux", "physicalType": "kGroup", "applications": ["kSQL","kOracle"]}`

		args := []string{
			ID,
			XIBMTenantID,
			Environment,
			Name,
			IsInternalEncrypted,
			EncryptionKey,
			ConnectionID,
			Connections,
			ConnectorGroupID,
			AdvancedConfigs,
			DataSourceConnectionID,
			LastModifiedTimestampUsecs,
			PhysicalParams,
		}

		It("Puts together UpdateProtectionSourceRegistration options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewUpdateProtectionSourceRegistrationCommandRunner(positiveFakeUtils, UpdateProtectionSourceRegistrationMockSender{})
			command := backuprecoveryv1.GetUpdateProtectionSourceRegistrationCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewUpdateProtectionSourceRegistrationCommandRunner(positiveFakeUtils, UpdateProtectionSourceRegistrationMockSender{})
			command := backuprecoveryv1.GetUpdateProtectionSourceRegistrationCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			ConnectionsContents := []byte(`[{"connectionId": 26, "entityId": 26, "connectorGroupId": 26, "dataSourceConnectionId": "DatasourceConnectionId"}]`)
			ConnectionsFileErr := os.WriteFile("tempdir/connections.json", ConnectionsContents, 0644)
			if ConnectionsFileErr != nil {
				Fail(ConnectionsFileErr.Error())
			}
			AdvancedConfigsContents := []byte(`[{"key": "configKey", "value": "configValue"}]`)
			AdvancedConfigsFileErr := os.WriteFile("tempdir/advanced-configs.json", AdvancedConfigsContents, 0644)
			if AdvancedConfigsFileErr != nil {
				Fail(AdvancedConfigsFileErr.Error())
			}
			PhysicalParamsContents := []byte(`{"endpoint": "xxx.xx.xx.xx", "forceRegister": true, "hostType": "kLinux", "physicalType": "kGroup", "applications": ["kSQL","kOracle"]}`)
			PhysicalParamsFileErr := os.WriteFile("tempdir/physical-params.json", PhysicalParamsContents, 0644)
			if PhysicalParamsFileErr != nil {
				Fail(PhysicalParamsFileErr.Error())
			}

			ID := `--id=26`
			XIBMTenantID := `--xibm-tenant-id=tenantId`
			Environment := `--environment=kPhysical`
			Name := `--name=update-protection-source`
			IsInternalEncrypted := `--is-internal-encrypted=true`
			EncryptionKey := `--encryption-key=encryptionKey`
			ConnectionID := `--connection-id=26`
			Connections := `--connections=@tempdir/connections.json`
			ConnectorGroupID := `--connector-group-id=26`
			AdvancedConfigs := `--advanced-configs=@tempdir/advanced-configs.json`
			DataSourceConnectionID := `--data-source-connection-id=DatasourceConnectionId`
			LastModifiedTimestampUsecs := `--last-modified-timestamp-usecs=26`
			PhysicalParams := `--physical-params=@tempdir/physical-params.json`

			argsWithFiles := []string{
				ID,
				XIBMTenantID,
				Environment,
				Name,
				IsInternalEncrypted,
				EncryptionKey,
				ConnectionID,
				Connections,
				ConnectorGroupID,
				AdvancedConfigs,
				DataSourceConnectionID,
				LastModifiedTimestampUsecs,
				PhysicalParams,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for UpdateProtectionSourceRegistration", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewUpdateProtectionSourceRegistrationCommandRunner(negativeFakeUtils, UpdateProtectionSourceRegistrationErrorSender{})
			command := backuprecoveryv1.GetUpdateProtectionSourceRegistrationCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("PatchProtectionSourceRegistration", func() {
		// put together mock arguments
		ID := `--id=26`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Environment := `--environment=kPhysical`

		args := []string{
			ID,
			XIBMTenantID,
			Environment,
		}

		It("Puts together PatchProtectionSourceRegistration options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewPatchProtectionSourceRegistrationCommandRunner(positiveFakeUtils, PatchProtectionSourceRegistrationMockSender{})
			command := backuprecoveryv1.GetPatchProtectionSourceRegistrationCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for PatchProtectionSourceRegistration", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewPatchProtectionSourceRegistrationCommandRunner(negativeFakeUtils, PatchProtectionSourceRegistrationErrorSender{})
			command := backuprecoveryv1.GetPatchProtectionSourceRegistrationCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("DeleteProtectionSourceRegistration", func() {
		// put together mock arguments
		ID := `--id=26`
		XIBMTenantID := `--xibm-tenant-id=tenantId`

		args := []string{
			ID,
			XIBMTenantID,
		}

		It("Puts together DeleteProtectionSourceRegistration options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDeleteProtectionSourceRegistrationCommandRunner(positiveFakeUtils, DeleteProtectionSourceRegistrationMockSender{})
			command := backuprecoveryv1.GetDeleteProtectionSourceRegistrationCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for DeleteProtectionSourceRegistration", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDeleteProtectionSourceRegistrationCommandRunner(negativeFakeUtils, DeleteProtectionSourceRegistrationErrorSender{})
			command := backuprecoveryv1.GetDeleteProtectionSourceRegistrationCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("RefreshProtectionSourceByID", func() {
		// put together mock arguments
		ID := `--id=26`
		XIBMTenantID := `--xibm-tenant-id=tenantId`

		args := []string{
			ID,
			XIBMTenantID,
		}

		It("Puts together RefreshProtectionSourceByID options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewRefreshProtectionSourceByIDCommandRunner(positiveFakeUtils, RefreshProtectionSourceByIDMockSender{})
			command := backuprecoveryv1.GetRefreshProtectionSourceByIDCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for RefreshProtectionSourceByID", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewRefreshProtectionSourceByIDCommandRunner(negativeFakeUtils, RefreshProtectionSourceByIDErrorSender{})
			command := backuprecoveryv1.GetRefreshProtectionSourceByIDCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetUpgradeTasks", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Ids := `--ids=26,27`

		args := []string{
			XIBMTenantID,
			Ids,
		}

		It("Puts together GetUpgradeTasks options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetUpgradeTasksCommandRunner(positiveFakeUtils, GetUpgradeTasksMockSender{})
			command := backuprecoveryv1.GetGetUpgradeTasksCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetUpgradeTasks", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetUpgradeTasksCommandRunner(negativeFakeUtils, GetUpgradeTasksErrorSender{})
			command := backuprecoveryv1.GetGetUpgradeTasksCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("CreateUpgradeTask", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		AgentIDs := `--agent-ids=26,27`
		Description := `--description=Upgrade task`
		Name := `--name=create-upgrade-task`
		RetryTaskID := `--retry-task-id=26`
		ScheduleEndTimeUsecs := `--schedule-end-time-usecs=26`
		ScheduleTimeUsecs := `--schedule-time-usecs=26`

		args := []string{
			XIBMTenantID,
			AgentIDs,
			Description,
			Name,
			RetryTaskID,
			ScheduleEndTimeUsecs,
			ScheduleTimeUsecs,
		}

		It("Puts together CreateUpgradeTask options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateUpgradeTaskCommandRunner(positiveFakeUtils, CreateUpgradeTaskMockSender{})
			command := backuprecoveryv1.GetCreateUpgradeTaskCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for CreateUpgradeTask", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateUpgradeTaskCommandRunner(negativeFakeUtils, CreateUpgradeTaskErrorSender{})
			command := backuprecoveryv1.GetCreateUpgradeTaskCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetProtectionPolicies", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		RequestInitiatorType := `--request-initiator-type=UIUser`
		Ids := `--ids=policyId1`
		PolicyNames := `--policy-names=policyName1`
		Types := `--types=Regular,Internal`
		ExcludeLinkedPolicies := `--exclude-linked-policies=true`
		IncludeReplicatedPolicies := `--include-replicated-policies=true`
		IncludeStats := `--include-stats=true`

		args := []string{
			XIBMTenantID,
			RequestInitiatorType,
			Ids,
			PolicyNames,
			Types,
			ExcludeLinkedPolicies,
			IncludeReplicatedPolicies,
			IncludeStats,
		}

		It("Puts together GetProtectionPolicies options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetProtectionPoliciesCommandRunner(positiveFakeUtils, GetProtectionPoliciesMockSender{})
			command := backuprecoveryv1.GetGetProtectionPoliciesCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetProtectionPolicies", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetProtectionPoliciesCommandRunner(negativeFakeUtils, GetProtectionPoliciesErrorSender{})
			command := backuprecoveryv1.GetGetProtectionPoliciesCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("CreateProtectionPolicy", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Name := `--name=create-protection-policy`
		BackupPolicy := `--backup-policy={"regular": {"incremental": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}, "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}}, "full": {"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}}, "fullBackups": [{"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}], "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "primaryBackupTarget": {"targetType": "Local", "archivalTargetSettings": {"targetId": 26, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}}, "useDefaultBackupTarget": true}}, "log": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "bmr": {"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "cdp": {"retention": {"unit": "Minutes", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "storageArraySnapshot": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}, "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}]}`
		Description := `--description=Protection Policy`
		BlackoutWindow := `--blackout-window=[{"day": "Sunday", "startTime": {"hour": 1, "minute": 15, "timeZone": "America/Los_Angeles"}, "endTime": {"hour": 1, "minute": 15, "timeZone": "America/Los_Angeles"}, "configId": "Config-Id"}]`
		ExtendedRetention := `--extended-retention=[{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]`
		RemoteTargetPolicy := `--remote-target-policy={"replicationTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "awsTargetConfig": {"region": 26, "sourceId": 26}, "azureTargetConfig": {"resourceGroup": 26, "sourceId": 26}, "targetType": "RemoteCluster", "remoteTargetConfig": {"clusterId": 26}}], "archivalTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}, "extendedRetention": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]}], "cloudSpinTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "target": {"awsParams": {"customTagList": [{"key": "custom-tag-key", "value": "custom-tag-value"}], "region": 3, "subnetId": 26, "vpcId": 26}, "azureParams": {"availabilitySetId": 26, "networkResourceGroupId": 26, "resourceGroupId": 26, "storageAccountId": 26, "storageContainerId": 26, "storageResourceGroupId": 26, "tempVmResourceGroupId": 26, "tempVmStorageAccountId": 26, "tempVmStorageContainerId": 26, "tempVmSubnetId": 26, "tempVmVirtualNetworkId": 26}, "id": 2}}], "onpremDeployTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "params": {"id": 4}}], "rpaasTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "targetType": "Tape"}]}`
		CascadedTargetsConfig := `--cascaded-targets-config=[{"sourceClusterId": 26, "remoteTargets": {"replicationTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "awsTargetConfig": {"region": 26, "sourceId": 26}, "azureTargetConfig": {"resourceGroup": 26, "sourceId": 26}, "targetType": "RemoteCluster", "remoteTargetConfig": {"clusterId": 26}}], "archivalTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}, "extendedRetention": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]}], "cloudSpinTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "target": {"awsParams": {"customTagList": [{"key": "custom-tag-key", "value": "custom-tag-value"}], "region": 3, "subnetId": 26, "vpcId": 26}, "azureParams": {"availabilitySetId": 26, "networkResourceGroupId": 26, "resourceGroupId": 26, "storageAccountId": 26, "storageContainerId": 26, "storageResourceGroupId": 26, "tempVmResourceGroupId": 26, "tempVmStorageAccountId": 26, "tempVmStorageContainerId": 26, "tempVmSubnetId": 26, "tempVmVirtualNetworkId": 26}, "id": 2}}], "onpremDeployTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "params": {"id": 4}}], "rpaasTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "targetType": "Tape"}]}}]`
		RetryOptions := `--retry-options={"retries": 0, "retryIntervalMins": 1}`
		DataLock := `--data-lock=Compliance`
		Version := `--version=38`
		IsCBSEnabled := `--is-cbs-enabled=true`
		LastModificationTimeUsecs := `--last-modification-time-usecs=26`
		TemplateID := `--template-id=protection-policy-template`

		args := []string{
			XIBMTenantID,
			Name,
			BackupPolicy,
			Description,
			BlackoutWindow,
			ExtendedRetention,
			RemoteTargetPolicy,
			CascadedTargetsConfig,
			RetryOptions,
			DataLock,
			Version,
			IsCBSEnabled,
			LastModificationTimeUsecs,
			TemplateID,
		}

		It("Puts together CreateProtectionPolicy options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateProtectionPolicyCommandRunner(positiveFakeUtils, CreateProtectionPolicyMockSender{})
			command := backuprecoveryv1.GetCreateProtectionPolicyCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateProtectionPolicyCommandRunner(positiveFakeUtils, CreateProtectionPolicyMockSender{})
			command := backuprecoveryv1.GetCreateProtectionPolicyCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			BackupPolicyContents := []byte(`{"regular": {"incremental": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}, "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}}, "full": {"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}}, "fullBackups": [{"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}], "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "primaryBackupTarget": {"targetType": "Local", "archivalTargetSettings": {"targetId": 26, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}}, "useDefaultBackupTarget": true}}, "log": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "bmr": {"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "cdp": {"retention": {"unit": "Minutes", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "storageArraySnapshot": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}, "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}]}`)
			BackupPolicyFileErr := os.WriteFile("tempdir/backup-policy.json", BackupPolicyContents, 0644)
			if BackupPolicyFileErr != nil {
				Fail(BackupPolicyFileErr.Error())
			}
			BlackoutWindowContents := []byte(`[{"day": "Sunday", "startTime": {"hour": 1, "minute": 15, "timeZone": "America/Los_Angeles"}, "endTime": {"hour": 1, "minute": 15, "timeZone": "America/Los_Angeles"}, "configId": "Config-Id"}]`)
			BlackoutWindowFileErr := os.WriteFile("tempdir/blackout-window.json", BlackoutWindowContents, 0644)
			if BlackoutWindowFileErr != nil {
				Fail(BlackoutWindowFileErr.Error())
			}
			ExtendedRetentionContents := []byte(`[{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]`)
			ExtendedRetentionFileErr := os.WriteFile("tempdir/extended-retention.json", ExtendedRetentionContents, 0644)
			if ExtendedRetentionFileErr != nil {
				Fail(ExtendedRetentionFileErr.Error())
			}
			RemoteTargetPolicyContents := []byte(`{"replicationTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "awsTargetConfig": {"region": 26, "sourceId": 26}, "azureTargetConfig": {"resourceGroup": 26, "sourceId": 26}, "targetType": "RemoteCluster", "remoteTargetConfig": {"clusterId": 26}}], "archivalTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}, "extendedRetention": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]}], "cloudSpinTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "target": {"awsParams": {"customTagList": [{"key": "custom-tag-key", "value": "custom-tag-value"}], "region": 3, "subnetId": 26, "vpcId": 26}, "azureParams": {"availabilitySetId": 26, "networkResourceGroupId": 26, "resourceGroupId": 26, "storageAccountId": 26, "storageContainerId": 26, "storageResourceGroupId": 26, "tempVmResourceGroupId": 26, "tempVmStorageAccountId": 26, "tempVmStorageContainerId": 26, "tempVmSubnetId": 26, "tempVmVirtualNetworkId": 26}, "id": 2}}], "onpremDeployTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "params": {"id": 4}}], "rpaasTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "targetType": "Tape"}]}`)
			RemoteTargetPolicyFileErr := os.WriteFile("tempdir/remote-target-policy.json", RemoteTargetPolicyContents, 0644)
			if RemoteTargetPolicyFileErr != nil {
				Fail(RemoteTargetPolicyFileErr.Error())
			}
			CascadedTargetsConfigContents := []byte(`[{"sourceClusterId": 26, "remoteTargets": {"replicationTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "awsTargetConfig": {"region": 26, "sourceId": 26}, "azureTargetConfig": {"resourceGroup": 26, "sourceId": 26}, "targetType": "RemoteCluster", "remoteTargetConfig": {"clusterId": 26}}], "archivalTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}, "extendedRetention": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]}], "cloudSpinTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "target": {"awsParams": {"customTagList": [{"key": "custom-tag-key", "value": "custom-tag-value"}], "region": 3, "subnetId": 26, "vpcId": 26}, "azureParams": {"availabilitySetId": 26, "networkResourceGroupId": 26, "resourceGroupId": 26, "storageAccountId": 26, "storageContainerId": 26, "storageResourceGroupId": 26, "tempVmResourceGroupId": 26, "tempVmStorageAccountId": 26, "tempVmStorageContainerId": 26, "tempVmSubnetId": 26, "tempVmVirtualNetworkId": 26}, "id": 2}}], "onpremDeployTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "params": {"id": 4}}], "rpaasTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "targetType": "Tape"}]}}]`)
			CascadedTargetsConfigFileErr := os.WriteFile("tempdir/cascaded-targets-config.json", CascadedTargetsConfigContents, 0644)
			if CascadedTargetsConfigFileErr != nil {
				Fail(CascadedTargetsConfigFileErr.Error())
			}
			RetryOptionsContents := []byte(`{"retries": 0, "retryIntervalMins": 1}`)
			RetryOptionsFileErr := os.WriteFile("tempdir/retry-options.json", RetryOptionsContents, 0644)
			if RetryOptionsFileErr != nil {
				Fail(RetryOptionsFileErr.Error())
			}

			XIBMTenantID := `--xibm-tenant-id=tenantId`
			Name := `--name=create-protection-policy`
			BackupPolicy := `--backup-policy=@tempdir/backup-policy.json`
			Description := `--description=Protection Policy`
			BlackoutWindow := `--blackout-window=@tempdir/blackout-window.json`
			ExtendedRetention := `--extended-retention=@tempdir/extended-retention.json`
			RemoteTargetPolicy := `--remote-target-policy=@tempdir/remote-target-policy.json`
			CascadedTargetsConfig := `--cascaded-targets-config=@tempdir/cascaded-targets-config.json`
			RetryOptions := `--retry-options=@tempdir/retry-options.json`
			DataLock := `--data-lock=Compliance`
			Version := `--version=38`
			IsCBSEnabled := `--is-cbs-enabled=true`
			LastModificationTimeUsecs := `--last-modification-time-usecs=26`
			TemplateID := `--template-id=protection-policy-template`

			argsWithFiles := []string{
				XIBMTenantID,
				Name,
				BackupPolicy,
				Description,
				BlackoutWindow,
				ExtendedRetention,
				RemoteTargetPolicy,
				CascadedTargetsConfig,
				RetryOptions,
				DataLock,
				Version,
				IsCBSEnabled,
				LastModificationTimeUsecs,
				TemplateID,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for CreateProtectionPolicy", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateProtectionPolicyCommandRunner(negativeFakeUtils, CreateProtectionPolicyErrorSender{})
			command := backuprecoveryv1.GetCreateProtectionPolicyCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetProtectionPolicyByID", func() {
		// put together mock arguments
		ID := `--id=testString`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		RequestInitiatorType := `--request-initiator-type=UIUser`

		args := []string{
			ID,
			XIBMTenantID,
			RequestInitiatorType,
		}

		It("Puts together GetProtectionPolicyByID options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetProtectionPolicyByIDCommandRunner(positiveFakeUtils, GetProtectionPolicyByIDMockSender{})
			command := backuprecoveryv1.GetGetProtectionPolicyByIDCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetProtectionPolicyByID", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetProtectionPolicyByIDCommandRunner(negativeFakeUtils, GetProtectionPolicyByIDErrorSender{})
			command := backuprecoveryv1.GetGetProtectionPolicyByIDCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("UpdateProtectionPolicy", func() {
		// put together mock arguments
		ID := `--id=testString`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Name := `--name=update-protection-policy`
		BackupPolicy := `--backup-policy={"regular": {"incremental": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}, "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}}, "full": {"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}}, "fullBackups": [{"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}], "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "primaryBackupTarget": {"targetType": "Local", "archivalTargetSettings": {"targetId": 26, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}}, "useDefaultBackupTarget": true}}, "log": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "bmr": {"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "cdp": {"retention": {"unit": "Minutes", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "storageArraySnapshot": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}, "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}]}`
		Description := `--description=Protection Policy`
		BlackoutWindow := `--blackout-window=[{"day": "Sunday", "startTime": {"hour": 1, "minute": 15, "timeZone": "America/Los_Angeles"}, "endTime": {"hour": 1, "minute": 15, "timeZone": "America/Los_Angeles"}, "configId": "Config-Id"}]`
		ExtendedRetention := `--extended-retention=[{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]`
		RemoteTargetPolicy := `--remote-target-policy={"replicationTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "awsTargetConfig": {"region": 26, "sourceId": 26}, "azureTargetConfig": {"resourceGroup": 26, "sourceId": 26}, "targetType": "RemoteCluster", "remoteTargetConfig": {"clusterId": 26}}], "archivalTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}, "extendedRetention": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]}], "cloudSpinTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "target": {"awsParams": {"customTagList": [{"key": "custom-tag-key", "value": "custom-tag-value"}], "region": 3, "subnetId": 26, "vpcId": 26}, "azureParams": {"availabilitySetId": 26, "networkResourceGroupId": 26, "resourceGroupId": 26, "storageAccountId": 26, "storageContainerId": 26, "storageResourceGroupId": 26, "tempVmResourceGroupId": 26, "tempVmStorageAccountId": 26, "tempVmStorageContainerId": 26, "tempVmSubnetId": 26, "tempVmVirtualNetworkId": 26}, "id": 2}}], "onpremDeployTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "params": {"id": 4}}], "rpaasTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "targetType": "Tape"}]}`
		CascadedTargetsConfig := `--cascaded-targets-config=[{"sourceClusterId": 26, "remoteTargets": {"replicationTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "awsTargetConfig": {"region": 26, "sourceId": 26}, "azureTargetConfig": {"resourceGroup": 26, "sourceId": 26}, "targetType": "RemoteCluster", "remoteTargetConfig": {"clusterId": 26}}], "archivalTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}, "extendedRetention": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]}], "cloudSpinTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "target": {"awsParams": {"customTagList": [{"key": "custom-tag-key", "value": "custom-tag-value"}], "region": 3, "subnetId": 26, "vpcId": 26}, "azureParams": {"availabilitySetId": 26, "networkResourceGroupId": 26, "resourceGroupId": 26, "storageAccountId": 26, "storageContainerId": 26, "storageResourceGroupId": 26, "tempVmResourceGroupId": 26, "tempVmStorageAccountId": 26, "tempVmStorageContainerId": 26, "tempVmSubnetId": 26, "tempVmVirtualNetworkId": 26}, "id": 2}}], "onpremDeployTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "params": {"id": 4}}], "rpaasTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "targetType": "Tape"}]}}]`
		RetryOptions := `--retry-options={"retries": 0, "retryIntervalMins": 1}`
		DataLock := `--data-lock=Compliance`
		Version := `--version=38`
		IsCBSEnabled := `--is-cbs-enabled=true`
		LastModificationTimeUsecs := `--last-modification-time-usecs=26`
		TemplateID := `--template-id=protection-policy-template`

		args := []string{
			ID,
			XIBMTenantID,
			Name,
			BackupPolicy,
			Description,
			BlackoutWindow,
			ExtendedRetention,
			RemoteTargetPolicy,
			CascadedTargetsConfig,
			RetryOptions,
			DataLock,
			Version,
			IsCBSEnabled,
			LastModificationTimeUsecs,
			TemplateID,
		}

		It("Puts together UpdateProtectionPolicy options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewUpdateProtectionPolicyCommandRunner(positiveFakeUtils, UpdateProtectionPolicyMockSender{})
			command := backuprecoveryv1.GetUpdateProtectionPolicyCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewUpdateProtectionPolicyCommandRunner(positiveFakeUtils, UpdateProtectionPolicyMockSender{})
			command := backuprecoveryv1.GetUpdateProtectionPolicyCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			BackupPolicyContents := []byte(`{"regular": {"incremental": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}, "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}}, "full": {"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}}, "fullBackups": [{"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}], "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "primaryBackupTarget": {"targetType": "Local", "archivalTargetSettings": {"targetId": 26, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}}, "useDefaultBackupTarget": true}}, "log": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "bmr": {"schedule": {"unit": "Days", "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "cdp": {"retention": {"unit": "Minutes", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "storageArraySnapshot": {"schedule": {"unit": "Minutes", "minuteSchedule": {"frequency": 1}, "hourSchedule": {"frequency": 1}, "daySchedule": {"frequency": 1}, "weekSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"]}, "monthSchedule": {"dayOfWeek": ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"], "weekOfMonth": "First", "dayOfMonth": 10}, "yearSchedule": {"dayOfYear": "First"}}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}, "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}]}`)
			BackupPolicyFileErr := os.WriteFile("tempdir/backup-policy.json", BackupPolicyContents, 0644)
			if BackupPolicyFileErr != nil {
				Fail(BackupPolicyFileErr.Error())
			}
			BlackoutWindowContents := []byte(`[{"day": "Sunday", "startTime": {"hour": 1, "minute": 15, "timeZone": "America/Los_Angeles"}, "endTime": {"hour": 1, "minute": 15, "timeZone": "America/Los_Angeles"}, "configId": "Config-Id"}]`)
			BlackoutWindowFileErr := os.WriteFile("tempdir/blackout-window.json", BlackoutWindowContents, 0644)
			if BlackoutWindowFileErr != nil {
				Fail(BlackoutWindowFileErr.Error())
			}
			ExtendedRetentionContents := []byte(`[{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]`)
			ExtendedRetentionFileErr := os.WriteFile("tempdir/extended-retention.json", ExtendedRetentionContents, 0644)
			if ExtendedRetentionFileErr != nil {
				Fail(ExtendedRetentionFileErr.Error())
			}
			RemoteTargetPolicyContents := []byte(`{"replicationTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "awsTargetConfig": {"region": 26, "sourceId": 26}, "azureTargetConfig": {"resourceGroup": 26, "sourceId": 26}, "targetType": "RemoteCluster", "remoteTargetConfig": {"clusterId": 26}}], "archivalTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}, "extendedRetention": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]}], "cloudSpinTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "target": {"awsParams": {"customTagList": [{"key": "custom-tag-key", "value": "custom-tag-value"}], "region": 3, "subnetId": 26, "vpcId": 26}, "azureParams": {"availabilitySetId": 26, "networkResourceGroupId": 26, "resourceGroupId": 26, "storageAccountId": 26, "storageContainerId": 26, "storageResourceGroupId": 26, "tempVmResourceGroupId": 26, "tempVmStorageAccountId": 26, "tempVmStorageContainerId": 26, "tempVmSubnetId": 26, "tempVmVirtualNetworkId": 26}, "id": 2}}], "onpremDeployTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "params": {"id": 4}}], "rpaasTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "targetType": "Tape"}]}`)
			RemoteTargetPolicyFileErr := os.WriteFile("tempdir/remote-target-policy.json", RemoteTargetPolicyContents, 0644)
			if RemoteTargetPolicyFileErr != nil {
				Fail(RemoteTargetPolicyFileErr.Error())
			}
			CascadedTargetsConfigContents := []byte(`[{"sourceClusterId": 26, "remoteTargets": {"replicationTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "awsTargetConfig": {"region": 26, "sourceId": 26}, "azureTargetConfig": {"resourceGroup": 26, "sourceId": 26}, "targetType": "RemoteCluster", "remoteTargetConfig": {"clusterId": 26}}], "archivalTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "tierSettings": {"awsTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAmazonS3Standard"}]}, "azureTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kAzureTierHot"}]}, "cloudPlatform": "AWS", "googleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kGoogleStandard"}]}, "oracleTiering": {"tiers": [{"moveAfterUnit": "Days", "moveAfter": 26, "tierType": "kOracleTierStandard"}]}}, "extendedRetention": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "runType": "Regular", "configId": "Config-Id"}]}], "cloudSpinTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "target": {"awsParams": {"customTagList": [{"key": "custom-tag-key", "value": "custom-tag-value"}], "region": 3, "subnetId": 26, "vpcId": 26}, "azureParams": {"availabilitySetId": 26, "networkResourceGroupId": 26, "resourceGroupId": 26, "storageAccountId": 26, "storageContainerId": 26, "storageResourceGroupId": 26, "tempVmResourceGroupId": 26, "tempVmStorageAccountId": 26, "tempVmStorageContainerId": 26, "tempVmSubnetId": 26, "tempVmVirtualNetworkId": 26}, "id": 2}}], "onpremDeployTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "params": {"id": 4}}], "rpaasTargets": [{"schedule": {"unit": "Runs", "frequency": 3}, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnRunSuccess": true, "configId": "Config-Id", "backupRunType": "Regular", "runTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "logRetention": {"unit": "Days", "duration": 0, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "targetId": 5, "targetType": "Tape"}]}}]`)
			CascadedTargetsConfigFileErr := os.WriteFile("tempdir/cascaded-targets-config.json", CascadedTargetsConfigContents, 0644)
			if CascadedTargetsConfigFileErr != nil {
				Fail(CascadedTargetsConfigFileErr.Error())
			}
			RetryOptionsContents := []byte(`{"retries": 0, "retryIntervalMins": 1}`)
			RetryOptionsFileErr := os.WriteFile("tempdir/retry-options.json", RetryOptionsContents, 0644)
			if RetryOptionsFileErr != nil {
				Fail(RetryOptionsFileErr.Error())
			}

			ID := `--id=testString`
			XIBMTenantID := `--xibm-tenant-id=tenantId`
			Name := `--name=update-protection-policy`
			BackupPolicy := `--backup-policy=@tempdir/backup-policy.json`
			Description := `--description=Protection Policy`
			BlackoutWindow := `--blackout-window=@tempdir/blackout-window.json`
			ExtendedRetention := `--extended-retention=@tempdir/extended-retention.json`
			RemoteTargetPolicy := `--remote-target-policy=@tempdir/remote-target-policy.json`
			CascadedTargetsConfig := `--cascaded-targets-config=@tempdir/cascaded-targets-config.json`
			RetryOptions := `--retry-options=@tempdir/retry-options.json`
			DataLock := `--data-lock=Compliance`
			Version := `--version=38`
			IsCBSEnabled := `--is-cbs-enabled=true`
			LastModificationTimeUsecs := `--last-modification-time-usecs=26`
			TemplateID := `--template-id=protection-policy-template`

			argsWithFiles := []string{
				ID,
				XIBMTenantID,
				Name,
				BackupPolicy,
				Description,
				BlackoutWindow,
				ExtendedRetention,
				RemoteTargetPolicy,
				CascadedTargetsConfig,
				RetryOptions,
				DataLock,
				Version,
				IsCBSEnabled,
				LastModificationTimeUsecs,
				TemplateID,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for UpdateProtectionPolicy", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewUpdateProtectionPolicyCommandRunner(negativeFakeUtils, UpdateProtectionPolicyErrorSender{})
			command := backuprecoveryv1.GetUpdateProtectionPolicyCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("DeleteProtectionPolicy", func() {
		// put together mock arguments
		ID := `--id=testString`
		XIBMTenantID := `--xibm-tenant-id=tenantId`

		args := []string{
			ID,
			XIBMTenantID,
		}

		It("Puts together DeleteProtectionPolicy options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDeleteProtectionPolicyCommandRunner(positiveFakeUtils, DeleteProtectionPolicyMockSender{})
			command := backuprecoveryv1.GetDeleteProtectionPolicyCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for DeleteProtectionPolicy", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDeleteProtectionPolicyCommandRunner(negativeFakeUtils, DeleteProtectionPolicyErrorSender{})
			command := backuprecoveryv1.GetDeleteProtectionPolicyCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetProtectionGroups", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantID`
		RequestInitiatorType := `--request-initiator-type=UIUser`
		Ids := `--ids=protectionGroupId1`
		Names := `--names=policyName1`
		PolicyIds := `--policy-ids=policyId1`
		IncludeGroupsWithDatalockOnly := `--include-groups-with-datalock-only=true`
		Environments := `--environments=kPhysical,kSQL`
		IsActive := `--is-active=true`
		IsDeleted := `--is-deleted=true`
		IsPaused := `--is-paused=true`
		LastRunLocalBackupStatus := `--last-run-local-backup-status=Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused`
		LastRunReplicationStatus := `--last-run-replication-status=Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused`
		LastRunArchivalStatus := `--last-run-archival-status=Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused`
		LastRunCloudSpinStatus := `--last-run-cloud-spin-status=Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused`
		LastRunAnyStatus := `--last-run-any-status=Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused`
		IsLastRunSlaViolated := `--is-last-run-sla-violated=true`
		IncludeLastRunInfo := `--include-last-run-info=true`
		PruneExcludedSourceIds := `--prune-excluded-source-ids=true`
		PruneSourceIds := `--prune-source-ids=true`
		UseCachedData := `--use-cached-data=true`
		SourceIds := `--source-ids=26,27`

		args := []string{
			XIBMTenantID,
			RequestInitiatorType,
			Ids,
			Names,
			PolicyIds,
			IncludeGroupsWithDatalockOnly,
			Environments,
			IsActive,
			IsDeleted,
			IsPaused,
			LastRunLocalBackupStatus,
			LastRunReplicationStatus,
			LastRunArchivalStatus,
			LastRunCloudSpinStatus,
			LastRunAnyStatus,
			IsLastRunSlaViolated,
			IncludeLastRunInfo,
			PruneExcludedSourceIds,
			PruneSourceIds,
			UseCachedData,
			SourceIds,
		}

		It("Puts together GetProtectionGroups options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetProtectionGroupsCommandRunner(positiveFakeUtils, GetProtectionGroupsMockSender{})
			command := backuprecoveryv1.GetGetProtectionGroupsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetProtectionGroups", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetProtectionGroupsCommandRunner(negativeFakeUtils, GetProtectionGroupsErrorSender{})
			command := backuprecoveryv1.GetGetProtectionGroupsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("CreateProtectionGroup", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Name := `--name=create-protection-group`
		PolicyID := `--policy-id=xxxxxxxxxxxxxxxx:xxxxxxxxxxxxx:xx`
		Environment := `--environment=kPhysical`
		Priority := `--priority=kLow`
		Description := `--description=Protection Group`
		StartTime := `--start-time={"hour": 0, "minute": 0, "timeZone": "America/Los_Angeles"}`
		EndTimeUsecs := `--end-time-usecs=26`
		LastModifiedTimestampUsecs := `--last-modified-timestamp-usecs=26`
		AlertPolicy := `--alert-policy={"backupRunStatus": ["kSuccess","kFailure","kSlaViolation","kWarning"], "alertTargets": [{"emailAddress": "alert1@domain.com", "language": "en-us", "recipientType": "kTo"}], "raiseObjectLevelFailureAlert": true, "raiseObjectLevelFailureAlertAfterLastAttempt": true, "raiseObjectLevelFailureAlertAfterEachAttempt": true}`
		Sla := `--sla=[{"backupRunType": "kIncremental", "slaMinutes": 1}]`
		QosPolicy := `--qos-policy=kBackupHDD`
		AbortInBlackouts := `--abort-in-blackouts=true`
		PauseInBlackouts := `--pause-in-blackouts=true`
		IsPaused := `--is-paused=true`
		AdvancedConfigs := `--advanced-configs=[{"key": "configKey", "value": "configValue"}]`
		PhysicalParams := `--physical-params={"protectionType": "kFile", "volumeProtectionTypeParams": {"objects": [{"id": 3, "volumeGuids": ["volumeGuid1"], "enableSystemBackup": true, "excludedVssWriters": ["writerName1","writerName2"]}], "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "performSourceSideDeduplication": true, "quiesce": true, "continueOnQuiesceFailure": true, "incrementalBackupAfterRestart": true, "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "dedupExclusionSourceIds": [26,27], "excludedVssWriters": ["writerName1","writerName2"], "cobmrBackup": true}, "fileProtectionTypeParams": {"excludedVssWriters": ["writerName1","writerName2"], "objects": [{"excludedVssWriters": ["writerName1","writerName2"], "id": 2, "filePaths": [{"includedPath": "~/dir1/", "excludedPaths": ["~/dir2"], "skipNestedVolumes": true}], "usesPathLevelSkipNestedVolumeSetting": true, "nestedVolumeTypesToSkip": ["volume1"], "followNasSymlinkTarget": true, "metadataFilePath": "~/dir3"}], "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "performSourceSideDeduplication": true, "performBrickBasedDeduplication": true, "taskTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "quiesce": true, "continueOnQuiesceFailure": true, "cobmrBackup": true, "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "dedupExclusionSourceIds": [26,27], "globalExcludePaths": ["~/dir1"], "globalExcludeFS": ["~/dir2"], "ignorableErrors": ["kEOF","kNonExistent"], "allowParallelRuns": true}}`
		MssqlParams := `--mssql-params={"fileProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "additionalHostParams": [{"disableSourceSideDeduplication": true, "hostId": 26}], "objects": [{"id": 6}], "performSourceSideDeduplication": true}, "nativeProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "numStreams": 38, "objects": [{"id": 6}], "withClause": "withClause"}, "protectionType": "kFile", "volumeProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "additionalHostParams": [{"enableSystemBackup": true, "hostId": 8, "volumeGuids": ["volumeGuid1"]}], "backupDbVolumesOnly": true, "incrementalBackupAfterRestart": true, "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "objects": [{"id": 6}]}}`

		args := []string{
			XIBMTenantID,
			Name,
			PolicyID,
			Environment,
			Priority,
			Description,
			StartTime,
			EndTimeUsecs,
			LastModifiedTimestampUsecs,
			AlertPolicy,
			Sla,
			QosPolicy,
			AbortInBlackouts,
			PauseInBlackouts,
			IsPaused,
			AdvancedConfigs,
			PhysicalParams,
			MssqlParams,
		}

		It("Puts together CreateProtectionGroup options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateProtectionGroupCommandRunner(positiveFakeUtils, CreateProtectionGroupMockSender{})
			command := backuprecoveryv1.GetCreateProtectionGroupCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateProtectionGroupCommandRunner(positiveFakeUtils, CreateProtectionGroupMockSender{})
			command := backuprecoveryv1.GetCreateProtectionGroupCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			StartTimeContents := []byte(`{"hour": 0, "minute": 0, "timeZone": "America/Los_Angeles"}`)
			StartTimeFileErr := os.WriteFile("tempdir/start-time.json", StartTimeContents, 0644)
			if StartTimeFileErr != nil {
				Fail(StartTimeFileErr.Error())
			}
			AlertPolicyContents := []byte(`{"backupRunStatus": ["kSuccess","kFailure","kSlaViolation","kWarning"], "alertTargets": [{"emailAddress": "alert1@domain.com", "language": "en-us", "recipientType": "kTo"}], "raiseObjectLevelFailureAlert": true, "raiseObjectLevelFailureAlertAfterLastAttempt": true, "raiseObjectLevelFailureAlertAfterEachAttempt": true}`)
			AlertPolicyFileErr := os.WriteFile("tempdir/alert-policy.json", AlertPolicyContents, 0644)
			if AlertPolicyFileErr != nil {
				Fail(AlertPolicyFileErr.Error())
			}
			SlaContents := []byte(`[{"backupRunType": "kIncremental", "slaMinutes": 1}]`)
			SlaFileErr := os.WriteFile("tempdir/sla.json", SlaContents, 0644)
			if SlaFileErr != nil {
				Fail(SlaFileErr.Error())
			}
			AdvancedConfigsContents := []byte(`[{"key": "configKey", "value": "configValue"}]`)
			AdvancedConfigsFileErr := os.WriteFile("tempdir/advanced-configs.json", AdvancedConfigsContents, 0644)
			if AdvancedConfigsFileErr != nil {
				Fail(AdvancedConfigsFileErr.Error())
			}
			PhysicalParamsContents := []byte(`{"protectionType": "kFile", "volumeProtectionTypeParams": {"objects": [{"id": 3, "volumeGuids": ["volumeGuid1"], "enableSystemBackup": true, "excludedVssWriters": ["writerName1","writerName2"]}], "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "performSourceSideDeduplication": true, "quiesce": true, "continueOnQuiesceFailure": true, "incrementalBackupAfterRestart": true, "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "dedupExclusionSourceIds": [26,27], "excludedVssWriters": ["writerName1","writerName2"], "cobmrBackup": true}, "fileProtectionTypeParams": {"excludedVssWriters": ["writerName1","writerName2"], "objects": [{"excludedVssWriters": ["writerName1","writerName2"], "id": 2, "filePaths": [{"includedPath": "~/dir1/", "excludedPaths": ["~/dir2"], "skipNestedVolumes": true}], "usesPathLevelSkipNestedVolumeSetting": true, "nestedVolumeTypesToSkip": ["volume1"], "followNasSymlinkTarget": true, "metadataFilePath": "~/dir3"}], "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "performSourceSideDeduplication": true, "performBrickBasedDeduplication": true, "taskTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "quiesce": true, "continueOnQuiesceFailure": true, "cobmrBackup": true, "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "dedupExclusionSourceIds": [26,27], "globalExcludePaths": ["~/dir1"], "globalExcludeFS": ["~/dir2"], "ignorableErrors": ["kEOF","kNonExistent"], "allowParallelRuns": true}}`)
			PhysicalParamsFileErr := os.WriteFile("tempdir/physical-params.json", PhysicalParamsContents, 0644)
			if PhysicalParamsFileErr != nil {
				Fail(PhysicalParamsFileErr.Error())
			}
			MssqlParamsContents := []byte(`{"fileProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "additionalHostParams": [{"disableSourceSideDeduplication": true, "hostId": 26}], "objects": [{"id": 6}], "performSourceSideDeduplication": true}, "nativeProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "numStreams": 38, "objects": [{"id": 6}], "withClause": "withClause"}, "protectionType": "kFile", "volumeProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "additionalHostParams": [{"enableSystemBackup": true, "hostId": 8, "volumeGuids": ["volumeGuid1"]}], "backupDbVolumesOnly": true, "incrementalBackupAfterRestart": true, "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "objects": [{"id": 6}]}}`)
			MssqlParamsFileErr := os.WriteFile("tempdir/mssql-params.json", MssqlParamsContents, 0644)
			if MssqlParamsFileErr != nil {
				Fail(MssqlParamsFileErr.Error())
			}

			XIBMTenantID := `--xibm-tenant-id=tenantId`
			Name := `--name=create-protection-group`
			PolicyID := `--policy-id=xxxxxxxxxxxxxxxx:xxxxxxxxxxxxx:xx`
			Environment := `--environment=kPhysical`
			Priority := `--priority=kLow`
			Description := `--description=Protection Group`
			StartTime := `--start-time=@tempdir/start-time.json`
			EndTimeUsecs := `--end-time-usecs=26`
			LastModifiedTimestampUsecs := `--last-modified-timestamp-usecs=26`
			AlertPolicy := `--alert-policy=@tempdir/alert-policy.json`
			Sla := `--sla=@tempdir/sla.json`
			QosPolicy := `--qos-policy=kBackupHDD`
			AbortInBlackouts := `--abort-in-blackouts=true`
			PauseInBlackouts := `--pause-in-blackouts=true`
			IsPaused := `--is-paused=true`
			AdvancedConfigs := `--advanced-configs=@tempdir/advanced-configs.json`
			PhysicalParams := `--physical-params=@tempdir/physical-params.json`
			MssqlParams := `--mssql-params=@tempdir/mssql-params.json`

			argsWithFiles := []string{
				XIBMTenantID,
				Name,
				PolicyID,
				Environment,
				Priority,
				Description,
				StartTime,
				EndTimeUsecs,
				LastModifiedTimestampUsecs,
				AlertPolicy,
				Sla,
				QosPolicy,
				AbortInBlackouts,
				PauseInBlackouts,
				IsPaused,
				AdvancedConfigs,
				PhysicalParams,
				MssqlParams,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for CreateProtectionGroup", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateProtectionGroupCommandRunner(negativeFakeUtils, CreateProtectionGroupErrorSender{})
			command := backuprecoveryv1.GetCreateProtectionGroupCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetProtectionGroupByID", func() {
		// put together mock arguments
		ID := `--id=testString`
		XIBMTenantID := `--xibm-tenant-id=tenantID`
		RequestInitiatorType := `--request-initiator-type=UIUser`
		IncludeLastRunInfo := `--include-last-run-info=true`
		PruneExcludedSourceIds := `--prune-excluded-source-ids=true`
		PruneSourceIds := `--prune-source-ids=true`

		args := []string{
			ID,
			XIBMTenantID,
			RequestInitiatorType,
			IncludeLastRunInfo,
			PruneExcludedSourceIds,
			PruneSourceIds,
		}

		It("Puts together GetProtectionGroupByID options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetProtectionGroupByIDCommandRunner(positiveFakeUtils, GetProtectionGroupByIDMockSender{})
			command := backuprecoveryv1.GetGetProtectionGroupByIDCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetProtectionGroupByID", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetProtectionGroupByIDCommandRunner(negativeFakeUtils, GetProtectionGroupByIDErrorSender{})
			command := backuprecoveryv1.GetGetProtectionGroupByIDCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("UpdateProtectionGroup", func() {
		// put together mock arguments
		ID := `--id=testString`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Name := `--name=update-protection-group`
		PolicyID := `--policy-id=xxxxxxxxxxxxxxxx:xxxxxxxxxxxxx:xx`
		Environment := `--environment=kPhysical`
		Priority := `--priority=kLow`
		Description := `--description=Protection Group`
		StartTime := `--start-time={"hour": 0, "minute": 0, "timeZone": "America/Los_Angeles"}`
		EndTimeUsecs := `--end-time-usecs=26`
		LastModifiedTimestampUsecs := `--last-modified-timestamp-usecs=26`
		AlertPolicy := `--alert-policy={"backupRunStatus": ["kSuccess","kFailure","kSlaViolation","kWarning"], "alertTargets": [{"emailAddress": "alert1@domain.com", "language": "en-us", "recipientType": "kTo"}], "raiseObjectLevelFailureAlert": true, "raiseObjectLevelFailureAlertAfterLastAttempt": true, "raiseObjectLevelFailureAlertAfterEachAttempt": true}`
		Sla := `--sla=[{"backupRunType": "kIncremental", "slaMinutes": 1}]`
		QosPolicy := `--qos-policy=kBackupHDD`
		AbortInBlackouts := `--abort-in-blackouts=true`
		PauseInBlackouts := `--pause-in-blackouts=true`
		IsPaused := `--is-paused=true`
		AdvancedConfigs := `--advanced-configs=[{"key": "configKey", "value": "configValue"}]`
		PhysicalParams := `--physical-params={"protectionType": "kFile", "volumeProtectionTypeParams": {"objects": [{"id": 3, "volumeGuids": ["volumeGuid1"], "enableSystemBackup": true, "excludedVssWriters": ["writerName1","writerName2"]}], "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "performSourceSideDeduplication": true, "quiesce": true, "continueOnQuiesceFailure": true, "incrementalBackupAfterRestart": true, "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "dedupExclusionSourceIds": [26,27], "excludedVssWriters": ["writerName1","writerName2"], "cobmrBackup": true}, "fileProtectionTypeParams": {"excludedVssWriters": ["writerName1","writerName2"], "objects": [{"excludedVssWriters": ["writerName1","writerName2"], "id": 2, "filePaths": [{"includedPath": "~/dir1/", "excludedPaths": ["~/dir2"], "skipNestedVolumes": true}], "usesPathLevelSkipNestedVolumeSetting": true, "nestedVolumeTypesToSkip": ["volume1"], "followNasSymlinkTarget": true, "metadataFilePath": "~/dir3"}], "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "performSourceSideDeduplication": true, "performBrickBasedDeduplication": true, "taskTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "quiesce": true, "continueOnQuiesceFailure": true, "cobmrBackup": true, "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "dedupExclusionSourceIds": [26,27], "globalExcludePaths": ["~/dir1"], "globalExcludeFS": ["~/dir2"], "ignorableErrors": ["kEOF","kNonExistent"], "allowParallelRuns": true}}`
		MssqlParams := `--mssql-params={"fileProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "additionalHostParams": [{"disableSourceSideDeduplication": true, "hostId": 26}], "objects": [{"id": 6}], "performSourceSideDeduplication": true}, "nativeProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "numStreams": 38, "objects": [{"id": 6}], "withClause": "withClause"}, "protectionType": "kFile", "volumeProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "additionalHostParams": [{"enableSystemBackup": true, "hostId": 8, "volumeGuids": ["volumeGuid1"]}], "backupDbVolumesOnly": true, "incrementalBackupAfterRestart": true, "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "objects": [{"id": 6}]}}`

		args := []string{
			ID,
			XIBMTenantID,
			Name,
			PolicyID,
			Environment,
			Priority,
			Description,
			StartTime,
			EndTimeUsecs,
			LastModifiedTimestampUsecs,
			AlertPolicy,
			Sla,
			QosPolicy,
			AbortInBlackouts,
			PauseInBlackouts,
			IsPaused,
			AdvancedConfigs,
			PhysicalParams,
			MssqlParams,
		}

		It("Puts together UpdateProtectionGroup options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewUpdateProtectionGroupCommandRunner(positiveFakeUtils, UpdateProtectionGroupMockSender{})
			command := backuprecoveryv1.GetUpdateProtectionGroupCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewUpdateProtectionGroupCommandRunner(positiveFakeUtils, UpdateProtectionGroupMockSender{})
			command := backuprecoveryv1.GetUpdateProtectionGroupCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			StartTimeContents := []byte(`{"hour": 0, "minute": 0, "timeZone": "America/Los_Angeles"}`)
			StartTimeFileErr := os.WriteFile("tempdir/start-time.json", StartTimeContents, 0644)
			if StartTimeFileErr != nil {
				Fail(StartTimeFileErr.Error())
			}
			AlertPolicyContents := []byte(`{"backupRunStatus": ["kSuccess","kFailure","kSlaViolation","kWarning"], "alertTargets": [{"emailAddress": "alert1@domain.com", "language": "en-us", "recipientType": "kTo"}], "raiseObjectLevelFailureAlert": true, "raiseObjectLevelFailureAlertAfterLastAttempt": true, "raiseObjectLevelFailureAlertAfterEachAttempt": true}`)
			AlertPolicyFileErr := os.WriteFile("tempdir/alert-policy.json", AlertPolicyContents, 0644)
			if AlertPolicyFileErr != nil {
				Fail(AlertPolicyFileErr.Error())
			}
			SlaContents := []byte(`[{"backupRunType": "kIncremental", "slaMinutes": 1}]`)
			SlaFileErr := os.WriteFile("tempdir/sla.json", SlaContents, 0644)
			if SlaFileErr != nil {
				Fail(SlaFileErr.Error())
			}
			AdvancedConfigsContents := []byte(`[{"key": "configKey", "value": "configValue"}]`)
			AdvancedConfigsFileErr := os.WriteFile("tempdir/advanced-configs.json", AdvancedConfigsContents, 0644)
			if AdvancedConfigsFileErr != nil {
				Fail(AdvancedConfigsFileErr.Error())
			}
			PhysicalParamsContents := []byte(`{"protectionType": "kFile", "volumeProtectionTypeParams": {"objects": [{"id": 3, "volumeGuids": ["volumeGuid1"], "enableSystemBackup": true, "excludedVssWriters": ["writerName1","writerName2"]}], "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "performSourceSideDeduplication": true, "quiesce": true, "continueOnQuiesceFailure": true, "incrementalBackupAfterRestart": true, "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "dedupExclusionSourceIds": [26,27], "excludedVssWriters": ["writerName1","writerName2"], "cobmrBackup": true}, "fileProtectionTypeParams": {"excludedVssWriters": ["writerName1","writerName2"], "objects": [{"excludedVssWriters": ["writerName1","writerName2"], "id": 2, "filePaths": [{"includedPath": "~/dir1/", "excludedPaths": ["~/dir2"], "skipNestedVolumes": true}], "usesPathLevelSkipNestedVolumeSetting": true, "nestedVolumeTypesToSkip": ["volume1"], "followNasSymlinkTarget": true, "metadataFilePath": "~/dir3"}], "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "performSourceSideDeduplication": true, "performBrickBasedDeduplication": true, "taskTimeouts": [{"timeoutMins": 26, "backupType": "kRegular"}], "quiesce": true, "continueOnQuiesceFailure": true, "cobmrBackup": true, "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "dedupExclusionSourceIds": [26,27], "globalExcludePaths": ["~/dir1"], "globalExcludeFS": ["~/dir2"], "ignorableErrors": ["kEOF","kNonExistent"], "allowParallelRuns": true}}`)
			PhysicalParamsFileErr := os.WriteFile("tempdir/physical-params.json", PhysicalParamsContents, 0644)
			if PhysicalParamsFileErr != nil {
				Fail(PhysicalParamsFileErr.Error())
			}
			MssqlParamsContents := []byte(`{"fileProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "additionalHostParams": [{"disableSourceSideDeduplication": true, "hostId": 26}], "objects": [{"id": 6}], "performSourceSideDeduplication": true}, "nativeProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "numStreams": 38, "objects": [{"id": 6}], "withClause": "withClause"}, "protectionType": "kFile", "volumeProtectionTypeParams": {"aagBackupPreferenceType": "kPrimaryReplicaOnly", "advancedSettings": {"clonedDbBackupStatus": "kError", "dbBackupIfNotOnlineStatus": "kError", "missingDbBackupStatus": "kError", "offlineRestoringDbBackupStatus": "kError", "readOnlyDbBackupStatus": "kError", "reportAllNonAutoprotectDbErrors": "kError"}, "backupSystemDbs": true, "excludeFilters": [{"filterString": "filterString", "isRegularExpression": false}], "fullBackupsCopyOnly": true, "logBackupNumStreams": 38, "logBackupWithClause": "backupWithClause", "prePostScript": {"preScript": {"path": "~/script1", "params": "param1", "timeoutSecs": 1, "isActive": true, "continueOnError": true}, "postScript": {"path": "~/script2", "params": "param2", "timeoutSecs": 1, "isActive": true}}, "useAagPreferencesFromServer": true, "userDbBackupPreferenceType": "kBackupAllDatabases", "additionalHostParams": [{"enableSystemBackup": true, "hostId": 8, "volumeGuids": ["volumeGuid1"]}], "backupDbVolumesOnly": true, "incrementalBackupAfterRestart": true, "indexingPolicy": {"enableIndexing": true, "includePaths": ["~/dir1"], "excludePaths": ["~/dir2"]}, "objects": [{"id": 6}]}}`)
			MssqlParamsFileErr := os.WriteFile("tempdir/mssql-params.json", MssqlParamsContents, 0644)
			if MssqlParamsFileErr != nil {
				Fail(MssqlParamsFileErr.Error())
			}

			ID := `--id=testString`
			XIBMTenantID := `--xibm-tenant-id=tenantId`
			Name := `--name=update-protection-group`
			PolicyID := `--policy-id=xxxxxxxxxxxxxxxx:xxxxxxxxxxxxx:xx`
			Environment := `--environment=kPhysical`
			Priority := `--priority=kLow`
			Description := `--description=Protection Group`
			StartTime := `--start-time=@tempdir/start-time.json`
			EndTimeUsecs := `--end-time-usecs=26`
			LastModifiedTimestampUsecs := `--last-modified-timestamp-usecs=26`
			AlertPolicy := `--alert-policy=@tempdir/alert-policy.json`
			Sla := `--sla=@tempdir/sla.json`
			QosPolicy := `--qos-policy=kBackupHDD`
			AbortInBlackouts := `--abort-in-blackouts=true`
			PauseInBlackouts := `--pause-in-blackouts=true`
			IsPaused := `--is-paused=true`
			AdvancedConfigs := `--advanced-configs=@tempdir/advanced-configs.json`
			PhysicalParams := `--physical-params=@tempdir/physical-params.json`
			MssqlParams := `--mssql-params=@tempdir/mssql-params.json`

			argsWithFiles := []string{
				ID,
				XIBMTenantID,
				Name,
				PolicyID,
				Environment,
				Priority,
				Description,
				StartTime,
				EndTimeUsecs,
				LastModifiedTimestampUsecs,
				AlertPolicy,
				Sla,
				QosPolicy,
				AbortInBlackouts,
				PauseInBlackouts,
				IsPaused,
				AdvancedConfigs,
				PhysicalParams,
				MssqlParams,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for UpdateProtectionGroup", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewUpdateProtectionGroupCommandRunner(negativeFakeUtils, UpdateProtectionGroupErrorSender{})
			command := backuprecoveryv1.GetUpdateProtectionGroupCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("DeleteProtectionGroup", func() {
		// put together mock arguments
		ID := `--id=testString`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		DeleteSnapshots := `--delete-snapshots=true`

		args := []string{
			ID,
			XIBMTenantID,
			DeleteSnapshots,
		}

		It("Puts together DeleteProtectionGroup options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDeleteProtectionGroupCommandRunner(positiveFakeUtils, DeleteProtectionGroupMockSender{})
			command := backuprecoveryv1.GetDeleteProtectionGroupCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for DeleteProtectionGroup", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDeleteProtectionGroupCommandRunner(negativeFakeUtils, DeleteProtectionGroupErrorSender{})
			command := backuprecoveryv1.GetDeleteProtectionGroupCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetProtectionGroupRuns", func() {
		// put together mock arguments
		ID := `--id=testString`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		RequestInitiatorType := `--request-initiator-type=UIUser`
		RunID := `--run-id=11:111`
		StartTimeUsecs := `--start-time-usecs=26`
		EndTimeUsecs := `--end-time-usecs=26`
		RunTypes := `--run-types=kAll,kHydrateCDP,kSystem,kStorageArraySnapshot,kIncremental,kFull,kLog`
		IncludeObjectDetails := `--include-object-details=true`
		LocalBackupRunStatus := `--local-backup-run-status=Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused`
		ReplicationRunStatus := `--replication-run-status=Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused`
		ArchivalRunStatus := `--archival-run-status=Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused`
		CloudSpinRunStatus := `--cloud-spin-run-status=Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,Paused`
		NumRuns := `--num-runs=26`
		ExcludeNonRestorableRuns := `--exclude-non-restorable-runs=false`
		RunTags := `--run-tags=tag1`
		UseCachedData := `--use-cached-data=true`
		FilterByEndTime := `--filter-by-end-time=true`
		SnapshotTargetTypes := `--snapshot-target-types=Local,Archival,RpaasArchival,StorageArraySnapshot,Remote`
		OnlyReturnSuccessfulCopyRun := `--only-return-successful-copy-run=true`
		FilterByCopyTaskEndTime := `--filter-by-copy-task-end-time=true`

		args := []string{
			ID,
			XIBMTenantID,
			RequestInitiatorType,
			RunID,
			StartTimeUsecs,
			EndTimeUsecs,
			RunTypes,
			IncludeObjectDetails,
			LocalBackupRunStatus,
			ReplicationRunStatus,
			ArchivalRunStatus,
			CloudSpinRunStatus,
			NumRuns,
			ExcludeNonRestorableRuns,
			RunTags,
			UseCachedData,
			FilterByEndTime,
			SnapshotTargetTypes,
			OnlyReturnSuccessfulCopyRun,
			FilterByCopyTaskEndTime,
		}

		It("Puts together GetProtectionGroupRuns options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetProtectionGroupRunsCommandRunner(positiveFakeUtils, GetProtectionGroupRunsMockSender{})
			command := backuprecoveryv1.GetGetProtectionGroupRunsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetProtectionGroupRuns", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetProtectionGroupRunsCommandRunner(negativeFakeUtils, GetProtectionGroupRunsErrorSender{})
			command := backuprecoveryv1.GetGetProtectionGroupRunsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("UpdateProtectionGroupRun", func() {
		// put together mock arguments
		ID := `--id=testString`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		UpdateProtectionGroupRunParams := `--update-protection-group-run-params=[{"runId": "11:111", "localSnapshotConfig": {"enableLegalHold": true, "deleteSnapshot": true, "dataLock": "Compliance", "daysToKeep": 26}, "replicationSnapshotConfig": {"newSnapshotConfig": [{"id": 26, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}], "updateExistingSnapshotConfig": [{"id": 4, "name": "update-snapshot-config", "enableLegalHold": true, "deleteSnapshot": true, "resync": true, "dataLock": "Compliance", "daysToKeep": 26}]}, "archivalSnapshotConfig": {"newSnapshotConfig": [{"id": 2, "archivalTargetType": "Tape", "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnlyFullySuccessful": true}], "updateExistingSnapshotConfig": [{"id": 3, "name": "update-snapshot-config", "archivalTargetType": "Tape", "enableLegalHold": true, "deleteSnapshot": true, "resync": true, "dataLock": "Compliance", "daysToKeep": 26}]}}]`

		args := []string{
			ID,
			XIBMTenantID,
			UpdateProtectionGroupRunParams,
		}

		It("Puts together UpdateProtectionGroupRun options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewUpdateProtectionGroupRunCommandRunner(positiveFakeUtils, UpdateProtectionGroupRunMockSender{})
			command := backuprecoveryv1.GetUpdateProtectionGroupRunCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewUpdateProtectionGroupRunCommandRunner(positiveFakeUtils, UpdateProtectionGroupRunMockSender{})
			command := backuprecoveryv1.GetUpdateProtectionGroupRunCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			UpdateProtectionGroupRunParamsContents := []byte(`[{"runId": "11:111", "localSnapshotConfig": {"enableLegalHold": true, "deleteSnapshot": true, "dataLock": "Compliance", "daysToKeep": 26}, "replicationSnapshotConfig": {"newSnapshotConfig": [{"id": 26, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}], "updateExistingSnapshotConfig": [{"id": 4, "name": "update-snapshot-config", "enableLegalHold": true, "deleteSnapshot": true, "resync": true, "dataLock": "Compliance", "daysToKeep": 26}]}, "archivalSnapshotConfig": {"newSnapshotConfig": [{"id": 2, "archivalTargetType": "Tape", "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnlyFullySuccessful": true}], "updateExistingSnapshotConfig": [{"id": 3, "name": "update-snapshot-config", "archivalTargetType": "Tape", "enableLegalHold": true, "deleteSnapshot": true, "resync": true, "dataLock": "Compliance", "daysToKeep": 26}]}}]`)
			UpdateProtectionGroupRunParamsFileErr := os.WriteFile("tempdir/update-protection-group-run-params.json", UpdateProtectionGroupRunParamsContents, 0644)
			if UpdateProtectionGroupRunParamsFileErr != nil {
				Fail(UpdateProtectionGroupRunParamsFileErr.Error())
			}

			ID := `--id=testString`
			XIBMTenantID := `--xibm-tenant-id=tenantId`
			UpdateProtectionGroupRunParams := `--update-protection-group-run-params=@tempdir/update-protection-group-run-params.json`

			argsWithFiles := []string{
				ID,
				XIBMTenantID,
				UpdateProtectionGroupRunParams,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for UpdateProtectionGroupRun", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewUpdateProtectionGroupRunCommandRunner(negativeFakeUtils, UpdateProtectionGroupRunErrorSender{})
			command := backuprecoveryv1.GetUpdateProtectionGroupRunCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("CreateProtectionGroupRun", func() {
		// put together mock arguments
		ID := `--id=runId`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		RunType := `--run-type=kRegular`
		Objects := `--objects=[{"id": 4, "appIds": [26,27], "physicalParams": {"metadataFilePath": "~/metadata"}}]`
		TargetsConfig := `--targets-config={"usePolicyDefaults": false, "replications": [{"id": 26, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}], "archivals": [{"id": 26, "archivalTargetType": "Tape", "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnlyFullySuccessful": true}], "cloudReplications": [{"awsTarget": {"region": 26, "sourceId": 26}, "azureTarget": {"resourceGroup": 26, "sourceId": 26}, "targetType": "AWS", "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}]}`

		args := []string{
			ID,
			XIBMTenantID,
			RunType,
			Objects,
			TargetsConfig,
		}

		It("Puts together CreateProtectionGroupRun options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateProtectionGroupRunCommandRunner(positiveFakeUtils, CreateProtectionGroupRunMockSender{})
			command := backuprecoveryv1.GetCreateProtectionGroupRunCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateProtectionGroupRunCommandRunner(positiveFakeUtils, CreateProtectionGroupRunMockSender{})
			command := backuprecoveryv1.GetCreateProtectionGroupRunCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			ObjectsContents := []byte(`[{"id": 4, "appIds": [26,27], "physicalParams": {"metadataFilePath": "~/metadata"}}]`)
			ObjectsFileErr := os.WriteFile("tempdir/objects.json", ObjectsContents, 0644)
			if ObjectsFileErr != nil {
				Fail(ObjectsFileErr.Error())
			}
			TargetsConfigContents := []byte(`{"usePolicyDefaults": false, "replications": [{"id": 26, "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}], "archivals": [{"id": 26, "archivalTargetType": "Tape", "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}, "copyOnlyFullySuccessful": true}], "cloudReplications": [{"awsTarget": {"region": 26, "sourceId": 26}, "azureTarget": {"resourceGroup": 26, "sourceId": 26}, "targetType": "AWS", "retention": {"unit": "Days", "duration": 1, "dataLockConfig": {"mode": "Compliance", "unit": "Days", "duration": 1, "enableWormOnExternalTarget": true}}}]}`)
			TargetsConfigFileErr := os.WriteFile("tempdir/targets-config.json", TargetsConfigContents, 0644)
			if TargetsConfigFileErr != nil {
				Fail(TargetsConfigFileErr.Error())
			}

			ID := `--id=runId`
			XIBMTenantID := `--xibm-tenant-id=tenantId`
			RunType := `--run-type=kRegular`
			Objects := `--objects=@tempdir/objects.json`
			TargetsConfig := `--targets-config=@tempdir/targets-config.json`

			argsWithFiles := []string{
				ID,
				XIBMTenantID,
				RunType,
				Objects,
				TargetsConfig,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for CreateProtectionGroupRun", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateProtectionGroupRunCommandRunner(negativeFakeUtils, CreateProtectionGroupRunErrorSender{})
			command := backuprecoveryv1.GetCreateProtectionGroupRunCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("PerformActionOnProtectionGroupRun", func() {
		// put together mock arguments
		ID := `--id=runId`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Action := `--action=Pause`
		PauseParams := `--pause-params=[{"runId": "11:111"}]`
		ResumeParams := `--resume-params=[{"runId": "11:111"}]`
		CancelParams := `--cancel-params=[{"runId": "11:111", "localTaskId": "123:456:789", "objectIds": [26,27], "replicationTaskId": ["123:456:789"], "archivalTaskId": ["123:456:789"], "cloudSpinTaskId": ["123:456:789"]}]`

		args := []string{
			ID,
			XIBMTenantID,
			Action,
			PauseParams,
			ResumeParams,
			CancelParams,
		}

		It("Puts together PerformActionOnProtectionGroupRun options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewPerformActionOnProtectionGroupRunCommandRunner(positiveFakeUtils, PerformActionOnProtectionGroupRunMockSender{})
			command := backuprecoveryv1.GetPerformActionOnProtectionGroupRunCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewPerformActionOnProtectionGroupRunCommandRunner(positiveFakeUtils, PerformActionOnProtectionGroupRunMockSender{})
			command := backuprecoveryv1.GetPerformActionOnProtectionGroupRunCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			PauseParamsContents := []byte(`[{"runId": "11:111"}]`)
			PauseParamsFileErr := os.WriteFile("tempdir/pause-params.json", PauseParamsContents, 0644)
			if PauseParamsFileErr != nil {
				Fail(PauseParamsFileErr.Error())
			}
			ResumeParamsContents := []byte(`[{"runId": "11:111"}]`)
			ResumeParamsFileErr := os.WriteFile("tempdir/resume-params.json", ResumeParamsContents, 0644)
			if ResumeParamsFileErr != nil {
				Fail(ResumeParamsFileErr.Error())
			}
			CancelParamsContents := []byte(`[{"runId": "11:111", "localTaskId": "123:456:789", "objectIds": [26,27], "replicationTaskId": ["123:456:789"], "archivalTaskId": ["123:456:789"], "cloudSpinTaskId": ["123:456:789"]}]`)
			CancelParamsFileErr := os.WriteFile("tempdir/cancel-params.json", CancelParamsContents, 0644)
			if CancelParamsFileErr != nil {
				Fail(CancelParamsFileErr.Error())
			}

			ID := `--id=runId`
			XIBMTenantID := `--xibm-tenant-id=tenantId`
			Action := `--action=Pause`
			PauseParams := `--pause-params=@tempdir/pause-params.json`
			ResumeParams := `--resume-params=@tempdir/resume-params.json`
			CancelParams := `--cancel-params=@tempdir/cancel-params.json`

			argsWithFiles := []string{
				ID,
				XIBMTenantID,
				Action,
				PauseParams,
				ResumeParams,
				CancelParams,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for PerformActionOnProtectionGroupRun", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewPerformActionOnProtectionGroupRunCommandRunner(negativeFakeUtils, PerformActionOnProtectionGroupRunErrorSender{})
			command := backuprecoveryv1.GetPerformActionOnProtectionGroupRunCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetRecoveries", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Ids := `--ids=11:111:11`
		ReturnOnlyChildRecoveries := `--return-only-child-recoveries=true`
		StartTimeUsecs := `--start-time-usecs=26`
		EndTimeUsecs := `--end-time-usecs=26`
		SnapshotTargetType := `--snapshot-target-type=Local,Archival,RpaasArchival,StorageArraySnapshot,Remote`
		ArchivalTargetType := `--archival-target-type=Tape,Cloud,Nas`
		SnapshotEnvironments := `--snapshot-environments=kPhysical,kSQL`
		Status := `--status=Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,LegalHold`
		RecoveryActions := `--recovery-actions=RecoverVMs,RecoverFiles,InstantVolumeMount,RecoverVmDisks,RecoverVApps,RecoverVAppTemplates,UptierSnapshot,RecoverRDS,RecoverAurora,RecoverS3Buckets,RecoverRDSPostgres,RecoverAzureSQL,RecoverApps,CloneApps,RecoverNasVolume,RecoverPhysicalVolumes,RecoverSystem,RecoverExchangeDbs,CloneAppView,RecoverSanVolumes,RecoverSanGroup,RecoverMailbox,RecoverOneDrive,RecoverSharePoint,RecoverPublicFolders,RecoverMsGroup,RecoverMsTeam,ConvertToPst,DownloadChats,RecoverMailboxCSM,RecoverOneDriveCSM,RecoverSharePointCSM,RecoverNamespaces,RecoverObjects,RecoverSfdcObjects,RecoverSfdcOrg,RecoverSfdcRecords,DownloadFilesAndFolders,CloneVMs,CloneView,CloneRefreshApp,CloneVMsToView,ConvertAndDeployVMs,DeployVMs`

		args := []string{
			XIBMTenantID,
			Ids,
			ReturnOnlyChildRecoveries,
			StartTimeUsecs,
			EndTimeUsecs,
			SnapshotTargetType,
			ArchivalTargetType,
			SnapshotEnvironments,
			Status,
			RecoveryActions,
		}

		It("Puts together GetRecoveries options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetRecoveriesCommandRunner(positiveFakeUtils, GetRecoveriesMockSender{})
			command := backuprecoveryv1.GetGetRecoveriesCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetRecoveries", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetRecoveriesCommandRunner(negativeFakeUtils, GetRecoveriesErrorSender{})
			command := backuprecoveryv1.GetGetRecoveriesCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("CreateRecovery", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Name := `--name=create-recovery`
		SnapshotEnvironment := `--snapshot-environment=kPhysical`
		PhysicalParams := `--physical-params={"objects": [{"snapshotId": "snapshotID", "pointInTimeUsecs": 26, "protectionGroupId": "protectionGroupID", "protectionGroupName": "protectionGroupName", "recoverFromStandby": true}], "recoveryAction": "RecoverPhysicalVolumes", "recoverVolumeParams": {"targetEnvironment": "kPhysical", "physicalTargetParams": {"mountTarget": {"id": 26}, "volumeMapping": [{"sourceVolumeGuid": "sourceVolumeGuid", "destinationVolumeGuid": "destinationVolumeGuid"}], "forceUnmountVolume": true, "vlanConfig": {"id": 38, "disableVlan": true}}}, "mountVolumeParams": {"targetEnvironment": "kPhysical", "physicalTargetParams": {"mountToOriginalTarget": true, "originalTargetConfig": {"serverCredentials": {"username": "Username", "password": "Password"}}, "newTargetConfig": {"mountTarget": {"id": 26}, "serverCredentials": {"username": "Username", "password": "Password"}}, "readOnlyMount": true, "volumeNames": ["volume1"], "vlanConfig": {"id": 38, "disableVlan": true}}}, "recoverFileAndFolderParams": {"filesAndFolders": [{"absolutePath": "~/folder1", "isDirectory": true, "isViewFileRecovery": true}], "targetEnvironment": "kPhysical", "physicalTargetParams": {"recoverTarget": {"id": 26}, "restoreToOriginalPaths": true, "overwriteExisting": true, "alternateRestoreDirectory": "~/dirAlt", "preserveAttributes": true, "preserveTimestamps": true, "preserveAcls": true, "continueOnError": true, "saveSuccessFiles": true, "vlanConfig": {"id": 38, "disableVlan": true}, "restoreEntityType": "kRegular"}}, "downloadFileAndFolderParams": {"expiryTimeUsecs": 26, "filesAndFolders": [{"absolutePath": "~/folder1", "isDirectory": true, "isViewFileRecovery": true}], "downloadFilePath": "~/downloadFile"}, "systemRecoveryParams": {"fullNasPath": "~/nas"}}`
		MssqlParams := `--mssql-params={"recoverAppParams": [{"snapshotId": "snapshotId", "pointInTimeUsecs": 26, "protectionGroupId": "protectionGroupId", "protectionGroupName": "protectionGroupName", "recoverFromStandby": true, "aagInfo": {"name": "aagInfoName", "objectId": 26}, "hostInfo": {"id": "hostInfoId", "name": "hostInfoName", "environment": "kPhysical"}, "isEncrypted": true, "sqlTargetParams": {"newSourceConfig": {"keepCdc": true, "multiStageRestoreOptions": {"enableAutoSync": true, "enableMultiStageRestore": true}, "nativeLogRecoveryWithClause": "LogRecoveryWithClause", "nativeRecoveryWithClause": "RecoveryWithClause", "overwritingPolicy": "FailIfExists", "replayEntireLastLog": true, "restoreTimeUsecs": 26, "secondaryDataFilesDirList": [{"directory": "~/dir1", "filenamePattern": ".sql"}], "withNoRecovery": true, "dataFileDirectoryLocation": "~/dir1", "databaseName": "recovery-database-sql", "host": {"id": 26}, "instanceName": "database-instance-1", "logFileDirectoryLocation": "~/dir2"}, "originalSourceConfig": {"keepCdc": true, "multiStageRestoreOptions": {"enableAutoSync": true, "enableMultiStageRestore": true}, "nativeLogRecoveryWithClause": "LogRecoveryWithClause", "nativeRecoveryWithClause": "RecoveryWithClause", "overwritingPolicy": "FailIfExists", "replayEntireLastLog": true, "restoreTimeUsecs": 26, "secondaryDataFilesDirList": [{"directory": "~/dir1", "filenamePattern": ".sql"}], "withNoRecovery": true, "captureTailLogs": true, "dataFileDirectoryLocation": "~/dir1", "logFileDirectoryLocation": "~/dir2", "newDatabaseName": "recovery-database-sql-new"}, "recoverToNewSource": true}, "targetEnvironment": "kSQL"}], "recoveryAction": "RecoverApps", "vlanConfig": {"id": 38, "disableVlan": true}}`
		RequestInitiatorType := `--request-initiator-type=UIUser`

		args := []string{
			XIBMTenantID,
			Name,
			SnapshotEnvironment,
			PhysicalParams,
			MssqlParams,
			RequestInitiatorType,
		}

		It("Puts together CreateRecovery options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateRecoveryCommandRunner(positiveFakeUtils, CreateRecoveryMockSender{})
			command := backuprecoveryv1.GetCreateRecoveryCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateRecoveryCommandRunner(positiveFakeUtils, CreateRecoveryMockSender{})
			command := backuprecoveryv1.GetCreateRecoveryCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			PhysicalParamsContents := []byte(`{"objects": [{"snapshotId": "snapshotID", "pointInTimeUsecs": 26, "protectionGroupId": "protectionGroupID", "protectionGroupName": "protectionGroupName", "recoverFromStandby": true}], "recoveryAction": "RecoverPhysicalVolumes", "recoverVolumeParams": {"targetEnvironment": "kPhysical", "physicalTargetParams": {"mountTarget": {"id": 26}, "volumeMapping": [{"sourceVolumeGuid": "sourceVolumeGuid", "destinationVolumeGuid": "destinationVolumeGuid"}], "forceUnmountVolume": true, "vlanConfig": {"id": 38, "disableVlan": true}}}, "mountVolumeParams": {"targetEnvironment": "kPhysical", "physicalTargetParams": {"mountToOriginalTarget": true, "originalTargetConfig": {"serverCredentials": {"username": "Username", "password": "Password"}}, "newTargetConfig": {"mountTarget": {"id": 26}, "serverCredentials": {"username": "Username", "password": "Password"}}, "readOnlyMount": true, "volumeNames": ["volume1"], "vlanConfig": {"id": 38, "disableVlan": true}}}, "recoverFileAndFolderParams": {"filesAndFolders": [{"absolutePath": "~/folder1", "isDirectory": true, "isViewFileRecovery": true}], "targetEnvironment": "kPhysical", "physicalTargetParams": {"recoverTarget": {"id": 26}, "restoreToOriginalPaths": true, "overwriteExisting": true, "alternateRestoreDirectory": "~/dirAlt", "preserveAttributes": true, "preserveTimestamps": true, "preserveAcls": true, "continueOnError": true, "saveSuccessFiles": true, "vlanConfig": {"id": 38, "disableVlan": true}, "restoreEntityType": "kRegular"}}, "downloadFileAndFolderParams": {"expiryTimeUsecs": 26, "filesAndFolders": [{"absolutePath": "~/folder1", "isDirectory": true, "isViewFileRecovery": true}], "downloadFilePath": "~/downloadFile"}, "systemRecoveryParams": {"fullNasPath": "~/nas"}}`)
			PhysicalParamsFileErr := os.WriteFile("tempdir/physical-params.json", PhysicalParamsContents, 0644)
			if PhysicalParamsFileErr != nil {
				Fail(PhysicalParamsFileErr.Error())
			}
			MssqlParamsContents := []byte(`{"recoverAppParams": [{"snapshotId": "snapshotId", "pointInTimeUsecs": 26, "protectionGroupId": "protectionGroupId", "protectionGroupName": "protectionGroupName", "recoverFromStandby": true, "aagInfo": {"name": "aagInfoName", "objectId": 26}, "hostInfo": {"id": "hostInfoId", "name": "hostInfoName", "environment": "kPhysical"}, "isEncrypted": true, "sqlTargetParams": {"newSourceConfig": {"keepCdc": true, "multiStageRestoreOptions": {"enableAutoSync": true, "enableMultiStageRestore": true}, "nativeLogRecoveryWithClause": "LogRecoveryWithClause", "nativeRecoveryWithClause": "RecoveryWithClause", "overwritingPolicy": "FailIfExists", "replayEntireLastLog": true, "restoreTimeUsecs": 26, "secondaryDataFilesDirList": [{"directory": "~/dir1", "filenamePattern": ".sql"}], "withNoRecovery": true, "dataFileDirectoryLocation": "~/dir1", "databaseName": "recovery-database-sql", "host": {"id": 26}, "instanceName": "database-instance-1", "logFileDirectoryLocation": "~/dir2"}, "originalSourceConfig": {"keepCdc": true, "multiStageRestoreOptions": {"enableAutoSync": true, "enableMultiStageRestore": true}, "nativeLogRecoveryWithClause": "LogRecoveryWithClause", "nativeRecoveryWithClause": "RecoveryWithClause", "overwritingPolicy": "FailIfExists", "replayEntireLastLog": true, "restoreTimeUsecs": 26, "secondaryDataFilesDirList": [{"directory": "~/dir1", "filenamePattern": ".sql"}], "withNoRecovery": true, "captureTailLogs": true, "dataFileDirectoryLocation": "~/dir1", "logFileDirectoryLocation": "~/dir2", "newDatabaseName": "recovery-database-sql-new"}, "recoverToNewSource": true}, "targetEnvironment": "kSQL"}], "recoveryAction": "RecoverApps", "vlanConfig": {"id": 38, "disableVlan": true}}`)
			MssqlParamsFileErr := os.WriteFile("tempdir/mssql-params.json", MssqlParamsContents, 0644)
			if MssqlParamsFileErr != nil {
				Fail(MssqlParamsFileErr.Error())
			}

			XIBMTenantID := `--xibm-tenant-id=tenantId`
			Name := `--name=create-recovery`
			SnapshotEnvironment := `--snapshot-environment=kPhysical`
			PhysicalParams := `--physical-params=@tempdir/physical-params.json`
			MssqlParams := `--mssql-params=@tempdir/mssql-params.json`
			RequestInitiatorType := `--request-initiator-type=UIUser`

			argsWithFiles := []string{
				XIBMTenantID,
				Name,
				SnapshotEnvironment,
				PhysicalParams,
				MssqlParams,
				RequestInitiatorType,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for CreateRecovery", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateRecoveryCommandRunner(negativeFakeUtils, CreateRecoveryErrorSender{})
			command := backuprecoveryv1.GetCreateRecoveryCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetRecoveryByID", func() {
		// put together mock arguments
		ID := `--id=testString`
		XIBMTenantID := `--xibm-tenant-id=tenantId`

		args := []string{
			ID,
			XIBMTenantID,
		}

		It("Puts together GetRecoveryByID options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetRecoveryByIDCommandRunner(positiveFakeUtils, GetRecoveryByIDMockSender{})
			command := backuprecoveryv1.GetGetRecoveryByIDCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetRecoveryByID", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetRecoveryByIDCommandRunner(negativeFakeUtils, GetRecoveryByIDErrorSender{})
			command := backuprecoveryv1.GetGetRecoveryByIDCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("DownloadFilesFromRecovery", func() {
		// put together mock arguments
		ID := `--id=testString`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		StartOffset := `--start-offset=26`
		Length := `--length=26`
		FileType := `--file-type=fileType`
		SourceName := `--source-name=sourceName`
		StartTime := `--start-time=startTime`
		IncludeTenants := `--include-tenants=true`

		args := []string{
			ID,
			XIBMTenantID,
			StartOffset,
			Length,
			FileType,
			SourceName,
			StartTime,
			IncludeTenants,
		}

		It("Puts together DownloadFilesFromRecovery options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDownloadFilesFromRecoveryCommandRunner(positiveFakeUtils, DownloadFilesFromRecoveryMockSender{})
			command := backuprecoveryv1.GetDownloadFilesFromRecoveryCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for DownloadFilesFromRecovery", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDownloadFilesFromRecoveryCommandRunner(negativeFakeUtils, DownloadFilesFromRecoveryErrorSender{})
			command := backuprecoveryv1.GetDownloadFilesFromRecoveryCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetDataSourceConnections", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		ConnectionIds := `--connection-ids=connectionId1,connectionId2`
		ConnectionNames := `--connection-names=connectionName1,connectionName2`

		args := []string{
			XIBMTenantID,
			ConnectionIds,
			ConnectionNames,
		}

		It("Puts together GetDataSourceConnections options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetDataSourceConnectionsCommandRunner(positiveFakeUtils, GetDataSourceConnectionsMockSender{})
			command := backuprecoveryv1.GetGetDataSourceConnectionsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetDataSourceConnections", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetDataSourceConnectionsCommandRunner(negativeFakeUtils, GetDataSourceConnectionsErrorSender{})
			command := backuprecoveryv1.GetGetDataSourceConnectionsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("CreateDataSourceConnection", func() {
		// put together mock arguments
		ConnectionName := `--connection-name=data-source-connection`
		XIBMTenantID := `--xibm-tenant-id=tenantId`

		args := []string{
			ConnectionName,
			XIBMTenantID,
		}

		It("Puts together CreateDataSourceConnection options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateDataSourceConnectionCommandRunner(positiveFakeUtils, CreateDataSourceConnectionMockSender{})
			command := backuprecoveryv1.GetCreateDataSourceConnectionCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for CreateDataSourceConnection", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateDataSourceConnectionCommandRunner(negativeFakeUtils, CreateDataSourceConnectionErrorSender{})
			command := backuprecoveryv1.GetCreateDataSourceConnectionCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("DeleteDataSourceConnection", func() {
		// put together mock arguments
		ConnectionID := `--connection-id=testString`
		XIBMTenantID := `--xibm-tenant-id=tenantId`

		args := []string{
			ConnectionID,
			XIBMTenantID,
		}

		It("Puts together DeleteDataSourceConnection options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDeleteDataSourceConnectionCommandRunner(positiveFakeUtils, DeleteDataSourceConnectionMockSender{})
			command := backuprecoveryv1.GetDeleteDataSourceConnectionCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for DeleteDataSourceConnection", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDeleteDataSourceConnectionCommandRunner(negativeFakeUtils, DeleteDataSourceConnectionErrorSender{})
			command := backuprecoveryv1.GetDeleteDataSourceConnectionCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("PatchDataSourceConnection", func() {
		// put together mock arguments
		ConnectionID := `--connection-id=connectionId`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		ConnectionName := `--connection-name=connectionName`

		args := []string{
			ConnectionID,
			XIBMTenantID,
			ConnectionName,
		}

		It("Puts together PatchDataSourceConnection options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewPatchDataSourceConnectionCommandRunner(positiveFakeUtils, PatchDataSourceConnectionMockSender{})
			command := backuprecoveryv1.GetPatchDataSourceConnectionCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for PatchDataSourceConnection", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewPatchDataSourceConnectionCommandRunner(negativeFakeUtils, PatchDataSourceConnectionErrorSender{})
			command := backuprecoveryv1.GetPatchDataSourceConnectionCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GenerateDataSourceConnectionRegistrationToken", func() {
		// put together mock arguments
		ConnectionID := `--connection-id=testString`
		XIBMTenantID := `--xibm-tenant-id=tenantId`

		args := []string{
			ConnectionID,
			XIBMTenantID,
		}

		It("Puts together GenerateDataSourceConnectionRegistrationToken options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGenerateDataSourceConnectionRegistrationTokenCommandRunner(positiveFakeUtils, GenerateDataSourceConnectionRegistrationTokenMockSender{})
			command := backuprecoveryv1.GetGenerateDataSourceConnectionRegistrationTokenCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GenerateDataSourceConnectionRegistrationToken", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGenerateDataSourceConnectionRegistrationTokenCommandRunner(negativeFakeUtils, GenerateDataSourceConnectionRegistrationTokenErrorSender{})
			command := backuprecoveryv1.GetGenerateDataSourceConnectionRegistrationTokenCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetDataSourceConnectors", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		ConnectorIds := `--connector-ids=connectorId1,connectorId2`
		ConnectorNames := `--connector-names=connectionName1,connectionName2`
		ConnectionID := `--connection-id=testString`

		args := []string{
			XIBMTenantID,
			ConnectorIds,
			ConnectorNames,
			ConnectionID,
		}

		It("Puts together GetDataSourceConnectors options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetDataSourceConnectorsCommandRunner(positiveFakeUtils, GetDataSourceConnectorsMockSender{})
			command := backuprecoveryv1.GetGetDataSourceConnectorsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetDataSourceConnectors", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetDataSourceConnectorsCommandRunner(negativeFakeUtils, GetDataSourceConnectorsErrorSender{})
			command := backuprecoveryv1.GetGetDataSourceConnectorsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("DeleteDataSourceConnector", func() {
		// put together mock arguments
		ConnectorID := `--connector-id=connectorId`
		XIBMTenantID := `--xibm-tenant-id=tenantId`

		args := []string{
			ConnectorID,
			XIBMTenantID,
		}

		It("Puts together DeleteDataSourceConnector options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDeleteDataSourceConnectorCommandRunner(positiveFakeUtils, DeleteDataSourceConnectorMockSender{})
			command := backuprecoveryv1.GetDeleteDataSourceConnectorCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for DeleteDataSourceConnector", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDeleteDataSourceConnectorCommandRunner(negativeFakeUtils, DeleteDataSourceConnectorErrorSender{})
			command := backuprecoveryv1.GetDeleteDataSourceConnectorCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("PatchDataSourceConnector", func() {
		// put together mock arguments
		ConnectorID := `--connector-id=connectorID`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		ConnectorName := `--connector-name=connectorName`

		args := []string{
			ConnectorID,
			XIBMTenantID,
			ConnectorName,
		}

		It("Puts together PatchDataSourceConnector options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewPatchDataSourceConnectorCommandRunner(positiveFakeUtils, PatchDataSourceConnectorMockSender{})
			command := backuprecoveryv1.GetPatchDataSourceConnectorCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for PatchDataSourceConnector", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewPatchDataSourceConnectorCommandRunner(negativeFakeUtils, PatchDataSourceConnectorErrorSender{})
			command := backuprecoveryv1.GetPatchDataSourceConnectorCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("DownloadAgent", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Platform := `--platform=kWindows`
		LinuxParams := `--linux-params={"packageType": "kScript"}`
		OutputFile := `--output-file=tempdir/test-output.txt`

		args := []string{
			XIBMTenantID,
			Platform,
			LinuxParams,
			OutputFile,
		}

		It("Puts together DownloadAgent options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDownloadAgentCommandRunner(positiveFakeUtils, DownloadAgentMockSender{})
			command := backuprecoveryv1.GetDownloadAgentCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDownloadAgentCommandRunner(positiveFakeUtils, DownloadAgentMockSender{})
			command := backuprecoveryv1.GetDownloadAgentCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			LinuxParamsContents := []byte(`{"packageType": "kScript"}`)
			LinuxParamsFileErr := os.WriteFile("tempdir/linux-params.json", LinuxParamsContents, 0644)
			if LinuxParamsFileErr != nil {
				Fail(LinuxParamsFileErr.Error())
			}

			XIBMTenantID := `--xibm-tenant-id=tenantId`
			Platform := `--platform=kWindows`
			LinuxParams := `--linux-params=@tempdir/linux-params.json`

			argsWithFiles := []string{
				XIBMTenantID,
				Platform,
				LinuxParams,
				OutputFile,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for DownloadAgent", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDownloadAgentCommandRunner(negativeFakeUtils, DownloadAgentErrorSender{})
			command := backuprecoveryv1.GetDownloadAgentCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetConnectorMetadata", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`

		args := []string{
			XIBMTenantID,
		}

		It("Puts together GetConnectorMetadata options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetConnectorMetadataCommandRunner(positiveFakeUtils, GetConnectorMetadataMockSender{})
			command := backuprecoveryv1.GetGetConnectorMetadataCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetConnectorMetadata", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetConnectorMetadataCommandRunner(negativeFakeUtils, GetConnectorMetadataErrorSender{})
			command := backuprecoveryv1.GetGetConnectorMetadataCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetObjectSnapshots", func() {
		// put together mock arguments
		ID := `--id=26`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		FromTimeUsecs := `--from-time-usecs=26`
		ToTimeUsecs := `--to-time-usecs=26`
		RunStartFromTimeUsecs := `--run-start-from-time-usecs=26`
		RunStartToTimeUsecs := `--run-start-to-time-usecs=26`
		SnapshotActions := `--snapshot-actions=RecoverVMs,RecoverFiles,InstantVolumeMount,RecoverVmDisks,MountVolumes,RecoverVApps,RecoverRDS,RecoverAurora,RecoverS3Buckets,RecoverApps,RecoverNasVolume,RecoverPhysicalVolumes,RecoverSystem,RecoverSanVolumes,RecoverNamespaces,RecoverObjects,DownloadFilesAndFolders,RecoverPublicFolders,RecoverVAppTemplates,RecoverMailbox,RecoverOneDrive,RecoverMsTeam,RecoverMsGroup,RecoverSharePoint,ConvertToPst,RecoverSfdcRecords,RecoverAzureSQL,DownloadChats,RecoverRDSPostgres,RecoverMailboxCSM,RecoverOneDriveCSM,RecoverSharePointCSM`
		RunTypes := `--run-types=kRegular,kFull,kLog,kSystem,kHydrateCDP,kStorageArraySnapshot`
		ProtectionGroupIds := `--protection-group-ids=protectionGroupId1`
		RunInstanceIds := `--run-instance-ids=26,27`
		RegionIds := `--region-ids=regionId1`
		ObjectActionKeys := `--object-action-keys=kVMware,kHyperV,kVCD,kAzure,kGCP,kKVM,kAcropolis,kAWS,kAWSNative,kAwsS3,kAWSSnapshotManager,kRDSSnapshotManager,kAuroraSnapshotManager,kAwsRDSPostgresBackup,kAwsRDSPostgres,kAwsAuroraPostgres,kAzureNative,kAzureSQL,kAzureSnapshotManager,kPhysical,kPhysicalFiles,kGPFS,kElastifile,kNetapp,kGenericNas,kIsilon,kFlashBlade,kPure,kIbmFlashSystem,kSQL,kExchange,kAD,kOracle,kView,kRemoteAdapter,kO365,kO365PublicFolders,kO365Teams,kO365Group,kO365Exchange,kO365OneDrive,kO365Sharepoint,kKubernetes,kCassandra,kMongoDB,kCouchbase,kHdfs,kHive,kHBase,kSAPHANA,kUDA,kSfdc,kO365ExchangeCSM,kO365OneDriveCSM,kO365SharepointCSM`

		args := []string{
			ID,
			XIBMTenantID,
			FromTimeUsecs,
			ToTimeUsecs,
			RunStartFromTimeUsecs,
			RunStartToTimeUsecs,
			SnapshotActions,
			RunTypes,
			ProtectionGroupIds,
			RunInstanceIds,
			RegionIds,
			ObjectActionKeys,
		}

		It("Puts together GetObjectSnapshots options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetObjectSnapshotsCommandRunner(positiveFakeUtils, GetObjectSnapshotsMockSender{})
			command := backuprecoveryv1.GetGetObjectSnapshotsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetObjectSnapshots", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetObjectSnapshotsCommandRunner(negativeFakeUtils, GetObjectSnapshotsErrorSender{})
			command := backuprecoveryv1.GetGetObjectSnapshotsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("CreateDownloadFilesAndFoldersRecovery", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		Name := `--name=create-download-files-and-folders-recovery`
		Object := `--object={"snapshotId": "snapshotId", "pointInTimeUsecs": 26, "protectionGroupId": "protectionGroupId", "protectionGroupName": "protectionGroupName", "recoverFromStandby": true}`
		FilesAndFolders := `--files-and-folders=[{"absolutePath": "~/home/dir1", "isDirectory": true}]`
		Documents := `--documents=[{"isDirectory": true, "itemId": "item1"}]`
		ParentRecoveryID := `--parent-recovery-id=parentRecoveryId`
		GlacierRetrievalType := `--glacier-retrieval-type=kStandard`

		args := []string{
			XIBMTenantID,
			Name,
			Object,
			FilesAndFolders,
			Documents,
			ParentRecoveryID,
			GlacierRetrievalType,
		}

		It("Puts together CreateDownloadFilesAndFoldersRecovery options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateDownloadFilesAndFoldersRecoveryCommandRunner(positiveFakeUtils, CreateDownloadFilesAndFoldersRecoveryMockSender{})
			command := backuprecoveryv1.GetCreateDownloadFilesAndFoldersRecoveryCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateDownloadFilesAndFoldersRecoveryCommandRunner(positiveFakeUtils, CreateDownloadFilesAndFoldersRecoveryMockSender{})
			command := backuprecoveryv1.GetCreateDownloadFilesAndFoldersRecoveryCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			ObjectContents := []byte(`{"snapshotId": "snapshotId", "pointInTimeUsecs": 26, "protectionGroupId": "protectionGroupId", "protectionGroupName": "protectionGroupName", "recoverFromStandby": true}`)
			ObjectFileErr := os.WriteFile("tempdir/object.json", ObjectContents, 0644)
			if ObjectFileErr != nil {
				Fail(ObjectFileErr.Error())
			}
			FilesAndFoldersContents := []byte(`[{"absolutePath": "~/home/dir1", "isDirectory": true}]`)
			FilesAndFoldersFileErr := os.WriteFile("tempdir/files-and-folders.json", FilesAndFoldersContents, 0644)
			if FilesAndFoldersFileErr != nil {
				Fail(FilesAndFoldersFileErr.Error())
			}
			DocumentsContents := []byte(`[{"isDirectory": true, "itemId": "item1"}]`)
			DocumentsFileErr := os.WriteFile("tempdir/documents.json", DocumentsContents, 0644)
			if DocumentsFileErr != nil {
				Fail(DocumentsFileErr.Error())
			}

			XIBMTenantID := `--xibm-tenant-id=tenantId`
			Name := `--name=create-download-files-and-folders-recovery`
			Object := `--object=@tempdir/object.json`
			FilesAndFolders := `--files-and-folders=@tempdir/files-and-folders.json`
			Documents := `--documents=@tempdir/documents.json`
			ParentRecoveryID := `--parent-recovery-id=parentRecoveryId`
			GlacierRetrievalType := `--glacier-retrieval-type=kStandard`

			argsWithFiles := []string{
				XIBMTenantID,
				Name,
				Object,
				FilesAndFolders,
				Documents,
				ParentRecoveryID,
				GlacierRetrievalType,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for CreateDownloadFilesAndFoldersRecovery", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewCreateDownloadFilesAndFoldersRecoveryCommandRunner(negativeFakeUtils, CreateDownloadFilesAndFoldersRecoveryErrorSender{})
			command := backuprecoveryv1.GetCreateDownloadFilesAndFoldersRecoveryCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("GetRestorePointsInTimeRange", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		EndTimeUsecs := `--end-time-usecs=45`
		Environment := `--environment=kVMware`
		ProtectionGroupIds := `--protection-group-ids=protectionGroupId1`
		StartTimeUsecs := `--start-time-usecs=15`
		SourceID := `--source-id=26`

		args := []string{
			XIBMTenantID,
			EndTimeUsecs,
			Environment,
			ProtectionGroupIds,
			StartTimeUsecs,
			SourceID,
		}

		It("Puts together GetRestorePointsInTimeRange options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetRestorePointsInTimeRangeCommandRunner(positiveFakeUtils, GetRestorePointsInTimeRangeMockSender{})
			command := backuprecoveryv1.GetGetRestorePointsInTimeRangeCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for GetRestorePointsInTimeRange", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewGetRestorePointsInTimeRangeCommandRunner(negativeFakeUtils, GetRestorePointsInTimeRangeErrorSender{})
			command := backuprecoveryv1.GetGetRestorePointsInTimeRangeCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("DownloadIndexedFile", func() {
		// put together mock arguments
		SnapshotsID := `--snapshots-id=snapshotId1`
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		FilePath := `--file-path=~/home/downloadFile`
		NvramFile := `--nvram-file=true`
		RetryAttempt := `--retry-attempt=26`
		StartOffset := `--start-offset=26`
		Length := `--length=26`

		args := []string{
			SnapshotsID,
			XIBMTenantID,
			FilePath,
			NvramFile,
			RetryAttempt,
			StartOffset,
			Length,
		}

		It("Puts together DownloadIndexedFile options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDownloadIndexedFileCommandRunner(positiveFakeUtils, DownloadIndexedFileMockSender{})
			command := backuprecoveryv1.GetDownloadIndexedFileCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for DownloadIndexedFile", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewDownloadIndexedFileCommandRunner(negativeFakeUtils, DownloadIndexedFileErrorSender{})
			command := backuprecoveryv1.GetDownloadIndexedFileCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("SearchIndexedObjects", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		ObjectType := `--object-type=Emails`
		ProtectionGroupIds := `--protection-group-ids=protectionGroupId1`
		StorageDomainIds := `--storage-domain-ids=26,27`
		TenantID := `--tenant-id=tenantId`
		IncludeTenants := `--include-tenants=false`
		Tags := `--tags=123:456:ABC-123,123:456:ABC-456`
		SnapshotTags := `--snapshot-tags=123:456:DEF-123,123:456:DEF-456`
		MustHaveTagIds := `--must-have-tag-ids=123:456:ABC-123`
		MightHaveTagIds := `--might-have-tag-ids=123:456:ABC-456`
		MustHaveSnapshotTagIds := `--must-have-snapshot-tag-ids=123:456:DEF-123`
		MightHaveSnapshotTagIds := `--might-have-snapshot-tag-ids=123:456:DEF-456`
		PaginationCookie := `--pagination-cookie=paginationCookie`
		Count := `--count=38`
		UseCachedData := `--use-cached-data=true`
		CassandraParams := `--cassandra-params={"cassandraObjectTypes": ["CassandraKeyspaces","CassandraTables"], "searchString": "searchString", "sourceIds": [26,27]}`
		CouchbaseParams := `--couchbase-params={"couchbaseObjectTypes": ["CouchbaseBuckets"], "searchString": "searchString", "sourceIds": [26,27]}`
		EmailParams := `--email-params={"attendeesAddresses": ["attendee1@domain.com"], "bccRecipientAddresses": ["bccrecipient@domain.com"], "ccRecipientAddresses": ["ccrecipient@domain.com"], "createdEndTimeSecs": 26, "createdStartTimeSecs": 26, "dueDateEndTimeSecs": 26, "dueDateStartTimeSecs": 26, "emailAddress": "email@domain.com", "emailSubject": "Email Subject", "firstName": "First Name", "folderNames": ["folder1"], "hasAttachment": true, "lastModifiedEndTimeSecs": 26, "lastModifiedStartTimeSecs": 26, "lastName": "Last Name", "middleName": "Middle Name", "organizerAddress": "organizer@domain.com", "receivedEndTimeSecs": 26, "receivedStartTimeSecs": 26, "recipientAddresses": ["recipient@domain.com"], "senderAddress": "sender@domain.com", "sourceEnvironment": "kO365", "taskStatusTypes": ["NotStarted","InProgress","Completed","WaitingOnOthers","Deferred"], "types": ["Email","Folder","Calendar","Contact","Task","Note"], "o365Params": {"domainIds": [26,27], "mailboxIds": [26,27]}}`
		ExchangeParams := `--exchange-params={"searchString": "searchString"}`
		FileParams := `--file-params={"searchString": "searchString", "types": ["File","Directory","Symlink"], "sourceEnvironments": ["kVMware","kHyperV","kSQL","kView","kRemoteAdapter","kPhysical","kPhysicalFiles","kPure","kIbmFlashSystem","kAzure","kNetapp","kGenericNas","kAcropolis","kIsilon","kGPFS","kKVM","kAWS","kExchange","kOracle","kGCP","kFlashBlade","kO365","kHyperFlex","kKubernetes","kElastifile","kSAPHANA","kUDA","kSfdc"], "sourceIds": [26,27], "objectIds": [26,27]}`
		HbaseParams := `--hbase-params={"hbaseObjectTypes": ["HbaseNamespaces","HbaseTables"], "searchString": "searchString", "sourceIds": [26,27]}`
		HdfsParams := `--hdfs-params={"hdfsTypes": ["HDFSFolders","HDFSFiles"], "searchString": "searchString", "sourceIds": [26,27]}`
		HiveParams := `--hive-params={"hiveObjectTypes": ["HiveDatabases","HiveTables","HivePartitions"], "searchString": "searchString", "sourceIds": [26,27]}`
		MongodbParams := `--mongodb-params={"mongoDBObjectTypes": ["MongoDatabases","MongoCollections"], "searchString": "searchString", "sourceIds": [26,27]}`
		MsGroupsParams := `--ms-groups-params={"mailboxParams": {"attendeesAddresses": ["attendee1@domain.com"], "bccRecipientAddresses": ["bccrecipient@domain.com"], "ccRecipientAddresses": ["ccrecipient@domain.com"], "createdEndTimeSecs": 26, "createdStartTimeSecs": 26, "dueDateEndTimeSecs": 26, "dueDateStartTimeSecs": 26, "emailAddress": "email@domain.com", "emailSubject": "Email Subject", "firstName": "First Name", "folderNames": ["folder1"], "hasAttachment": true, "lastModifiedEndTimeSecs": 26, "lastModifiedStartTimeSecs": 26, "lastName": "Last Name", "middleName": "Middle Name", "organizerAddress": "organizer@domain.com", "receivedEndTimeSecs": 26, "receivedStartTimeSecs": 26, "recipientAddresses": ["recipient@domain.com"], "senderAddress": "sender@domain.com", "sourceEnvironment": "kO365", "taskStatusTypes": ["NotStarted","InProgress","Completed","WaitingOnOthers","Deferred"], "types": ["Email","Folder","Calendar","Contact","Task","Note"]}, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "siteParams": {"categoryTypes": ["Document","Excel","Powerpoint","Image","OneNote"], "creationEndTimeSecs": 26, "creationStartTimeSecs": 26, "includeFiles": true, "includeFolders": true, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "ownerNames": ["ownerName1"], "searchString": "searchString", "sizeBytesLowerLimit": 26, "sizeBytesUpperLimit": 26}}`
		MsTeamsParams := `--ms-teams-params={"categoryTypes": ["Document","Excel","Powerpoint","Image","OneNote"], "channelNames": ["channelName1"], "channelParams": {"channelEmail": "channel@domain.com", "channelId": "channelId", "channelName": "channelName", "includePrivateChannels": true, "includePublicChannels": true}, "creationEndTimeSecs": 26, "creationStartTimeSecs": 26, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "ownerNames": ["ownerName1"], "searchString": "searchString", "sizeBytesLowerLimit": 26, "sizeBytesUpperLimit": 26, "types": ["Channel","Chat","Conversation","File","Folder"]}`
		OneDriveParams := `--one-drive-params={"categoryTypes": ["Document","Excel","Powerpoint","Image","OneNote"], "creationEndTimeSecs": 26, "creationStartTimeSecs": 26, "includeFiles": true, "includeFolders": true, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "ownerNames": ["ownerName1"], "searchString": "searchString", "sizeBytesLowerLimit": 26, "sizeBytesUpperLimit": 26}`
		PublicFolderParams := `--public-folder-params={"searchString": "searchString", "types": ["Calendar","Contact","Post","Folder","Task","Journal","Note"], "hasAttachment": true, "senderAddress": "sender@domain.com", "recipientAddresses": ["recipient@domain.com"], "ccRecipientAddresses": ["ccrecipient@domain.com"], "bccRecipientAddresses": ["bccrecipient@domain.com"], "receivedStartTimeSecs": 26, "receivedEndTimeSecs": 26}`
		SfdcParams := `--sfdc-params={"mutationTypes": ["All","Added","Removed","Changed"], "objectName": "objectName", "queryString": "queryString", "snapshotId": "snapshotId"}`
		SharepointParams := `--sharepoint-params={"categoryTypes": ["Document","Excel","Powerpoint","Image","OneNote"], "creationEndTimeSecs": 26, "creationStartTimeSecs": 26, "includeFiles": true, "includeFolders": true, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "ownerNames": ["ownerName1"], "searchString": "searchString", "sizeBytesLowerLimit": 26, "sizeBytesUpperLimit": 26}`
		UdaParams := `--uda-params={"searchString": "searchString", "sourceIds": [26,27]}`

		args := []string{
			XIBMTenantID,
			ObjectType,
			ProtectionGroupIds,
			StorageDomainIds,
			TenantID,
			IncludeTenants,
			Tags,
			SnapshotTags,
			MustHaveTagIds,
			MightHaveTagIds,
			MustHaveSnapshotTagIds,
			MightHaveSnapshotTagIds,
			PaginationCookie,
			Count,
			UseCachedData,
			CassandraParams,
			CouchbaseParams,
			EmailParams,
			ExchangeParams,
			FileParams,
			HbaseParams,
			HdfsParams,
			HiveParams,
			MongodbParams,
			MsGroupsParams,
			MsTeamsParams,
			OneDriveParams,
			PublicFolderParams,
			SfdcParams,
			SharepointParams,
			UdaParams,
		}

		It("Puts together SearchIndexedObjects options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewSearchIndexedObjectsCommandRunner(positiveFakeUtils, SearchIndexedObjectsMockSender{})
			command := backuprecoveryv1.GetSearchIndexedObjectsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Reads JSON strings from a file when argument starts with @ symbol", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewSearchIndexedObjectsCommandRunner(positiveFakeUtils, SearchIndexedObjectsMockSender{})
			command := backuprecoveryv1.GetSearchIndexedObjectsCommand(runner)

			// Set up files for all arguments that support reading a JSON string from a file.
			defer GinkgoRecover()
			CassandraParamsContents := []byte(`{"cassandraObjectTypes": ["CassandraKeyspaces","CassandraTables"], "searchString": "searchString", "sourceIds": [26,27]}`)
			CassandraParamsFileErr := os.WriteFile("tempdir/cassandra-params.json", CassandraParamsContents, 0644)
			if CassandraParamsFileErr != nil {
				Fail(CassandraParamsFileErr.Error())
			}
			CouchbaseParamsContents := []byte(`{"couchbaseObjectTypes": ["CouchbaseBuckets"], "searchString": "searchString", "sourceIds": [26,27]}`)
			CouchbaseParamsFileErr := os.WriteFile("tempdir/couchbase-params.json", CouchbaseParamsContents, 0644)
			if CouchbaseParamsFileErr != nil {
				Fail(CouchbaseParamsFileErr.Error())
			}
			EmailParamsContents := []byte(`{"attendeesAddresses": ["attendee1@domain.com"], "bccRecipientAddresses": ["bccrecipient@domain.com"], "ccRecipientAddresses": ["ccrecipient@domain.com"], "createdEndTimeSecs": 26, "createdStartTimeSecs": 26, "dueDateEndTimeSecs": 26, "dueDateStartTimeSecs": 26, "emailAddress": "email@domain.com", "emailSubject": "Email Subject", "firstName": "First Name", "folderNames": ["folder1"], "hasAttachment": true, "lastModifiedEndTimeSecs": 26, "lastModifiedStartTimeSecs": 26, "lastName": "Last Name", "middleName": "Middle Name", "organizerAddress": "organizer@domain.com", "receivedEndTimeSecs": 26, "receivedStartTimeSecs": 26, "recipientAddresses": ["recipient@domain.com"], "senderAddress": "sender@domain.com", "sourceEnvironment": "kO365", "taskStatusTypes": ["NotStarted","InProgress","Completed","WaitingOnOthers","Deferred"], "types": ["Email","Folder","Calendar","Contact","Task","Note"], "o365Params": {"domainIds": [26,27], "mailboxIds": [26,27]}}`)
			EmailParamsFileErr := os.WriteFile("tempdir/email-params.json", EmailParamsContents, 0644)
			if EmailParamsFileErr != nil {
				Fail(EmailParamsFileErr.Error())
			}
			ExchangeParamsContents := []byte(`{"searchString": "searchString"}`)
			ExchangeParamsFileErr := os.WriteFile("tempdir/exchange-params.json", ExchangeParamsContents, 0644)
			if ExchangeParamsFileErr != nil {
				Fail(ExchangeParamsFileErr.Error())
			}
			FileParamsContents := []byte(`{"searchString": "searchString", "types": ["File","Directory","Symlink"], "sourceEnvironments": ["kVMware","kHyperV","kSQL","kView","kRemoteAdapter","kPhysical","kPhysicalFiles","kPure","kIbmFlashSystem","kAzure","kNetapp","kGenericNas","kAcropolis","kIsilon","kGPFS","kKVM","kAWS","kExchange","kOracle","kGCP","kFlashBlade","kO365","kHyperFlex","kKubernetes","kElastifile","kSAPHANA","kUDA","kSfdc"], "sourceIds": [26,27], "objectIds": [26,27]}`)
			FileParamsFileErr := os.WriteFile("tempdir/file-params.json", FileParamsContents, 0644)
			if FileParamsFileErr != nil {
				Fail(FileParamsFileErr.Error())
			}
			HbaseParamsContents := []byte(`{"hbaseObjectTypes": ["HbaseNamespaces","HbaseTables"], "searchString": "searchString", "sourceIds": [26,27]}`)
			HbaseParamsFileErr := os.WriteFile("tempdir/hbase-params.json", HbaseParamsContents, 0644)
			if HbaseParamsFileErr != nil {
				Fail(HbaseParamsFileErr.Error())
			}
			HdfsParamsContents := []byte(`{"hdfsTypes": ["HDFSFolders","HDFSFiles"], "searchString": "searchString", "sourceIds": [26,27]}`)
			HdfsParamsFileErr := os.WriteFile("tempdir/hdfs-params.json", HdfsParamsContents, 0644)
			if HdfsParamsFileErr != nil {
				Fail(HdfsParamsFileErr.Error())
			}
			HiveParamsContents := []byte(`{"hiveObjectTypes": ["HiveDatabases","HiveTables","HivePartitions"], "searchString": "searchString", "sourceIds": [26,27]}`)
			HiveParamsFileErr := os.WriteFile("tempdir/hive-params.json", HiveParamsContents, 0644)
			if HiveParamsFileErr != nil {
				Fail(HiveParamsFileErr.Error())
			}
			MongodbParamsContents := []byte(`{"mongoDBObjectTypes": ["MongoDatabases","MongoCollections"], "searchString": "searchString", "sourceIds": [26,27]}`)
			MongodbParamsFileErr := os.WriteFile("tempdir/mongodb-params.json", MongodbParamsContents, 0644)
			if MongodbParamsFileErr != nil {
				Fail(MongodbParamsFileErr.Error())
			}
			MsGroupsParamsContents := []byte(`{"mailboxParams": {"attendeesAddresses": ["attendee1@domain.com"], "bccRecipientAddresses": ["bccrecipient@domain.com"], "ccRecipientAddresses": ["ccrecipient@domain.com"], "createdEndTimeSecs": 26, "createdStartTimeSecs": 26, "dueDateEndTimeSecs": 26, "dueDateStartTimeSecs": 26, "emailAddress": "email@domain.com", "emailSubject": "Email Subject", "firstName": "First Name", "folderNames": ["folder1"], "hasAttachment": true, "lastModifiedEndTimeSecs": 26, "lastModifiedStartTimeSecs": 26, "lastName": "Last Name", "middleName": "Middle Name", "organizerAddress": "organizer@domain.com", "receivedEndTimeSecs": 26, "receivedStartTimeSecs": 26, "recipientAddresses": ["recipient@domain.com"], "senderAddress": "sender@domain.com", "sourceEnvironment": "kO365", "taskStatusTypes": ["NotStarted","InProgress","Completed","WaitingOnOthers","Deferred"], "types": ["Email","Folder","Calendar","Contact","Task","Note"]}, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "siteParams": {"categoryTypes": ["Document","Excel","Powerpoint","Image","OneNote"], "creationEndTimeSecs": 26, "creationStartTimeSecs": 26, "includeFiles": true, "includeFolders": true, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "ownerNames": ["ownerName1"], "searchString": "searchString", "sizeBytesLowerLimit": 26, "sizeBytesUpperLimit": 26}}`)
			MsGroupsParamsFileErr := os.WriteFile("tempdir/ms-groups-params.json", MsGroupsParamsContents, 0644)
			if MsGroupsParamsFileErr != nil {
				Fail(MsGroupsParamsFileErr.Error())
			}
			MsTeamsParamsContents := []byte(`{"categoryTypes": ["Document","Excel","Powerpoint","Image","OneNote"], "channelNames": ["channelName1"], "channelParams": {"channelEmail": "channel@domain.com", "channelId": "channelId", "channelName": "channelName", "includePrivateChannels": true, "includePublicChannels": true}, "creationEndTimeSecs": 26, "creationStartTimeSecs": 26, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "ownerNames": ["ownerName1"], "searchString": "searchString", "sizeBytesLowerLimit": 26, "sizeBytesUpperLimit": 26, "types": ["Channel","Chat","Conversation","File","Folder"]}`)
			MsTeamsParamsFileErr := os.WriteFile("tempdir/ms-teams-params.json", MsTeamsParamsContents, 0644)
			if MsTeamsParamsFileErr != nil {
				Fail(MsTeamsParamsFileErr.Error())
			}
			OneDriveParamsContents := []byte(`{"categoryTypes": ["Document","Excel","Powerpoint","Image","OneNote"], "creationEndTimeSecs": 26, "creationStartTimeSecs": 26, "includeFiles": true, "includeFolders": true, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "ownerNames": ["ownerName1"], "searchString": "searchString", "sizeBytesLowerLimit": 26, "sizeBytesUpperLimit": 26}`)
			OneDriveParamsFileErr := os.WriteFile("tempdir/one-drive-params.json", OneDriveParamsContents, 0644)
			if OneDriveParamsFileErr != nil {
				Fail(OneDriveParamsFileErr.Error())
			}
			PublicFolderParamsContents := []byte(`{"searchString": "searchString", "types": ["Calendar","Contact","Post","Folder","Task","Journal","Note"], "hasAttachment": true, "senderAddress": "sender@domain.com", "recipientAddresses": ["recipient@domain.com"], "ccRecipientAddresses": ["ccrecipient@domain.com"], "bccRecipientAddresses": ["bccrecipient@domain.com"], "receivedStartTimeSecs": 26, "receivedEndTimeSecs": 26}`)
			PublicFolderParamsFileErr := os.WriteFile("tempdir/public-folder-params.json", PublicFolderParamsContents, 0644)
			if PublicFolderParamsFileErr != nil {
				Fail(PublicFolderParamsFileErr.Error())
			}
			SfdcParamsContents := []byte(`{"mutationTypes": ["All","Added","Removed","Changed"], "objectName": "objectName", "queryString": "queryString", "snapshotId": "snapshotId"}`)
			SfdcParamsFileErr := os.WriteFile("tempdir/sfdc-params.json", SfdcParamsContents, 0644)
			if SfdcParamsFileErr != nil {
				Fail(SfdcParamsFileErr.Error())
			}
			SharepointParamsContents := []byte(`{"categoryTypes": ["Document","Excel","Powerpoint","Image","OneNote"], "creationEndTimeSecs": 26, "creationStartTimeSecs": 26, "includeFiles": true, "includeFolders": true, "o365Params": {"domainIds": [26,27], "groupIds": [26,27], "siteIds": [26,27], "teamsIds": [26,27], "userIds": [26,27]}, "ownerNames": ["ownerName1"], "searchString": "searchString", "sizeBytesLowerLimit": 26, "sizeBytesUpperLimit": 26}`)
			SharepointParamsFileErr := os.WriteFile("tempdir/sharepoint-params.json", SharepointParamsContents, 0644)
			if SharepointParamsFileErr != nil {
				Fail(SharepointParamsFileErr.Error())
			}
			UdaParamsContents := []byte(`{"searchString": "searchString", "sourceIds": [26,27]}`)
			UdaParamsFileErr := os.WriteFile("tempdir/uda-params.json", UdaParamsContents, 0644)
			if UdaParamsFileErr != nil {
				Fail(UdaParamsFileErr.Error())
			}

			XIBMTenantID := `--xibm-tenant-id=tenantId`
			ObjectType := `--object-type=Emails`
			ProtectionGroupIds := `--protection-group-ids=protectionGroupId1`
			StorageDomainIds := `--storage-domain-ids=26,27`
			TenantID := `--tenant-id=tenantId`
			IncludeTenants := `--include-tenants=false`
			Tags := `--tags=123:456:ABC-123,123:456:ABC-456`
			SnapshotTags := `--snapshot-tags=123:456:DEF-123,123:456:DEF-456`
			MustHaveTagIds := `--must-have-tag-ids=123:456:ABC-123`
			MightHaveTagIds := `--might-have-tag-ids=123:456:ABC-456`
			MustHaveSnapshotTagIds := `--must-have-snapshot-tag-ids=123:456:DEF-123`
			MightHaveSnapshotTagIds := `--might-have-snapshot-tag-ids=123:456:DEF-456`
			PaginationCookie := `--pagination-cookie=paginationCookie`
			Count := `--count=38`
			UseCachedData := `--use-cached-data=true`
			CassandraParams := `--cassandra-params=@tempdir/cassandra-params.json`
			CouchbaseParams := `--couchbase-params=@tempdir/couchbase-params.json`
			EmailParams := `--email-params=@tempdir/email-params.json`
			ExchangeParams := `--exchange-params=@tempdir/exchange-params.json`
			FileParams := `--file-params=@tempdir/file-params.json`
			HbaseParams := `--hbase-params=@tempdir/hbase-params.json`
			HdfsParams := `--hdfs-params=@tempdir/hdfs-params.json`
			HiveParams := `--hive-params=@tempdir/hive-params.json`
			MongodbParams := `--mongodb-params=@tempdir/mongodb-params.json`
			MsGroupsParams := `--ms-groups-params=@tempdir/ms-groups-params.json`
			MsTeamsParams := `--ms-teams-params=@tempdir/ms-teams-params.json`
			OneDriveParams := `--one-drive-params=@tempdir/one-drive-params.json`
			PublicFolderParams := `--public-folder-params=@tempdir/public-folder-params.json`
			SfdcParams := `--sfdc-params=@tempdir/sfdc-params.json`
			SharepointParams := `--sharepoint-params=@tempdir/sharepoint-params.json`
			UdaParams := `--uda-params=@tempdir/uda-params.json`

			argsWithFiles := []string{
				XIBMTenantID,
				ObjectType,
				ProtectionGroupIds,
				StorageDomainIds,
				TenantID,
				IncludeTenants,
				Tags,
				SnapshotTags,
				MustHaveTagIds,
				MightHaveTagIds,
				MustHaveSnapshotTagIds,
				MightHaveSnapshotTagIds,
				PaginationCookie,
				Count,
				UseCachedData,
				CassandraParams,
				CouchbaseParams,
				EmailParams,
				ExchangeParams,
				FileParams,
				HbaseParams,
				HdfsParams,
				HiveParams,
				MongodbParams,
				MsGroupsParams,
				MsTeamsParams,
				OneDriveParams,
				PublicFolderParams,
				SfdcParams,
				SharepointParams,
				UdaParams,
			}
			command.SetArgs(argsWithFiles)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for SearchIndexedObjects", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewSearchIndexedObjectsCommandRunner(negativeFakeUtils, SearchIndexedObjectsErrorSender{})
			command := backuprecoveryv1.GetSearchIndexedObjectsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("SearchObjects", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		RequestInitiatorType := `--request-initiator-type=UIUser`
		SearchString := `--search-string=searchString`
		Environments := `--environments=kPhysical,kSQL`
		ProtectionTypes := `--protection-types=kAgent,kNative,kSnapshotManager,kRDSSnapshotManager,kAuroraSnapshotManager,kAwsS3,kAwsRDSPostgresBackup,kAwsAuroraPostgres,kAwsRDSPostgres,kAzureSQL,kFile,kVolume`
		ProtectionGroupIds := `--protection-group-ids=protectionGroupId1`
		ObjectIds := `--object-ids=26,27`
		OsTypes := `--os-types=kLinux,kWindows`
		SourceIds := `--source-ids=26,27`
		SourceUUIDs := `--source-uuids=sourceUuid1`
		IsProtected := `--is-protected=true`
		IsDeleted := `--is-deleted=true`
		LastRunStatusList := `--last-run-status-list=Accepted,Running,Canceled,Canceling,Failed,Missed,Succeeded,SucceededWithWarning,OnHold,Finalizing,Skipped,LegalHold`
		ClusterIdentifiers := `--cluster-identifiers=clusterIdentifier1`
		IncludeDeletedObjects := `--include-deleted-objects=true`
		PaginationCookie := `--pagination-cookie=paginationCookie`
		Count := `--count=38`
		MustHaveTagIds := `--must-have-tag-ids=123:456:ABC-123`
		MightHaveTagIds := `--might-have-tag-ids=123:456:ABC-456`
		MustHaveSnapshotTagIds := `--must-have-snapshot-tag-ids=123:456:DEF-123`
		MightHaveSnapshotTagIds := `--might-have-snapshot-tag-ids=123:456:DEF-456`
		TagSearchName := `--tag-search-name=tagName`
		TagNames := `--tag-names=tag1`
		TagTypes := `--tag-types=System,Custom,ThirdParty`
		TagCategories := `--tag-categories=Security`
		TagSubCategories := `--tag-sub-categories=Classification,Threats,Anomalies,Dspm`
		IncludeHeliosTagInfoForObjects := `--include-helios-tag-info-for-objects=true`
		ExternalFilters := `--external-filters=filter1`

		args := []string{
			XIBMTenantID,
			RequestInitiatorType,
			SearchString,
			Environments,
			ProtectionTypes,
			ProtectionGroupIds,
			ObjectIds,
			OsTypes,
			SourceIds,
			SourceUUIDs,
			IsProtected,
			IsDeleted,
			LastRunStatusList,
			ClusterIdentifiers,
			IncludeDeletedObjects,
			PaginationCookie,
			Count,
			MustHaveTagIds,
			MightHaveTagIds,
			MustHaveSnapshotTagIds,
			MightHaveSnapshotTagIds,
			TagSearchName,
			TagNames,
			TagTypes,
			TagCategories,
			TagSubCategories,
			IncludeHeliosTagInfoForObjects,
			ExternalFilters,
		}

		It("Puts together SearchObjects options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewSearchObjectsCommandRunner(positiveFakeUtils, SearchObjectsMockSender{})
			command := backuprecoveryv1.GetSearchObjectsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for SearchObjects", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewSearchObjectsCommandRunner(negativeFakeUtils, SearchObjectsErrorSender{})
			command := backuprecoveryv1.GetSearchObjectsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	Describe("SearchProtectedObjects", func() {
		// put together mock arguments
		XIBMTenantID := `--xibm-tenant-id=tenantId`
		RequestInitiatorType := `--request-initiator-type=UIUser`
		SearchString := `--search-string=searchString`
		Environments := `--environments=kPhysical,kSQL`
		SnapshotActions := `--snapshot-actions=RecoverVMs,RecoverFiles,InstantVolumeMount,RecoverVmDisks,MountVolumes,RecoverVApps,RecoverRDS,RecoverAurora,RecoverS3Buckets,RecoverApps,RecoverNasVolume,RecoverPhysicalVolumes,RecoverSystem,RecoverSanVolumes,RecoverNamespaces,RecoverObjects,DownloadFilesAndFolders,RecoverPublicFolders,RecoverVAppTemplates,RecoverMailbox,RecoverOneDrive,RecoverMsTeam,RecoverMsGroup,RecoverSharePoint,ConvertToPst,RecoverSfdcRecords,RecoverAzureSQL,DownloadChats,RecoverRDSPostgres,RecoverMailboxCSM,RecoverOneDriveCSM,RecoverSharePointCSM`
		ObjectActionKey := `--object-action-key=kPhysical`
		ProtectionGroupIds := `--protection-group-ids=protectionGroupId1`
		ObjectIds := `--object-ids=26,27`
		SubResultSize := `--sub-result-size=38`
		FilterSnapshotFromUsecs := `--filter-snapshot-from-usecs=26`
		FilterSnapshotToUsecs := `--filter-snapshot-to-usecs=26`
		OsTypes := `--os-types=kLinux,kWindows`
		SourceIds := `--source-ids=26,27`
		RunInstanceIds := `--run-instance-ids=26,27`
		CdpProtectedOnly := `--cdp-protected-only=true`
		UseCachedData := `--use-cached-data=true`

		args := []string{
			XIBMTenantID,
			RequestInitiatorType,
			SearchString,
			Environments,
			SnapshotActions,
			ObjectActionKey,
			ProtectionGroupIds,
			ObjectIds,
			SubResultSize,
			FilterSnapshotFromUsecs,
			FilterSnapshotToUsecs,
			OsTypes,
			SourceIds,
			RunInstanceIds,
			CdpProtectedOnly,
			UseCachedData,
		}

		It("Puts together SearchProtectedObjects options model", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewSearchProtectedObjectsCommandRunner(positiveFakeUtils, SearchProtectedObjectsMockSender{})
			command := backuprecoveryv1.GetSearchProtectedObjectsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})

		It("Tests error handling for SearchProtectedObjects", func() {
			backuprecoveryv1.Service = &testing_utilities.TestServiceCommandHelper{}
			runner := backuprecoveryv1.NewSearchProtectedObjectsCommandRunner(negativeFakeUtils, SearchProtectedObjectsErrorSender{})
			command := backuprecoveryv1.GetSearchProtectedObjectsCommand(runner)

			command.SetArgs(args)

			_, err := command.ExecuteC()
			Expect(err).To(BeNil())
		})
	})

	// Test the Service Command Getter
	It("Gets the parent command for BackupRecoveryV1", func() {
		backuprecoveryv1.InitializeService(positiveFakeUtils)
		command := backuprecoveryv1.GetBackupRecoveryV1Command(positiveFakeUtils)
		Expect(command.Use).To(Equal("backup-recovery [command] [options]"))
	})

	// Test the analytics header
	It("Sets a custom analytics header on the service instance", func() {
		backuprecoveryv1.InitializeService(positiveFakeUtils)
		command := backuprecoveryv1.GetBackupRecoveryV1Command(positiveFakeUtils)
		// need to explicitly set empty args or the ginkgo default args get picked up and cause errors
		command.SetArgs([]string{})
		command.SetHelpFunc(func(c *cobra.Command, a []string) {
			// calling the parent command without a subcommand will print the help menu
			// stub out the method for the test
		})

		err := command.Execute()
		Expect(err).To(BeNil())

		flagSet := command.Flags()
		backuprecoveryv1.Service.InitializeServiceInstance(flagSet)

		CheckAnalyticsHeader(backuprecoveryv1.ServiceInstance)
	})
	// Test the Service URL global flag
	It("Sets the service URL with a flag", func() {
		backuprecoveryv1.InitializeService(positiveFakeUtils)
		// set the url in the environment to verify that the flag overrides this value
		os.Setenv("BACKUP_RECOVERY_URL", "override-this.com/api")

		// put together mock arguments
		ServiceURL := "--service-url=https://ibm.cloud.com/my-api"

		args := []string{
			ServiceURL,
		}

		command := backuprecoveryv1.GetBackupRecoveryV1Command(positiveFakeUtils)
		command.SetArgs(args)
		command.SetHelpFunc(func(c *cobra.Command, a []string) {
			// calling the parent command without a subcommand will print the help menu
			// stub out the method for the test
		})

		err := command.Execute()
		Expect(err).To(BeNil())

		flagSet := command.Flags()
		backuprecoveryv1.Service.InitializeServiceInstance(flagSet)

		CheckServiceURL(backuprecoveryv1.ServiceInstance)
	})

	Describe("Config command tests", func() {
		// For setting values.
		configSetRunner := backuprecoveryv1.NewConfigSetCommandRunner(positiveFakeUtils)
		configSetCommand := backuprecoveryv1.GetConfigSetCommand(configSetRunner)

		// For cleaning up values.
		configUnsetRunner := backuprecoveryv1.NewConfigUnsetCommandRunner(positiveFakeUtils)
		configUnsetCommand := backuprecoveryv1.GetConfigUnsetCommand(configUnsetRunner)

		It("Service URL", func() {
			backuprecoveryv1.InitializeService(positiveFakeUtils)
			var err error

			configSetCommand.SetArgs([]string{"service-url", "https://ibm.cloud.com/my-api"})
			err = configSetCommand.Execute()
			Expect(err).To(BeNil())

			serviceCommand := backuprecoveryv1.GetBackupRecoveryV1Command(positiveFakeUtils)
			serviceCommand.SetHelpFunc(func(c *cobra.Command, a []string) {})
			flagSet := serviceCommand.Flags()
			backuprecoveryv1.Service.InitializeServiceInstance(flagSet)

			CheckServiceURL(backuprecoveryv1.ServiceInstance)

			// Clean up.
			configUnsetCommand.SetArgs([]string{"service-url"})
			err = configUnsetCommand.Execute()
			Expect(err).To(BeNil())
		})
	})

	Describe("Sets, Gets, and Unsets config options", func() {
		It("Tests  option", func() {
			checkConfigCommandsForOption("service-url", `https://ibm.cloud.com/my-api`)
		})
	})

	Describe(`Utility function tests`, func() {
		It(`Invoke CreateMockMap() successfully`, func() {
			mockMap := CreateMockMap()
			Expect(mockMap).ToNot(BeNil())
		})

		It(`Invoke CreateMockByteArray() successfully`, func() {
			bytes := CreateMockByteArray("VGhpcyBpcyBhIG1vY2sgYnl0ZSBhcnJheSB2YWx1ZS4=")
			Expect(bytes).ToNot(BeNil())
		})

		It(`Invoke CreateMockUUID() successfully`, func() {
			mockUUID := CreateMockUUID("9fab83da-98cb-4f18-a7ba-b6f0435c9673")
			Expect(mockUUID).ToNot(BeNil())
		})

		It(`Invoke CreateMockDate() successfully`, func() {
			mockDate := CreateMockDate("2019-01-01")
			Expect(mockDate).ToNot(BeNil())
		})

		It(`Invoke CreateMockDateTime() successfully`, func() {
			mockDateTime := CreateMockDateTime("2019-01-01T12:00:00.000Z")
			Expect(mockDateTime).ToNot(BeNil())
		})

		It(`Invoke ResolveModel() successfully`, func() {
			model := ResolveModel(map[string]string{
				"foo": "bar",
			})
			Expect(model).ToNot(BeNil())
		})
	})
})

func checkConfigCommandsForOption(name string, exampleValue string) {
	backuprecoveryv1.InitializeService(positiveFakeUtils)
	var err error

	noValueMsg := "No value has been set. Use the 'set' command to set a value."
	okMsg := "OK"

	configSetRunner := backuprecoveryv1.NewConfigSetCommandRunner(positiveFakeUtils)
	configSetCommand := backuprecoveryv1.GetConfigSetCommand(configSetRunner)

	configGetRunner := backuprecoveryv1.NewConfigGetCommandRunner(positiveFakeUtils)
	configGetCommand := backuprecoveryv1.GetConfigGetCommand(configGetRunner)

	configUnsetRunner := backuprecoveryv1.NewConfigUnsetCommandRunner(positiveFakeUtils)
	configUnsetCommand := backuprecoveryv1.GetConfigUnsetCommand(configUnsetRunner)

	// check unset and get without any values set
	configUnsetCommand.SetArgs([]string{name})
	err = configUnsetCommand.Execute()
	Expect(err).To(BeNil())
	Expect(positiveFakeUtils.LastThingSaid).To(Equal(noValueMsg))

	configGetCommand.SetArgs([]string{name})
	err = configGetCommand.Execute()
	Expect(err).To(BeNil())
	Expect(positiveFakeUtils.LastThingSaid).To(Equal(noValueMsg))

	// check set
	configSetCommand.SetArgs([]string{name, exampleValue})
	err = configSetCommand.Execute()
	Expect(err).To(BeNil())
	Expect(positiveFakeUtils.LastThingSaid).To(Equal(okMsg))

	// check that get prints the correct value when set
	configGetCommand.SetArgs([]string{name})
	err = configGetCommand.Execute()
	Expect(err).To(BeNil())
	Expect(positiveFakeUtils.LastThingSaid).To(Equal(exampleValue))

	// check that unset removes the value
	configUnsetCommand.SetArgs([]string{name})
	err = configUnsetCommand.Execute()
	Expect(err).To(BeNil())
	Expect(positiveFakeUtils.LastThingSaid).To(Equal(okMsg))

	configGetCommand.SetArgs([]string{name})
	err = configGetCommand.Execute()
	Expect(err).To(BeNil())
	Expect(positiveFakeUtils.LastThingSaid).To(Equal(noValueMsg))
}
