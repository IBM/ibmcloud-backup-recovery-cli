# IBM Cloud Backup Recovery CLI Plug-in

**Note:**  
IBM Cloud Backup and Recovery is the Limited Availability (LA) offering in the present release and is currently not available under the "General Availability (GA)". Only after the GA release, it will be available through the "IBM Global Catalog" for delivery and consumption from all available Data Center Region/Zones. For more details or questions about products, sales, or support, visit [IBM HELP](https://www.ibm.com/contact/global).

## Summary

This repository contains the source for the Backup Recovery CLI plug-in.

## Requirements

- Have an [IBM Cloud Account](https://cloud.ibm.com).
- Have [IBM Cloud CLI](https://cloud.ibm.com/docs/cli?topic=cli-getting-started) installed.

## Installation

```ibmcloud plugin install backup-recovery```

## Authentication

There are three ways to provide credentials to authenticate the CLI plugin:

1. Export them as environment variables.

2. Store them in a [credentials file](https://github.com/IBM/ibm-cloud-sdk-common/blob/main/README.md#storing-configuration-properties-in-a-file)
Properties must have the format `<service-name>_<property-key>`. For example, `BACKUP_RECOVERY_URL`. See [Define Configuration Properties](https://github.com/IBM/ibm-cloud-sdk-common/blob/main/README.md#define-configuration-properties) for more info.
If using a credentials file, it must be called `ibm-credentials.env` or the name must be provided with an environment variable called `IBM_CREDENTIALS_FILE`. See [Complete Configuration-loading Process](https://github.com/IBM/ibm-cloud-sdk-common/blob/main/README.md#complete-configuration-loading-process) for more information about how the credentials file is located.

3. Login to IBM Cloud on the command line - `ibmcloud login`. The CLI plugin will read the IAM access token stored in the CLI context and will refresh it if it expires.

## Commands

### backup-recovery

```yaml

NAME:
  backup-recovery - REST API used to configure protection source.

USAGE:
  ibmcloud backup-recovery [command] [options]

COMMANDS:
  agent-download             Download agent.
  agent-upgrade-task         Commands for AgentUpgradeTask resource.
  config                     Control persistent configuration.
  connector-metadata-get     Get information about the available connectors.
  data-source-connection     Commands for DataSourceConnection resource.
  data-source-connector      Commands for DataSourceConnector resource.
  download-recovery-create   Create a download files and folders recovery.
  indexed-file-download      Download an indexed file.
  indexed-objects-search     List indexed objects.
  object-snapshots-list      List the snapshots for a given object.
  objects-search             List Objects.
  protected-objects-search   List Protected Objects.
  protection-group           Commands for ProtectionGroup resource.
  protection-group-run       Commands for ProtectionGroupRun resource.
  protection-policy          Commands for ProtectionPolicy resource.
  protection-source          Commands for ProtectionSource resource.
  recovery                   Commands for Recovery resource.
  restore-points             List Restore Points in a given time range.

OPTIONS:
  -h, --help      Show help
  -q, --quiet     Suppresses verbose messages.
  -v, --version   Version of the plugin.

Use "ibmcloud backup-recovery service-command --help" for more information about a command.

```

## Trace logging

To see detailed HTTP information (full requests and responses) in the CLI plugin output, enable tracing using one of the following methods. The setting can be "false" (default, turns off tracing), "true" (turns on tracing, logs are sent to stderr), or a path to a file (turns on tracing, logs are sent to the file).

1. Set the global "trace" setting with the [config command](https://cloud.ibm.com/docs/cli?topic=cli-ibmcloud_cli#ibmcloud_config):
`ibmcloud config trace true`

2. Set the global "trace" environment variable:
`export IBMCLOUD_TRACE=/path/to/trace.log`

Note that both of these methods turn on tracing globally for all `ibmcloud` usage.

## License

This IBM CLI Plugin project is released under the Apache 2.0 license.
The license's full text can be found in [LICENSE](LICENSE).
