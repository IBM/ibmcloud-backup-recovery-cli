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
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/spf13/cobra"
	translation "ibmcloud-backup-recovery-cli/i18n"
)

func NewConfigCommandRunner(utils Utilities) *ConfigCommandRunner {
	return &ConfigCommandRunner{utils: utils}
}

type ConfigCommandRunner struct {
	utils Utilities
}

func GetConfigCommand(r *ConfigCommandRunner) *cobra.Command {
	commands := []*cobra.Command{
		GetConfigListCommand(NewConfigListCommandRunner(r.utils)),
		GetConfigGetCommand(NewConfigGetCommandRunner(r.utils)),
		GetConfigUnsetCommand(NewConfigUnsetCommandRunner(r.utils)),
		GetConfigSetCommand(NewConfigSetCommandRunner(r.utils)),
	}

	cmd := &cobra.Command{
		Use:                   "config",
		Short:                 translation.T("config-command-short-description"),
		Long:                  translation.T("config-command-long-description"),
		DisableFlagsInUseLine: true,
	}

	cmd.AddCommand(commands...)

	// the global parameters for the service command don't actually apply here, so
	// the help output is more clear when it is removed from the template
	cmd.SetUsageTemplate(`{{printHeader "name-header-help-menu"}}:
  {{.Name}} - {{.Long}}

{{printHeader "usage-header-help-menu"}}:
  ibmcloud {{.UseLine}}{{if gt (len .Aliases) 0}}

{{printHeader "aliases-header-help-menu"}}:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

{{printHeader "examples-header-help-menu"}}:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

{{printHeader "commands-header-help-menu"}}:{{$nameAndAliasPadding := (getNameAndAliasPadding .Commands)}}{{range .Commands}}{{if .IsAvailableCommand}}
  {{rpad .NameAndAliases $nameAndAliasPadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{printHeader "options-header-help-menu"}}:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}{{end}}
`)

	return cmd
}

func NewConfigListCommandRunner(utils Utilities) *ConfigListCommandRunner {
	return &ConfigListCommandRunner{utils: utils}
}

type ConfigListCommandRunner struct {
	utils Utilities
}

func GetConfigListCommand(r *ConfigListCommandRunner) *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "list",
		Short:                 translation.T("config-list-command-short-description"),
		Long:                  translation.T("config-list-command-long-description"),
		DisableFlagsInUseLine: true,
		Run:                   r.Run,
	}

	return cmd
}

func (r *ConfigListCommandRunner) Run(cmd *cobra.Command, args []string) {
	config := r.utils.GetPluginConfig()
	configOptions := []string{
		"service-url",
	}
	table := terminal.NewTable(terminal.Output, configOptions)
	tableData := make([]string, len(configOptions))
	for i, opt := range configOptions {
		if config.Exists(serviceName + "-" + opt) {
			value, err := config.GetString(serviceName + "-" + opt)
			if err != nil {
				core.GetLogger().Warn(translation.T("config-list-read-error", getConfigCmdNameMap(opt)))
				core.GetLogger().Info(err.Error())
				tableData[i] = "-"
			} else {
				tableData[i] = value
			}
		} else {
			tableData[i] = "-"
		}
	}

	table.Add(tableData...)
	table.Print()
}

func NewConfigGetCommandRunner(utils Utilities) *ConfigGetCommandRunner {
	return &ConfigGetCommandRunner{utils: utils}
}

type ConfigGetCommandRunner struct {
	utils Utilities
}

func GetConfigGetCommand(r *ConfigGetCommandRunner) *cobra.Command {
	commands := []*cobra.Command{
		NewConfigGetCommand(r.utils, "service-url"),
	}

	cmd := &cobra.Command{
		Use:                   "get [option]",
		Short:                 translation.T("config-get-command-short-description"),
		Long:                  translation.T("config-get-command-long-description"),
		DisableFlagsInUseLine: true,
	}

	cmd.AddCommand(commands...)

	return cmd
}

func NewConfigGetCommand(utils Utilities, name string) *cobra.Command {
	return &cobra.Command{
		Use:                   name,
		Short:                 translation.T("config-get-subcommand-short-description", getConfigCmdNameMap(name)),
		Long:                  translation.T("config-get-subcommand-long-description", getConfigCmdNameMap(name)),
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			config := utils.GetPluginConfig()
			if config.Exists(serviceName+ "-" +name) {
				value, err := config.GetString(serviceName+ "-" +name)
				utils.HandleError(err, translation.T("config-get-subcommand-read-error"))
				utils.Print(value)
			} else {
				utils.Print(translation.T("config-subcommand-no-value-set"))
			}
		},
	}
}

func NewConfigUnsetCommandRunner(utils Utilities) *ConfigUnsetCommandRunner {
	return &ConfigUnsetCommandRunner{utils: utils}
}

type ConfigUnsetCommandRunner struct {
	utils Utilities
}

func GetConfigUnsetCommand(r *ConfigUnsetCommandRunner) *cobra.Command {
	commands := []*cobra.Command{
		NewConfigUnsetCommand(r.utils, "service-url"),
	}

	cmd := &cobra.Command{
		Use:                   "unset [option]",
		Short:                 translation.T("config-unset-command-short-description"),
		Long:                  translation.T("config-unset-command-long-description"),
		DisableFlagsInUseLine: true,
	}

	cmd.AddCommand(commands...)

	return cmd
}

func NewConfigUnsetCommand(utils Utilities, name string) *cobra.Command {
	return &cobra.Command{
		Use:                   name,
		Short:                 translation.T("config-unset-subcommand-short-description", getConfigCmdNameMap(name)),
		Long:                  translation.T("config-unset-subcommand-long-description", getConfigCmdNameMap(name)),
		DisableFlagsInUseLine: true,
		Run: func(cmd *cobra.Command, args []string) {
			config := utils.GetPluginConfig()
			if config.Exists(serviceName+ "-" +name) {
				err := config.Erase(serviceName+ "-" +name)
				utils.HandleError(err, translation.T("config-subcommand-unset-error"))
				utils.Ok()
			} else {
				utils.Print(translation.T("config-subcommand-no-value-set"))
			}
		},
	}
}

func NewConfigSetCommandRunner(utils Utilities) *ConfigSetCommandRunner {
	return &ConfigSetCommandRunner{utils: utils}
}

type ConfigSetCommandRunner struct {
	utils Utilities
}

func GetConfigSetCommand(r *ConfigSetCommandRunner) *cobra.Command {
	commands := []*cobra.Command{
		NewConfigSetCommand(r.utils, "service-url"),
	}

	cmd := &cobra.Command{
		Use:                   "set [option]",
		Short:                 translation.T("config-set-command-short-description"),
		Long:                  translation.T("config-set-command-long-description"),
		DisableFlagsInUseLine: true,
	}

	cmd.AddCommand(commands...)

	return cmd
}

func NewConfigSetCommand(utils Utilities, name string) *cobra.Command {
	return &cobra.Command{
		Use:                   name,
		Short:                 translation.T("config-set-subcommand-short-description", getConfigCmdNameMap(name)),
		Long:                  translation.T("config-set-subcommand-long-description", getConfigCmdNameMap(name)),
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			config := utils.GetPluginConfig()
			err := config.Set(serviceName+ "-" +name, args[0])
			utils.HandleError(err, translation.T("config-subcommand-set-error"))
			utils.Ok()
		},
	}
}

func getConfigCmdNameMap(s string) map[string]interface{} {
	return map[string]interface{}{
		"NAME": s,
	}
}
