package version

import "github.com/IBM-Cloud/ibm-cloud-cli-sdk/plugin"

// plugin major version
const PluginMajorVersion = 1

// plugin minor version
const PluginMinorVersion = 2

// plugin build version
const PluginBuildVersion = 3

var pluginVersion = plugin.VersionType{
	Major: PluginMajorVersion,
	Minor: PluginMinorVersion,
	Build: PluginBuildVersion,
}

// get plugin version as a string
func GetPluginVersion() plugin.VersionType {
	return pluginVersion
}
