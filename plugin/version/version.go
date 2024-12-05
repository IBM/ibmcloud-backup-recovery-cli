package version

import "github.com/IBM-Cloud/ibm-cloud-cli-sdk/plugin"

// plugin major version
const PluginMajorVersion = 1

// plugin minor version
const PluginMinorVersion = 0

// plugin build version
const PluginBuildVersion = 0

var pluginVersion = plugin.VersionType{
	Major: PluginMajorVersion,
	Minor: PluginMinorVersion,
	Build: PluginBuildVersion,
}

// get plugin version as a string
func GetPluginVersion() plugin.VersionType {
	return pluginVersion
}
