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

package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/bluemix/configuration/core_config"
	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/bluemix/terminal"
	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/plugin"
	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/ghodss/yaml"
	JmesPath "github.com/jmespath/go-jmespath"
	"github.com/spf13/pflag"
	translation "ibmcloud-backup-recovery-cli/i18n"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const (
	EmptyString     = ""
	MaxExplodeLevel = 2
)

type CustomPrinterFunc func(interface{}) bool

type Utils struct {
	ui                       terminal.UI
	OutputFormat             string
	JMESQuery                string
	jmesQueries              JMESQueries
	serviceSpecificErrorMsgs map[string]string
	// provide plugin points for users to customize output printing
	customOutputPrinter        CustomPrinterFunc
	customJsonPrinter          CustomPrinterFunc
	customErrorResponseHandler func(interface{})
}

type Operation int

const (
	OPRead Operation = iota + 1 // Start from 1, so 0 is invalid.
	OPList
	OPCreate
	OPUpdate
	OPDelete
	OPOther
)

type OperationMetadata struct {
	// Type of the operation.
	OperationType Operation

	// Used for LIST type operations.
	ListPropertyName string // The name of the property in the result that we will be exploded.

	// Pagination metadata
	NextPageProp   string // The property that contains the query parameter.
	QueryParam     string // The exact name of the query parameter that will be used to get the next page.
	UseHref        bool   // Whether we need to get the parameter from a Href value or not.
	InResponseBody bool   // Whether the query parameter directly available in the response body.
	AllPages       bool   // Indicates if the operation was called with the "--all-pages" flag.
}

type JMESQueries struct {
	Success  JMESQuery
	Error    JMESQuery
	AllPages JMESQuery
}

type JMESQuery struct {
	Default string
	Table   string
}

var (
	// The context of the current plug-in.
	context plugin.PluginContext

	// The string value of the currently running command.
	currentCommand     string
	currentCommandFull []string

	// The metadata of the operation, related of the current command.
	operationMetadata OperationMetadata

	// The order of the headers in the table.
	TableHeaderOrder []string

	// The function that is called when an error happens and the plugin should exit.
	ExitFunction = func() { os.Exit(1) }
)

func NewUtils(ui terminal.UI) *Utils {
	return &Utils{ui: ui}
}

func (u *Utils) SetTableHeaderOrder(order []string) {
	TableHeaderOrder = order
}

func (u *Utils) SetOperationMetadata(data interface{}) error {
	if opMetadata, ok := data.(OperationMetadata); ok {
		operationMetadata = opMetadata
		return nil
	}

	actualType := reflect.TypeOf(data).String()
	err := errors.New(translation.T("operation-metadata-assertion-error", map[string]interface{}{"TYPE": actualType}))
	return err
}

func (u *Utils) SetJMESQueries(queries interface{}) error {
	if q, ok := queries.(JMESQueries); ok {
		u.jmesQueries = q
		return nil
	}

	actualType := reflect.TypeOf(queries).String()
	err := errors.New(translation.T("jmespath-queries-assertion-error", map[string]interface{}{"TYPE": actualType}))
	return err
}

func (u *Utils) GetServiceURL(GetServiceURLForRegion func(string) (string, error)) string {
	// if GetServiceURLForRegion returns an error, it doesn't matter. just use the empty string
	// it returns and continue - the SDK will use the default URL
	region := u.GetRegionFromContext()
	serviceUrl, _ := GetServiceURLForRegion(region)
	if serviceUrl == "" {
		// check for private endpoint
		serviceUrl, _ = GetServiceURLForRegion("private." + region)
	}

	return serviceUrl
}

func checkForBadURL(err error, additionalMessage string) error {
	message := err.Error()
	isBadURLError := strings.Contains(message, "no such host")
	if isBadURLError {
		err = errors.New(message + "\n\n" + additionalMessage)
	}

	return err
}

func (u *Utils) HandleErrorResponse(errorBody interface{}) {
	if u.customErrorResponseHandler != nil {
		u.customErrorResponseHandler(errorBody)
		return
	}

	u.HandleErrorResponseImpl(errorBody)
}

func (u *Utils) HandleErrorResponseImpl(errorBody interface{}) {
	// Error messages must be returned in table format.
	u.SetOutputFormat("table")

	u.setErrorJMESQuery()

	// Try to parse the error body to have a better result printed to the user.
	// If it fails, we fall back to the original behavior.
	var error errorResponse

	// First, we need to convert our `interface{}` to a JSON.
	tmp, marshalErr := json.Marshal(errorBody)

	// Create a new decoder to validate the JSON object has the fields we expect
	// for the errorResponse type - a standard unmarshal ignores unknown fields.
	decoder := json.NewDecoder(bytes.NewReader(tmp))
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&error)

	if err == nil && marshalErr == nil && !error.IsEmpty() {
		u.PrintOutput(error, terminal.ErrOutput)
	} else {
		u.PrintOutput(errorBody, terminal.ErrOutput)
	}

	u.NonZeroExit()
}

func (u *Utils) CheckResponseForError(response *core.DetailedResponse, err error) (bool, interface{}) {
	// get json body of the response to print - may be success or error body
	successBody, errorBody, errorGettingResult := u.GetResult(response, err)

	if errorGettingResult != nil {
		errorGettingResult = checkForBadURL(errorGettingResult, u.serviceSpecificErrorMsgs["badURL"])
		extraText := translation.T("no-service-response-error")

		// It may be that the service returned an error response without any content. Make that
		// scenario clear to the user, as opposed to the scenario where we don't get a response.
		if isErrorResponse(response) {
			extraText = translation.T("empty-error-response-message")
		}
		u.HandleError(errorGettingResult, extraText)
	}

	// Error body is either an error response body, or a success response body that the
	// SDK couldn't process e.g. due to a deserialization error.
	if errorBody != nil {
		// We have an error response, clear out any operation metadata.
		operationMetadata = OperationMetadata{}
		u.HandleErrorResponse(errorBody)
		return false, nil
	}

	return true, successBody
}

func (u *Utils) ProcessResponse(response *core.DetailedResponse, err error) {
	if ok, result := u.CheckResponseForError(response, err); ok {
		if u.JMESQuery == "" {
			u.setSuccessJMESQuery()
		}
		u.PrintOutput(result, terminal.Output)
	} else {
		u.NonZeroExit()
	}
}

func (u *Utils) ProcessBinaryResponse(response *core.DetailedResponse, err error, outputFilename string) {
	if ok, result := u.CheckResponseForError(response, err); ok {
		// write the binary data to the file
		err := u.WriteFile(result, outputFilename)
		u.HandleError(err, translation.T("file-response-error", map[string]interface{}{
			"FILENAME": outputFilename,
		}))

		u.Ok()
		if u.OutputIsNotMachineReadable() {
			// this is silenced in quiet mode
			u.Verbose(translation.T("output-file-confirmation", map[string]interface{}{
				"FILENAME": outputFilename,
			}))
		} else {
			u.PrintOutput(EmptyString, terminal.Output)
		}
	} else {
		u.NonZeroExit()
	}
}

func (u *Utils) ProcessEmptyResponse(response *core.DetailedResponse, err error) {
	if ok, _ := u.CheckResponseForError(response, err); ok {
		u.Ok()
		if !u.OutputIsNotMachineReadable() {
			u.PrintOutput(EmptyString, terminal.Output)
		}
	} else {
		u.NonZeroExit()
	}
}

func (u *Utils) PrintOutput(result interface{}, tableWriter io.Writer) {
	if u.customOutputPrinter != nil {
		if ok := u.customOutputPrinter(result); ok {
			return
		}
	}

	u.PrintOutputImpl(result, tableWriter)
}

func (u *Utils) PrintOutputImpl(result interface{}, tableWriter io.Writer) {
	// this eliminates any knowledge of structs, leaving the result to match the json
	// structure and key names the user expects
	result = u.MakeResultGeneric(result)

	// Save the original result for later. We will need it to
	// determine the pagination data and create the next page command.
	originalResult := result

	// the jmes query applies to everything, so do it first
	if u.JMESQuery != EmptyString {
		result = u.applyJMESQuery(result, u.JMESQuery)
	}

	// print something based on the output format
	switch strings.ToLower(u.OutputFormat) {
	case "yaml":
		yamlified, yErr := yaml.Marshal(result)
		u.HandleError(yErr, translation.T("yaml-conversion-error"))

		u.Print(string(yamlified))

	case "json":
		u.PrintJSON(result)

	case "tui":
		if err := startTUI(result); err != nil {
			u.HandleError(err, translation.T("tui-app-error"))
		}

	default:
		u.printTable(result, originalResult, tableWriter)
	}
}

// setErrorJMESQuery sets the appropriate "default" JMESPath query for
// an error (response) scenario in the currently running command.
func (u *Utils) setErrorJMESQuery() {
	isTable := u.OutputIsNotMachineReadable()

	u.SetJMESQuery(u.jmesQueries.Error.Default)
	if u.jmesQueries.Error.Table != "" && isTable {
		u.SetJMESQuery(u.jmesQueries.Error.Table)
	}
}

// setSuccessJMESQuery sets the appropriate "default" JMESPath query for
// a success (non-error response) scenario in the currently running command.
func (u *Utils) setSuccessJMESQuery() {
	isTable := u.OutputIsNotMachineReadable()
	isAllPages := operationMetadata.AllPages

	u.SetJMESQuery(u.jmesQueries.Success.Default)
	if u.jmesQueries.Success.Table != "" && isTable {
		u.SetJMESQuery(u.jmesQueries.Success.Table)
	}
	if u.jmesQueries.AllPages.Default != "" && isAllPages {
		u.SetJMESQuery(u.jmesQueries.AllPages.Default)
	}
	if u.jmesQueries.AllPages.Table != "" && isAllPages && isTable {
		u.SetJMESQuery(u.jmesQueries.AllPages.Table)
	}
}

func (u *Utils) applyJMESQuery(data interface{}, query string) interface{} {
	jmes, err := JmesPath.Compile(query)
	u.HandleError(err, translation.T("jmespath-compile-error", map[string]interface{}{"QUERY": query}))

	result, err := jmes.Search(data)
	u.HandleError(err, translation.T("jmespath-application-error"))

	return result
}

func (u *Utils) printTable(result, originalResult interface{}, tableWriter io.Writer) {
	if u.JMESQuery == "" && operationMetadata.OperationType == OPList && operationMetadata.ListPropertyName != "" {
		result = u.applyJMESQuery(result, operationMetadata.ListPropertyName)
	}

	tableData := FormatTableData(result, u.JMESQuery)
	table, truncated := CreateTable(tableData, tableWriter, 0)
	if table == nil {
		u.Print(translation.T("no-data-for-table"))
	} else {
		table.Print()

		if truncated > 0 {
			u.notifyHiddenData(truncated, result)
		}
	}

	// Get the query parameter for the next page.
	var next string
	if operationMetadata.OperationType == OPList && operationMetadata.NextPageProp != "" {
		// Only look for the param when the operation is LIST and the next page property is defined.
		nextPageQuery := operationMetadata.NextPageProp

		if operationMetadata.InResponseBody {
			// Check the parameter in the response body.
			nextPageQuery += "." + operationMetadata.QueryParam
			if nextPageString, ok := u.applyJMESQuery(originalResult, nextPageQuery).(string); ok {
				next = nextPageString
			}
		} else {
			// Try to retrieve the parameter from the URL of the next page.
			if operationMetadata.UseHref {
				nextPageQuery += ".href"
			}

			if nextPageString, ok := u.applyJMESQuery(originalResult, nextPageQuery).(string); ok {
				nextPage, err := core.GetQueryParam(&nextPageString, operationMetadata.QueryParam)
				u.HandleError(err, translation.T("error-getting-query-param"))
				if nextPage != nil {
					next = *nextPage
				}
			}
		}
	}

	if next == "" {
		// No parameter, no next page.
		return
	}

	// Now construct the command for fetching the next page.
	var updated bool
	newFlag := fmt.Sprintf("--%s %s", operationMetadata.QueryParam, next)
	// Update or add the flag that indicates the next page.
	for i := range currentCommandFull {
		if "--"+operationMetadata.QueryParam == currentCommandFull[i] {
			// We found the the flag, the next item will be the value.
			// Flags are validated against missing values, so there is no need to check the slice lenght.
			currentCommandFull[i+1] = next
			updated = true
			break
		}
	}
	if !updated {
		// If the flag wasn't found, append it to the end of the command.
		currentCommandFull = append(currentCommandFull, newFlag)
	}

	// Namespaces are not included by default, due to the behaviour of the core CLI package
	// so we need to get the from the context (if set) and add it before the other args.
	if context.CommandNamespace() != "" {
		currentCommandFull = append(strings.Fields(context.CommandNamespace()), currentCommandFull...)
	}

	u.Verbose("\n" + translation.T("next-page-command-message", map[string]interface{}{"ARGS": strings.Join(currentCommandFull, " ")}))
}

func (u *Utils) notifyHiddenData(truncated int, result interface{}) {
	// Add a new line to the stdout between the table and the info messages.
	u.Verbose("")

	if truncated > 0 {
		u.Verbose(translation.T("truncated-table", map[string]interface{}{"TRUNCATED_COLUMNS": truncated}))
	}
}

func (u *Utils) PrintJSON(result interface{}) {
	if u.customJsonPrinter != nil {
		if ok := u.customJsonPrinter(result); ok {
			return
		}
	}

	u.PrintJSONImpl(result)
}

func (u *Utils) PrintJSONImpl(result interface{}) {
	// this will print raw json
	b, _ := json.MarshalIndent(result, EmptyString, "  ")
	u.Print(string(b))
}

func (u *Utils) HandleError(err error, message string) {
	if err != nil {
		// if we get here, the output will not be machine readble
		// so its okay to print "Failed"
		if message == "" {
			u.ui.Failed(err.Error())
		} else {
			u.ui.Failed(message + ":\n" + err.Error())
		}
		u.NonZeroExit()
	}
}

func (u *Utils) ConfirmRunningCommand() {
	if u.OutputIsNotMachineReadable() {
		// this will be silenced in "quiet" mode
		// otherwise, it prints independently of log level
		u.Verbose("...")
	}
}

func (u *Utils) Ok() {
	if u.OutputIsNotMachineReadable() {
		u.ui.Ok()
	}
}

func (u *Utils) Verbose(message string) {
	// Wrapper around the `Verbose` method in the `ui` package,
	// which sends messages to stdout and will be suppressed in
	// quiet mode.
	u.ui.Verbose(message)
}

func (u *Utils) Print(message string) {
	// Wrapper around the `Print` method in the `ui` package,
	// which sends messages to stdout and can't be suppressed.
	u.ui.Print(message)
}

func (u *Utils) Warn(message string) {
	// wrapper around the Warn message in the ui package,
	// which sends messages to stderr instead of stdout
	u.ui.Warn(message)
}

func (u *Utils) Prompt(message string, options *terminal.PromptOptions) *terminal.Prompt {
	return u.ui.Prompt(message, options)
}

func (u *Utils) WriteFile(fileInterface interface{}, filename string) error {
	// open a new file
	outFile, outFileErr := os.Create(filepath.Clean(filename))
	if outFileErr != nil {
		return outFileErr
	}
	defer func() {
		if err := outFile.Close(); err != nil {
			u.HandleError(
				err,
				translation.T("file-closing-error", map[string]interface{}{
					"FILENAME": filename,
				}),
			)
		}
	}()

	file, ok := fileInterface.(io.ReadCloser)
	if !ok {
		return errors.New(translation.T("file-conversion-error"))
	}

	_, FileWriteErr := io.Copy(outFile, file)
	return FileWriteErr
}

func (u *Utils) MakeResultGeneric(result interface{}) interface{} {
	bytes, err := json.Marshal(result)
	u.HandleError(err, translation.T("json-conversion-error"))

	var data interface{}
	err = json.Unmarshal(bytes, &data)
	u.HandleError(err, translation.T("json-conversion-error"))

	return data
}

func (u *Utils) GetResult(response *core.DetailedResponse, err error) (interface{}, interface{}, error) {
	// based on the current code in the go sdk core, this situation is impossible.
	// adding this check as a failsafe should external behavior ever change in the future
	if response == nil && err == nil {
		return nil, nil, errors.New(translation.T("no-service-response-error"))
	}

	// this means there was an error response or an error in the go sdk
	if err != nil {
		if response != nil {
			// If the response is a success response, the error must be coming from the SDK.
			// Make that clear with a prefix added to the error message.
			if !isErrorResponse(response) {
				err = u.CreateErrorWithMessage(err, translation.T("response-processing-error"))
			}
			// If the result is present, we want to print it for the user in a later step.
			// In the two cases below, we also want the user to see "failed" and the error message
			if response.GetResult() != nil {
				u.ui.Failed(err.Error())
				return nil, response.GetResult(), nil
			} else if response.GetRawResult() != nil {
				u.ui.Failed(err.Error())
				// convert the raw result to a string and return as an error
				return nil, string(response.GetRawResult()), nil
			}
		}

		// if the response is nil, or if both the result and raw result are nil,
		// return the error
		return nil, nil, err
	}

	// this means there was a success response
	return response.GetResult(), nil, nil
}

// Exit the program with a non-zero exit code.
// This should only be called in an error situation.
func (u *Utils) NonZeroExit() {
	ExitFunction()
}

func (u *Utils) OutputIsNotMachineReadable() bool {
	return strings.ToLower(u.OutputFormat) != "json" && strings.ToLower(u.OutputFormat) != "yaml"
}

// The following methods allow access to the properties from
// instances of the Utilities *interface* that this
// struct satisfies

func (u *Utils) ExposeOutputFormatVar() *string {
	return &u.OutputFormat
}

func (u *Utils) ExposeJMESQueryVar() *string {
	return &u.JMESQuery
}

func (u *Utils) SetOutputFormat(value string) {
	u.OutputFormat = value
}

func (u *Utils) SetJMESQuery(value string) {
	u.JMESQuery = value
}

func (u *Utils) GetOutputFormat() string {
	return u.OutputFormat
}

func (u *Utils) GetJMESQuery() string {
	return u.JMESQuery
}

func (u *Utils) SetServiceErrorMessages(msgs map[string]string) {
	u.serviceSpecificErrorMsgs = msgs
}

// store the name of the currently executed command
// to enable context-aware logic in the utilities
func (u *Utils) SetCommandName(args []string) {
	// Save the full command with every single arguments and options.
	currentCommandFull = args

	// the first arg should always be the command name
	// but make sure the array isnt empty
	if len(args) > 0 {
		currentCommand = args[0]
	}
}

func (u *Utils) GetCommandName() string {
	return currentCommand
}

func (u *Utils) SetContext(c plugin.PluginContext) {
	context = c
}

func (u *Utils) GetPluginConfig() plugin.PluginConfig {
	return context.PluginConfig()
}

func (u *Utils) GetAuthenticator(serviceName string) (core.Authenticator, error) {
	authenticator, err := core.GetAuthenticatorFromEnvironment(serviceName)
	if authenticator != nil && err == nil {
		return authenticator, err
	}

	if token := getActiveIAMToken(); token != "" {
		authenticator, err = core.NewBearerTokenAuthenticator(token)
		return authenticator, err
	}

	if err == nil {
		// if there are no credentials in the environment at all,
		// there wont be an error, just a nil authenticator,
		// but we dont want the code to progress - we want to trigger
		// the error message that addresses credentials
		err = errors.New(translation.T("no-credentials"))
	}

	return nil, err
}

func (u *Utils) GetRegionFromContext() string {
	return context.CurrentRegion().Name // e.g. us-south
}

func (u *Utils) IsPrivateEndpointEnabled() bool {
	return context.IsPrivateEndpointEnabled()
}

func (u *Utils) PostProcessServiceConfiguration(service *core.BaseService, serviceName string) error {
	externalVars, err := core.GetServiceProperties(serviceName)
	if err != nil {
		return err
	}

	// if the url is set in the environment, it would have been overwritten by the
	// programatically-set URL from the plug-in context. however, the external
	// variables should take priority so we need to check for it again here
	if url, ok := externalVars[core.PROPNAME_SVC_URL]; ok && url != "" {
		err = service.SetServiceURL(url)
		if err != nil {
			return err
		}
	}

	// if disableSSL is set in the environment, everything will be how it should be already
	// if it is NOT set in the environment, we should check to see if SSL verification is
	// disabled in the plug-in context and handle that information as needed
	if _, set := externalVars[core.PROPNAME_SVC_DISABLE_SSL]; !set {
		// check disable ssl verification - this is currently the only service level parameter
		// supported in the plug-in context
		if context.IsSSLDisabled() {
			service.DisableSSLVerification()
			// propagate this to request-based authenticators
			authType := service.Options.Authenticator.AuthenticationType()
			if authType == core.AUTHTYPE_IAM {
				authenticator := service.Options.Authenticator.(*core.IamAuthenticator)
				authenticator.DisableSSLVerification = true
			} else if authType == core.AUTHTYPE_CP4D {
				authenticator := service.Options.Authenticator.(*core.CloudPakForDataAuthenticator)
				authenticator.DisableSSLVerification = true
			}
		}
	}

	return nil
}

func getActiveIAMToken() string {
	// no point in looking for a token if the user isn't logged in
	if !context.IsLoggedIn() {
		return ""
	}

	// read current token
	token := sanitizeToken(context.IAMToken())
	// the token should never be empty while logged in,
	// but check for that just in case
	if token == "" {
		return token
	}

	// check if token is still active
	tokenInfo := core_config.NewIAMTokenInfo(token)
	expireTime := tokenInfo.Expiry.Unix()
	thirtySeconds := int64(30)
	// if token is nearing expiration, refresh it
	// allow a 30 second buffer to ensure the token does
	// not expire while the rest of the code is executing
	if core.GetCurrentTime() > (expireTime - thirtySeconds) {
		newToken, err := context.RefreshIAMToken()
		if err != nil {
			return ""
		}

		token = sanitizeToken(newToken)
	}

	return token
}

func sanitizeToken(token string) string {
	return strings.TrimPrefix(token, "Bearer ")
}

func (u *Utils) InitializeLogger(quiet bool) {
	if quiet {
		u.ui.SetQuiet(true)
		// the CLI SDK still logs errors in quiet mode, so match that behavior for now
		core.SetLoggingLevel(core.LevelError)
	}

	// in the ibm-cloud-cli-sdk package, the quiet flag has no bearing
	// on trace logs. this is handled the same way here, for consistency
	trace := context.Trace()
	var logDestination io.Writer

	switch strings.ToLower(trace) {
	case "", "false":
		// do nothing
	case "true":
		logDestination = terminal.ErrOutput
	default:
		// assume it's a file and try to use it
		file, err := os.OpenFile(filepath.Clean(trace), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
		if err != nil {
			u.Warn(translation.T("log-file-creation-error", map[string]interface{}{
				"PATH":  trace,
				"ERROR": err.Error(),
			}))

			// if the file cannot be opened, still log the trace output to stderr.
			// this matches the behavior in the ibm-cloud-cli-sdk package
			logDestination = terminal.ErrOutput
		} else {
			logDestination = file
		}
	}

	// the trace logger exposed by the ibm-cloud-cli-sdk package creates a problem -
	// it requires that the "Client" field in the base service be overridden. this would
	// prevent any retries or disabling of ssl verification. to maintain those features,
	// the logger in the go core will be used instead of the trace logger. it outputs nearly
	// identical information
	if logDestination != nil {
		goLogger := log.New(logDestination, "", log.LstdFlags)
		core.SetLogger(core.NewLogger(core.LevelDebug, goLogger, goLogger))
	}
}

func (u *Utils) ConfirmDelete(force bool) bool {
	if force {
		return true
	}

	var confirmed bool

	// require a value from the user
	options := &terminal.PromptOptions{
		Required: true,
	}

	err := u.Prompt(translation.T("confirm-delete"), options).Resolve(&confirmed)
	u.HandleError(err, translation.T("confirmation-error"))

	return confirmed
}

func (u *Utils) ValidateRequiredFlags(required []string, flags *pflag.FlagSet, serviceName string) error {
	config := u.GetPluginConfig()
	missingFlags := make([]string, 0)
	for _, flagName := range required {
		if !flags.Changed(flagName) && !config.Exists(serviceName+"-"+flagName) {
			missingFlags = append(missingFlags, `"`+flagName+`"`)
		}
	}

	if len(missingFlags) > 0 {
		return errors.New(translation.T("missing-required-flags-error", map[string]interface{}{
			"FLAGS": strings.Join(missingFlags, ", "),
		}))
	}

	return nil
}

// Creates a new error with a descriptive message placed before the original
// error message. This is primarily used for interactive mode.
func (u *Utils) CreateErrorWithMessage(err error, msg string) error {
	if err != nil {
		err = errors.New(msg + ":\n" + err.Error())
	}

	return err
}

// ValidateJSON checks the input JSON string for extraneous fields that are
// not defined on the model.
func (u *Utils) ValidateJSON(input, JSONValidator string) ([]string, error) {
	asBytes, err, errMsg := GetJsonStringAsBytes(input)
	u.HandleError(err, errMsg)

	var rawInput interface{}
	if err = json.Unmarshal(asBytes, &rawInput); err != nil {
		return nil, err
	}

	var validator struct {
		Schemas map[string][]string `json:"schemas"`
		Fields  []string            `json:"fields"`
	}

	if err = json.Unmarshal([]byte(JSONValidator), &validator); err != nil {
		return nil, err
	}

	validationResult := []string{}
	validateJSON(rawInput, validator.Fields, validator.Schemas, "#", &validationResult)

	return validationResult, nil
}

func validateJSON(rawInput interface{}, fields []string, schemas map[string][]string, currentPath string, result *[]string) {
	if inputSlice, ok := rawInput.([]interface{}); ok {
		// If the current input object is a slice we simply
		// iterate over the elements and check them one by one.
		// (All elements should have the same type.)
		for i, input := range inputSlice {
			validateJSON(input, fields, schemas, fmt.Sprintf("%s.[%d]", currentPath, i), result)
		}
	} else if inputMap, ok := rawInput.(map[string]interface{}); ok {
		// If it's a map we do 2 things:
		// 1. Iterate over the keys and check whether it is allowed or not
		// 2. Go over the inner values recursively (slices, maps)
		for flagName, flagValue := range inputMap {
			var found, hasAdditionalProperties bool

			// Try to find the current field name inside the allowed fields.
			for _, validatorField := range fields {
				// If the fields contains a reference, get both
				// the field name and the referenced model.
				var referencedSchema string
				if strings.Contains(validatorField, "#") {
					fieldParts := strings.Split(validatorField, "#")
					validatorField = fieldParts[0]
					referencedSchema = fieldParts[1]
				}
				if validatorField == flagName {
					found = true

					// Try to validate the inner values if there is a referenced schema for this field.
					if referencedSchema != "" {
						validateJSON(flagValue, schemas[referencedSchema], schemas, fmt.Sprintf("%s.%s", currentPath, flagName), result)
					} else {
						break
					}
				} else if validatorField == "" && referencedSchema == "hasAdditionalProperties" {
					hasAdditionalProperties = true
				}
			}

			if !found && !hasAdditionalProperties {
				*result = append(*result, fmt.Sprintf("%s.%s", currentPath, flagName))
			}
		}
	}
}

// Static utility functions

func ReadAsFile(userInput string) bool {
	return strings.HasPrefix(userInput, "@")
}

func GetJsonStringAsBytes(data string) (stringAsBytes []byte, err error, msg string) {
	if ReadAsFile(data) {
		// read the json from a file
		// the [1:] removes the @ symbol from the string, used to designate a file
		fileContents, fileErr := os.ReadFile(data[1:])
		if fileErr != nil {
			err = fileErr
			msg = translation.T("file-reading-error", map[string]interface{}{
				"FILENAME": data[1:],
			})
			return
		}
		stringAsBytes = fileContents
	} else {
		stringAsBytes = []byte(data)
	}

	// Check if the data is already a valid JSON.
	// If it is, just return the unmodified data.
	if jsonErr := json.Unmarshal(stringAsBytes, new(interface{})); jsonErr == nil {
		return
	}

	// Next, try to parse the data as YAML. If there is an error, return the original
	// data, otherwise continue processing.
	var yamlData interface{}
	if yamlErr := yaml.Unmarshal(stringAsBytes, &yamlData); yamlErr != nil {
		return
	}

	// Primitive values are valid YAML documents, but unmarshaling and marshaling them
	// changes the original data, for example it surrounds strings with quotes.
	if isPrimitive(yamlData) {
		return
	}

	// Now we can try to convert the data - assuming it's YAML - to JSON.
	if converted, yamlErr := yaml.YAMLToJSON(stringAsBytes); yamlErr == nil {
		stringAsBytes = converted
	}

	return
}

// min is just a convenient function to get the minimum value between two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max is just a convenient function to get the maximum value between two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// isPrimitive returns whether the give object is a primitive type or not.
// It treats every object primitive other than slices, arrays and map.
func isPrimitive(data interface{}) bool {
	dataType := reflect.ValueOf(data).Kind()
	if dataType == reflect.Slice || dataType == reflect.Array || dataType == reflect.Map {
		return false
	}

	return true
}

// isErrorResponse indicates if the response is an error response if it
// contains a non-2xx status code.
func isErrorResponse(response *core.DetailedResponse) bool {
	return response != nil && (response.StatusCode < 200 || response.StatusCode >= 300)
}
