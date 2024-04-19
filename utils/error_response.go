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
	"fmt"

	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/bluemix/terminal"
)

// errorResponse represents the error container model from the API handbook.
// Reference: https://cloud.ibm.com/docs/api-handbook?topic=api-handbook-errors
type errorResponse struct {
	Errors     []errorContainer `json:"errors"`
	Trace      string           `json:"trace,omitempty"`
	StatusCode int              `json:"status_code,omitempty"`
}

type errorContainer struct {
	Code     string       `json:"code,omitempty"`
	Message  string       `json:"message,omitempty"`
	MoreInfo string       `json:"more_info,omitempty"`
	Target   *errorTarget `json:"target,omitempty"`
}

// IsEmpty returns true if the struct doesn't contain any populated error
// containers. In this case, it's better not to use this struct and to
// proceed with the raw error reponse.
func (er errorResponse) IsEmpty() bool {
	return len(er.Errors) == 0 || errorsAreEmpty(er.Errors)
}

// MarshalJSON returns the JSON representation of the `errorResponse` structure.
// We override the default behavior to replace the `Errors` slice with a string
// value, which will be a sub-table created from the actual errors.
func (er errorResponse) MarshalJSON() ([]byte, error) {
	// Calculate the terminal width for the sub-table, to make long lines truncated correctly.
	// "terminal width" - "length of the longest header" - "column spacing"
	terminalWidth := GetTerminalWidth() - 10 - 3

	// Create a map of interfaces from the structure.
	result := make(map[string]any)
	result["StatusCode"] = er.StatusCode
	if er.Trace != "" {
		result["Trace"] = er.Trace
	}

	// A buffer where the tables will be written - instead of stderr.
	var tableOutput bytes.Buffer

	// Create a transposed sub-table from each error in the `Errors` field.
	// To do that, we unmarshal the error to an empty interface because
	// that's what the `FormatTableData` expects. If any errors occur
	// during this process, we use the original logic as a fallback.
	for _, error := range er.Errors {
		var errorMap any
		tmp, err := json.Marshal(error)
		if err != nil {
			return json.Marshal(er)
		}
		err = json.Unmarshal(tmp, &errorMap)
		if err != nil {
			return json.Marshal(er)
		}

		tableData := FormatTableData(errorMap, EmptyString)
		table, _ := CreateTable(tableData, &tableOutput, terminalWidth)
		table.Print()
	}

	// Add the sub-table to the result after removing all colors from it.
	result["Errors"] = terminal.Decolorize(tableOutput.String())

	return json.Marshal(result)
}

// errorTarget represents the error target model from the API handbook.
type errorTarget struct {
	Type string `json:"type,omitempty"`
	Name string `json:"name,omitempty"`
}

// MarshalJSON returns the JSON representation of the `errorTarget` structure.
// We override the default behavior to get a simplified value
// which is only a single formatted string.
func (et errorTarget) MarshalJSON() ([]byte, error) {
	// Use a dash to show the value is missing instead if skipping it,
	// to have a more consistent result. Note that, this should rarely happen.
	if et.Type == "" {
		et.Type = "-"
	}
	if et.Name == "" {
		et.Name = "-"
	}

	return []byte(fmt.Sprintf(`"Type: %s; Name: %s"`, et.Type, et.Name)), nil
}

// errorsAreEmpty is a utility function that checks the stored error
// containers to make sure none of them are empty (have no information
// stored). If any empty structs were created from a response, it may
// cause a panic in the marshalling logic.
func errorsAreEmpty(errs []errorContainer) (result bool) {
	for _, err := range errs {
		if err == (errorContainer{}) {
			result = true
			break
		}
	}
	return
}
