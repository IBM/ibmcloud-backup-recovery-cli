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
	"reflect"
	"strconv"
	"strings"
	"unsafe"

	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/bluemix/terminal"
	JmesPath "github.com/jmespath/go-jmespath"
)

// If there was a jmespath query against the data, this function will
// extract the final segment as it may need to be used as a column header.
// If no query was given, use a default of "values".
func GetLastQuerySegment(query string) string {
	if query == "" {
		return "values"
	}

	queryArr := strings.Split(query, ".")
	return queryArr[len(queryArr)-1]
}

// Return the dereferenced value if a pointer or interface,
// hand the value back if not.
func DerefValue(thing reflect.Value) reflect.Value {
	if thing.Kind() == reflect.Interface {
		// interface elements can be pointers
		return DerefValue(thing.Elem())
	} else if thing.Kind() == reflect.Ptr {
		return thing.Elem()
	} else {
		return thing
	}
}

// Takes the final value that is to be written to the table
// and formats it as a string if possible.
func GetStringValue(thing reflect.Value) string {
	result, _ := GetStringValueExploded(thing, 0)
	return result
}

// GetStringValueExploded returns the string representation of the given object,
// along with a callback function.
// If levelsToExplode is more than 0, all nested object (like maps and slice of maps)
// will be exploded until the speficied level is reached.
// The returned callback function (render) can be used to re-calculate the string representation
// of the given value based on the provided terminal width.
// Note that the callback function is optional, so make sure it's checked before calling!
func GetStringValueExploded(thing reflect.Value, levelsToExplode int) (result string, render func(terminalWidth int) string) {
	result = "-"

	// Make sure the thing is not a pointer.
	thing = DerefValue(thing)

	// don't bother with invalid values
	if !thing.IsValid() {
		return
	}

	actualValue := thing.Interface()
	switch thing.Kind() {
	case reflect.String:
		result = thing.String()

	case reflect.Bool:
		result = strconv.FormatBool(actualValue.(bool))

	case reflect.Int64:
		result = strconv.FormatInt(actualValue.(int64), 10)

	case reflect.Float32:
		// FormatFloat must take a float64 as its first value, so typecast is needed
		result = strconv.FormatFloat(float64(actualValue.(float32)), 'g', -1, 32)

	case reflect.Float64:
		result = strconv.FormatFloat(actualValue.(float64), 'g', -1, 64)

	case reflect.Map:
		if len(thing.MapKeys()) == 0 {
			break
		} else if levelsToExplode > 0 {
			// Reduce the levels to be exploded by 1.
			tableData := getTableForMap(thing, levelsToExplode-1)

			render = func(terminalWidth int) string {
				var tableOutput bytes.Buffer
				table, _ := CreateTable(tableData, &tableOutput, terminalWidth)
				if table != nil {
					table.Print()
					return terminal.Decolorize(tableOutput.String())
				}
				return ""
			}

			// Call the function immediately to return a default value.
			result = render(0)
		} else {
			tableData := getTableForMap(thing, levelsToExplode-1)
			render = func(terminalWidth int) string {
				var tableOutput bytes.Buffer
				table, _ := CreateTable(tableData, &tableOutput, terminalWidth)
				if table != nil {
					table.Print()
					return terminal.Decolorize(tableOutput.String())
				}
				return ""
			}

			// Call the function immediately to return a default value.
			result = render(0)
		}

	case reflect.Slice:
		// print something if an array was returned but is hidden
		// to indicate that there is data there
		if thing.Len() > 0 {
			// Get each element for the result list.
			elems := []string{}
			// Create a slice for the callback functions.
			callbacks := []func(int) string{}
			for i := 0; i < thing.Len(); i++ {
				// We don't change the levels here, because nothing has been exploded.
				value, render := GetStringValueExploded(thing.Index(i), levelsToExplode)
				elems = append(elems, value)
				callbacks = append(callbacks, render)
			}

			// Concatenate the elements for the final value.
			elemType := DerefValue(thing.Index(0)).Kind()
			if elemType == reflect.Map {
				render = func(terminalWidth int) string {
					var results []string
					for i, cb := range callbacks {
						var result string
						if cb != nil {
							result = cb(terminalWidth)
						} else {
							// Fallback to to the original result.
							result = elems[i]
						}
						results = append(results, result)
					}

					return strings.Join(results, "")
				}

				// Call the function immediately to return a default value.
				result = render(0)
			} else {
				result = "[" + strings.Join(elems, ", ") + "]"
			}
		} else {
			result = "-"
		}

	default:
		// fmt.Println("Type not yet supported: " + thing.Kind().String())
		result = "-"
	}

	return
}

// for an array value, get the "Kind" of its individual elements
func GetArrayElementType(value reflect.Value) reflect.Kind {
	arrayElementType := value.Type().Elem().Kind()

	if arrayElementType == reflect.Interface {
		// base the underlying types on the first value
		firstInterface := DerefValue(value.Index(0))
		arrayElementType = firstInterface.Kind()
	}

	return arrayElementType
}

// IsArrayType returns true if the given `reflect.Kind` is
// a Slice or Array. Returns false otherwise.
func IsArrayType(kind reflect.Kind) bool {
	return kind == reflect.Slice || kind == reflect.Array
}

// validates the data to ensure a table can be printed
// returns false if the table doesn't have sufficient data
func IsValidTableData(data *TableData) bool {
	return data != nil && len(data.Headers) > 0
}

// GetHeadersFromJMES is a recursive function which operates on the parsed
// JMESPath object. It extracts the keys from the multi select hashes.
// Always the last occurrence will be used, which is the intended
// behaviour since that's the final selection for the columns.
// It relies heavily on the reflection package, because the details are
// hidden (unexported) in the package and there is no other way to get them.
func GetHeadersFromJMES(value interface{}, inMultiSelectHash bool) []string {
	// Since this function contains a few lines of "unsafe" code,
	// we need to make sure the process will recover if
	// a panic happens somewhere, to not stop the execution.
	defer func() { _ = recover() }()

	headers := []string{}
	currentNodes := []JmesPath.ASTNode{}

	// Gather the nodes that need to be processed.
	if node, ok := value.(JmesPath.ASTNode); ok {
		// Single node.
		currentNodes = append(currentNodes, node)
	} else if nodes, ok := value.([]JmesPath.ASTNode); ok {
		// List of nodes, coming from a `children` field.
		currentNodes = nodes
	}

	for _, _node := range currentNodes {
		node := _node // Avoid addressing the loop variable. (CWE-118)

		// NodeType is a custom integer based type. The values are assigned by using `iota`.
		// More info: https://github.com/jmespath/go-jmespath/blob/master/parser.go
		nodetype := reflect.ValueOf(&node).Elem().FieldByName("nodeType").Int()

		switch nodetype {
		// MultiSelectHash
		case 13:
			// Indicate that, this node is MultiSelectHash, because that means we want to
			// collect the values from its KeyValPair children.
			inMultiSelectHash = true
		// KeyValPair
		case 11:
			// Append the value of this node if it's inside a MultiSelectHash.
			if inMultiSelectHash {
				value := reflect.ValueOf(&node).Elem().FieldByName("value").Elem().String()
				headers = append(headers, value)
			}
			continue
		}

		// To access the unexported `children` field we have to do some reflection magic.
		// Get the current value of the node.
		currentNode := reflect.ValueOf(node)
		// Create a new node with the type of the current.
		newNode := reflect.New(currentNode.Type()).Elem()
		// Copy the current node's value to the new one.
		newNode.Set(currentNode)
		// Get the reference to the `children` field.
		childrenField := newNode.FieldByName("children")
		// Create a new interface that point to the memory address of the `children` field.
		children := reflect.NewAt(childrenField.Type(), unsafe.Pointer(childrenField.UnsafeAddr())).Elem().Interface() // #nosec G115
		// Process the children slice recursively.
		innerHeaders := GetHeadersFromJMES(children, inMultiSelectHash)
		if len(innerHeaders) != 0 {
			headers = innerHeaders
		}
	}

	return headers
}
