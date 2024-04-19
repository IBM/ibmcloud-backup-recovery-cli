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
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/bluemix/terminal"
	"golang.org/x/term"
	JmesPath "github.com/jmespath/go-jmespath"
)

var (
	customHeaderOrder []string
	lastQuerySegment  string
)

// TableCell represents a single piece of data within a table.
type TableCell struct {
	// Value is string representation of the cell's raw Value.
	Value string
	// callback is a function that can be used to re-calculate/re-render
	// the value of the cell, based on a - probably - updated terminal width.
	// It's useful when the data is complex and its final form depends on
	// the size that the cell can take - within the table.
	callback func(terminalWidth int) string
}

// String returns the string value of the cell.
// If it's empty but a callback function is defined,
// it executes it and sets the result to the value field.
func (v *TableCell) String() string {
	if v.Value != "" {
		return v.Value
	}

	if v.callback != nil {
		v.Value = v.callback(0)
	}

	return v.Value
}

// MaxWidth calculates the maximum width of the cell
// in its final form. For example if the value has multiple
// lines, it checks each of them and return the length of
// the widest one.
func (v *TableCell) MaxWidth() int {
	var (
		maxWidth = 0
		lines    = strings.Split(v.String(), "\n")
	)

	for _, line := range lines {
		maxWidth = max(maxWidth, len(line))
	}

	return maxWidth
}

// TableData contains all the data that belong to a table.
type TableData struct {
	Headers      []TableCell
	Values       [][]TableCell
	IsTransposed bool
}

// SetRawHeaders sets a list of raw (string) headers on the table.
func (td *TableData) SetRawHeaders(values []string) {
	for _, v := range values {
		td.Headers = append(td.Headers, TableCell{Value: v})
	}
}

// SetRawValues sets a list of raw (slice of strings) values on the table.
func (td *TableData) SetRawValues(values [][]string) {
	for _, v := range values {
		var row []TableCell

		for _, cell := range v {
			row = append(row, TableCell{Value: cell})
		}

		td.Values = append(td.Values, row)
	}
}

// CreateTable creates a printable table from the given table data.
// Returns the table and an integer value that indicates the number
// of the truncated columns compared to the original result.
// If terminalWidth is more than 0, the table will be truncated based
// on that value. Otherwise the function tries to determine this value.
func CreateTable(data *TableData, tableWriter io.Writer, terminalWidth int) (terminal.Table, int) {
	var truncated int

	if !IsValidTableData(data) {
		return nil, 0
	}

	// Only try to determine the width when the output is the stdout
	// and it has not been defined by the user.
	if tableWriter == os.Stdout && terminalWidth < 1 {
		terminalWidth = GetTerminalWidth()
	}

	// If the width is zero, that means we couldn't determine the actual size
	// of the terminal screen so do not try to truncate the table.
	if terminalWidth > 0 {
		truncated = truncateTable(data, terminalWidth)
	}

	// Make the final string list of the headers.
	headers := make([]string, len(data.Headers))
	for i, h := range data.Headers {
		headers[i] = h.String()
	}
	// Create the final table object and add the rows.
	table := terminal.NewTable(tableWriter, headers)
	for _, row := range data.Values {
		rowStr := make([]string, len(row))
		for i, c := range row {
			rowStr[i] = c.String()
		}

		table.Add(rowStr...)
	}

	return table, truncated
}

// Use lazy initialization to return either the
// current or user-defined terminal width
func GetTerminalWidth() int {
	// There is no safe and easy way to cast `uintptr` to `int`
	// so let's just make this line to be ignored by gosec.
	terminalWidth, _, err := term.GetSize(int(os.Stdout.Fd())) // #nosec G115
	if err != nil {
		terminalWidth = -1
	}

	return terminalWidth
}

func FormatTableData(result interface{}, jmesQuery string) *TableData {
	var table *TableData

	// get last segment of jmes query in case it needs to be
	// used as a column header
	lastQuerySegment = GetLastQuerySegment(jmesQuery)

	if jmesQuery != "" {
		// Create a custom order of the headers, based on the provides JMESPath query.
		// Since at this point the query has already been used there is no need to check errors.
		parsed, _ := JmesPath.NewParser().Parse(jmesQuery)
		customHeaderOrder = GetHeadersFromJMES(parsed, false)
	}

	resultValue := DerefValue(reflect.ValueOf(result))

	// if nothing is passed in, there's nothing to do
	if !resultValue.IsValid() {
		return nil
	}

	kind := resultValue.Kind()

	if IsArrayType(kind) {
		// Data is in the form of an array.
		table = getTableForArray(resultValue)
	} else if resultValue.Kind() == reflect.Map {
		// Data is in the form of a map.
		// Nested objects will be exploded and rendered as sub-tables in 2 levels deep.
		table = getTableForMap(resultValue, MaxExplodeLevel)
	} else {
		// Data is almost certainly in the form of a single, primitive value.
		table = getTableForSingleValue(resultValue)
	}

	return table
}

// truncateTable modifies the **original** table data based on the given terminal width.
// If any row would exceed the terminal, the data will be truncated at the end
// and an additional column will be added to mark there is more data in the result.
// Also, if the calculated number of columns is lower than the required,
// the content will be shrunk, instead of dropping the columns.
// Returns an integer that indicates the number of the truncated columns.
func truncateTable(data *TableData, terminalWidth int) int {
	const (
		colSpacing               = 3 // From the CLI's terminal package.
		infoColName              = "More info"
		extraColLength           = colSpacing + len(infoColName)
		minVisibleContentDivisor = 5 // At least 20% of the last col have to be visible.
		minColSizeRatio          = 4 // Minium size when resizing (terminal width / this value)
		absoluteMinColWidth      = 5 // The minimum number of characters for a column if it's about to be resized (2 chars + "...")
		maxLineInCells           = 3 // The maximum number of lines in a single cell.
	)
	var (
		colCount    = len(data.Headers)
		minColCount = 3                     // The minimum number of columns to be displayed.
		colWidths   = make([]int, colCount) // The calculated width of each column in the table.

		// A nested function to update the list with the maximum column widths.
		updateColWidths = func(row []TableCell, widths []int) {
			for i, cell := range row {
				cellWidth := len(cell.String())
				if widths[i] < cellWidth {
					widths[i] = cellWidth
				}
			}
		}
	)

	// Find the maximum width of each column.
	updateColWidths(data.Headers, colWidths)
	for _, row := range data.Values {
		updateColWidths(row, colWidths)
	}

	// If there are less columns in the result, override the related constraint. (e.g. transposed tables)
	minColCount = min(minColCount, colCount)

	// Determine the initial number of columns that should fit the screen.
	// This can change later during the optimization phase.
	var targetColCount int
	var resizeRequired bool
	remainingSpace := terminalWidth + colSpacing // Add an extra col space so we don't have to handle the first iteration differently.

	if data.IsTransposed {
		// Must have 2 columns in transposed tables.
		targetColCount = 2
	} else {
		for i, columnWidth := range colWidths {
			spaceNeeded := columnWidth + colSpacing
			totalSpaceNeeded := spaceNeeded // Temporary variable to not modify the original one.
			if i+1 < colCount {
				totalSpaceNeeded += extraColLength
			}

			if remainingSpace-totalSpaceNeeded < 0 {
				// If at least a small part of the last column could be displayed, include it.
				reduction := columnWidth - columnWidth/minVisibleContentDivisor
				if remainingSpace-(totalSpaceNeeded-reduction) > absoluteMinColWidth {
					targetColCount++
					// We need resize this column later.
					resizeRequired = true
				}

				break
			}

			// Reduce the remaining space for the next iteration.
			remainingSpace -= spaceNeeded

			targetColCount++
		}

		// Target at least 1 column, even if the 1st one exceeds the terminal.
		// This is necessary to make the upcoming calculations work correctly.
		targetColCount = max(targetColCount, 1)

		// Stop processing if all columns fit the terminal in normal table (arrays) mode.
		if !resizeRequired && targetColCount == colCount {
			return 0
		} else {
			// If the terminal is smaller than the absolute minimum required width, return an empty table.
			// 1 character wide columns are possible, so the min should be: `X   More info`
			if terminalWidth < 1+extraColLength {
				data.Headers = []TableCell{}
				data.Values = [][]TableCell{}
				return colCount
			}
		}
	}

	// Reaching this point means there is at least 1 column that's need to be processed,
	// so let's try to find the optimal widths and add extra columns on the fly if possible.
	// This is the optimization phase which intends to maximize the displayed content.
	// For example, do not push columns off the table just because the first col is too wide.

	var widestIdx int       // Used later to give back remaining spaces.
	var setWidest sync.Once // Used to avoid multiple if statements.
	for {
		// Find the widest column and calculate the row length in each iteration.
		var rowWidth int
		var widest, idx int
		for i := 0; i < targetColCount; i++ {
			colWidth := colWidths[i]
			rowWidth += colWidth

			if colWidth > widest {
				widest = colWidth
				idx = i
			}
		}

		// Find out how many columns could be shown if we reduce the size of the widest column.
		var newColCount int
		reduction := widest - terminalWidth/minColSizeRatio
		if reduction > 0 {
			// Used to avoid updating the same column multiple times.
			var updateWidest sync.Once

			// Loop over the remaining columns to see if we can add more
			// by reducing the size of the current widest column.
			for i := targetColCount; i < colCount; i++ {
				extraSpace := terminalWidth - (rowWidth - reduction) - (targetColCount-1)*colSpacing

				// Include the info column if needed.
				if i+1 != colCount {
					extraSpace -= extraColLength
				}

				// Check if at least the minimum amount of content would be visible from the next column.
				minContentWidth := colWidths[i] / minVisibleContentDivisor
				if extraSpace-minContentWidth >= absoluteMinColWidth {
					// If so, add it to the table and reduce the size of the widest column.
					newColCount++
					targetColCount++
					updateWidest.Do(func() {
						colWidths[idx] = widest - reduction
					})

					// Use the full size of the current "new" column if possible,
					// so the iteration can  continue and there is a chance for more columns.
					if extraSpace-colWidths[i] > 0 {
						reduction -= colWidths[i] + colSpacing
						// Since there is more space in the row and the iteration
						// will continue, save the widest column's index to regain
						// some width if there will be no more columns after this one.
						setWidest.Do(func() { widestIdx = idx })
					} else {
						// No more space for new columns.
						break
					}
				} else {
					// Not enough space for this column.
					break
				}
			}
		}

		// We have the exact number of columns that will be included in the table, so now finalize their widths.
		if newColCount == 0 {
			var netTerminalWidth int // Net usable space, no spacing and info column.

			if targetColCount < minColCount {
				// Force the minimum number of columns to be rendered.
				// If it's really not possible (e.g if the terminal is ridiculously small), try with fewer and fewer.

				targetColCount = minColCount

				for {
					if targetColCount == 0 {
						// Mission: Impossible :>
						data.Headers = []TableCell{}
						data.Values = [][]TableCell{}
						return colCount
					}

					// Calculate the "net" space that can be used by the columns.
					// Logic: "width of the terminal" - "all white space between cols" - "info column"
					netTerminalWidth = terminalWidth - (targetColCount-1)*colSpacing - extraColLength

					// Since we don't have enough columns, we try to force render the minimum amount.
					// To do this, we need to re-calculate the initial column widths.
					targetColWidth := netTerminalWidth / targetColCount
					remainder := netTerminalWidth % targetColCount

					// Reduce the number of columns if it's really necessary.
					if targetColWidth < absoluteMinColWidth || netTerminalWidth < targetColCount*targetColWidth {
						targetColCount--
						continue
					}

					// Start to reduce the width of the columns, starting from the widest.
					for i := 0; i < targetColCount; i++ {
						// First, we need to find it.
						var (
							rowWidth    int
							widest, idx int
						)
						for i := 0; i < minColCount; i++ {
							colWidth := colWidths[i]
							rowWidth += colWidth

							if colWidth > widest {
								widest = colWidth
								idx = i
							}
						}

						// Now it's time to reduce the size.
						// Logic: get the net length we can use. Subtract the length of the other columns. Add the remainder to not waste space.
						targetSize := netTerminalWidth - (rowWidth - widest) + remainder
						remainder = 0 // Reset
						if targetSize < targetColWidth {
							// Use the minimum width if the target is too small and jump to the 2nd widest.
							colWidths[idx] = targetColWidth
						} else {
							// Quit the loop if we reduced enough, we reached the final size.
							colWidths[idx] = targetSize
							break
						}
					}

					// The width of the columns have been calculated.
					break
				}
			} else {
				// We have enough columns, now we only need to take care about the size of the last one.
				// Calculate the width of a single row and adjust it.
				netTerminalWidth = terminalWidth - (targetColCount-1)*colSpacing
				if targetColCount < colCount {
					// Reduce the available space if not all columns will be shown.
					netTerminalWidth -= extraColLength
				}

				// Calculate the final width of the rows.
				var finalRowWidth int
				for i := 0; i < targetColCount; i++ {
					finalRowWidth += colWidths[i]
				}

				// Handle remaining space whether it's positive or negative.
				remainingSpace := netTerminalWidth - finalRowWidth
				if remainingSpace > 0 {
					// If positive, it's means there is spare space that we can use.
					colWidths[widestIdx] += remainingSpace
				} else {
					// Negative value means we need more space, so let's reduce more.
					newLastColWidth := colWidths[targetColCount-1] + remainingSpace

					// Handle some rare transposed table scenarios to avoid panics.
					if newLastColWidth < absoluteMinColWidth {
						// If the reduced last column would be smaller than the minimum value,
						// reduce the first one. This can only (?) happen with transposed tables
						// where there must be 2 columns, so we do not need to check anything else.
						newFirstColWidth := colWidths[0] - (absoluteMinColWidth - newLastColWidth)
						if newFirstColWidth < absoluteMinColWidth {
							// Still not enough space... Mission: Impossible :>
							data.Headers = []TableCell{}
							data.Values = [][]TableCell{}
							return colCount
						}

						// Update the reduces column widths with the final values.
						colWidths[0] = newFirstColWidth
						colWidths[targetColCount-1] = absoluteMinColWidth
					} else {
						// There will be enough content after shrinking, so let's update the last column.
						colWidths[targetColCount-1] += remainingSpace
					}
				}
			}

			break
		}
	}

	// An inner function to update the width of each cell in a row.
	updateRow := func(row []TableCell, isHeader bool) {
		for i := 0; i < targetColCount; i++ {
			cell := &row[i]

			// Explicitly call the callback function to re-render the sub-table with the correctly truncated lines.
			if cell.callback != nil {
				// Calculate the max space that this sub table can take inside the parent table.
				maxTableWidth := terminalWidth - (colWidths[0] + colSpacing)
				newValue := cell.callback(maxTableWidth)

				// Empty maps and list of maps only contain newline characters
				// when they cannot fit to the given space, so let's check the
				// returned value. If it only contains newlines, set "..." as
				// the value to indicate hidden data.
				if strings.Trim(newValue, "\n") == "" {
					cell.Value = "..."
				} else {
					cell.Value = newValue
				}
			}

			maxWidth := colWidths[i]
			// Step to the next cell if the content of this one fits in the space.
			if cell.MaxWidth() <= maxWidth {
				continue
			}

			// Multi line headers are not supported, so truncate them if needed.
			if isHeader {
				cell.Value = cell.String()[:maxWidth-3] + "..."
				continue
			}

			// Break the content into separate lines.
			var lines []string
			var isMore bool
			for i := 0; i < maxLineInCells; i++ {
				chunk := cell.String()[i*maxWidth:]
				if len(chunk) > maxWidth {
					lines = append(lines, chunk[:maxWidth])
					isMore = true
				} else {
					// There is no more text, this is the last line.
					lines = append(lines, chunk)
					isMore = false
					break
				}
			}

			// Indicate if there are more characters, by replacing the last 3 characters with dots (...).
			if isMore {
				lastLineRef := &lines[maxLineInCells-1]
				if strings.HasPrefix(cell.String(), "[") && strings.HasSuffix(cell.String(), "]") {
					// Handle arrays nicely.
					*lastLineRef = (*lastLineRef)[:maxWidth-4] + "...]"
				} else {
					*lastLineRef = (*lastLineRef)[:maxWidth-3] + "..."
				}
			}

			// Save the wrapped/truncated cell content.
			cell.Value = strings.Join(lines, "\n")
		}
	}

	// Update the headers in non-transposed tables.
	if !data.IsTransposed {
		data.Headers = data.Headers[:targetColCount]
		updateRow(data.Headers, true)
		if targetColCount < colCount {
			data.Headers = append(data.Headers, TableCell{Value: infoColName})
		}
	}

	for i, row := range data.Values {
		values := row[:targetColCount]
		updateRow(values, false)
		if !data.IsTransposed && targetColCount < colCount {
			extraCol := new(TableCell)
			extraCol.Value = "..."
			values = append(values, *extraCol)
		}
		data.Values[i] = values
	}

	// Return the number of hidden columns.
	return colCount - targetColCount
}

// Sorts tableHeaders to match the order of TableHeaderOrder. All headers
// not in TableHeaderOrder are appended to the end in alphabetical order.
func getSortedTableHeaders(tableHeaders []string) []string {
	orderedHeaders := []string{}
	addedSet := make(map[string]bool)

	// sort given tableHeaders so we may perform binary search
	sort.Strings(tableHeaders)
	// add headers from TableHeaderOrder to the result
	for _, header := range TableHeaderOrder {
		index := sort.SearchStrings(tableHeaders, header)
		if index < len(tableHeaders) && tableHeaders[index] == header {
			// header is in the list of given tableHeaders
			orderedHeaders = append(orderedHeaders, header)
			addedSet[header] = true
		}
	}

	// tableHeaders already sorted alphabetically
	// add remaining headers in alphabetical order
	for _, header := range tableHeaders {
		if !addedSet[header] {
			orderedHeaders = append(orderedHeaders, header)
		}
	}

	return orderedHeaders
}

// makeSingleRowTableFromMap takes a map and creates a sorted Table,
// where the keys in the map are the headers, and the values are the first row.
func makeSingleRowTableFromMap(tableMap map[string]TableCell, remainingExplodeLevel int) *TableData {
	table := new(TableData)

	// Collect the table headers from the single row.
	tableHeaders := make([]string, 0)
	for header := range tableMap {
		tableHeaders = append(tableHeaders, header)
	}

	// Sort the collected table headers.
	var sortedTableHeaders []string
	// `remainingExplodeLevel` indicates the number of levels to explode in nested objects,
	// so if it equals to the max value, that means this is a top level table. This is important,
	// becaues we only use custom ordering on the top level. It's not yet supported in sub-tables.
	if remainingExplodeLevel == MaxExplodeLevel && len(tableHeaders) == len(customHeaderOrder) {
		// If there is a custom order specified in the JMESPath query, we use that,
		sortedTableHeaders = customHeaderOrder
	} else {
		// else we use the default ordering.
		sortedTableHeaders = getSortedTableHeaders(tableHeaders)
	}

	// Map has single row.
	row := make([]TableCell, len(sortedTableHeaders))
	for i, header := range sortedTableHeaders {
		cell := TableCell{
			Value:    tableMap[header].Value,
			callback: tableMap[header].callback,
		}
		row[i] = cell
	}

	headers := make([]TableCell, len(sortedTableHeaders))
	for i, h := range sortedTableHeaders {
		headers[i] = TableCell{Value: h}
	}

	table.Headers = headers
	table.Values = [][]TableCell{row}

	return table
}

// for an array of maps, it may be the case that not all maps share the same keys
// this function will iterate through all of the maps to assemble a superset of unique
// keys to use when creating the table
func getAllKeysForMapArray(mapArray reflect.Value) (map[string]reflect.Value, []string) {
	// maintain a superset of all unique keys across the maps
	masterKeyList := make(map[string]reflect.Value)
	// maintain an ordered set of keys to help enforce alignment between headers and values
	orderedKeys := make([]string, 0)

	for i := 0; i < mapArray.Len(); i++ {
		mapElement := DerefValue(mapArray.Index(i))

		iter := mapElement.MapRange()
		for iter.Next() {
			keyAsString := iter.Key().String()

			// check for uniqueness
			_, exists := masterKeyList[keyAsString]

			// url fields clutter the table and don't provide much value, so they are skipped.
			// Similarly, crn values are too long to include in a cell without overwhelming the
			// width of most screens. Skip them as well
			if !exists && strings.ToLower(keyAsString) != "url" && strings.ToLower(keyAsString) != "crn" {
				masterKeyList[keyAsString] = iter.Key()
				orderedKeys = append(orderedKeys, keyAsString)
			}
		}
	}

	return masterKeyList, getSortedTableHeaders(orderedKeys)
}

// rotates a table so that the headers are in the first
// column and the values are in the 2...N columns
// however, right now, this only occurs when there is only
// one row to transpose (for a flat map)
func transposeTable(data *TableData) *TableData {
	if !IsValidTableData(data) {
		return data
	}

	// collect all values in a single array of arrays
	// we will create the new table from this
	newTableValues := make([][]TableCell, 0)

	// move the headers to their new spots - as the first elements
	// of each new array
	for _, header := range data.Headers {
		newRow := []TableCell{header}
		newTableValues = append(newTableValues, newRow)
	}

	// for each row in the original table, process the values and move
	// them to the new table
	for _, rowToProcess := range data.Values {
		for i, valueToMove := range rowToProcess {
			newTableValues[i] = append(newTableValues[i], valueToMove)
		}
	}

	// create the new table from newTableValues
	table := new(TableData)

	// the table printing code in the terminal package distinguishes the first row
	// (normally the headers) by putting them in bold. it doesn't make sense to
	// arbitrarily bold the first row, so fill the header values with empty strings
	table.Headers = make([]TableCell, len(newTableValues[0])) //#nosec G602

	// use the newly transposed table as the values
	table.Values = newTableValues
	table.IsTransposed = true

	return table
}

/**********	ARRAY **********/
// These methods deal with data in the form of an array
// by printing each value in its own row in the table.

// Determine the type of the elements in the array and return
// the appropriate table.
func getTableForArray(resultValue reflect.Value) *TableData {
	if resultValue.Len() == 0 {
		return nil
	}

	var table *TableData

	arrayElementType := GetArrayElementType(resultValue)

	switch arrayElementType {
	case reflect.Map:
		table = getTableForMapArray(resultValue)

	default:
		// should be array of primitives
		table = getTableForPrimitivesArray(resultValue)
	}

	return table
}

// The property names, or keys, from all of the maps are used as the
// column headers for the table and the values are used to fill each row.
func getTableForMapArray(resultValue reflect.Value) *TableData {
	table := new(TableData)
	tableHeaders := make([]string, 0)
	tableValues := make([][]TableCell, 0)

	masterKeyList, orderedKeys := getAllKeysForMapArray(resultValue)
	tableHeaders = append(tableHeaders, orderedKeys...)

	// Make sure we extracted the correct number of headers before overriding the default order.
	if len(tableHeaders) == len(customHeaderOrder) {
		// TODO: if the number of the elements in the slices above are different
		// the plug-in will silently ignore the custom order of the columns,
		// therefore the user won't see any message about what has happend and why.
		tableHeaders = customHeaderOrder
	}

	// cycle through all of the maps in the array
	for i := 0; i < resultValue.Len(); i++ {
		mapElement := DerefValue(resultValue.Index(i))
		rowValues := make([]TableCell, 0)

		// cycle through the keys and pull out the values
		for _, key := range tableHeaders {
			field := mapElement.MapIndex(masterKeyList[key])
			cell := TableCell{Value: GetStringValue(field)}
			rowValues = append(rowValues, cell)
		}

		// add row to table before moving to next map
		tableValues = append(tableValues, rowValues)
	}

	headers := make([]TableCell, len(tableHeaders))
	for i, h := range tableHeaders {
		headers[i] = TableCell{Value: h}
	}

	table.Headers = headers
	table.Values = tableValues

	return table
}

// This logic assumes that the result is a list of primitive types. This typically
// results from the use of a JMESPath query, so the final segment of the query is used
// as the column header.
func getTableForPrimitivesArray(resultValue reflect.Value) *TableData {
	table := new(TableData)
	tableValues := make([][]TableCell, 0)

	for i := 0; i < resultValue.Len(); i++ {
		listElement := resultValue.Index(i)
		tableValues = append(tableValues, []TableCell{TableCell{Value: GetStringValue(listElement)}})
	}

	table.Headers = []TableCell{TableCell{Value: lastQuerySegment}}
	table.Values = tableValues

	return table
}

/**********	MAP	**********/
// This method deals with data in the form of a single map.
// The keys are used as column headers and the values are printed
// along a single row.

// Iterates through a map and collects the keys and values
// together, ensuring that they are aligned properly.
func getTableForMap(resultValue reflect.Value, levelsToExplode int) *TableData {
	tableMap := make(map[string]TableCell)

	// loop through map fields
	iter := resultValue.MapRange()
	for iter.Next() {
		key := iter.Key().String()
		// url fields clutter the table and don't provide much value, so they are skipped.
		// Similarly, crn values are too long to include in a cell without overwhelming the
		// width of most screens. Skip them as well
		if strings.ToLower(key) != "url" && strings.ToLower(key) != "crn" {
			value, callback := GetStringValueExploded(iter.Value(), levelsToExplode)
			tableMap[key] = TableCell{
				Value:    value,
				callback: callback,
			}
		}
	}

	tableData := transposeTable(makeSingleRowTableFromMap(tableMap, levelsToExplode))

	return tableData
}

/**********	SINGLE VALUE	**********/
// This method deals with data in the form of a single, primitive value.
// This is assumed to occur because of a JMESPath query, so the final
// segment of the query is used for the header of the single column. The value
// is printed as the single row.

func getTableForSingleValue(resultValue reflect.Value) *TableData {
	table := new(TableData)
	tableValues := make([][]TableCell, 0)

	singleValue := TableCell{Value: GetStringValue(resultValue)}
	tableValues = append(tableValues, []TableCell{singleValue})

	table.Headers = []TableCell{TableCell{Value: lastQuerySegment}}
	table.Values = tableValues

	return table
}
