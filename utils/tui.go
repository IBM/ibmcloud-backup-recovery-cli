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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	translation "ibmcloud-backup-recovery-cli/i18n"
	"os"
	"reflect"
)

// Using this to increase the padding between the columns in the table.
const columnSpacing = "   "

var (
	app    *tview.Application
	tables tableStack

	// A maximum column width. We need to use it because we cannot
	// yet handle too wide columns that would surpass the screen.
	maxColWidth          int
	currentTerminalWidht int

	// Common style related variables.
	headerStyle  = tcell.StyleDefault.Underline(true)
	defaultColor = tcell.NewRGBColor(95, 0, 255)
)

// tableStackElem represents a single item in the stack.
// It stores the reference to the table object, the raw data
// and the path to the table inside the result.
type tableStackElem struct {
	table *tview.Table
	data  any
	path  string
}

// tableStack is collection of tableItems (basically the tables) with some helper methods.
type tableStack struct {
	tables []tableStackElem
}

// Append adds a new element to the top of the stack.
func (ts *tableStack) Append(table *tview.Table, data any, path string) {
	newTable := tableStackElem{
		table: table,
		data:  data,
		path:  path,
	}

	ts.tables = append(ts.tables, newTable)
}

// Last returns the last element in the stack.
func (ts *tableStack) Last() tableStackElem {
	lastIdx := ts.Len() - 1
	lastItem := ts.tables[lastIdx]
	return lastItem
}

// Pop removes and returns the last element in the stack.
func (ts *tableStack) Pop() tableStackElem {
	table := ts.Last()
	newLastIdx := ts.Len() - 1
	ts.tables = ts.tables[0:newLastIdx]

	return table
}

// Len returns the number of the elements in the stack.
func (ts *tableStack) Len() int {
	return len(ts.tables)
}

// startTUI makes the necessary initializations and starts a new TUI appplication.
func startTUI(data any) error {
	// Try to get the current size of the terminal to calculate the absolute maximum column width.
	// We use some arbitrary values here. Feel free to suggest better alternatives!
	maxColWidth = getMaxColWidth(0)

	// Set the default background color, so we don't need to do it manually on each UI element.
	tview.Styles.PrimitiveBackgroundColor = tcell.ColorNone
	tview.Styles.ContrastBackgroundColor = tcell.ColorNone

	// Create a new application.
	app = tview.NewApplication()

	// Set up a callback function that will handle resizing the terminal.
	app.SetBeforeDrawFunc(func(screen tcell.Screen) bool {
		// Since this callback if called before every single "draw" event,
		// we need to make sure the column resizing only happens when the
		// width has changed. To do this, we compare the current and the
		// previous size of the terminal.
		newTerminalWidth, _ := screen.Size()
		if newTerminalWidth != currentTerminalWidht {
			currentTerminalWidht = newTerminalWidth
			maxColWidth = getMaxColWidth(currentTerminalWidht)

			// Now we need to set it to all cells in each table.
			for _, table := range tables.tables {
				tableObj := table.table
				rowCount := tableObj.GetRowCount()
				colCount := tableObj.GetColumnCount()
				for r := 0; r < rowCount; r++ {
					for c := 0; c < colCount; c++ {
						cell := tableObj.GetCell(r, c)
						cell.SetMaxWidth(maxColWidth)
					}
				}
			}
		}
		// Return false to not interrupt the process chain.
		return false
	})

	// Build the initial table and set it as the root view.
	table := createTable(data, "result")
	changeView(table, "result", true)

	// Start the app.
	return app.EnableMouse(true).Run()
}

// showErrorDialog displays a popup to the user with the given message, but the color
// of the border is red to indicate that the message is coming from an error.
func showErrorDialog(message string, okCallback func()) {
	okButtonText := translation.T("tui-button-ok")
	errorModal := tview.NewModal().
		SetText(message).
		AddButtons([]string{okButtonText}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == okButtonText {
				okCallback()
			}
		})

	errorModal.SetButtonBackgroundColor(defaultColor)
	// This sets the frame/border to red, so it's more
	// clear that the message is coming from an error.
	errorModal.Box.SetBorderColor(tcell.ColorRed)

	changeView(errorModal, "", false)
}

// showFileSaveDialog takes the currently displayed table (top element on the stack)
// and writes its content to a file on the given path.
func showFileSaveDialog(path string) {
	// Use a default path.
	if path == "" {
		path = "result.json"
	}

	pathFieldText := translation.T("tui-path")

	saveForm := tview.NewForm()
	saveForm.SetBorder(true).
		SetTitle(" " + translation.T("tui-save-table-dialog-title") + " ")
	saveForm.
		SetButtonBackgroundColor(defaultColor).
		SetFieldBackgroundColor(defaultColor).
		SetLabelColor(tcell.ColorNone).
		SetButtonsAlign(tview.AlignCenter).
		AddInputField(pathFieldText, path, 0, nil, nil).
		AddButton(translation.T("tui-button-save"), func() {
			// Get the path from the input field and try to save the raw data to that file.
			path := saveForm.GetFormItemByLabel(pathFieldText).(*tview.InputField).GetText()
			t := tables.Last()
			if err := saveTable(t.data, path); err == nil {
				// Everything is fine, go back to the last active table.
				changeView(t.table, t.path, true)
			} else {
				// Something went wrong. Show an error dialog,
				showErrorDialog(err.Error(), func() {
					// then switch back to this view if the user pressed the "OK" button.
					showFileSaveDialog(path)
				})
			}
		}).
		AddButton(translation.T("tui-button-cancel"), func() {
			changeView(tables.Last().table, tables.Last().path, false)
		})

	// Add the form to a new flexbox layout.
	layout := tview.NewFlex().
		AddItem(tview.NewBox(), 0, 3, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(tview.NewBox(), 0, 3, false).
			AddItem(saveForm, 7, 1, true).
			AddItem(tview.NewBox(), 0, 3, false), 0, 2, true).
		AddItem(tview.NewBox(), 0, 3, false)

	changeView(layout, "", false)
}

// showExitDialog displays a popup and ask a confirmation from the user
// whether they really want to exit from the application or not.
func showExitDialog() {
	quitButtonText := translation.T("tui-button-quit")
	cancelButtonText := translation.T("tui-button-cancel")
	modal := tview.NewModal().
		SetText(translation.T("tui-exit-prompt")).
		AddButtons([]string{quitButtonText, cancelButtonText}).
		SetDoneFunc(func(buttonIndex int, buttonLabel string) {
			if buttonLabel == quitButtonText {
				app.Stop()
			} else if buttonLabel == cancelButtonText {
				changeView(tables.Last().table, tables.Last().path, true)
			}
		})
	modal.SetButtonBackgroundColor(defaultColor)

	changeView(modal, "", false)
}

// showHelpDialog displays a popup with the available keybinding, based on the currently active view.
func showHelpDialog(isTable bool) {
	// Create basic form,
	helpForm := tview.NewForm()
	helpForm.
		SetButtonBackgroundColor(defaultColor).
		SetFieldBackgroundColor(defaultColor).
		SetButtonsAlign(tview.AlignCenter).
		SetItemPadding(0)

	// then add the text fields.
	helpForm.
		AddTextView("↑/k", translation.T("tui-up"), 0, 1, true, false).
		AddTextView("↓/j", translation.T("tui-down"), 0, 1, true, false).
		AddTextView("→/l", translation.T("tui-right"), 0, 1, true, false).
		AddTextView("←/h", translation.T("tui-left"), 0, 1, true, false).
		AddTextView("g/"+translation.T("tui-home-key"), translation.T("tui-start"), 0, 1, true, false).
		AddTextView("G/"+translation.T("tui-end-key"), translation.T("tui-end"), 0, 1, true, false).
		AddTextView("ctrl-f/"+translation.T("tui-pagedown-key"), translation.T("tui-pagedown"), 0, 1, true, false).
		AddTextView("ctrl-b/"+translation.T("tui-pageup-key"), translation.T("tui-pageup"), 0, 1, true, false)
	if isTable {
		helpForm.
			AddTextView(translation.T("tui-enter-key"), translation.T("tui-select-cell"), 0, 1, true, false).
			AddTextView("s", translation.T("tui-sabe-table-long"), 0, 1, true, false)
	}
	helpForm.
		AddTextView(translation.T("tui-esc-key"), translation.T("tui-close"), 0, 1, true, false).
		AddTextView("ctrl-c", translation.T("tui-quit"), 0, 1, true, false)

	helpForm.
		AddButton(translation.T("tui-button-cancel"), func() {
			changeView(tables.Last().table, tables.Last().path, true)
		})

	helpForm.SetBorder(true)
	helpForm.SetTitle(" " + translation.T("tui-help-dialog-title") + " ")

	// Calculate the height. It depends on the number of the text field.
	// 6 is the "minimum required height for the button and the spacing."
	height := 6 + helpForm.GetFormItemCount()

	// Add the form to a new flexbox layout.
	layout := tview.NewFlex().
		AddItem(tview.NewBox(), 0, 1, false).
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(tview.NewBox(), 0, 1, false).
			AddItem(helpForm, height, 1, true).
			AddItem(tview.NewBox(), 0, 1, false), 0, 1, true).
		AddItem(tview.NewBox(), 0, 1, false)

	// Close the help view when ESC is pressed.
	layout.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEscape {
			changeView(tables.Last().table, tables.Last().path, true)
		}

		return event
	})

	changeView(layout, "", false)
}

// changeView is a helper function. It makes the switching between different views eaiser.
func changeView(view tview.Primitive, path string, showFooter bool) {
	if path != "" {
		path = translation.T("tui-header-path") + " " + path
	}

	frame := tview.NewFrame(view).
		AddText(path, true, tview.AlignLeft, tcell.ColorDefault).
		SetBorders(1, 0, 1, 1, 1, 1)

	if showFooter {
		frame.AddText("? - "+translation.T("tui-help"), false, tview.AlignCenter, tcell.ColorGray)
	}

	app.SetRoot(frame, true)
}

// createTable creates a new table from the given dataset and adds it to the stack.
func createTable(data any, path string) *tview.Table {
	// If the data is not an array/slice (should be a map)
	// transform it two make the further processing easier.
	dataType := reflect.ValueOf(data).Kind()
	if dataType == reflect.Map {
		data = []interface{}{data}
	}

	table := tview.NewTable().
		Select(1, 1).
		SetFixed(1, 1).
		SetSelectable(true, true).
		SetSelectedStyle(tcell.StyleDefault.Background(defaultColor))

	// Handle ESC key press.
	table.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			if tables.Len() < 2 {
				showExitDialog()
			} else {
				tables.Pop()
				changeView(tables.Last().table, "", true)
			}
		}
	})

	// Handle "save table" and "show help".
	table.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 's':
			showFileSaveDialog("")
		case '?':
			showHelpDialog(true)
		}

		return event
	})

	// Handle cell selection (entering to the content).
	table.SetSelectedFunc(func(r, c int) {
		cellData := table.GetCell(r, c).GetReference()
		var newView tview.Primitive
		newPath := fmt.Sprintf("%s > %d > %s", path, r, table.GetCell(0, c).Text)
		if isPrimitive(cellData) {
			newView = createTextView(cellData)
		} else {
			newView = createTable(cellData, newPath)
		}
		changeView(newView, newPath, true)
	})

	// Fill the table with cells,
	populateTable(table, data)
	// then add it to the stack before returning.
	tables.Append(table, data, path)

	return table
}

// createTextView creates a new simple text view from the given cell data.
func createTextView(cellData any) *tview.TextView {
	textView := tview.NewTextView().
		SetText(GetStringValue(reflect.ValueOf(cellData))).
		SetDynamicColors(true).
		SetRegions(true).
		SetChangedFunc(func() {
			app.Draw()
		})

	// Go back to the last active table when ESC is pressed.
	textView.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			changeView(tables.Last().table, tables.Last().path, true)
		}
	})

	// Handle "show help".
	textView.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Rune() == '?' {
			showHelpDialog(false)
		}
		return event
	})

	return textView
}

// populateTable takes a raw dataset and loads it into the referenced table object.
func populateTable(table *tview.Table, data any) {
	// Make sure we have to correct data type.
	var tableData []any
	if d, ok := data.([]any); ok {
		tableData = d
	} else {
		return
	}

	if len(tableData) == 0 {
		return
	}

	// Preserve the name of the columns for the row processing step.
	var colNames []string

	// Process each line in the table data.
	for r := 0; r < len(tableData); r++ {
		// We need to make sure each item has the correct type before processing.
		if row, ok := tableData[r].(map[string]any); !ok {
			continue
		} else {
			// On the first item we need to iterate twice, because we need to add the column names, then the actual data.
			// Note that, each item in the slice is a map, so we have the field names and the field values in each row.
			if len(colNames) == 0 {
				colNames = getColumnNames(row)
				for i, colName := range colNames {
					// Create and set the column cells.
					cell := tview.
						NewTableCell(colName).
						SetMaxWidth(maxColWidth).
						SetStyle(headerStyle).
						SetSelectable(false)

					table.SetCell(0, i, cell)
				}
			}

			// Go over the fields in this row and add them to the table.
			for c := 0; c < len(colNames); c++ {
				colName := colNames[c]

				// Empty column name means it's for the indices.
				var cell *tview.TableCell
				if colName == "" {
					cell = tview.NewTableCell(fmt.Sprint(r+1) + columnSpacing).
						SetSelectable(false)
				} else {
					value := GetStringValue(reflect.ValueOf(row[colName]))
					cell = tview.NewTableCell(value + columnSpacing).
						SetMaxWidth(maxColWidth)
					cell.SetReference(row[colName])
				}

				table.SetCell(r+1, c, cell)
			}
		}
	}
}

// getColumnNames is a helper function which takes a single row from the result
// and extracts the name of the fields that will be used as the column names.
func getColumnNames(row map[string]any) []string {
	var result = make([]string, 0)

	// The row index column first,
	colName := ""
	result = append(result, colName)

	// then the rest.
	for colName := range row {
		result = append(result, colName)
	}

	return result
}

// saveTable takes a raw data and tries to write is as a JSON string to the given path.
func saveTable(data interface{}, path string) error {
	// A simple wrapper function to produce a clearer error message.
	fileErr := func(err error) error {
		return errors.New(translation.T("tui-save-table-error", map[string]interface{}{
			"PATH":  path,
			"ERROR": err,
		}))
	}

	// File truncation is not supported.
	if _, err := os.Stat(path); err == nil {
		return fileErr(os.ErrExist)
	}

	b, err := json.MarshalIndent(data, EmptyString, "  ")
	if err != nil {
		return fileErr(err)
	}

	return os.WriteFile(path, b, 0600)
}

// getMaxColWidth returns the maximum possbible (and convenient) size that each column can take in the table.
// If the width of the terminal is set to 0, the function tries to determine it.
func getMaxColWidth(termWidth int) int {
	if termWidth == 0 {
		termWidth = GetTerminalWidth()
	}

	if termWidth > 0 {
		return termWidth / 3
	} else {
		return 50
	}
}
