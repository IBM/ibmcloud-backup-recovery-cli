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

package utils_test

import (
	"ibmcloud-backup-recovery-cli/utils"
	"fmt"
	"reflect"
	"strings"

	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/testhelpers/terminal"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Test suite
var _ = Describe("Table Printer", func() {

	AfterEach(func() {
		utils.TableHeaderOrder = []string{}
	})

	Describe("CreateTable", func() {
		It("Should return nil if input is nil", func() {
			ui := terminal.NewFakeUI()
			var data *utils.TableData = nil
			table, truncatedCols := utils.CreateTable(data, ui.Writer(), 0)
			Expect(table).To(BeNil())
			Expect(truncatedCols).To(Equal(0))
		})

		It("Should return nil if there are no headers", func() {
			ui := terminal.NewFakeUI()
			data := new(utils.TableData)
			table, truncatedCols := utils.CreateTable(data, ui.Writer(), 0)
			Expect(table).To(BeNil())
			Expect(truncatedCols).To(Equal(0))
		})

		It("Should still return table if there are no values", func() {
			ui := terminal.NewFakeUI()
			data := new(utils.TableData)
			data.SetRawHeaders([]string{"header"})
			table, truncatedCols := utils.CreateTable(data, ui.Writer(), 0)
			Expect(table).NotTo(BeNil())
			Expect(truncatedCols).To(Equal(0))
		})

		It("Should return table when provided values", func() {
			ui := terminal.NewFakeUI()
			data := new(utils.TableData)
			data.SetRawHeaders([]string{"header"})
			data.SetRawValues([][]string{
				{"1"},
				{"2"},
			})
			table, truncatedCols := utils.CreateTable(data, ui.Writer(), 0)
			Expect(table).NotTo(BeNil())
			Expect(truncatedCols).To(Equal(0))
		})

		When("The result data is average", func() {
			var (
				ui   *terminal.FakeUI
				data *utils.TableData
			)

			Context("The table is not transposed", func() {
				BeforeEach(func() {
					ui = terminal.NewFakeUI()
					data = new(utils.TableData)
					data.SetRawHeaders([]string{"Expiration", "ID", "Locks", "Name", "Secret_Type", "State", "secret_group_id"})
					data.SetRawValues([][]string{
						{"2023-10-21T02:13:35.000Z", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", "0", "test-certificate", "private_cert", "active", "default"},
						{"-", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", "0", "test-user-credentials-with-labels", "username_password", "active", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
						{"-", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", "0", "test-user-credentials-no-labels", "username_password", "active", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
					})
				})

				It("Should create the correct table in small terminal (50)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 50)
					Expect(table).NotTo(BeNil())
					table.Print()
					tableLines := strings.Split(ui.Outputs(), "\n")
					Expect(tableLines[0]).To(Equal("Expiration     ID                Locks   More info"))
					Expect(tableLines[1]).To(Equal("2023-10-21T0   XXXXXXXX-XXXX-X   0       ..."))
					Expect(tableLines[2]).To(Equal("2:13:35.000Z   XXX-XXXX-XXXXXX           "))
					Expect(tableLines[3]).To(Equal("               XXXXXX                    "))
					Expect(tableLines[4]).To(Equal("-              XXXXXXXX-XXXX-X   0       ..."))
					Expect(tableLines).To(HaveLen(11))
					Expect(truncatedCols).To(Equal(4))
				})

				It("Should create the correct table in medium terminal (100)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 100)
					Expect(table).NotTo(BeNil())
					table.Print()
					tableLines := strings.Split(ui.Outputs(), "\n")
					Expect(tableLines[0]).To(Equal("Expiration                 ID                                     Locks   Name             More info"))
					Expect(tableLines[1]).To(Equal("2023-10-21T02:13:35.000Z   XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX   0       test-certifica   ..."))
					Expect(tableLines[2]).To(Equal("                                                                          te               "))
					Expect(tableLines[3]).To(Equal("-                          XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX   0       test-user-cred   ..."))
					Expect(tableLines).To(HaveLen(10))
					Expect(truncatedCols).To(Equal(3))
				})

				It("Should create the correct table in normal terminal (200)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 200)
					Expect(table).NotTo(BeNil())
					table.Print()
					tableLines := strings.Split(ui.Outputs(), "\n")
					Expect(tableLines[0]).To(Equal("Expiration                 ID                                     Locks   Name                                Secret_Type         State    secret_group_id"))
					Expect(tableLines[1]).To(Equal("2023-10-21T02:13:35.000Z   XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX   0       test-certificate                    private_cert        active   default"))
					Expect(tableLines[2]).To(Equal("-                          XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX   0       test-user-credentials-with-labels   username_password   active   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"))
					Expect(tableLines).To(HaveLen(5))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should not panic with different terminal sizes (from 20 to 200, increases by 5)", func() {
					width := 20

					// Catch panics to add the current width which will make the debugging easier.
					defer func() {
						if p := recover(); p != nil {
							panic(fmt.Sprintf("Panicked with terminal size '%d': %s", width, p))
						}
					}()

					for width <= 200 {
						ui := terminal.NewFakeUI()
						data := new(utils.TableData)
						data.SetRawHeaders([]string{"Expiration", "ID", "Locks", "Name", "Secret_Type", "State", "secret_group_id"})
						data.SetRawValues([][]string{
							{"2023-10-21T02:13:35.000Z", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", "0", "test-certificate", "private_cert", "active", "default"},
							{"-", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", "0", "test-user-credentials-with-labels", "username_password", "active", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
							{"-", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", "0", "test-user-credentials-no-labels", "username_password", "active", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
						})

						table, _ := utils.CreateTable(data, ui.Writer(), width)
						Expect(table).NotTo(BeNil())
						width += 5
					}
				})
			})

			Context("The table is transposed", func() {
				BeforeEach(func() {
					ui = terminal.NewFakeUI()
					data = new(utils.TableData)
					data.IsTransposed = true
					data.SetRawHeaders([]string{"", ""})
					data.SetRawValues([][]string{
						{"Expiration", "2023-10-21T02:13:35.000Z"},
						{"ID", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"},
						{"Locks", "0"},
						{"Name", "test-certificate"},
						{"Secret_Type", "private_cert"},
						{"State", "active"},
						{"secret_group_id", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
					})
				})

				It("Should create the correct table in small terminal (50)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 50)
					Expect(table).NotTo(BeNil())
					table.Print()
					output := ui.Outputs()
					Expect(output).To(Equal("                  \nExpiration        2023-10-21T02:13:35.000Z\nID                XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXX\n                  XXXX\nLocks             0\nName              test-certificate\nSecret_Type       private_cert\nState             active\nsecret_group_id   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should create the correct table in medium terminal (100)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 100)
					Expect(table).NotTo(BeNil())
					table.Print()
					output := ui.Outputs()
					Expect(output).To(Equal("                  \nExpiration        2023-10-21T02:13:35.000Z\nID                XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX\nLocks             0\nName              test-certificate\nSecret_Type       private_cert\nState             active\nsecret_group_id   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should create the correct table in normal terminal (200)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 200)
					Expect(table).NotTo(BeNil())
					table.Print()
					output := ui.Outputs()
					Expect(output).To(Equal("                  \nExpiration        2023-10-21T02:13:35.000Z\nID                XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX\nLocks             0\nName              test-certificate\nSecret_Type       private_cert\nState             active\nsecret_group_id   XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n"))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should not panic with different terminal sizes (from 20 to 200, increases by 5)", func() {
					width := 20

					// Catch panics to add the current width which will make the debugging easier.
					defer func() {
						if p := recover(); p != nil {
							panic(fmt.Sprintf("Panicked with terminal size '%d': %s", width, p))
						}
					}()

					for width <= 200 {
						ui := terminal.NewFakeUI()
						data := new(utils.TableData)
						data.IsTransposed = true
						data.SetRawHeaders([]string{"", ""})
						data.SetRawValues([][]string{
							{"Expiration", "2023-10-21T02:13:35.000Z"},
							{"ID", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"},
							{"Locks", "0"},
							{"Name", "test-certificate"},
							{"Secret_Type", "private_cert"},
							{"State", "active"},
							{"secret_group_id", "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"},
						})

						table, _ := utils.CreateTable(data, ui.Writer(), width)
						Expect(table).NotTo(BeNil())
						width += 5
					}
				})
			})
		})

		When("The result data has a wide column at the end", func() {
			var (
				ui   *terminal.FakeUI
				data *utils.TableData
			)

			Context("The table is not transposed", func() {
				BeforeEach(func() {
					ui = terminal.NewFakeUI()
					data = new(utils.TableData)
					data.SetRawHeaders([]string{"ID", "AI", "Name", "Description"})
					data.SetRawValues([][]string{
						{"1", "yes", "Foo", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."},
						{"2", "yes", "Bar", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."},
						{"3", "no", "Baz", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."},
					})
				})

				It("Should create the correct table in small terminal (50)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 50)
					Expect(table).NotTo(BeNil())
					table.Print()
					tableLines := strings.Split(ui.Outputs(), "\n")
					Expect(tableLines[0]).To(Equal("ID   AI    Name   Description"))
					Expect(tableLines[1]).To(Equal("1    yes   Foo    Lorem ipsum dolor sit amet, cons"))
					Expect(tableLines[2]).To(Equal("                  ectetur adipiscing elit, sed do "))
					Expect(tableLines[3]).To(Equal("                  eiusmod tempor incididunt ut ..."))
					Expect(tableLines[4]).To(Equal("2    yes   Bar    Lorem ipsum dolor sit amet, cons"))
					Expect(tableLines).To(HaveLen(11))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should create the correct table in medium terminal (100)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 100)
					Expect(table).NotTo(BeNil())
					table.Print()
					tableLines := strings.Split(ui.Outputs(), "\n")
					Expect(tableLines[0]).To(Equal("ID   AI    Name   Description"))
					Expect(tableLines[1]).To(Equal("1    yes   Foo    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor inc"))
					Expect(tableLines[2]).To(Equal("                  ididunt ut labore et dolore magna aliqua."))
					Expect(tableLines[3]).To(Equal("2    yes   Bar    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor inc"))
					Expect(tableLines).To(HaveLen(8))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should create the correct table in normal terminal (200)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 200)
					Expect(table).NotTo(BeNil())
					table.Print()
					tableLines := strings.Split(ui.Outputs(), "\n")
					Expect(tableLines[0]).To(Equal("ID   AI    Name   Description"))
					Expect(tableLines[1]).To(Equal("1    yes   Foo    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."))
					Expect(tableLines[2]).To(Equal("2    yes   Bar    Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."))
					Expect(tableLines).To(HaveLen(5))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should not panic with different terminal sizes (from 20 to 200, increases by 5)", func() {
					width := 20

					// Catch panics to add the current width which will make the debugging easier.
					defer func() {
						if p := recover(); p != nil {
							panic(fmt.Sprintf("Panicked with terminal size '%d': %s", width, p))
						}
					}()

					for width <= 200 {
						ui := terminal.NewFakeUI()
						data := new(utils.TableData)
						data.SetRawHeaders([]string{"ID", "AI", "Name", "Description"})
						data.SetRawValues([][]string{
							{"1", "yes", "Foo", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."},
							{"2", "yes", "Bar", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."},
							{"3", "no", "Baz", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."},
						})

						table, _ := utils.CreateTable(data, ui.Writer(), 200)
						Expect(table).NotTo(BeNil())
						width += 5
					}
				})
			})

			Context("The table is transposed", func() {
				BeforeEach(func() {
					ui = terminal.NewFakeUI()
					data = new(utils.TableData)
					data.IsTransposed = true
					data.SetRawHeaders([]string{"", ""})
					data.SetRawValues([][]string{
						{"ID", "1"},
						{"AI", "yes"},
						{"Name", "Foo"},
						{"Description", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."},
					})
				})

				It("Should create the correct table in small terminal (50)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 50)
					Expect(table).NotTo(BeNil())
					table.Print()
					output := ui.Outputs()
					Expect(output).To(Equal("              \nID            1\nAI            yes\nName          Foo\nDescription   Lorem ipsum dolor sit amet, consecte\n              tur adipiscing elit, sed do eiusmod \n              tempor incididunt ut labore et do...\n"))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should create the correct table in medium terminal (100)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 100)
					Expect(table).NotTo(BeNil())
					table.Print()
					output := ui.Outputs()
					Expect(output).To(Equal("              \nID            1\nAI            yes\nName          Foo\nDescription   Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incidid\n              unt ut labore et dolore magna aliqua.\n"))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should create the correct table in normal terminal (200)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 200)
					Expect(table).NotTo(BeNil())
					table.Print()
					output := ui.Outputs()
					Expect(output).To(Equal("              \nID            1\nAI            yes\nName          Foo\nDescription   Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\n"))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should not panic with different terminal sizes (from 20 to 200, increases by 5)", func() {
					width := 20

					// Catch panics to add the current width which will make the debugging easier.
					defer func() {
						if p := recover(); p != nil {
							panic(fmt.Sprintf("Panicked with terminal size '%d': %s", width, p))
						}
					}()

					for width <= 200 {
						ui := terminal.NewFakeUI()
						data := new(utils.TableData)
						data.IsTransposed = true
						data.SetRawHeaders([]string{"", ""})
						data.SetRawValues([][]string{
							{"ID", "1"},
							{"AI", "yes"},
							{"Name", "Foo"},
							{"Description", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."},
						})

						table, _ := utils.CreateTable(data, ui.Writer(), width)
						Expect(table).NotTo(BeNil())
						width += 5
					}
				})
			})
		})

		When("The result data has a wide column at the beginning", func() {
			var (
				ui   *terminal.FakeUI
				data *utils.TableData
			)

			Context("The table is not transposed", func() {
				BeforeEach(func() {
					ui = terminal.NewFakeUI()
					data = new(utils.TableData)
					data.SetRawHeaders([]string{"Description", "ID", "AI", "Name"})
					data.SetRawValues([][]string{
						{"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.", "1", "yes", "Foo"},
						{"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.", "2", "yes", "Bar"},
						{"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.", "3", "no", "Baz"},
					})
				})

				Context("And the wide column is an array", func() {
					It("Should handle array values properly", func() {
						ui := terminal.NewFakeUI()
						data := new(utils.TableData)
						data.SetRawHeaders([]string{"Array", "ID", "AI", "Name"})
						data.SetRawValues([][]string{
							{"[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]", "1", "yes", "Foo"},
							{"[1, 2, 3, 4, 5, 6, 7]", "2", "no", "Bar"},
						})

						table, truncatedCols := utils.CreateTable(data, ui.Writer(), 20)
						Expect(table).NotTo(BeNil())
						table.Print()
						output := ui.Outputs()
						lines := strings.Split(output, "\n")
						Expect(lines[0]).To(Equal("Array      More info"))
						Expect(lines[1]).To(Equal("[1, 2, 3   ..."))
						Expect(lines[2]).To(Equal(", 4, 5,    "))
						Expect(lines[3]).To(Equal("6, 7...]   "))
						Expect(lines[4]).To(Equal("[1, 2, 3   ..."))
						Expect(lines[5]).To(Equal(", 4, 5,    "))
						Expect(lines[6]).To(Equal("6, 7]      "))
						Expect(truncatedCols).To(Equal(3))
					})
				})

				It("Should create the correct table in small terminal (50)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 50)
					Expect(table).NotTo(BeNil())
					table.Print()
					tableLines := strings.Split(ui.Outputs(), "\n")
					Expect(tableLines[0]).To(Equal("Description                        ID   AI    Name"))
					Expect(tableLines[1]).To(Equal("Lorem ipsum dolor sit amet, cons   1    yes   Foo"))
					Expect(tableLines[2]).To(Equal("ectetur adipiscing elit, sed do               "))
					Expect(tableLines[3]).To(Equal("eiusmod tempor incididunt ut ...              "))
					Expect(tableLines[4]).To(Equal("Lorem ipsum dolor sit amet, cons   2    yes   Bar"))
					Expect(tableLines).To(HaveLen(11))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should create the correct table in medium terminal (100)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 100)
					Expect(table).NotTo(BeNil())
					table.Print()
					tableLines := strings.Split(ui.Outputs(), "\n")
					Expect(tableLines[0]).To(Equal("Description                                                                          ID   AI    Name"))
					Expect(tableLines[1]).To(Equal("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor inc   1    yes   Foo"))
					Expect(tableLines[2]).To(Equal("ididunt ut labore et dolore magna aliqua.                                                       "))
					Expect(tableLines[3]).To(Equal("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor inc   2    yes   Bar"))
					Expect(tableLines).To(HaveLen(8))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should create the correct table in normal terminal (200)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 200)
					Expect(table).NotTo(BeNil())
					table.Print()
					tableLines := strings.Split(ui.Outputs(), "\n")
					Expect(tableLines[0]).To(Equal("Description                                                                                                                   ID   AI    Name"))
					Expect(tableLines[1]).To(Equal("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.   1    yes   Foo"))
					Expect(tableLines[2]).To(Equal("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.   2    yes   Bar"))
					Expect(tableLines).To(HaveLen(5))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should not panic with different terminal sizes (from 20 to 200, increases by 5)", func() {
					width := 20

					// Catch panics to add the current width which will make the debugging easier.
					defer func() {
						if p := recover(); p != nil {
							panic(fmt.Sprintf("Panicked with terminal size '%d': %s", width, p))
						}
					}()

					for width <= 200 {
						ui := terminal.NewFakeUI()
						data := new(utils.TableData)
						data.SetRawHeaders([]string{"Description", "ID", "AI", "Name"})
						data.SetRawValues([][]string{
							{"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.", "1", "yes", "Foo"},
							{"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.", "2", "yes", "Bar"},
							{"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.", "3", "no", "Baz"},
						})

						table, _ := utils.CreateTable(data, ui.Writer(), width)
						Expect(table).NotTo(BeNil())
						width += 5
					}
				})
			})

			Context("The table is transposed", func() {
				BeforeEach(func() {
					ui = terminal.NewFakeUI()
					data = new(utils.TableData)
					data.IsTransposed = true
					data.SetRawHeaders([]string{"", ""})
					data.SetRawValues([][]string{
						{"Description", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."},
						{"ID", "1"},
						{"AI", "yes"},
						{"Name", "Foo"},
					})
				})

				It("Should create the correct table in small terminal (50)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 50)
					Expect(table).NotTo(BeNil())
					table.Print()
					output := ui.Outputs()
					Expect(output).To(Equal("              \nDescription   Lorem ipsum dolor sit amet, consecte\n              tur adipiscing elit, sed do eiusmod \n              tempor incididunt ut labore et do...\nID            1\nAI            yes\nName          Foo\n"))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should create the correct table in medium terminal (100)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 100)
					Expect(table).NotTo(BeNil())
					table.Print()
					output := ui.Outputs()
					Expect(output).To(Equal("              \nDescription   Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incidid\n              unt ut labore et dolore magna aliqua.\nID            1\nAI            yes\nName          Foo\n"))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should create the correct table in normal terminal (200)", func() {
					table, truncatedCols := utils.CreateTable(data, ui.Writer(), 200)
					Expect(table).NotTo(BeNil())
					table.Print()
					output := ui.Outputs()
					Expect(output).To(Equal("              \nDescription   Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.\nID            1\nAI            yes\nName          Foo\n"))
					Expect(truncatedCols).To(Equal(0))
				})

				It("Should not panic with different terminal sizes (from 20 to 200, increases by 5)", func() {
					width := 20

					// Catch panics to add the current width which will make the debugging easier.
					defer func() {
						if p := recover(); p != nil {
							panic(fmt.Sprintf("Panicked with terminal size '%d': %s", width, p))
						}
					}()

					for width <= 200 {
						ui := terminal.NewFakeUI()
						data := new(utils.TableData)
						data.IsTransposed = true
						data.SetRawHeaders([]string{"", ""})
						data.SetRawValues([][]string{
							{"Description", "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."},
							{"ID", "1"},
							{"AI", "yes"},
							{"Name", "Foo"},
						})

						table, _ := utils.CreateTable(data, ui.Writer(), width)
						Expect(table).NotTo(BeNil())
						width += 5
					}
				})
			})
		})

		It("Should not return a truncated table", func() {
			ui := terminal.NewFakeUI()
			data := new(utils.TableData)
			data.SetRawHeaders([]string{"header1", "header2", "header3", "header4", "header5", "header6"})
			colCount := len(data.Headers)
			table, truncatedCols := utils.CreateTable(data, ui.Writer(), 1000)
			Expect(table).NotTo(BeNil())
			Expect(data.Headers).To(HaveLen(colCount))
			Expect(truncatedCols).To(Equal(0))
		})
	})

	Describe("FormatTableData", func() {
		It("Should return nil if given a nil value", func() {
			var x interface{} = nil
			data := utils.FormatTableData(x, "")
			Expect(data).To(BeNil())
		})

		It("Should return a table for a slice of string pointers", func() {
			str1 := "foo"
			str2 := "bar"

			// slice value
			x := []*string{&str1, &str2}

			// slice values should be explicitly handled in the formatter
			Expect(reflect.ValueOf(x).Kind()).To(Equal(reflect.Slice))

			data := utils.FormatTableData(x, "")

			// for a single array, there should only be one column
			// i.e. only one header
			Expect(len(data.Headers)).To(Equal(1))
			Expect(data.Headers[0].Value).To(Equal("values")) // the default column header

			// there should be a row for each value in the array, so two
			// each row should only have one item
			Expect(len(data.Values)).To(Equal(2))
			Expect(len(data.Values[0])).To(Equal(1))
			Expect(len(data.Values[1])).To(Equal(1))

			Expect(data.Values[0][0].Value).To(Equal("foo"))
			Expect(data.Values[1][0].Value).To(Equal("bar"))
		})

		It("Should return a table for an array of numbers", func() {
			// array value
			// note: the go sdk only produces integers of type int64
			x := [2]int64{1, 2}

			// array values should be explicitly handled in the formatter
			Expect(reflect.ValueOf(x).Kind()).To(Equal(reflect.Array))

			// pass in a mock jmesquery
			data := utils.FormatTableData(x, "resources[0].list_prop")

			// for a single array, there should only be one column
			// i.e. only one header
			Expect(len(data.Headers)).To(Equal(1))
			Expect(data.Headers[0].Value).To(Equal("list_prop")) // the last query segment

			// there should be a row for each value in the array, so two
			// each row should only have one item
			Expect(len(data.Values)).To(Equal(2))
			Expect(len(data.Values[0])).To(Equal(1))
			Expect(len(data.Values[1])).To(Equal(1))

			Expect(data.Values[0][0].Value).To(Equal("1"))
			Expect(data.Values[1][0].Value).To(Equal("2"))
		})

		It("Should return a table for a list of maps", func() {
			// slice of maps
			x := []map[string]int64{
				{"foo": 1, "bar": 2},
				{"foo": 3, "bar": 4},
			}

			utils.TableHeaderOrder = []string{"foo", "bar"}

			data := utils.FormatTableData(x, "")

			// there should be two columns and two rows
			Expect(len(data.Headers)).To(Equal(2))
			Expect(data.Headers[0].Value).To(Equal("foo"))
			Expect(data.Headers[1].Value).To(Equal("bar"))

			Expect(len(data.Values)).To(Equal(2))
			Expect(len(data.Values[0])).To(Equal(2))
			Expect(len(data.Values[1])).To(Equal(2))

			Expect(data.Values[0][0].Value).To(Equal("1"))
			Expect(data.Values[0][1].Value).To(Equal("2"))
			Expect(data.Values[1][0].Value).To(Equal("3"))
			Expect(data.Values[1][1].Value).To(Equal("4"))
		})

		It("Should include all columns in the final table, even if they aren't present in all maps", func() {
			// slice of maps
			x := []map[string]int64{
				{"foo": 1},
				{"bar": 4},
			}

			utils.TableHeaderOrder = []string{"foo", "bar"}

			data := utils.FormatTableData(x, "")

			// there should be two columns and two rows
			Expect(len(data.Headers)).To(Equal(2))
			Expect(data.Headers[0].Value).To(Equal("foo"))
			Expect(data.Headers[1].Value).To(Equal("bar"))

			Expect(len(data.Values)).To(Equal(2))
			Expect(len(data.Values[0])).To(Equal(2))
			Expect(len(data.Values[1])).To(Equal(2))

			Expect(data.Values[0][0].Value).To(Equal("1"))
			Expect(data.Values[0][1].Value).To(Equal("-"))
			Expect(data.Values[1][0].Value).To(Equal("-"))
			Expect(data.Values[1][1].Value).To(Equal("4"))
		})

		It("Should skip url fields for a list of maps", func() {
			// slice of maps
			x := []map[string]int64{
				{"url": 1, "bar": 2},
				{"foo": 3, "bar": 4},
			}

			data := utils.FormatTableData(x, "")

			// there should be two columns and no headers should be "url"
			Expect(len(data.Headers)).To(Equal(2))
			for _, header := range data.Headers {
				Expect(header).NotTo(Equal("url"))
			}
		})

		It("Should skip crn fields for a list of maps", func() {
			// slice of maps
			x := []map[string]int64{
				{"crn": 1, "bar": 2},
				{"foo": 3, "bar": 4},
			}

			data := utils.FormatTableData(x, "")

			// there should be two columns and no headers should be "crn"
			Expect(len(data.Headers)).To(Equal(2))
			for _, header := range data.Headers {
				Expect(header).NotTo(Equal("crn"))
			}
		})

		It("Should return a transposed table for a map with one map array property", func() {
			// map with one array property
			x := map[string]interface{}{
				"array_values": []map[string]int64{
					{"black": 1, "green": 2},
					{"black": 3, "green": 4},
				},
				"foo": "foo_prop",
				"bar": int64(42),
			}

			utils.TableHeaderOrder = []string{"foo", "bar", "array_values"}

			data := utils.FormatTableData(x, "")

			// there should be four columns and two rows
			Expect(data.Headers).To(ContainElements(utils.TableCell{}))

			Expect(len(data.Values)).To(Equal(3))
			Expect(len(data.Values[0])).To(Equal(2))
			Expect(len(data.Values[1])).To(Equal(2))
			Expect(len(data.Values[2])).To(Equal(2))

			Expect(data.Values[0][0].Value).To(Equal("foo"))
			Expect(data.Values[0][1].Value).To(Equal("foo_prop"))

			Expect(data.Values[1][0].Value).To(Equal("bar"))
			Expect(data.Values[1][1].Value).To(Equal("42"))

			Expect(data.Values[2][0].Value).To(Equal("array_values"))
			Expect(data.Values[2][1].Value).To(Equal("        \nblack   1\ngreen   2\n        \nblack   3\ngreen   4\n"))
		})

		It("Should return a table for a map with two array properties", func() {
			// map with two array properties
			x := map[string]interface{}{
				"array_values":      []int64{1, 2, 3, 4},
				"more_array_values": []int64{5, 6},
				"foo":               "foo_prop",
				"bar":               int64(42),
			}

			utils.TableHeaderOrder = []string{"array_values", "more_array_values", "foo", "bar"}

			data := utils.FormatTableData(x, "")

			// there should be two columns because output is transposed
			Expect(len(data.Headers)).To(Equal(2))

			Expect(data.Headers[0].Value).To(Equal(""))
			Expect(data.Headers[1].Value).To(Equal(""))

			Expect(len(data.Values)).To(Equal(4))
			Expect(len(data.Values[0])).To(Equal(2))

			Expect(data.Values[0][0].Value).To(Equal("array_values"))
			Expect(data.Values[0][1].Value).To(Equal("[1, 2, 3, 4]"))
			Expect(data.Values[1][0].Value).To(Equal("more_array_values"))
			Expect(data.Values[1][1].Value).To(Equal("[5, 6]"))
			Expect(data.Values[2][0].Value).To(Equal("foo"))
			Expect(data.Values[2][1].Value).To(Equal("foo_prop"))
			Expect(data.Values[3][0].Value).To(Equal("bar"))
			Expect(data.Values[3][1].Value).To(Equal("42"))
		})

		It("Should return a table for a map with no array properties", func() {
			// map with all non-arrays
			x := map[string]interface{}{
				"foo": "foo_prop",
				"bar": int64(42),
			}

			utils.TableHeaderOrder = []string{"foo", "bar"}

			data := utils.FormatTableData(x, "")

			// there should be two columns and two rows
			Expect(len(data.Headers)).To(Equal(2))
			Expect(data.Headers[0].Value).To(Equal(""))
			Expect(data.Headers[1].Value).To(Equal(""))

			Expect(len(data.Values)).To(Equal(2))
			Expect(len(data.Values[0])).To(Equal(2))

			Expect(data.Values[0][0].Value).To(Equal("foo"))
			Expect(data.Values[0][1].Value).To(Equal("foo_prop"))
			Expect(data.Values[1][0].Value).To(Equal("bar"))
			Expect(data.Values[1][1].Value).To(Equal("42"))
		})

		It("Should skip url and crn fields in a flat map", func() {
			// map with all non-arrays
			x := map[string]interface{}{
				"foo": "foo_prop",
				"bar": int64(42),
				"url": "www.ibm.com/skipthisurlitissuperlong",
				"crn": "crn:v1:public:someservice:some-region:scopeid123:instance_id456:thing:thing_id789",
			}

			data := utils.FormatTableData(x, "")

			// there should be two columns and no headers should be "url"
			Expect(len(data.Headers)).To(Equal(2))
			for _, header := range data.Headers {
				Expect(header).NotTo(Equal("url"))
				Expect(header).NotTo(Equal("crn"))
			}
		})

		It("Should return a table for an empty map", func() {
			x := map[string]interface{}{}
			data := utils.FormatTableData(x, "")

			// there should be no column headers
			// this is how the table printer knows not to print
			// an empty table
			Expect(len(data.Headers)).To(Equal(0))
			Expect(len(data.Values)).To(Equal(1))
		})

		It("Should return a table for a single value", func() {
			x := int64(4)
			data := utils.FormatTableData(x, "resource.number_prop")

			// there should be one column and one row
			Expect(len(data.Headers)).To(Equal(1))
			Expect(data.Headers[0].Value).To(Equal("number_prop"))

			Expect(len(data.Values)).To(Equal(1))
			Expect(len(data.Values[0])).To(Equal(1))

			Expect(data.Values[0][0].Value).To(Equal("4"))
		})
	})
})
