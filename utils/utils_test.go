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
	"errors"
	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/plugin"
	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/testhelpers/terminal"
	"github.com/IBM/go-sdk-core/v5/core"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/spf13/pflag"
	u "ibmcloud-backup-recovery-cli/utils"
	"io"
	"os"
	"reflect"
	"strings"
)

// set up a temporary directory to hold test files
var _ = BeforeSuite(func() {
	// create a temp mock directory
	defer GinkgoRecover()
	dirErr := os.Mkdir("tempdir", 0755)
	if dirErr != nil {
		Fail(dirErr.Error())
	}
})

// cleanup test file directory
var _ = AfterSuite(func() {
	defer GinkgoRecover()
	err := os.RemoveAll("tempdir")
	if err != nil {
		Fail(err.Error())
	}
})

// Test suite
var _ = Describe("Utils", func() {
	Describe("PrintOutput", func() {
		obj := map[string]interface{}{"foo": 1, "bar": "info"}

		yamlOutput := "bar: info\nfoo: 1\n\n"
		jsonOutput := "{\n  \"bar\": \"info\",\n  \"foo\": 1\n}\n"

		It("Should process the JMESPath", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.SetJMESQuery("foo")
			utils.SetOutputFormat("json")

			// using json as output format to simplify the output
			utils.PrintOutput(obj, ui.Writer())
			Expect(ui.Outputs()).To(Equal("1\n"))
		})

		It("Should marshal YAML", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.SetOutputFormat("yaml")
			utils.PrintOutput(obj, ui.Writer())
			Expect(ui.Outputs()).To(Equal(yamlOutput))
		})

		It("Should marshal JSON", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.SetOutputFormat("json")
			utils.PrintOutput(obj, ui.Writer())
			Expect(ui.Outputs()).To(Equal(jsonOutput))
		})

		It("Should default to the table", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.PrintOutput(obj, ui.Writer())

			// just check that the fields are printed and that the format isnt yaml or json
			// we can test the actual table output elsewhere
			Expect(strings.Contains(ui.Outputs(), "foo")).To(Equal(true))
			Expect(strings.Contains(ui.Outputs(), "bar")).To(Equal(true))

			Expect(ui.Outputs()).NotTo(Equal(jsonOutput))
			Expect(ui.Outputs()).NotTo(Equal(yamlOutput))
		})

		// the response processers may call PrintOutput with an empty string
		// verify that it handles that
		It("Should print an empty string for JSON", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.SetOutputFormat("json")
			utils.PrintOutput(u.EmptyString, ui.Writer())
			Expect(ui.Outputs()).To(Equal("\"\"\n"))
		})

		It("Should print an empty string for YAML", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.SetOutputFormat("yaml")
			utils.PrintOutput(u.EmptyString, ui.Writer())
			Expect(ui.Outputs()).To(Equal("\"\"\n\n"))
		})
	})

	Describe("ConfirmRunningCommand", func() {
		It("Should print something if output format is not 'json' or 'yaml'", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.ConfirmRunningCommand()
			Expect(ui.Outputs()).To(Equal("...\n"))
		})

		It("Should not print anything if output format is 'json'", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.SetOutputFormat("json")
			utils.ConfirmRunningCommand()
			Expect(ui.Outputs()).To(Equal(""))
		})

		It("Should not print anything if output format is 'yaml'", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.SetOutputFormat("yaml")
			utils.ConfirmRunningCommand()
			Expect(ui.Outputs()).To(Equal(""))
		})
	})

	Describe("ReadAsFile", func() {
		It("Should return true if the first character of the input is @", func() {
			result := u.ReadAsFile("@path/to/file.txt")
			Expect(result).To(Equal(true))
		})

		It("Should return false is the first character of the input is not @", func() {
			result := u.ReadAsFile("some json string")
			Expect(result).To(Equal(false))
		})
	})

	Describe("Ok", func() {
		It("Should print 'Ok' when output format is not json/yaml", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.Ok()
			Expect(ui.Outputs()).To(Equal("OK\n"))
		})

		It("Should not print 'Ok' when output format is json/yaml", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.SetOutputFormat("json")
			utils.Ok()
			Expect(ui.Outputs()).To(Equal(u.EmptyString))
		})
	})

	Describe("Verbose", func() {
		It("should print nothing in quiet mode", func() {
			ui := terminal.NewFakeUI()
			ui.SetQuiet(true)
			utils := u.NewUtils(ui)
			str := "test string"
			utils.Verbose(str)
			Expect(ui.Outputs()).To(Equal(""))
		})

		It("should print to the stdout in non quiet mode", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			str := "test string"
			utils.Verbose(str)
			Expect(ui.Outputs()).To(Equal(str + "\n"))
		})
	})

	Describe("Print", func() {
		It("should print to the stdout in quiet mode", func() {
			ui := terminal.NewFakeUI()
			ui.SetQuiet(true)
			utils := u.NewUtils(ui)
			str := "test string"
			utils.Print(str)
			Expect(ui.Outputs()).To(Equal(str + "\n"))
		})

		It("should print to the stdout in non quiet mode", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			str := "test string"
			utils.Print(str)
			Expect(ui.Outputs()).To(Equal(str + "\n"))
		})
	})

	It("Warn", func() {
		ui := terminal.NewFakeUI()
		utils := u.NewUtils(ui)
		str := "test warning"
		utils.Warn(str)
		Expect(ui.Errors()).To(Equal(str + "\n"))
	})

	Describe("WriteFile", func() {
		It("Should write data to a new file", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			message := "This is a mock file."
			filepath := "tempdir/new-file.txt"
			err := utils.WriteFile(io.NopCloser(strings.NewReader(message)), filepath)
			Expect(err).To(BeNil())

			_, fileDoesntExist := os.Stat(filepath)
			Expect(fileDoesntExist).To(BeNil())
		})

		It("Should return an error if file cannot be created", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			message := "This is a mock file."
			filepath := "tempdir/not-here/negative-test.txt"

			err := utils.WriteFile(io.NopCloser(strings.NewReader(message)), filepath)
			Expect(err).NotTo(BeNil())
		})

		It("Should return an error if data given is not binary", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			err := utils.WriteFile("not binary data", "tempdir/negative-test.txt")
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("interface conversion: file argument is not io.ReadCloser"))
		})
	})

	Describe("GetJsonStringAsBytes", func() {
		jsonString := `{"foo": "bar", "baz": 123, "true": false, "nested": [{"prop1": 1}, {"prop2": 2}]}`
		yamlString := "foo: bar\nbaz: 123\ntrue: false\nnested:\n- prop1: 1\n- prop2: 2"

		It("Should read string from file and return byte array value of contents", func() {
			// create a file to read from
			message := []byte("This is a mock file.")
			fileErr := os.WriteFile("tempdir/test-file.txt", message, 0644)
			if fileErr != nil {
				Fail(fileErr.Error())
			}

			result, err, msg := u.GetJsonStringAsBytes("@tempdir/test-file.txt")
			Expect(result).To(Equal([]byte(message)))
			Expect(err).To(BeNil())
			Expect(msg).To(Equal(""))
		})

		It("Should return byte array value of string", func() {
			string := "some json string"
			result, err, msg := u.GetJsonStringAsBytes(string)
			Expect(result).To(Equal([]byte(string)))
			Expect(err).To(BeNil())
			Expect(msg).To(Equal(""))
		})

		It("Should return the unmodified JSON", func() {
			result, err, msg := u.GetJsonStringAsBytes(jsonString)
			Expect(result).To(Equal([]byte(jsonString)))
			Expect(err).To(BeNil())
			Expect(msg).To(Equal(""))
		})

		It("Should return the converted JSON", func() {
			result, err, msg := u.GetJsonStringAsBytes(yamlString)
			Expect(result).To(MatchJSON(jsonString))
			Expect(err).To(BeNil())
			Expect(msg).To(Equal(""))
		})
	})

	Describe("MakeResultGeneric", func() {
		type TestStruct struct {
			Foo string `json:"foo,omitempty"`
			Bar string `json:"bar,omitempty"`
		}

		It("Should convert a struct instance to an interface of type 'map'", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			testInstance := TestStruct{
				Foo: "one",
				Bar: "two",
			}

			Expect(reflect.ValueOf(testInstance).Kind()).To(Equal(reflect.Struct))

			data := utils.MakeResultGeneric(testInstance)
			value := reflect.ValueOf(data)
			Expect(value.Kind()).To(Equal(reflect.Map))
		})
	})

	Describe("GetResult", func() {
		It("Should return response body if the response is successful", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			res := new(core.DetailedResponse)
			res.Result = "success body"
			result, errBody, err := utils.GetResult(res, nil)

			Expect(err).To(BeNil())
			Expect(errBody).To(BeNil())
			Expect(result).To(Equal("success body"))
		})

		It("Should return all nils if the response is successful but empty", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			res := new(core.DetailedResponse)
			result, errBody, err := utils.GetResult(res, nil)

			Expect(err).To(BeNil())
			Expect(errBody).To(BeNil())
			Expect(result).To(BeNil())
		})

		It("Should return error body and print 'FAILED' if error result is present", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			res := new(core.DetailedResponse)
			res.Result = "error body"
			resErr := errors.New("error message")
			result, errBody, err := utils.GetResult(res, resErr)

			Expect(err).To(BeNil())
			Expect(result).To(BeNil())
			Expect(errBody).To(Equal("error body"))
			Expect(strings.Contains(ui.Errors(), "FAILED")).To(Equal(true))
			Expect(strings.Contains(ui.Errors(), "error message")).To(Equal(true))
		})

		It("Should only return the error object if one exists but the response is empty", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			resErr := errors.New("error message")
			result, errBody, err := utils.GetResult(nil, resErr)

			Expect(result).To(BeNil())
			Expect(errBody).To(BeNil())
			Expect(err).To(Equal(resErr))
		})

		It("Should only return the error object if one exists but the result is empty", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			res := new(core.DetailedResponse)
			resErr := errors.New("error message")
			result, errBody, err := utils.GetResult(res, resErr)

			Expect(result).To(BeNil())
			Expect(errBody).To(BeNil())
			Expect(err).To(Equal(resErr))
		})

		It("Should return an error when response and error are both nil", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			result, errBody, err := utils.GetResult(nil, nil)

			expectedError := errors.New("No information was returned from the service")

			Expect(result).To(BeNil())
			Expect(errBody).To(BeNil())
			Expect(err).To(Equal(expectedError))
		})

		It("Should return raw response and print 'FAILED' if body result is not present but raw result is", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			rawResultAsString := "request is missing something"

			res := new(core.DetailedResponse)
			res.RawResult = []byte(rawResultAsString)

			// response errors always accompany the raw result
			resErr := errors.New("error message")

			result, errBody, err := utils.GetResult(res, resErr)

			Expect(result).To(BeNil())
			Expect(errBody).To(Equal(rawResultAsString))
			Expect(err).To(BeNil())
			Expect(strings.Contains(ui.Errors(), "FAILED")).To(Equal(true))
			Expect(strings.Contains(ui.Errors(), "error message")).To(Equal(true))
		})
	})

	Describe("OutputIsNotMachineReadable", func() {
		It("Should return true if output format is not 'json' or 'yaml'", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			result := utils.OutputIsNotMachineReadable()
			Expect(result).To(Equal(true))
		})

		It("Should return false if output format is 'json'", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.SetOutputFormat("json")
			result := utils.OutputIsNotMachineReadable()
			Expect(result).To(Equal(false))
		})

		It("Should return false if output format is 'yaml'", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.SetOutputFormat("yaml")
			result := utils.OutputIsNotMachineReadable()
			Expect(result).To(Equal(false))
		})
	})

	Describe("Expose Property Pointers", func() {
		It("Should return a pointer to the utils OutputFormat property", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			pointer := utils.ExposeOutputFormatVar()

			// expect to be string pointer type
			value := reflect.ValueOf(pointer)
			Expect(value.Kind()).To(Equal(reflect.Ptr))
			Expect(value.Elem().Kind()).To(Equal(reflect.String))

			*pointer = "string"
			Expect(utils.OutputFormat).To(Equal("string"))
		})

		It("Should return a pointer to the utils JMESQuery property", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			pointer := utils.ExposeJMESQueryVar()

			// expect to be string pointer type
			value := reflect.ValueOf(pointer)
			Expect(value.Kind()).To(Equal(reflect.Ptr))
			Expect(value.Elem().Kind()).To(Equal(reflect.String))

			*pointer = "string"
			Expect(utils.JMESQuery).To(Equal("string"))
		})
	})

	Describe("Property Setters", func() {
		It("Should set the OutputFormat property", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			utils.SetOutputFormat("string")

			Expect(utils.OutputFormat).To(Equal("string"))
		})

		It("Should set the JMESQuery property", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)

			utils.SetJMESQuery("string")

			Expect(utils.JMESQuery).To(Equal("string"))
		})
	})

	Describe("Property Getters", func() {
		It("Should get the OutputFormat property", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.OutputFormat = "string"

			Expect(utils.GetOutputFormat()).To(Equal("string"))
		})

		It("Should get the JMESQuery property", func() {
			ui := terminal.NewFakeUI()
			utils := u.NewUtils(ui)
			utils.JMESQuery = "string"

			Expect(utils.GetJMESQuery()).To(Equal("string"))
		})
	})

	Describe("ValidateRequiredFlags", func() {
		context := plugin.InitPluginContext("test")
		ui := terminal.NewFakeUI()
		utils := u.NewUtils(ui)
		utils.SetContext(context)
		name := "test"

		// create a flag set
		flags := pflag.NewFlagSet("test", 0)
		flags.AddFlag(&pflag.Flag{
			Name: "foo",
			// the changed property is how we determine if a flag is set or not
			Changed: true,
		})

		It("Should not error if there are no required flags", func() {
			required := []string{}
			err := utils.ValidateRequiredFlags(required, flags, name)
			Expect(err).To(BeNil())
		})

		It("Should not error if all required flags are present", func() {
			required := []string{
				"foo",
			}

			err := utils.ValidateRequiredFlags(required, flags, name)
			Expect(err).To(BeNil())
		})

		It("Should error if not all required flags are present", func() {
			required := []string{
				"foo",
				"bar",
			}

			err := utils.ValidateRequiredFlags(required, flags, name)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("required flag(s) \"bar\" not set"))
		})
	})

	Describe("CreateErrorWithMessage", func() {
		ui := terminal.NewFakeUI()
		utils := u.NewUtils(ui)

		message := "descriptive info"
		originalError := errors.New("error message")

		It("Should return nil when the error is nil", func() {
			err := utils.CreateErrorWithMessage(nil, message)
			Expect(err).To(BeNil())
		})

		It("Should add the message as a prefix to the error message", func() {
			err := utils.CreateErrorWithMessage(originalError, message)
			Expect(err).NotTo(BeNil())
			Expect(err.Error()).To(Equal("descriptive info:\nerror message"))
		})
	})

	Describe("Get/Set Command Name", func() {
		ui := terminal.NewFakeUI()
		utils := u.NewUtils(ui)

		It("Should not fail or set a command name if args are empty", func() {
			var args []string
			utils.SetCommandName(args)
			Expect(utils.GetCommandName()).To(Equal(""))
		})

		It("Should set name to first element in args, then give access through getter", func() {
			args := []string{"regions", "--cloud-id", "03219"}
			utils.SetCommandName(args)
			name := utils.GetCommandName()
			Expect(name).To(Equal("regions"))
		})
	})

	Describe("ValidateJSON", func() {
		ui := terminal.NewFakeUI()
		utils := u.NewUtils(ui)

		It("Should pass and return an empty slice", func() {
			input := `{"prop1": "foo", "prop2": "bar", "prop3": "baz"}`
			validator := `{"fields": ["prop1","prop2","prop3"]}`
			result, err := utils.ValidateJSON(input, validator)
			Expect(err).To(BeNil())
			Expect(result).To(HaveLen(0))
		})

		It("Should pass on extraneous fields due to additional properties (simple)", func() {
			input := `{"prop1": "foo", "prop2": "bar", "prop3": "baz"}`
			validator := `{"fields": ["#hasAdditionalProperties"]}`
			result, err := utils.ValidateJSON(input, validator)
			Expect(err).To(BeNil())
			Expect(result).To(HaveLen(0))
		})

		It("Should pass on extraneous fields due to additional properties (nested map)", func() {
			input := `{"prop1": "foo", "prop2": "bar", "prop3": {"prop4": {"prop5": 111, "prop6": 222}}}`
			validator := `{"schemas": {"Prop3Schema": ["prop4#PROP4"], "PROP4": ["#hasAdditionalProperties"]}, "fields": ["prop1","prop2","prop3#Prop3Schema"]}`
			result, err := utils.ValidateJSON(input, validator)
			Expect(err).To(BeNil())
			Expect(result).To(HaveLen(0))
		})

		It("Should pass on extraneous fields due to inner additional properties (nested map)", func() {
			input := `{"prop1": "foo", "prop2": "bar", "prop3": {"prop4": {"prop5": 111, "prop6": 222, "extraField": 999}}}`
			validator := `{"schemas": {"prop3": ["prop4#PROP3"], "PROP3": ["prop5", "#hasAdditionalProperties"]}, "fields": ["prop1","prop2","prop3#prop3"]}`
			result, err := utils.ValidateJSON(input, validator)
			Expect(err).To(BeNil())
			Expect(result).To(HaveLen(0))
		})

		It("Should found an extraneous field and return a slice with a single element (simple)", func() {
			input := `{"prop1": "foo", "prop2": "bar", "prop3": "baz"}`
			validator := `{"fields": ["prop1","prop2","prop"]}`
			result, err := utils.ValidateJSON(input, validator)
			Expect(err).To(BeNil())
			Expect(result).To(HaveLen(1))
			Expect(result).To(ContainElement("#.prop3"))
		})

		It("Should found multiple extraneous fields and return a slice with 2 elements (simple)", func() {
			input := `{"prop1": "foo", "prop2": "bar", "prop3": "baz", "prop4": "foobar"}`
			validator := `{"fields": ["prop1","prop2","prop"]}`
			result, err := utils.ValidateJSON(input, validator)
			Expect(err).To(BeNil())
			Expect(result).To(HaveLen(2))
			Expect(result).To(ContainElements("#.prop3", "#.prop4"))
		})

		It("Should found multiple extraneous fields and return a slice with 2 elements (simple)", func() {
			input := `{"prop1": "foo", "prop2": "bar", "prop3": "baz", "prop4": {"prop5": "lorem", "prop6": "ipsum"}}`
			validator := `{"fields": ["prop1","prop2","prop"]}`
			result, err := utils.ValidateJSON(input, validator)
			Expect(err).To(BeNil())
			Expect(result).To(HaveLen(2))
			Expect(result).To(ContainElements("#.prop3", "#.prop4"))
		})

		It("Should found extraneous fields and return a slice with a single element (nested map)", func() {
			input := `{"prop1": "foo", "prop2": "bar", "prop3": {"prop4": {"prop5": 111, "prop6": 222}}}`
			validator := `{"schemas": {"prop3schema": ["prop4#PROP4"], "PROP4": ["prop5"]}, "fields": ["prop1","prop2","prop3#prop3schema"]}`
			result, err := utils.ValidateJSON(input, validator)
			Expect(err).To(BeNil())
			Expect(result).To(HaveLen(1))
			Expect(result).To(ContainElement("#.prop3.prop4.prop6"))
		})

		It("Should found extraneous fields and return a slice with a single element (nested array)", func() {
			input := `{"prop1": "foo", "prop2": "bar", "prop3": [{"prop4": 0}, {"prop4": [{"prop5": 111, "prop6": 222}]}]}`
			validator := `{"schemas": {"prop3": ["prop4#prop4"], "prop4": ["prop5"]}, "fields": ["prop1","prop2","prop3#prop3"]}`
			result, err := utils.ValidateJSON(input, validator)
			Expect(err).To(BeNil())
			Expect(result).To(HaveLen(1))
			Expect(result).To(ContainElement("#.prop3.[1].prop4.[0].prop6"))
		})

		It("Should found extraneous fields and return a slice with multiple elements (nested array)", func() {
			input := `{"prop1": "foo", "prop2": "bar", "prop3": [{"prop4": 0}, {"prop4": [{"prop5": 111, "prop6": 222, "prop7": 333}], "prop8": 444}]}`
			validator := `{"schemas": {"prop3": ["prop4#prop4"], "prop4": ["prop5"]}, "fields": ["prop1","prop2","prop3#prop3"]}`
			result, err := utils.ValidateJSON(input, validator)
			Expect(err).To(BeNil())
			Expect(result).To(HaveLen(3))
			Expect(result).To(ContainElements("#.prop3.[1].prop8", "#.prop3.[1].prop4.[0].prop6", "#.prop3.[1].prop4.[0].prop7"))
		})

		It("Should found extraneous fields and return a slice with a single element (nested map, additional properties)", func() {
			// Note that the additional properties are enabled on the top level, but we have an extra field in an inner map.
			input := `{"prop1": "foo", "prop2": "bar", "prop3": {"prop4": {"prop5": 111, "prop6": 222}}, "prop7": 333}`
			validator := `{"schemas": {"prop3": ["prop4#PROP3"], "PROP3": ["prop5"]}, "fields": ["prop1","prop2","prop3#prop3", "#hasAdditionalProperties"]}`
			result, err := utils.ValidateJSON(input, validator)
			Expect(err).To(BeNil())
			Expect(result).To(HaveLen(1))
			Expect(result).To(ContainElement("#.prop3.prop4.prop6"))
		})
	})

	Describe("Set operation metadata", func() {
		ui := terminal.NewFakeUI()
		utils := u.NewUtils(ui)

		It("Should not fail if the correct type used", func() {
			data := u.OperationMetadata{}
			err := utils.SetOperationMetadata(data)
			Expect(err).To(BeNil())
		})

		It("Should fail if incorrect type used", func() {
			data := map[string]interface{}{}
			err := utils.SetOperationMetadata(data)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Set JMESPath queries", func() {
		ui := terminal.NewFakeUI()
		utils := u.NewUtils(ui)

		It("Should not fail if the correct type used", func() {
			data := u.JMESQueries{}
			err := utils.SetJMESQueries(data)
			Expect(err).To(BeNil())
		})

		It("Should fail if incorrect type used", func() {
			data := "clouds[*].name"
			err := utils.SetJMESQueries(data)
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("ProcessResponse", func() {
		ui := terminal.NewFakeUI()
		utils := u.NewUtils(ui)

		AfterEach(func() {
			utils.SetJMESQuery("")
		})

		Context("Success response", func() {
			response := new(core.DetailedResponse)
			response.StatusCode = 200
			response.Result = `{"clouds": []}`

			It("Should set the correct JMESPath query - no `all-pages`, table output", func() {
				utils.SetOutputFormat("table")
				err := utils.SetOperationMetadata(u.OperationMetadata{})
				Expect(err).To(BeNil())

				data := u.JMESQueries{
					Success: u.JMESQuery{
						Default: "clouds",
						Table:   "clouds[*].Name",
					},
				}
				err = utils.SetJMESQueries(data)
				Expect(err).To(BeNil())

				utils.ProcessResponse(response, nil)
				Expect(utils.GetJMESQuery()).To(Equal(data.Success.Table))

				// Reset.
				utils.SetJMESQuery("")
				// Remove the `table` query to make sure the default is used.
				data.Success.Table = ""
				err = utils.SetJMESQueries(data)
				Expect(err).To(BeNil())

				utils.ProcessResponse(response, nil)
				Expect(utils.GetJMESQuery()).To(Equal(data.Success.Default))
			})

			It("Should set the correct JMESPath query - no `all-pages`, JSON output", func() {
				utils.SetOutputFormat("json")
				err := utils.SetOperationMetadata(u.OperationMetadata{})
				Expect(err).To(BeNil())

				data := u.JMESQueries{
					Success: u.JMESQuery{
						Default: "clouds",
						Table:   "clouds[*].Name",
					},
				}
				err = utils.SetJMESQueries(data)
				Expect(err).To(BeNil())

				utils.ProcessResponse(response, nil)
				Expect(utils.GetJMESQuery()).To(Equal(data.Success.Default))
			})

			It("Should set the correct JMESPath query - `all-pages`, table output", func() {
				utils.SetOutputFormat("table")
				err := utils.SetOperationMetadata(u.OperationMetadata{AllPages: true})
				Expect(err).To(BeNil())

				data := u.JMESQueries{
					Success: u.JMESQuery{
						Default: "clouds",
						Table:   "clouds[*].name",
					},
					AllPages: u.JMESQuery{
						Default: "clouds.allpages",
						Table:   "clouds[*].allpages",
					},
				}
				err = utils.SetJMESQueries(data)
				Expect(err).To(BeNil())

				utils.ProcessResponse(response, nil)
				Expect(utils.GetJMESQuery()).To(Equal(data.AllPages.Table))

				// Reset.
				utils.SetJMESQuery("")
				// Remove the `table` query to make sure the default is used.
				data.AllPages.Table = ""
				err = utils.SetJMESQueries(data)
				Expect(err).To(BeNil())

				utils.ProcessResponse(response, nil)
				Expect(utils.GetJMESQuery()).To(Equal(data.AllPages.Default))

				// Reset.
				utils.SetJMESQuery("")
				// Remove the all `AllPages` queries to use the `Success` as the default.
				data.AllPages = u.JMESQuery{}
				err = utils.SetJMESQueries(data)
				Expect(err).To(BeNil())

				utils.ProcessResponse(response, nil)
				Expect(utils.GetJMESQuery()).To(Equal(data.Success.Table))
			})

			It("Should set the correct JMESPath query - `all-pages`, JSON output", func() {
				utils.SetOutputFormat("json")
				err := utils.SetOperationMetadata(u.OperationMetadata{AllPages: true})
				Expect(err).To(BeNil())

				data := u.JMESQueries{
					Success: u.JMESQuery{
						Default: "clouds",
						Table:   "clouds[*].name",
					},
					AllPages: u.JMESQuery{
						Default: "clouds.allpages",
						Table:   "clouds[*].allpages",
					},
				}
				err = utils.SetJMESQueries(data)
				Expect(err).To(BeNil())

				utils.ProcessResponse(response, nil)
				Expect(utils.GetJMESQuery()).To(Equal(data.AllPages.Default))

				// Reset.
				utils.SetJMESQuery("")
				// Remove the all `AllPages` queries to use the `Success` as the default.
				data.AllPages = u.JMESQuery{}
				err = utils.SetJMESQueries(data)
				Expect(err).To(BeNil())

				utils.ProcessResponse(response, nil)
				Expect(utils.GetJMESQuery()).To(Equal(data.Success.Default))
			})
		})

		Context("Error response", func() {
			response := new(core.DetailedResponse)
			response.StatusCode = 403
			response.Result = "You have no permission to view this resource. Get out!"
			responseErr := errors.New("forbidden")

			u.ExitFunction = func() {}

			It("Should set the correct JMESPath query - no `all-pages`, table output", func() {
				utils.SetOutputFormat("table")
				err := utils.SetOperationMetadata(u.OperationMetadata{})
				Expect(err).To(BeNil())

				data := u.JMESQueries{
					Error: u.JMESQuery{
						Default: "errors",
						Table:   "errors[*].reason",
					},
				}
				err = utils.SetJMESQueries(data)
				Expect(err).To(BeNil())

				utils.ProcessResponse(response, responseErr)
				Expect(utils.GetJMESQuery()).To(Equal(data.Error.Table))

				// Reset.
				utils.SetJMESQuery("")
				// Remove the `table` query to make sure the default is used.
				data.Error.Table = ""
				err = utils.SetJMESQueries(data)
				Expect(err).To(BeNil())

				utils.ProcessResponse(response, responseErr)
				Expect(utils.GetJMESQuery()).To(Equal(data.Error.Default))
			})

			It("Should set the correct JMESPath query - `all-pages`, JSON output", func() {
				utils.SetOutputFormat("json")
				err := utils.SetOperationMetadata(u.OperationMetadata{AllPages: true})
				Expect(err).To(BeNil())

				data := u.JMESQueries{
					Error: u.JMESQuery{
						Default: "errors",
						Table:   "errors[*].reason",
					},
				}
				err = utils.SetJMESQueries(data)
				Expect(err).To(BeNil())

				utils.ProcessResponse(response, responseErr)
				// Should be table, regardless the output.
				Expect(utils.GetJMESQuery()).To(Equal(data.Error.Table))

				// Reset.
				utils.SetJMESQuery("")
				// Remove the `table` query to make sure the default is used.
				data.Error.Table = ""
				err = utils.SetJMESQueries(data)
				Expect(err).To(BeNil())

				utils.ProcessResponse(response, responseErr)
				Expect(utils.GetJMESQuery()).To(Equal(data.Error.Default))
			})
		})
	})
})
