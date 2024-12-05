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
	"reflect"

	JmesPath "github.com/jmespath/go-jmespath"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Test suite
var _ = Describe("Table Printer Utils", func() {

	Describe("GetLastQuerySegment", func() {
		It("Should return default if query is empty", func() {
			seg := utils.GetLastQuerySegment("")
			Expect(seg).To(Equal("values"))
		})

		It("Should return last segment in query, split by period", func() {
			seg := utils.GetLastQuerySegment("foo.bar.resources")
			Expect(seg).To(Equal("resources"))
		})

		It("Should return whole query if it contains no periods", func() {
			seg := utils.GetLastQuerySegment("resources")
			Expect(seg).To(Equal("resources"))
		})
	})

	Describe("DerefValue", func() {
		It("Should return value if not pointer or interface", func() {
			x := "foo"
			value := reflect.ValueOf(x)
			Expect(value.Kind()).To(Equal(reflect.String))

			Expect(utils.DerefValue(value).Kind()).To(Equal(reflect.String))
		})

		It("Should return element if value is pointer", func() {
			x := "foo"
			value := reflect.ValueOf(&x)
			Expect(value.Kind()).To(Equal(reflect.Ptr))

			Expect(utils.DerefValue(value).Kind()).To(Equal(reflect.String))
		})

		It("Should return element if value is interface", func() {
			x := map[string]interface{}{
				"foo": "bar",
			}
			value := reflect.ValueOf(x["foo"])
			Expect(utils.DerefValue(value).Kind()).To(Equal(reflect.String))
		})
	})

	Describe("GetStringValue", func() {
		It("Should return a hyphen when given a nil value", func() {
			data := reflect.ValueOf(nil)
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("-"))
		})

		It("Should handle a string", func() {
			data := reflect.ValueOf("test")
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("test"))
		})

		It("Should handle a boolean", func() {
			data := reflect.ValueOf(true)
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("true"))
		})

		It("Should handle an int64", func() {
			var x int64 = 42
			data := reflect.ValueOf(x)
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("42"))
		})

		It("Should handle a float32", func() {
			var x float32 = 3.14
			data := reflect.ValueOf(x)
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("3.14"))
		})

		It("Should handle float64", func() {
			var x float64 = 0.3333
			data := reflect.ValueOf(x)
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("0.3333"))
		})

		It("Should handle a map", func() {
			data := reflect.ValueOf(map[string]int{"a": 1, "b": 2})
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("<Nested Object>"))
		})

		It("Should handle an empty map", func() {
			data := reflect.ValueOf(map[string]int{})
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("-"))
		})

		It("Should handle a slice with integers", func() {
			data := reflect.ValueOf([]int64{1, 2, 3})
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("[1, 2, 3]"))
		})

		It("Should handle a slice with strings", func() {
			data := reflect.ValueOf([]string{"foo", "bar", "baz"})
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("[foo, bar, baz]"))
		})

		It("Should handle a slice with integers", func() {
			data := reflect.ValueOf([]interface{}{"foo", "bar"})
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("[foo, bar]"))
		})

		It("Should handle a slice with inner slices", func() {
			data := reflect.ValueOf([][]int64{[]int64{1, 2, 3}, []int64{5, 6, 7}})
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("[[1, 2, 3], [5, 6, 7]]"))
		})

		It("Should handle a slice with no elements", func() {
			data := reflect.ValueOf([]string{})
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("-"))
		})

		It("Should return a hyphen for an unsupported type (like struct)", func() {
			type TestStruct struct {
				Foo string
			}

			data := reflect.ValueOf(TestStruct{Foo: "bar"})
			str := utils.GetStringValue(data)
			Expect(str).To(Equal("-"))
		})
	})

	Describe("GetStringValueExploded", func() {
		It("Should handle a map", func() {
			data := reflect.ValueOf(map[string]int64{"a": 1, "b": 2})
			str, callback := utils.GetStringValueExploded(data, 1)
			Expect(str).To(Equal("    \na   1\nb   2\n"))
			Expect(callback).ToNot(BeNil())
		})

		It("Should handle an empty map", func() {
			data := reflect.ValueOf(map[string]interface{}{})
			str, callback := utils.GetStringValueExploded(data, 1)
			Expect(str).To(Equal("-"))
			Expect(callback).To(BeNil())
		})

		It("Should handle an array of maps", func() {
			data := reflect.ValueOf([]map[string]int64{map[string]int64{"a": 1, "b": 2}, map[string]int64{"c": 3, "d": 4}})
			str, callback := utils.GetStringValueExploded(data, 1)
			Expect(str).To(Equal("    \na   1\nb   2\n    \nc   3\nd   4\n"))
			Expect(callback).ToNot(BeNil())
		})
	})

	Describe("GetArrayElementType", func() {
		It("Should return the type of element in the array", func() {
			data := []string{"foo", "bar"}
			value := reflect.ValueOf(data)
			kind := utils.GetArrayElementType(value)

			Expect(kind).To(Equal(reflect.String))
		})

		It("Should determine type of array element when wrapped in interface", func() {
			var foo interface{}
			var bar interface{}

			foo = "foo"
			bar = "bar"

			data := []interface{}{foo, bar}

			value := reflect.ValueOf(data)
			kind := utils.GetArrayElementType(value)

			Expect(kind).To(Equal(reflect.String))
		})
	})

	Describe("IsArrayType", func() {
		It("Should return true if kind is a slice", func() {
			x := []string{"foo", "bar"}

			kind := reflect.ValueOf(x).Kind()
			Expect(kind).To(Equal(reflect.Slice))

			Expect(utils.IsArrayType(kind)).To(Equal(true))
		})

		It("Should return true if kind is an array", func() {
			x := [2]int64{1, 2}

			kind := reflect.ValueOf(x).Kind()
			Expect(kind).To(Equal(reflect.Array))

			Expect(utils.IsArrayType(kind)).To(Equal(true))
		})

		It("Should return false if kind is not array or slice", func() {
			x := map[string]string{"foo": "one", "bar": "two"}

			kind := reflect.ValueOf(x).Kind()
			Expect(kind).To(Equal(reflect.Map))

			Expect(utils.IsArrayType(kind)).To(Equal(false))
		})
	})

	Describe("IsValidTableData", func() {
		It("Should return true if table exists and has headers", func() {
			data := new(utils.TableData)
			data.Headers = []utils.TableCell{utils.TableCell{Value: "header"}}
			data.Values = [][]utils.TableCell{[]utils.TableCell{utils.TableCell{Value: "value"}}}

			Expect(utils.IsValidTableData(data)).To(Equal(true))
		})

		It("Should return false if data is nil", func() {
			var data *utils.TableData

			Expect(utils.IsValidTableData(data)).To(Equal(false))
		})

		It("Should return false if data has no headers", func() {
			data := new(utils.TableData)
			data.Values = [][]utils.TableCell{[]utils.TableCell{utils.TableCell{Value: "value"}}}

			Expect(utils.IsValidTableData(data)).To(Equal(false))
		})
	})
	Describe("GetHeadersFromJMES", func() {
		It("Should return the correct headers when there are multiple SelectHashMaps", func() {
			parsed, err := JmesPath.NewParser().Parse(`objects[*].{"id::": "id",name: name,d: description}[*].{"_description_": d, "id": "id::"," { n }": name}`)
			Expect(err).To(BeNil())
			headers := utils.GetHeadersFromJMES(parsed, false)
			Expect(headers).To(Equal([]string{"_description_", "id", " { n }"}))
		})

		It("Should return the correct headers when the SelectHashMaps is not the last element", func() {
			parsed, err := JmesPath.NewParser().Parse(`objects[*].{"id::": "id",name: name,d: description}[*]`)
			Expect(err).To(BeNil())
			headers := utils.GetHeadersFromJMES(parsed, false)
			Expect(headers).To(Equal([]string{"id::", "name", "d"}))
		})

		It("Should not return any headers", func() {
			parsed, err := JmesPath.NewParser().Parse(`objects[*]`)
			Expect(err).To(BeNil())
			headers := utils.GetHeadersFromJMES(parsed, false)
			Expect(headers).To(BeEmpty())
		})
	})
})
