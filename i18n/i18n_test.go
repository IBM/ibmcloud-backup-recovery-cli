/**
 * (C) Copyright IBM Corp. 2023.
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

package i18n

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test the `GetResourcePath` function.
func TestGetResourcePath(t *testing.T) {
	localResourcePath := GetResourcePath()
	assert.Equal(t, resourcePath, localResourcePath)
}

// Test the `SetResourcePath` function.
func TestSetResourcePath(t *testing.T) {
	originalResourcePath := resourcePath

	newResourcePath := "fake-resource-path"
	SetResourcePath(newResourcePath)
	assert.Equal(t, resourcePath, newResourcePath)

	// Set back to the original.
	resourcePath = originalResourcePath
}

// Test the `initLocale` function with a valid value.
func TestInitWithLocaleSuccess(t *testing.T) {
	translateFunc := initWithLocale("en_US")
	assert.NotNil(t, translateFunc)
}

// Test the `initLocale` function with an invalid value.
func TestInitWithLocaleFail(t *testing.T) {
	assert.Panics(t, func() { initWithLocale("fake-locale") })
}

// Test the `loadResources` with an existing resource.
func TestLoadResourcesExist(t *testing.T) {
	err := loadResources("en_US")
	assert.Nil(t, err)
}

// Test the `loadResource` function when the resource doesn't exist.
func TestLoadResourcesNotExist(t *testing.T) {
	err := loadResources("fake_locale")
	assert.NotNil(t, err)
}

// Test Go's built-in resource embedding feature, to make sure
// it works as it should and we get the exactly same file.
func TestGoResourceEmbedding(t *testing.T) {
	filePath := "resources/all.en_US.json"
	bytes, err := resources.ReadFile(filePath)
	assert.Nil(t, err)

	// Read the file manually.
	bytesFile, err := os.ReadFile(filePath)
	assert.Nil(t, err)
	assert.Equal(t, bytesFile, bytes)
}

// Test the `supportedLocal` function with different locales.
func TestSupportedLocale(t *testing.T) {
	locale := supportedLocale("fake-locale")
	assert.Empty(t, locale)

	supported := SUPPORTED_LOCALES[0]
	locale = supportedLocale(supported)
	assert.Equal(t, supported, locale)

	locale = supportedLocale("zh_sg")
	assert.Equal(t, "zh_Hans", locale)

	locale = supportedLocale("zh_hk")
	assert.Equal(t, "zh_Hant", locale)
}

// Test the `normalizeLocale` function with different locales.
func TestNormalizeLocale(t *testing.T) {
	normalized := normalizeLocale("eNuS")
	assert.Equal(t, "enus", normalized)

	normalized = normalizeLocale("EN-US")
	assert.Equal(t, "en_us", normalized)

	normalized = normalizeLocale("en-US-x")
	assert.Equal(t, "en_us-x", normalized)
}

// Test the `defaultLocaleForLang` function with different values.
func TestDefaultLocaleForLang(t *testing.T) {
	defaultLocale := defaultLocaleForLang("")
	assert.Empty(t, defaultLocale)

	locale := SUPPORTED_LOCALES[0]
	lang := strings.ToUpper(locale[0:2])
	defaultLocale = defaultLocaleForLang(lang)
	assert.Equal(t, locale, defaultLocale)
}
