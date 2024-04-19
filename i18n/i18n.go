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
	"embed"
	"fmt"
	"path"
	"strings"

	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/i18n"
	goi18n "github.com/nicksnyder/go-i18n/v2/i18n"

	"github.com/IBM-Cloud/ibm-cloud-cli-sdk/bluemix/configuration/core_config"
)

const (
	DEFAULT_LOCALE = "en_US"
)

var SUPPORTED_LOCALES = []string{
	"en_US",
}

var resourcePath = "resources"
var bundle *goi18n.Bundle

//go:embed resources
var resources embed.FS

func GetResourcePath() string {
	return resourcePath
}

func SetResourcePath(path string) {
	resourcePath = path
}

var T i18n.TranslateFunc = Init(core_config.NewCoreConfig(func(e error) {}), new(LocaleDetector))

func Init(coreConfig core_config.Repository, detector Detector) i18n.TranslateFunc {
	bundle = i18n.Bundle()
	userLocale := coreConfig.Locale()
	if userLocale != "" {
		return initWithLocale(userLocale)
	}
	locale := supportedLocale(detector.DetectLocale())
	if locale == "" {
		locale = defaultLocaleForLang(detector.DetectLanguage())
	}
	if locale == "" {
		locale = DEFAULT_LOCALE
	}
	return initWithLocale(locale)
}

func initWithLocale(locale string) i18n.TranslateFunc {
	err := loadResources(locale)
	if err != nil {
		panic(err)
	}
	return i18n.MustTfunc(locale)
}

func loadResources(locale string) (err error) {
	resourceName := fmt.Sprintf("all.%s.json", locale)
	// resourcePath is i18n/resources
	// force absolute path to ensure resourceName is properly cleaned
	resourceName = path.Join("/", resourceName)
	// resulting path should always be cleaned of relative references (../)
	resourceKey := path.Join(resourcePath, resourceName)
	bytes, err := resources.ReadFile(resourceKey)
	if err != nil {
		return
	}
	_, err = bundle.ParseMessageFileBytes(bytes, resourceKey)
	return
}

func supportedLocale(locale string) string {
	locale = normalizeLocale(locale)
	for _, l := range SUPPORTED_LOCALES {
		if strings.EqualFold(locale, l) {
			return l
		}
	}
	switch locale {
	case "zh_cn", "zh_sg":
		return "zh_Hans"
	case "zh_hk", "zh_tw":
		return "zh_Hant"
	}
	return ""
}

func normalizeLocale(locale string) string {
	return strings.ToLower(strings.Replace(locale, "-", "_", 1))
}

func defaultLocaleForLang(lang string) string {
	if lang != "" {
		lang = strings.ToLower(lang)
		for _, l := range SUPPORTED_LOCALES {
			if lang == l[0:2] {
				return l
			}
		}
	}
	return ""
}
