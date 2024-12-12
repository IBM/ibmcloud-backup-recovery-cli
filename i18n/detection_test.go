/**
 * (C) Copyright IBM Corp. 2022.
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

package i18n_test

import (
	"os"

	"ibmcloud-backup-recovery-cli/i18n"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Detection", func() {
	BeforeEach(func() {
		os.Clearenv()
	})

	Describe("DetectLocale", func() {
		It("Should return the locale from LC_ALL", func() {
			os.Setenv("LC_ALL", "fr_FR.UTF-8")
			detector := new(i18n.LocaleDetector)
			result := detector.DetectLocale()
			Expect(result).Should(Equal("fr-FR"))

			os.Setenv("LC_ALL", "en_US.UTF-8")
			result = detector.DetectLocale()
			Expect(result).Should(Equal("en-US"))
		})

		It("Should return the locale from LANG if LC_ALL isn't set", func() {
			os.Setenv("LANG", "fr_FR.UTF-8")
			detector := new(i18n.LocaleDetector)
			result := detector.DetectLocale()
			Expect(result).Should(Equal("fr-FR"))

			os.Setenv("LANG", "en_US.UTF-8")
			result = detector.DetectLocale()
			Expect(result).Should(Equal("en-US"))
		})

		It("Should return the most appropriate locale from the country code only", func() {
			os.Setenv("LANG", "fr")
			detector := new(i18n.LocaleDetector)
			result := detector.DetectLocale()
			Expect(result).Should(Equal("fr"))

			// Should return an empty string, becase it's not possible
			// to return an exact match for the langague when the country
			// code is only "US".
			os.Setenv("LANG", "us")
			result = detector.DetectLocale()
			Expect(result).Should(BeEmpty())
		})
	})

	Describe("DetectLanguage", func() {
		It("Should return the language from LC_ALL", func() {
			os.Setenv("LC_ALL", "fr_FR.UTF-8")
			detector := new(i18n.LocaleDetector)
			result := detector.DetectLanguage()
			Expect(result).Should(Equal("fr"))

			os.Setenv("LC_ALL", "en_US.UTF-8")
			result = detector.DetectLanguage()
			Expect(result).Should(Equal("en"))
		})

		It("Should return the language from LANG if LC_ALL isn't set", func() {
			os.Setenv("LANG", "fr_FR.UTF-8")
			detector := new(i18n.LocaleDetector)
			result := detector.DetectLanguage()
			Expect(result).Should(Equal("fr"))

			os.Setenv("LANG", "en_US.UTF-8")
			result = detector.DetectLanguage()
			Expect(result).Should(Equal("en"))
		})
	})
})
