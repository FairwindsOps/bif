/*
Copyright © 2023 FairwindsOps, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package bif

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	tw "github.com/olekukonko/tablewriter"
)

type BaseImageVulnerabilityReport struct {
	ImageRepository string             `json:"image_repository"`
	ImageTag        string             `json:"image_tag"`
	ImagePlatform   *string            `json:"image_platform,omitempty"`
	BaseImages      []*ReportBaseImage `json:"base_images"`
}

type ReportBaseImage struct {
	ImageRepository string                 `json:"image_repository"`
	ImageTag        string                 `json:"image_tag"`
	Vulnerabilities []*ReportVulnerability `json:"vulnerabilities,omitempty"`
	LastScan        *time.Time             `json:"last_scan"`
	Upgrades        *[]ImageUpgrade        `json:"upgrades,omitempty"`
}

type ReportVulnerability struct {
	ID       string  `json:"id,omitempty"`
	Severity string  `json:"severity,omitempty"`
	CVSS     float64 `json:"cvss,omitempty"`
}

// ImageUpgrade is a repository:tag combo with a list of fixed vulnerabilities
// over the base image
type ImageUpgrade struct {
	Type                 string                 `json:"type"`
	ImageTag             string                 `json:"image_tag"`
	LastScan             *time.Time             `json:"last_scan"`
	FixedVulnerabilities []*ReportVulnerability `json:"fixed_vulnerabilities"`
}

func (c *Client) TableOutput(report *BaseImageVulnerabilityReport) (string, error) {
	tableString := &strings.Builder{}
	table := tw.NewWriter(tableString)
	table.SetHeader([]string{"Base Image", "Last Scan", "CVE", "Severity", "CVSS", "Fixed In"})
	table.SetBorder(false)

	if c.ColorizeOutput {
		table.SetHeaderColor(
			tw.Colors{tw.Bold, tw.FgCyanColor},
			tw.Colors{tw.FgCyanColor},
			tw.Colors{tw.FgWhiteColor, tw.Bold},
			tw.Colors{tw.FgWhiteColor},
			tw.Colors{tw.FgWhiteColor},
			tw.Colors{tw.FgCyanColor},
		)
	}

	for _, baseImage := range report.BaseImages {

		sortErrors := false
		// Sort with critical at the top
		sort.Slice(baseImage.Vulnerabilities, func(i, j int) bool {
			switch c.SortBy {
			case "severity":
				sortMap := map[string]int{
					"CRITICAL": 4,
					"HIGH":     3,
					"MEDIUM":   2,
					"LOW":      1,
					"UKNOWN":   0,
				}

				switch c.SortOrder {
				case "desc":
					return sortMap[baseImage.Vulnerabilities[i].Severity] > sortMap[baseImage.Vulnerabilities[j].Severity]
				case "asc":
					return sortMap[baseImage.Vulnerabilities[i].Severity] < sortMap[baseImage.Vulnerabilities[j].Severity]
				case "default":
					sortErrors = true
				}
			case "cvss":
				switch c.SortOrder {
				case "desc":
					return baseImage.Vulnerabilities[i].CVSS > baseImage.Vulnerabilities[j].CVSS
				case "asc":
					return baseImage.Vulnerabilities[i].CVSS < baseImage.Vulnerabilities[j].CVSS
				default:
					sortErrors = true
				}
			case "id":
				switch c.SortOrder {
				case "desc":
					return baseImage.Vulnerabilities[i].ID < baseImage.Vulnerabilities[j].ID
				case "asc":
					return baseImage.Vulnerabilities[i].ID > baseImage.Vulnerabilities[j].ID
				default:
					sortErrors = true
				}
			default:
				sortErrors = true
			}
			return false
		})

		if sortErrors {
			return "", fmt.Errorf("A default condition was encountered during sorting, this is likely a bug with the consumer of this library. Please report it.")
		}
		for _, vuln := range baseImage.Vulnerabilities {
			fixedIn := []string{}
			if baseImage.Upgrades != nil {
				for _, upgrade := range *baseImage.Upgrades {
					for _, fixedVuln := range upgrade.FixedVulnerabilities {
						if vuln.ID == fixedVuln.ID {
							fixedIn = append(fixedIn, upgrade.ImageTag)
						}
					}
				}
			}

			var fixedString string
			for idx, fixed := range fixedIn {
				if idx == 0 {
					fixedString = fixed
				} else {
					fixedString = fixedString + ", " + fixed
				}
			}

			var lastScan string
			if baseImage.LastScan == nil {
				lastScan = "unknown"
			} else {
				lastScan = baseImage.LastScan.Format("2006-01-02")
			}
			row := []string{
				baseImage.ImageRepository + ":" + baseImage.ImageTag,
				lastScan,
				vuln.ID,
				vuln.Severity,
				strconv.FormatFloat(vuln.CVSS, 'f', 2, 64),
				fixedString,
			}

			criticalHighColor := []tw.Colors{{tw.FgCyanColor}, {tw.FgCyanColor}, {tw.FgHiRedColor}, {tw.Bold, tw.FgHiRedColor}, {tw.FgHiRedColor}, {tw.FgCyanColor}}
			mediumColor := []tw.Colors{{tw.FgCyanColor}, {tw.FgCyanColor}, {tw.FgHiGreenColor}, {tw.Bold, tw.FgHiGreenColor}, {tw.Bold, tw.FgHiGreenColor}, {tw.FgCyanColor}}
			lowColor := []tw.Colors{{tw.FgCyanColor}, {tw.FgCyanColor}, {tw.FgHiCyanColor}, {tw.Bold, tw.FgHiCyanColor}, {tw.Bold, tw.FgHiCyanColor}, {tw.FgCyanColor}}
			defaultColor := []tw.Colors{{tw.FgCyanColor}, {tw.FgCyanColor}}

			if !c.ColorizeOutput {
				criticalHighColor = []tw.Colors{}
				mediumColor = []tw.Colors{}
				lowColor = []tw.Colors{}
				defaultColor = []tw.Colors{}
			}

			switch vuln.Severity {
			case "CRITICAL":
				table.Rich(row, criticalHighColor)
			case "HIGH":
				table.Rich(row, criticalHighColor)
			case "MEDIUM":
				table.Rich(row, mediumColor)
			case "LOW":
				table.Rich(row, lowColor)
			default:
				table.Rich(row, defaultColor)
			}
		}
	}

	table.SetAutoMergeCells(false)
	table.SetAutoMergeCellsByColumnIndex([]int{0, 1})
	table.Render()

	outputString := fmt.Sprintf("Input: %s %s \n\n%s", report.ImageRepository, report.ImageTag, tableString.String())
	return outputString, nil
}
