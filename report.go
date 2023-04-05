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

import "time"

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
