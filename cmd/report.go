package cmd

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
