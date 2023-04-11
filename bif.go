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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/thoas/go-funk"
	"gopkg.in/yaml.v3"
)

type Client struct {
	APIURL string `json:"apiURL"`
	Token  string `json:"token"`

	// Table Output Options
	OutputFormat   string `json:"outputFormat"`
	ColorizeOutput bool   `json:"colorizeOutput"`
	SortBy         string `json:"sortBy"`
	SortOrder      string `json:"sortOrder"`

	// Inputs
	Image       string
	ImageLayers []string
}

var OutputFormats []string = []string{
	"json",
	"yaml",
	"table",
}

var SortColumns []string = []string{
	"id",
	"severity",
	"cvss",
}

var SortOrder []string = []string{
	"asc",
	"desc",
}

func (c *Client) ValidateOptions() error {
	if !funk.Contains(OutputFormats, c.OutputFormat) {
		return fmt.Errorf("no valid output format found - must be one of %v", OutputFormats)
	}

	c.SortBy = strings.ToLower(c.SortBy)
	if !funk.Contains(SortColumns, c.SortBy) {
		return fmt.Errorf("invalid sort-by selection - must be one of %v", SortColumns)
	}

	c.SortOrder = strings.ToLower(c.SortOrder)
	if !funk.Contains(SortOrder, c.SortOrder) {
		return fmt.Errorf("invalid sort-order selection - must be one of %v", SortOrder)
	}

	if c.ImageLayers == nil && c.Image == "" {
		return fmt.Errorf("You must specify either --image or --image-layers.")
	}

	if c.ImageLayers != nil && c.Image != "" {
		return fmt.Errorf("Please specify only one of --image or --image-layers.")
	}

	return nil
}

func (c *Client) GetBaseImageOutput() (string, error) {
	var report *BaseImageVulnerabilityReport
	if c.Image != "" {
		var err error
		report, err = c.GetBaseImageReport(c.Image)
		if err != nil {
			return "", err
		}
	}

	if c.ImageLayers != nil {
		var err error
		report, err = c.GetImageLayerReport(c.ImageLayers)
		if err != nil {
			return "", err
		}
	}

	switch c.OutputFormat {
	case "json":
		output, err := json.MarshalIndent(report, "", "  ")
		return string(output), err
	case "yaml":
		output, err := yaml.Marshal(report)
		return string(output), err
	case "table":
		output, err := c.TableOutput(report)
		return output, err

	default:
		return "", fmt.Errorf("no valid output format found - must be one of %v", OutputFormats)
	}
}

func (c *Client) GetBaseImageReport(image string) (*BaseImageVulnerabilityReport, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/base?image_tag=%s", c.APIURL, image), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating http request: %s", err.Error())
	}
	body, err := c.MakeRequest(req)
	if err != nil {
		return nil, err
	}

	report := &BaseImageVulnerabilityReport{}
	if err := json.Unmarshal(body, report); err != nil {
		return nil, err
	}
	return report, nil
}

func (c *Client) GetImageLayerReport(imageLayers []string) (*BaseImageVulnerabilityReport, error) {
	payload, err := json.Marshal(c.ImageLayers)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/base", c.APIURL), bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("error creating http request: %s", err.Error())
	}

	body, err := c.MakeRequest(req)
	if err != nil {
		return nil, err
	}

	report := &BaseImageVulnerabilityReport{}
	if err := json.Unmarshal(body, report); err != nil {
		return nil, err
	}
	return report, nil
}

// MakeRequest performs an HTTP request using the client. It adds the proper headers
// as well as authentication and does error handling
func (c *Client) MakeRequest(req *http.Request) ([]byte, error) {
	req.Header.Add("Authorization", "Bearer "+c.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %s", err.Error())
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %s", err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		type BifError struct {
			Response string
		}
		errorMessage := &BifError{}
		if err := json.Unmarshal(body, errorMessage); err != nil {
			fmt.Printf("could not read response %s\n", err.Error())
		}

		return nil, fmt.Errorf("got %d status from bif: %s", resp.StatusCode, errorMessage.Response)
	}

	return body, nil
}
