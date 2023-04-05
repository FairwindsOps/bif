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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Client struct {
	APIURL string `json:"apiURL"`
	Token  string `json:"token"`
}

func (c *Client) GetBaseImage(image string) error {
	report, err := c.getBaseImageReport(image)
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))

	return nil
}

func (c *Client) getBaseImageReport(image string) (*BaseImageVulnerabilityReport, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/base?image_tag=%s", c.APIURL, image), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating http request: %s", err.Error())
	}
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

	report := &BaseImageVulnerabilityReport{}
	if err := json.Unmarshal(body, report); err != nil {
		return nil, err
	}
	return report, nil
}
