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
package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

func getBaseImage(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("The find command requires a single docker image reference as an argument.")
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://bif-server-6biex2p5nq-uc.a.run.app/base?image_tag=%s", args[0]), nil)
	if err != nil {
		return fmt.Errorf("error creating http request: %s", err.Error())
	}
	req.Header.Add("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("error making request: %s", err.Error())
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response: %s", err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		type BifError struct {
			Response string
		}
		errorMessage := &BifError{}
		if err := json.Unmarshal(body, errorMessage); err != nil {
			fmt.Printf("could not read response %s\n", err.Error())
		}

		return fmt.Errorf("got %d status from bif: %s", resp.StatusCode, errorMessage.Response)
	}

	report := &BaseImageVulnerabilityReport{}
	if err := json.Unmarshal(body, report); err != nil {
		return err
	}
	output, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(output))

	return nil
}
