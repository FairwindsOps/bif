package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"

	"github.com/manifoldco/promptui"
)

func requestInsightsOSSToken() error {
	validateEmail := func(input string) error {
		_, err := mail.ParseAddress(input)
		if err != nil {
			return fmt.Errorf("invalid email: %s", err.Error())
		}
		return nil
	}

	prompt := promptui.Prompt{
		Label:    "Please enter your email address in order to receive a token",
		Validate: validateEmail,
	}

	result, err := prompt.Run()
	if err != nil {
		return err
	}

	body := struct {
		Email   string `json:"email"`
		Project string `json:"project"`
	}{
		Email:   result,
		Project: "saffire", // TODO: Update this once BIF is available as an option in the backend
	}

	out, err := json.Marshal(body)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", insightsURL+"/v0/oss/users", bytes.NewBuffer(out))
	if err != nil {
		return err
	}
	req.Header.Add("content-type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading response: %s", err.Error())
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("non-zero response (%d) from api: %s", resp.StatusCode, string(responseBody))
	}

	return nil
}
