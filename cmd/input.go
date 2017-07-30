// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package cmd

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/segmentio/go-prompt"
)

// LoginDetails used to authenticate to ADFS
type LoginDetails struct {
	Username string
	Password string
	Hostname string
}

// Validate validate the login details
func (ld *LoginDetails) Validate() error {
	if ld.Hostname == "" {
		return errors.New("Missing hostname")
	}
	if ld.Username == "" {
		return errors.New("Missing username")
	}
	if ld.Password == "" {
		return errors.New("Missing password")
	}
	return nil
}

// PromptForLoginDetails prompt the user to present their username, password and hostname
func PromptForLoginDetails(username, hostname, password string) (*LoginDetails, error) {

	hostname = promptFor("Hostname [%s]", hostname)

	fmt.Println("To use saved username and password just hit enter.")

	username = promptFor("Username [%s]", username)

	if enteredPassword := prompt.PasswordMasked("Password"); enteredPassword != "" {
		password = enteredPassword
	}

	fmt.Println("")

	return &LoginDetails{
		Username: strings.TrimSpace(username),
		Password: strings.TrimSpace(password),
		Hostname: strings.TrimSpace(hostname),
	}, nil
}

func promptFor(promptString, defaultValue string) string {
	var val string

	// do while
	for ok := true; ok; ok = strings.TrimSpace(defaultValue) == "" && strings.TrimSpace(val) == "" {
		val = prompt.String(promptString, defaultValue)
	}

	if val == "" {
		val = defaultValue
	}

	return val
}
