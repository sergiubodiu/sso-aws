// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package saml

import (
	"fmt"
	"strings"
	"encoding/xml"
	"net/url"
	"io/ioutil"
	"bytes"
	"net/http"
	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
	"bufio"
	"os"
	"strconv"
)

type AWSAccount struct {
	Name  string
	Roles []*AWSRole
}

// AWSRole aws role attributes
type AWSRole struct {
	RoleARN      string
	PrincipalARN string
	Name         string
}

const (
	assertionTag          = "Assertion"
	attributeStatementTag = "AttributeStatement"
	attributeTag          = "Attribute"
)

//ErrMissingElement is the error type that indicates an element and/or attribute is
//missing. It provides a structured error that can be more appropriately acted
//upon.
type ErrMissingElement struct {
	Tag, Attribute string
}

//ErrMissingAssertion indicates that an appropriate assertion element could not
//be found in the SAML Response
var (
	ErrMissingAssertion = ErrMissingElement{Tag: assertionTag}
)

func (e ErrMissingElement) Error() string {
	if e.Attribute != "" {
		return fmt.Sprintf("missing %s attribute on %s element", e.Attribute, e.Tag)
	}
	return fmt.Sprintf("missing %s element", e.Tag)
}

// ParseAWSAccounts extract the aws accounts from the saml assertion
func ParseAWSAccounts(samlAssertion string) ([]*AWSAccount, error) {
	awsURL := "https://signin.aws.amazon.com/saml"

	res, err := http.PostForm(awsURL, url.Values{"SAMLResponse": {samlAssertion}})
	if err != nil {
		return nil, errors.Wrap(err, "error retieving AWS login form")
	}

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.Wrap(err, "error retieving AWS login body")
	}

	return ExtractAWSAccounts(data)
}

// ExtractAWSAccounts extract the accounts from the AWS html page
func ExtractAWSAccounts(data []byte) ([]*AWSAccount, error) {
	accounts := []*AWSAccount{}

	doc, err := goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("fieldset > div.saml-account").Each(func(i int, s *goquery.Selection) {
		account := new(AWSAccount)
		account.Name = s.Find("div.saml-account-name").Text()
		s.Find("label").Each(func(i int, s *goquery.Selection) {
			role := new(AWSRole)
			role.Name = s.Text()
			role.RoleARN, _ = s.Attr("for")
			account.Roles = append(account.Roles, role)
		})
		accounts = append(accounts, account)
	})

	return accounts, nil
}

// ExtractAwsRoles given an assertion document extract the aws roles
func ExtractAwsRoles(data []byte) ([]string, error) {

	awsroles := []string{}
	r := Response{}

	if err := xml.Unmarshal(data, &r); err != nil {
		fmt.Printf("error: %r", err)
		return awsroles, err
	}

	if r.Assertion == nil {
		return nil, ErrMissingAssertion
	}

	if r.Assertion.AttributeStatement == nil {
		return nil, ErrMissingElement{Tag: attributeStatementTag}
	}

	if r.Assertion.AttributeStatement.Attributes == nil {
		return nil, ErrMissingElement{Tag: attributeTag}
	}

	attributes := r.Assertion.AttributeStatement.Attributes
	for _, attribute := range attributes {
		if attribute.Name != "https://aws.amazon.com/SAML/Attributes/Role" {
			continue
		}
		atributeValues := attribute.Values
		for _, attrValue := range atributeValues {
			awsroles = append(awsroles, attrValue.Value)
		}
	}

	return awsroles, nil
}

// ParseAWSRoles parses and splits the roles while also validating the contents
func ParseAWSRoles(roles []string) ([]*AWSRole, error) {
	awsRoles := make([]*AWSRole, len(roles))

	for i, role := range roles {
		awsRole, err := parseRole(role)
		if err != nil {
			return nil, err
		}

		awsRoles[i] = awsRole
	}

	return awsRoles, nil
}

func parseRole(role string) (*AWSRole, error) {
	tokens := strings.Split(role, ",")

	if len(tokens) != 2 {
		return nil, fmt.Errorf("Invalid role string only %d tokens", len(tokens))
	}

	awsRole := &AWSRole{}

	for _, token := range tokens {
		if strings.Contains(token, ":saml-provider") {
			awsRole.PrincipalARN = token
		}
		if strings.Contains(token, ":role") {
			awsRole.RoleARN = token
		}
	}

	if awsRole.PrincipalARN == "" {
		return nil, fmt.Errorf("Unable to locate PrincipalARN in: %s", role)
	}

	if awsRole.RoleARN == "" {
		return nil, fmt.Errorf("Unable to locate RoleARN in: %s", role)
	}

	return awsRole, nil
}
// AssignPrincipals assign principal from roles
func AssignPrincipals(awsRoles []*AWSRole, awsAccounts []*AWSAccount) {

	awsPrincipalARNs := make(map[string]string)
	for _, awsRole := range awsRoles {
		awsPrincipalARNs[awsRole.RoleARN] = awsRole.PrincipalARN
	}

	for _, awsAccount := range awsAccounts {
		for _, awsRole := range awsAccount.Roles {
			awsRole.PrincipalARN = awsPrincipalARNs[awsRole.RoleARN]
		}
	}

}

// LocateRole locate role by name
func LocateRole(awsRoles []*AWSRole, roleName string) (*AWSRole, error) {
	for _, awsRole := range awsRoles {
		if awsRole.RoleARN == roleName {
			return awsRole, nil
		}
	}

	return nil, fmt.Errorf("Supplied RoleArn not found in saml assertion: %s", roleName)
}

// PromptForAWSRoleSelection present a list of roles to the user for selection
func PromptForAWSRoleSelection(accounts []*AWSAccount) (*AWSRole, error) {

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Please choose the role you would like to assume: ")

	roles := []*AWSRole{}

	for _, account := range accounts {
		fmt.Println(account.Name)
		for _, role := range account.Roles {
			fmt.Println("[", len(roles), "]: ", role.Name)
			fmt.Println()
			roles = append(roles, role)
		}
	}

	fmt.Print("Selection: ")
	selectedRoleIndex, _ := reader.ReadString('\n')

	v, err := strconv.Atoi(strings.TrimSpace(selectedRoleIndex))

	if err != nil {
		return nil, fmt.Errorf("Unrecognised role index")
	}

	if v > len(roles) {
		return nil, fmt.Errorf("You selected an invalid role index")
	}

	return roles[v], nil
}

