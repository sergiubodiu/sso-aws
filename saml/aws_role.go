// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package saml

import (
	"fmt"
	"strings"
	"encoding/xml"
	"io/ioutil"
	"github.com/pkg/errors"
	"os"

	"github.com/aws/aws-sdk-go/aws/session"
	"log"
	"github.com/aws/aws-sdk-go/service/sts"
	ini "gopkg.in/ini.v1"
	"github.com/mitchellh/go-homedir"
	"path/filepath"
)

type AWSAccount struct {
	Id 			string
	Name		string
	Roles 		[]*AWSRole
}

// AWSRole aws role attributes
type AWSRole struct {
	AccountId		string
	Name         string
	RoleARN      	string
	PrincipalARN 	string
}

func (a AWSRole) String() string {
	return fmt.Sprintf("[%s. %s, %s, %s]", a.Name, a.AccountId, a.RoleARN, a.PrincipalARN)
}

const (
	assertionTag          = "Assertion"
	attributeStatementTag = "AttributeStatement"
	attributeTag          = "Attribute"
)

type ErrMissingElement struct {
	Tag, Attribute string
}

var (
	ErrMissingAssertion = ErrMissingElement{Tag: assertionTag}
)

func (e ErrMissingElement) Error() string {
	if e.Attribute != "" {
		return fmt.Sprintf("missing %s attribute on %s element", e.Attribute, e.Tag)
	}
	return fmt.Sprintf("missing %s element", e.Tag)
}

// ExtractAwsRoles given an assertion document extract the aws roles
func ExtractAwsRoles(data []byte) ([]*AWSRole, error) {

	r := Response{}

	if err := xml.Unmarshal(data, &r); err != nil {
		fmt.Printf("error: %r", err)
		return nil, err
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

	awsroles := []string{}
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

	return parseAWSRoles(awsroles)
}

func parseAWSRoles(roles []string) ([]*AWSRole, error) {
	if len(roles) == 0 {
		return nil, fmt.Errorf("No roles to assume, Please check you are permitted to assume roles for the AWS service")
	}
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

	if splits := strings.SplitAfter(awsRole.RoleARN, "role/"); len(splits) == 2 {
		awsRole.Name = splits[1]
	}

	if accounts := strings.Split(awsRole.PrincipalARN, ":"); len(accounts) == 6 && len(accounts[4]) == 12 {
		awsRole.AccountId = accounts[4]
	}
	return awsRole, nil
}

// LocateRole locate role by name
func LocateRole(awsAccount *AWSAccount, roleName string) (*AWSRole, error) {
	fmt.Println("Locate role ", roleName)
	for _, awsRole := range awsAccount.Roles {
		if roleName == awsRole.Name {
			return awsRole, nil
		}
	}

	return nil, fmt.Errorf("Supplied Role not found in saml assertion: %s", roleName)
}

func AssignPrincipals(awsRoles []*AWSRole, awsAccount *AWSAccount) {
	roles := []*AWSRole{}
	for _, role := range awsRoles {
		if awsAccount.Id == role.AccountId {
			roles = append(roles, role)
		}
	}
	awsAccount.Roles = roles
}

func GetCredentials(role *AWSRole, samlAssertion string) *sts.Credentials {
	fmt.Println("Selected role:", role.RoleARN)

	sess, err := session.NewSession()
	if err != nil {
		log.Fatal("failed to create session")
		os.Exit(1)
	}

	svc := sts.New(sess)

	duration := int64(3600);
	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    &role.PrincipalARN, // Required
		RoleArn:         &role.RoleARN,      // Required
		SAMLAssertion:   &samlAssertion,     // Required
		DurationSeconds: &duration,       // 1 hour
	}

	fmt.Println("Requesting AWS credentials using SAML assertion")

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		log.Fatal("error retrieving STS credentials using SAML")
	}

	return resp.Credentials
}

func SaveCredentials(id, secret, token string) (string, error) {
	fmt.Println("Saving Credentials")


	filename, err := credentialsFile()
	if err != nil {
		return "", err
	}
	os.Setenv("AWS_ACCESS_KEY_ID", id)
	os.Setenv("AWS_SECRET_ACCESS_KEY_ID", secret)
	os.Setenv("AWS_SESSION_TOKEN", token)
	os.Setenv("AWS_SECURITY_TOKEN", token)

	fmt.Println("Saving config: ", filename)
	config, err := ini.Load(filename)
	if err != nil {
		return "", errors.Wrap(err, "error saving credentials")
	}

	iniProfile, err := config.NewSection("default")
	iniProfile.NewKey("aws_access_key_id", id)
	iniProfile.NewKey("aws_secret_access_key_id", secret)
	iniProfile.NewKey("aws_session_token", token)
	iniProfile.NewKey("aws_security_token", token)
	return filename, config.SaveTo(filename)
}

func credentialsFile() (string, error) {
	home,_ := homedir.Dir()
	awsDir := filepath.Join(home, ".aws")

	if _, err := os.Stat(awsDir); os.IsNotExist(err) {
		fmt.Println("Creating .aws directory ", awsDir)
		os.MkdirAll(awsDir, 0600)
	}

	credentialsFile := filepath.Join(awsDir, "credentials")
	if _, err := os.Stat(credentialsFile); os.IsNotExist(err) {
		fmt.Println("Saving credentialsFile ", credentialsFile)

		if err = ioutil.WriteFile(credentialsFile, []byte("[default]"), 0600); err != nil {
			return "", errors.New("can't write the credentials file")
		}
	}
	return credentialsFile, nil
}
