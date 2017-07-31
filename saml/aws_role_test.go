// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package saml

import (
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"os"
	"testing"
)

func TestExtractRoles(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)

	awsRoles, err := ExtractAwsRoles([]byte(data))
	assert.Nil(t, err)

	assert.Len(t, awsRoles, 2)
	assert.Equal(t, "arn:aws:iam::000000000001:saml-provider/example-idp", awsRoles[0].PrincipalARN)
	assert.Equal(t, "arn:aws:iam::000000000001:role/Production", awsRoles[0].RoleARN)

	assert.Equal(t, "arn:aws:iam::000000000001:saml-provider/example-idp", awsRoles[1].PrincipalARN)
	assert.Equal(t, "arn:aws:iam::000000000001:role/Development", awsRoles[1].RoleARN)
}

func TestParseRoles(t *testing.T) {

	roles := []string{
		"arn:aws:iam::000000000001:saml-provider/example-idp,arn:aws:iam::000000000001:role/admin",
		"arn:aws:iam::000000000001:role/admin,arn:aws:iam::000000000001:saml-provider/example-idp",
	}

	awsRoles, err := parseAWSRoles(roles)

	assert.Len(t, awsRoles, 2)

	for _, awsRole := range awsRoles {
		assert.Equal(t, "arn:aws:iam::000000000001:saml-provider/example-idp", awsRole.PrincipalARN)
		assert.Equal(t, "arn:aws:iam::000000000001:role/admin", awsRole.RoleARN)
		assert.Equal(t, "000000000001", awsRole.AccountId)
		assert.Equal(t, "admin", awsRole.Name)
	}

	roles = []string{""}
	awsRoles, err = parseAWSRoles(roles)

	assert.NotNil(t, err)
	assert.Nil(t, awsRoles)

}

func TestAssignPrincipals(t *testing.T) {
	awsRoles := []*AWSRole{
		&AWSRole{
			PrincipalARN: "arn:aws:iam::000000000001:saml-provider/example-idp",
			RoleARN:      "arn:aws:iam::000000000001:role/Development",
			Name:		"Development",
			AccountId:  "000000000001",
		},
		&AWSRole{
			PrincipalARN: "arn:aws:iam::000000000002:saml-provider/example-idp",
			RoleARN:      "arn:aws:iam::000000000002:role/Development",
			Name:		"Development",
			AccountId:  "000000000002",
		},
	}

	awsAccount := &AWSAccount{
		Id: "000000000001",
	}

	AssignPrincipals(awsRoles, awsAccount)

	assert.Equal(t, "arn:aws:iam::000000000001:saml-provider/example-idp", awsAccount.Roles[0].PrincipalARN)
}

func TestLocateRole(t *testing.T) {
	awsAccount := &AWSAccount{
		Id: "000000000001",
		Roles: []*AWSRole{
			&AWSRole{
				PrincipalARN: "arn:aws:iam::000000000001:saml-provider/example-idp",
				RoleARN:      "arn:aws:iam::000000000001:role/Development",
				Name:         "Development",
				AccountId:    "000000000001",
			},
			&AWSRole{
				PrincipalARN: "arn:aws:iam::000000000001:saml-provider/example-idp",
				RoleARN:      "arn:aws:iam::000000000001:role/Production",
				Name:         "Production",
				AccountId:    "000000000001",
			},
		},
	}

	role, _ := LocateRole(awsAccount, "Development")

	assert.NotNil(t, role)

	assert.Equal(t, "arn:aws:iam::000000000001:role/Development", role.RoleARN)
	assert.Equal(t, "arn:aws:iam::000000000001:saml-provider/example-idp", role.PrincipalARN)
}

func TestSaveCredentials(t *testing.T) {
	id := "id"
	secret := "secret"
	token := "token"

	filename, err := SaveCredentials(id, secret, token)
	assert.Nil(t, err)
	assert.NotEmpty(t, filename)

	assert.Equal(t, id, os.Getenv("AWS_ACCESS_KEY_ID"))
	assert.Equal(t, secret, os.Getenv("AWS_SECRET_ACCESS_KEY_ID"))
	assert.Equal(t, token, os.Getenv("AWS_SESSION_TOKEN"))
	assert.Equal(t, token, os.Getenv("AWS_SECURITY_TOKEN"))
}