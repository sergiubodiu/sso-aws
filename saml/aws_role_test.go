// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package saml

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"io/ioutil"
)

func TestExtractRoles(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)

	roles, err := ExtractAwsRoles([]byte(data))
	assert.Nil(t, err)

	awsRoles, err := ParseAWSRoles(roles)

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

	awsRoles, err := ParseAWSRoles(roles)

	assert.Len(t, awsRoles, 2)

	for _, awsRole := range awsRoles {
		assert.Equal(t, "arn:aws:iam::000000000001:saml-provider/example-idp", awsRole.PrincipalARN)
		assert.Equal(t, "arn:aws:iam::000000000001:role/admin", awsRole.RoleARN)
	}

	roles = []string{""}
	awsRoles, err = ParseAWSRoles(roles)

	assert.NotNil(t, err)
	assert.Nil(t, awsRoles)

}

func TestExtractAWSAccounts(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/saml.html")
	assert.Nil(t, err)

	accounts, err := ExtractAWSAccounts(data)
	assert.Nil(t, err)
	assert.Len(t, accounts, 2)

	account := accounts[0]
	assert.Equal(t, account.Name, "Account: account-alias (000000000001)")

	assert.Len(t, account.Roles, 2)
	role := account.Roles[0]
	assert.Equal(t, role.RoleARN, "arn:aws:iam::000000000001:role/Development")
	assert.Equal(t, role.Name, "Development")
	role = account.Roles[1]
	assert.Equal(t, role.RoleARN, "arn:aws:iam::000000000001:role/Production")
	assert.Equal(t, role.Name, "Production")

	account = accounts[1]
	assert.Equal(t, account.Name, "Account: 000000000002")

	assert.Len(t, account.Roles, 1)
	role = account.Roles[0]
	assert.Equal(t, role.RoleARN, "arn:aws:iam::000000000002:role/Production")
	assert.Equal(t, role.Name, "Production")
}

func TestAssignPrincipals(t *testing.T) {
	awsRoles := []*AWSRole{
		&AWSRole{
			PrincipalARN: "arn:aws:iam::000000000001:saml-provider/example-idp",
			RoleARN:      "arn:aws:iam::000000000001:role/Development",
		},
	}

	awsAccounts := []*AWSAccount{
		&AWSAccount{
			Roles: []*AWSRole{
				&AWSRole{
					RoleARN: "arn:aws:iam::000000000001:role/Development",
				},
			},
		},
	}

	AssignPrincipals(awsRoles, awsAccounts)

	assert.Equal(t, "arn:aws:iam::000000000001:saml-provider/example-idp", awsAccounts[0].Roles[0].PrincipalARN)
}

func TestLocateRole(t *testing.T) {
	awsRoles := []*AWSRole{
		&AWSRole{
			PrincipalARN: "arn:aws:iam::000000000001:saml-provider/example-idp",
			RoleARN:      "arn:aws:iam::000000000001:role/Development",
		},
		&AWSRole{
			PrincipalARN: "arn:aws:iam::000000000002:saml-provider/example-idp",
			RoleARN:      "arn:aws:iam::000000000002:role/Development",
		},
	}

	role, err := LocateRole(awsRoles, "arn:aws:iam::000000000001:role/Development")

	assert.Empty(t, err)

	assert.Equal(t, "arn:aws:iam::000000000001:role/Development", role.RoleARN)
}