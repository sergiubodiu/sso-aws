// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package saml

import (
	"testing"
	"io/ioutil"
	"github.com/stretchr/testify/assert"
)

func TestExtractAWSAccounts(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/saml.html")
	assert.Nil(t, err)

	accounts, err := extractAWSAccounts(data)
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
