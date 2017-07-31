// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package saml

import (
	"net/http"
	"net/url"
	"io/ioutil"
	"bytes"
	"github.com/PuerkitoBio/goquery"
	"github.com/pkg/errors"
)

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

	return extractAWSAccounts(data)
}

// ExtractAWSAccounts extract the accounts from the AWS html page
func extractAWSAccounts(data []byte) ([]*AWSAccount, error) {
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
