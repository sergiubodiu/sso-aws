// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package cmd

import (
	"github.com/pkg/errors"
	"fmt"
	"strings"
	"log"
	"net/url"
	"github.com/PuerkitoBio/goquery"
	"io/ioutil"
	"bytes"
	"crypto/tls"
	"net/http/cookiejar"
	"golang.org/x/net/publicsuffix"
	"net/http"
)

// ADFSClient wrapper around ADFS enabling authentication and retrieval of assertions
type ADFSClient struct {
	client *http.Client
}

// NewADFSClient create a new ADFS client
func NewADFSClient(skipVerify bool) (*ADFSClient, error) {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify, Renegotiation: tls.RenegotiateFreelyAsClient},
	}

	options := &cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	}

	jar, err := cookiejar.New(options)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Transport: tr, Jar: jar}

	return &ADFSClient{
		client: client,
	}, nil
}

// Authenticate authenticate to ADFS and return the data from the body of the SAML assertion.
func (ac *ADFSClient) Authenticate(loginDetails *LoginDetails) (string, error) {
	var authSubmitURL string
	var samlAssertion string
	authForm := url.Values{}

	adfsURL := fmt.Sprintf("https://%s/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices", loginDetails.Hostname)

	res, err := ac.client.Get(adfsURL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving form")
	}

	doc, err := goquery.NewDocumentFromResponse(res)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "failed to build document from response")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		updateFormData(authForm, s, loginDetails)
	})

	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, ok := s.Attr("action")
		if !ok {
			return
		}
		authSubmitURL = action
	})

	if authSubmitURL == "" {
		return samlAssertion, fmt.Errorf("unable to locate IDP authentication form submit URL")
	}

	//log.Printf("id authentication url: %s", authSubmitURL)

	req, err := http.NewRequest("POST", authSubmitURL, strings.NewReader(authForm.Encode()))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building authentication request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err = ac.client.Do(req)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving login form")
	}

	//log.Printf("res code = %v status = %s", res.StatusCode, res.Status)

	data, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error retieving body")
	}

	doc, err = goquery.NewDocumentFromReader(bytes.NewBuffer(data))
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error parsing document")
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, ok := s.Attr("name")
		if !ok {
			log.Fatalf("unable to locate IDP authentication form submit URL")
		}
		if name == "SAMLResponse" {
			val, ok := s.Attr("value")
			if !ok {
				log.Fatalf("unable to locate saml assertion value")
			}
			samlAssertion = val
		}
	})

	if samlAssertion == "" {
		fmt.Println("Response did not contain a valid SAML assertion")
		fmt.Println("Please check your username and password is correct")
	}

	return samlAssertion, nil
}

func updateFormData(authForm url.Values, s *goquery.Selection, user *LoginDetails) {
	name, ok := s.Attr("name")
	//	log.Printf("name = %s ok = %v", name, ok)
	if !ok {
		return
	}
	lname := strings.ToLower(name)
	if strings.Contains(lname, "user") {
		authForm.Add(name, user.Username)
	} else if strings.Contains(lname, "email") {
		authForm.Add(name, user.Username)
	} else if strings.Contains(lname, "pass") {
		authForm.Add(name, user.Password)
	} else {
		// pass through any hidden fields
		val, ok := s.Attr("value")
		if !ok {
			return
		}
		authForm.Add(name, val)
	}
}
