// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package saml

import (
	"encoding/xml"
	"time"
	"testing"
	"io/ioutil"
	"github.com/stretchr/testify/assert"
)

var TimeNow = func() time.Time {
	rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Thu Jul 27 02:54:39.386 UTC 2017")
	return rv
}

func TestParseAssertionResponse(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/assertion.xml")
	assert.Nil(t, err)

	r := Response{}

	err = xml.Unmarshal([]byte(data), &r)
	assert.Nil(t, err)

	assert.Equal(t, r.Assertion,  &Assertion{
		ID:           "aaf23196-1773-2113-474a-fe114412ab72",
		IssueInstant: TimeNow(),
		Version:      "2.0",
		Issuer: &Issuer{
			Format: "",
			Value:  "http://id.example.com/adfs/services/trust",
			XMLName: xml.Name{
				Space: "urn:oasis:names:tc:SAML:2.0:assertion",
				Local: "Issuer",
			},
		},
		Signature: &Signature{
			CanonicalizationMethod: Method{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
			SignatureMethod:        Method{Algorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"},
			ReferenceTransforms: []Method{
				{Algorithm: "http://www.w3.org/2000/09/xmldsig#enveloped-signature"},
				{Algorithm: "http://www.w3.org/2001/10/xml-exc-c14n#"},
			},
			DigestMethod:    Method{Algorithm: "http://www.w3.org/2001/04/xmlenc#sha256"},
			DigestValue:     "XXX",
			SignatureValue:  "XXX",
			KeyName:         "",
			X509Certificate: &SignatureX509Data{"XXX"},
			XMLName: xml.Name{
				Space: "http://www.w3.org/2000/09/xmldsig#",
				Local: "Signature",
			},
		},
		Subject: &Subject{
			NameID: &NameID{
				Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
				NameQualifier: "",
				SPNameQualifier: "",
				Value: "EXAMPLE\\sergiubodiu",
			},
			SubjectConfirmation: &SubjectConfirmation{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: SubjectConfirmationData{
					Address:      "",
					InResponseTo: "aaf23196-1773-2113-474a-fe114412ab72",
					NotOnOrAfter: TimeNow(),
					Recipient:    "https://signin.aws.amazon.com/saml",
				},
			},
			XMLName: xml.Name{
				Space: "urn:oasis:names:tc:SAML:2.0:assertion",
				Local: "Subject",
			},
		},
		Conditions: &Conditions{
			NotBefore:    TimeNow(),
			NotOnOrAfter: TimeNow(),
			AudienceRestriction: &AudienceRestriction{
				Audience: &Audience{Value: "urn:amazon:webservices"},
			},
		},
		AuthnStatement: &AuthnStatement{
			AuthnInstant:        TimeNow(),
			SessionIndex:        "aaf23196-1773-2113-474a-fe114412ab72",
			SessionNotOnOrAfter: TimeNow(),
			SubjectLocality:     SubjectLocality{},
			AuthnContext: AuthnContext{
				AuthnContextClassRef: &AuthnContextClassRef{Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
			},
		},
		AttributeStatement: &AttributeStatement{
			Attributes: []Attribute{
				{
					FriendlyName: "",
					Name:         "https://aws.amazon.com/SAML/Attributes/RoleSessionName",
					NameFormat:   "",
					Values: []AttributeValue{
						{
							Type:  "",
							Value: "sergiu.bodiu@example.com",
						},
					},
				},
				{
					FriendlyName: "",
					Name:         "https://aws.amazon.com/SAML/Attributes/Role",
					NameFormat:   "",
					Values: []AttributeValue{
						{
							Type:  "",
							Value: "arn:aws:iam::000000000001:saml-provider/example-idp,arn:aws:iam::000000000001:role/Production",
						},
						{
							Type: "",
							Value: "arn:aws:iam::000000000001:saml-provider/example-idp,arn:aws:iam::000000000001:role/Development",
						},
					},
				},
			},
		},
	})

	assert.Len(t, r.Assertion.AttributeStatement.Attributes, 2)
}

func TestParseAssertion(t *testing.T) {
	r := Assertion{}

	data := `
		<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_f85be5f5-584c-4711-8c9d-5b13c4c49f89" IssueInstant="2017-07-27T02:54:39.386Z" Version="2.0">
			<AttributeStatement>
				<Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
					<AttributeValue>sergiu.bodiu@example.com</AttributeValue>
				</Attribute>
				<Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
					<AttributeValue>arn:aws:iam::000000000001:saml-provider/ExampleADFS,arn:aws:iam::000000000001:role/Production</AttributeValue>
					<AttributeValue>arn:aws:iam::000000000001:saml-provider/ExampleADFS,arn:aws:iam::000000000001:role/Development</AttributeValue>
				</Attribute>
			</AttributeStatement>
		</Assertion>
	`

	err := xml.Unmarshal([]byte(data), &r)
	assert.Nil(t, err)
	assert.Len(t, r.AttributeStatement.Attributes, 2)
}
