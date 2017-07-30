// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package saml

import (
	"encoding/xml"
	"time"
)

func (a *Assertion) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Assertion
	aux := &struct {
		IssueInstant TimeInstant `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	a.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// Method is part of Signature.
type Method struct {
	Algorithm string `xml:",attr"`
}

// SignatureX509Data represents the <X509Data> element of <Signature>
type SignatureX509Data struct {
	X509Certificate string `xml:"X509Certificate,omitempty"`
}

// Signature is a model for the Signature object specified by XMLDSIG. This is
// convenience object when constructing XML that you'd like to sign. For example:
//
//    type Foo struct {
//       Stuff string
//       Signature Signature
//    }
//
//    f := Foo{Suff: "hello"}
//    f.Signature = DefaultSignature()
//    buf, _ := xml.Marshal(f)
//    buf, _ = Sign(key, buf)
//
type Signature struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`

	CanonicalizationMethod Method             `xml:"SignedInfo>CanonicalizationMethod"`
	SignatureMethod        Method             `xml:"SignedInfo>SignatureMethod"`
	ReferenceTransforms    []Method           `xml:"SignedInfo>Reference>Transforms>Transform"`
	DigestMethod           Method             `xml:"SignedInfo>Reference>DigestMethod"`
	DigestValue            string             `xml:"SignedInfo>Reference>DigestValue"`
	SignatureValue         string             `xml:"SignatureValue"`
	KeyName                string             `xml:"KeyInfo>KeyName,omitempty"`
	X509Certificate        *SignatureX509Data `xml:"KeyInfo>X509Data,omitempty"`
}

// AuthnRequest represents the SAML object of the same name, a request from a service provider
// to authenticate a user.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnRequest struct {
	XMLName                     xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	AssertionConsumerServiceURL string    `xml:",attr"`
	Destination                 string    `xml:",attr"`
	ID                          string    `xml:",attr"`
	IssueInstant                time.Time `xml:",attr"`

	// Protocol binding is a URI reference that identifies a SAML protocol binding to be used when returning
	// the <Response> message. See [SAMLBind] for more information about protocol bindings and URI references
	// defined for them. This attribute is mutually exclusive with the AssertionConsumerServiceIndex attribute
	// and is typically accompanied by the AssertionConsumerServiceURL attribute.
	ProtocolBinding string `xml:",attr"`

	Version      string            `xml:",attr"`
	Issuer       Issuer            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature    *Signature 	   `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	NameIDPolicy NameIDPolicy      `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
}

func (a *AuthnRequest) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AuthnRequest
	aux := &struct {
		IssueInstant TimeInstant `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	a.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// Issuer represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Format  string   `xml:",attr"`
	Value   string   `xml:",chardata"`
}

// NameIDPolicy represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type NameIDPolicy struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	AllowCreate bool     `xml:",attr"`
	Format      string   `xml:",chardata"`
}

// Response represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Response struct {
	XMLName            xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	Destination        string    `xml:",attr"`
	ID                 string    `xml:",attr"`
	InResponseTo       string    `xml:",attr"`
	IssueInstant       time.Time `xml:",attr"`
	Version            string    `xml:",attr"`
	Issuer             *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Status             *Status   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	EncryptedAssertion *EncryptedAssertion
	Assertion          *Assertion `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
}

func (r *Response) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Response
	aux := &struct {
		IssueInstant TimeInstant `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(r),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	r.IssueInstant = time.Time(aux.IssueInstant)
	return nil
}

// Status represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Status struct {
	XMLName    xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode StatusCode
}

// StatusCode represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type StatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value   string   `xml:",attr"`
}

// StatusSuccess is the value of a StatusCode element when the authentication succeeds.
// (nominally a constant, except for testing)
var StatusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"

// EncryptedAssertion represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type EncryptedAssertion struct {
	Assertion     *Assertion
	EncryptedData []byte `xml:",innerxml"`
}

// Assertion represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Assertion struct {
	XMLName            xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string    `xml:",attr"`
	IssueInstant       time.Time `xml:",attr"`
	Version            string    `xml:",attr"`
	Issuer             *Issuer   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Signature          *Signature
	Subject            *Subject
	Conditions         *Conditions
	AuthnStatement     *AuthnStatement
	AttributeStatement *AttributeStatement
}

// Subject represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Subject struct {
	XMLName             xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID              *NameID
	SubjectConfirmation *SubjectConfirmation
}

// NameID represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type NameID struct {
	Format          string `xml:",attr"`
	NameQualifier   string `xml:",attr"`
	SPNameQualifier string `xml:",attr"`
	Value           string `xml:",chardata"`
}

// SubjectConfirmation represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type SubjectConfirmation struct {
	Method                  string `xml:",attr"`
	SubjectConfirmationData SubjectConfirmationData
}

// SubjectConfirmationData represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type SubjectConfirmationData struct {
	Address      string    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	NotOnOrAfter time.Time `xml:",attr"`
	Recipient    string    `xml:",attr"`
}

func (s *SubjectConfirmationData) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias SubjectConfirmationData
	aux := &struct {
		NotOnOrAfter TimeInstant `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(s),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	s.NotOnOrAfter = time.Time(aux.NotOnOrAfter)
	return nil
}

// Conditions represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Conditions struct {
	NotBefore           time.Time `xml:",attr"`
	NotOnOrAfter        time.Time `xml:",attr"`
	AudienceRestriction *AudienceRestriction
}

func (c *Conditions) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias Conditions
	aux := &struct {
		NotBefore    TimeInstant `xml:",attr"`
		NotOnOrAfter TimeInstant `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(c),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	c.NotBefore = time.Time(aux.NotBefore)
	c.NotOnOrAfter = time.Time(aux.NotOnOrAfter)
	return nil
}

// AudienceRestriction represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AudienceRestriction struct {
	Audience *Audience
}

// Audience represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Audience struct {
	Value string `xml:",chardata"`
}

// AuthnStatement represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnStatement struct {
	AuthnInstant        time.Time `xml:",attr"`
	SessionNotOnOrAfter time.Time `xml:",attr"`
	SessionIndex        string    `xml:",attr"`
	SubjectLocality     SubjectLocality
	AuthnContext        AuthnContext
}

func (a *AuthnStatement) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type Alias AuthnStatement
	aux := &struct {
		AuthnInstant TimeInstant `xml:",attr"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := d.DecodeElement(&aux, &start); err != nil {
		return err
	}
	a.AuthnInstant = time.Time(aux.AuthnInstant)
	return nil
}

// SubjectLocality represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type SubjectLocality struct {
	Address string `xml:",attr"`
}

// AuthnContext represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnContext struct {
	AuthnContextClassRef *AuthnContextClassRef
}

// AuthnContextClassRef represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AuthnContextClassRef struct {
	Value string `xml:",chardata"`
}

// AttributeStatement represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AttributeStatement struct {
	Attributes []Attribute `xml:"Attribute"`
}

// Attribute represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type Attribute struct {
	FriendlyName string           `xml:",attr"`
	Name         string           `xml:",attr"`
	NameFormat   string           `xml:",attr"`
	Values       []AttributeValue `xml:"AttributeValue"`
}

// AttributeValue represents the SAML object of the same name.
//
// See http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
type AttributeValue struct {
	Type   string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Value  string `xml:",chardata"`
	NameID *NameID
}