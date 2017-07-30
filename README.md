Single Sign-On AWS CLI access using SAML 2.0
==========
CLI tool which enables you to login and retrieve AWS temporary credentials using SAML with ADFS

This is based on python code from [How to Implement Federated API and CLI Access Using SAML 2.0 and AD FS](https://aws.amazon.com/blogs/security/how-to-implement-federated-api-and-cli-access-using-saml-2-0-and-ad-fs/).

How you can implement federated API and CLI access for your users using AWS Go SDK:

 * Prompt user for credentials
 * Opens the initial IdP url and follows all of the HTTP302 redirects
 * Programmatically get the SAML assertion
 * Parse the response and extract all the necessary values
 * Exchange the role and SAML assertion with [AWS STS service](https://docs.aws.amazon.com/STS/latest/APIReference/Welcome.html) to get a temporary set of credentials
 * Save these creds to an aws profile named "saml"

Requirements
------------

* Identity Provider
   * ADFS (2.x or 3.x)
* AWS SAML Provider configured

Usage
------------


go get -u github.com/spf13/cobra/cobra

cobra init github.com/sergiubodiu/sso-aws -a "Sergiu Bodiu" -l MIT