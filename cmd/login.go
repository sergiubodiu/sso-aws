// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/viper"
	"github.com/spf13/cobra"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/sergiubodiu/sso-aws/saml"
	"github.com/aws/aws-sdk-go/aws"

	"log"
)

// LoginFlags login specific command flags
type LoginFlags struct {
	Hostname   string
	Username   string
	Password   string
	RoleArn    string
	SkipVerify bool
	SkipPrompt bool
}

var lf LoginFlags

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Login to a SAML 2.0 IDP",
	Long:  `Login to a SAML 2.0 IDP and convert the SAML assertion to an STS token.`,
	Run: loginRun,
}

func init() {
	RootCmd.AddCommand(loginCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// loginCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// loginCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	loginCmd.PersistentFlags().String("foo", "", "A help for foo")
	loginCmd.Flags().StringVarP(&lf.Username, "username", "u", "","The username used to login.")
	loginCmd.Flags().StringVarP(&lf.Password, "password", "p", "", "The password used to login.")
	loginCmd.Flags().StringVar(&lf.RoleArn, "role","", "The ARN of the role to assume.")
	loginCmd.Flags().StringVar(&lf.Hostname,"hostname", "", "The hostname of the SAML IDP server used to login.")
	loginCmd.Flags().BoolVarP(&lf.SkipVerify, "skip-verify", "s", false, "Skip verification of server certificate.")
	loginCmd.Flags().BoolVar(&lf.SkipPrompt, "skip-prompt", false, "Skip prompting for parameters during login.")
}

// RoleSupplied role arn has been passed as a flag
func (lf *LoginFlags) RoleSupplied() bool {
	return lf.RoleArn != ""
}

// Login login to ADFS
func loginRun(cmd *cobra.Command, args []string)  {
	viper.GetString("datafile")

	loginFlags := &lf

	// fmt.Println("LookupCredentials", hostname)
	loginDetails, err := resolveLoginDetails(loginFlags)
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Authenticating as %s to https://%s\n", loginDetails.Username,loginDetails.Hostname)

	provider, err := NewADFSClient(loginFlags.SkipVerify)
	if err != nil {
		log.Fatal(err)
	}

	err = loginDetails.Validate()
	if err != nil {
		log.Fatal("error validating login details")
		os.Exit(1)
	}

	samlAssertion, err := provider.Authenticate(loginDetails)
	if err != nil {
		log.Fatal("error authenticating to IdP")
		os.Exit(1)

	}

	if samlAssertion == "" {
		fmt.Println("Response did not contain a valid SAML assertion")
		fmt.Println("Please check your username and password is correct")
		os.Exit(1)
	}

	data, err := base64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		log.Fatal("error decoding saml assertion")
		os.Exit(1)
	}

	roles, err := saml.ExtractAwsRoles(data)
	if err != nil {
		log.Fatal("error parsing aws roles")
		os.Exit(1)
	}

	if len(roles) == 0 {
		fmt.Println("No roles to assume")
		fmt.Println("Please check you are permitted to assume roles for the AWS service")
		os.Exit(1)
	}

	awsRoles, err := saml.ParseAWSRoles(roles)
	if err != nil {
		log.Fatal("error parsing aws roles")
		os.Exit(1)
	}

	role, err := resolveRole(awsRoles, samlAssertion, loginFlags)
	if err != nil {
		log.Fatal("Failed to assume role, please check you are permitted to assume the given role for the AWS service")
		os.Exit(1)
	}

	// fmt.Println("Selected role:", role.RoleARN)

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

	// fmt.Println("Saving credentials")

	//sharedCreds := saml.NewSharedCredentials(loginFlags.Profile)

	//err = sharedCreds.Save(aws.StringValue(resp.Credentials.AccessKeyId), aws.StringValue(resp.Credentials.SecretAccessKey), aws.StringValue(resp.Credentials.SessionToken))
	//if err != nil {
	//	return errors.Wrap(err, "error saving credentials")
	//}

	fmt.Println("Logged in as:", aws.StringValue(resp.AssumedRoleUser.Arn))
	fmt.Println("")
	fmt.Println("Your new access key pair has been stored in the AWS configuration")
	fmt.Printf("Note that it will expire at %v\n", resp.Credentials.Expiration.Local())

	//fmt.Println("Saving config:", config.Filename)
	//config.SaveUsername(loginDetails.Username)
	//config.SaveHostname(loginDetails.Hostname)
}

func resolveLoginDetails(loginFlags *LoginFlags) (*LoginDetails, error) {

	// if skip prompt was passed just pass back the flag values
	if loginFlags.SkipPrompt {
		return &LoginDetails{
			Username: loginFlags.Username,
			Password: loginFlags.Password,
			Hostname: loginFlags.Hostname,
		}, nil
	}

	return PromptForLoginDetails(loginFlags.Username, loginFlags.Hostname, loginFlags.Password)
}

func resolveRole(awsRoles []*saml.AWSRole, samlAssertion string, loginFlags *LoginFlags) (*saml.AWSRole, error) {
	var role = new(saml.AWSRole)

	if len(awsRoles) == 1 {
		if loginFlags.RoleSupplied() {
			return saml.LocateRole(awsRoles, loginFlags.RoleArn)
		}
		role = awsRoles[0]
	} else if len(awsRoles) == 0 {
		return nil, errors.New("no roles available")
	}

	awsAccounts, err := saml.ParseAWSAccounts(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing aws role accounts")
	}

	saml.AssignPrincipals(awsRoles, awsAccounts)

	if loginFlags.RoleSupplied() {
		return saml.LocateRole(awsRoles, loginFlags.RoleArn)
	}

	for {
		role, err = saml.PromptForAWSRoleSelection(awsAccounts)
		if err == nil {
			break
		}
		fmt.Println("error selecting role, try again")
	}

	return role, nil
}

