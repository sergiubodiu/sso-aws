// Copyright © 2017 Sergiu Bodiu
//
// Use of this source code is governed by and MIT
// license that can be found in the LICENSE file
package cmd

import (
	"encoding/base64"
	"fmt"
	"os"
	"log"
	"strconv"
	"github.com/spf13/viper"
	"github.com/spf13/cobra"
	"github.com/sergiubodiu/sso-aws/saml"

	"bufio"
	"strings"
)

// LoginFlags login specific command flags
type LoginFlags struct {
	Account     string
	Hostname   string
	Username   string
	Password   string
	Role    string
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

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:

	loginCmd.Flags().StringVarP(&lf.Username, "username", "u", "","The username used to login.")
	loginCmd.Flags().StringVarP(&lf.Password, "password", "p", "", "The password used to login.")
	loginCmd.Flags().StringVarP(&lf.Account, "account", "a", "", "The account to assume.")
	loginCmd.Flags().StringVar(&lf.Role, "role","", "The role to assume.")
	loginCmd.Flags().StringVar(&lf.Hostname,"hostname", "", "The hostname of the SAML IDP server used to login.")
	loginCmd.Flags().BoolVarP(&lf.SkipVerify, "skip-verify", "s", false, "Skip verification of server certificate.")
	loginCmd.Flags().BoolVar(&lf.SkipPrompt, "skip-prompt", false, "Skip prompting for parameters during login.")
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
	}

	samlAssertion, err := provider.Authenticate(loginDetails)
	if err != nil {
		log.Fatal("error authenticating to IdP")
	}

	role, err := resolveRoleDetails(loginFlags, samlAssertion)
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}

	credentials := saml.GetCredentials(role, samlAssertion)

	filename, err := saml.SaveCredentials(stringValue(credentials.AccessKeyId), stringValue(credentials.SecretAccessKey), stringValue(credentials.SessionToken))
	if err != nil {
		log.Fatal("error saving credentials ", err)
	}

	fmt.Println("")
	fmt.Printf("Credential is saved to file %s under default profile\n", filename)
	fmt.Printf("Here are your short-term credentials. Expires: %v\n", credentials.Expiration.Local())
}

// PromptForAWSRoleSelection present a list of roles to the user for selection
func promptForAWSRoleSelection(account *saml.AWSAccount) (*saml.AWSRole, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("Please choose the role you would like to assume: ")

	roles := []*saml.AWSRole{}

	fmt.Println(account.Name)
	for _, role := range account.Roles {
		fmt.Println("[", len(roles), "]: ", role.Name)
		fmt.Println()
		roles = append(roles, role)
	}

	fmt.Print("Selection: ")
	selectedRoleIndex, _ := reader.ReadString('\n')

	v, err := strconv.Atoi(strings.TrimSpace(selectedRoleIndex))

	if err != nil {
		return nil, fmt.Errorf("Unrecognised role index")
	}

	if v > len(roles) {
		return nil, fmt.Errorf("You selected an invalid role index")
	}

	return roles[v], nil
}

func resolveRoleDetails(loginFlags *LoginFlags, samlAssertion string) (*saml.AWSRole, error) {
	data, err := base64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		log.Fatal("error decoding saml assertion")
	}

	awsRoles, err := saml.ExtractAwsRoles(data)
	if err != nil {
		log.Fatal("error parsing aws roles")
	}

	account := new(saml.AWSAccount)
	account.Id = loginFlags.Account

	if loginFlags.Role != "" {
	saml.AssignPrincipals(awsRoles, account)
		return saml.LocateRole(account, loginFlags.Role)
	}

	//accounts, err := saml.ParseAWSAccounts(samlAssertion)
	//if err != nil {
	//	log.Fatal("Failed to assume role, please check you are permitted to assume the given role for the AWS service")
	//}
	//account = accounts[0]

	for {
		awsRole, err := promptForAWSRoleSelection(account)
		if err == nil {
			return awsRole, nil
		}
		fmt.Println("error selecting role, try again")
	}
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

func stringValue(v *string) string {
	if v != nil {
		return *v
	}
	return ""
}
