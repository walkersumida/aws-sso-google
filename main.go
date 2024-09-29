package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/walkersumida/aws-sso-google/auth"
	"github.com/walkersumida/aws-sso-google/credential"
	"github.com/walkersumida/aws-sso-google/saml"
	"github.com/walkersumida/aws-sso-google/sts"
)

func run() error {
	var clean bool
	var awsRoleArn, idpID, awsProfile, spID, username string
	var rootCmd = &cobra.Command{
		Use:     "aws-sso-google",
		Version: "0.1.1",
		Short:   "Acquire AWS STS credentials via Google Workspace SAML in a browser",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := credential.New(awsProfile)
			saml := saml.New(awsRoleArn, idpID, spID, username, clean)
			sts := sts.New()
			a := auth.New(c, saml, sts)
			cred, err := a.SAMLAuth(awsRoleArn, awsProfile, idpID, spID, username, clean)
			if err != nil {
				return err
			}

			fmt.Println(cred)

			return nil
		},
	}

	rootCmd.Flags().BoolVarP(&clean, "clean", "c", false, "Clean browser session")
	rootCmd.Flags().StringVarP(&awsProfile, "aws-profile", "p", "", "AWS profile")
	rootCmd.Flags().StringVarP(&awsRoleArn, "aws-role-arn", "r", "", "AWS role arn")
	rootCmd.Flags().StringVarP(&idpID, "idp-id", "i", "", "Google SSO IdP identifier")
	rootCmd.Flags().StringVarP(&spID, "sp-id", "s", "", "Google SSO SP identifier")
	rootCmd.Flags().StringVarP(&username, "username", "u", "", "Google Email address")

	if err := rootCmd.MarkFlagRequired("aws-role-arn"); err != nil {
		return err
	}
	if err := rootCmd.MarkFlagRequired("idp-id"); err != nil {
		return err
	}
	if err := rootCmd.MarkFlagRequired("aws-profile"); err != nil {
		return err
	}
	if err := rootCmd.MarkFlagRequired("sp-id"); err != nil {
		return err
	}

	if err := rootCmd.Execute(); err != nil {
		return err
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%+v\n", err)
		os.Exit(1)
	}
}
