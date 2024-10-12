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
	var duration int32
	var awsRegion, awsRoleArn, idpID, awsProfile, spID, username string
	var rootCmd = &cobra.Command{
		Use:     "aws-sso-google",
		Version: "0.4.0",
		Short:   "Acquire AWS STS credentials via Google Workspace SAML in a browser",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := credential.New(awsProfile)
			saml := saml.New(awsRoleArn, idpID, spID, username, clean)
			sts := sts.New(awsProfile, awsRegion, awsRoleArn, duration)
			a := auth.New(c, saml, sts)
			cred, err := a.SAMLAuth()
			if err != nil {
				return err
			}

			credential.Println(cred)

			return nil
		},
	}

	rootCmd.Flags().BoolVarP(&clean, "clean", "c", false, "Clean browser session")
	rootCmd.Flags().Int32VarP(&duration, "duration", "d", 3600, "Credential duration in seconds")
	rootCmd.Flags().StringVarP(&awsProfile, "aws-profile", "p", "", "AWS profile")
	rootCmd.Flags().StringVarP(&awsRegion, "aws-region", "e", "", "AWS region")
	rootCmd.Flags().StringVarP(&awsRoleArn, "aws-role-arn", "r", "", "AWS role arn")
	rootCmd.Flags().StringVarP(&idpID, "idp-id", "i", "", "Google SSO IdP identifier")
	rootCmd.Flags().StringVarP(&spID, "sp-id", "s", "", "Google SSO SP identifier")
	rootCmd.Flags().StringVarP(&username, "username", "u", "", "Google Email address")

	if err := rootCmd.MarkFlagRequired("aws-profile"); err != nil {
		return err
	}
	if err := rootCmd.MarkFlagRequired("aws-role-arn"); err != nil {
		return err
	}
	if err := rootCmd.MarkFlagRequired("idp-id"); err != nil {
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
