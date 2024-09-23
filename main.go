package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/walkersumida/aws-sso-google/credential"
	"github.com/walkersumida/aws-sso-google/saml"
	"github.com/walkersumida/aws-sso-google/sts"
)

func samlAuth(awsRoleArn, profile, idpID, spID, username string, clean bool) (string, error) {
	cred := credential.New(profile)
	if err := cred.Load(); err != nil {
		return "", err
	}
	if !cred.IsExpired() {
		out, err := cred.Output()
		if err != nil {
			return "", err
		}

		return out, nil
	}

	s := saml.New(awsRoleArn, idpID, spID, username, clean)
	samlRes, err := s.Signin()
	if err != nil {
		return "", err
	}

	sts := sts.New(samlRes.PrincipalArn, profile, awsRoleArn, samlRes.SAMLResponse)
	stsRes, err := sts.AssumeRoleWithSAML()
	if err != nil {
		return "", err
	}

	cred.SetAccessKeyId(stsRes.Credentials.AccessKeyId)
	cred.SetExpiration(stsRes.Credentials.Expiration)
	cred.SetProfile(profile)
	cred.SetSecretAccessKey(stsRes.Credentials.SecretAccessKey)
	cred.SetSessionToken(stsRes.Credentials.SessionToken)
	if err := cred.Save(); err != nil {
		return "", err
	}

	out, err := cred.Output()
	if err != nil {
		return "", err
	}

	return out, nil
}

func run() error {
	var clean bool
	var awsRoleArn, idpID, profile, spID, username string
	var rootCmd = &cobra.Command{
		Use:     "aws-sso-google",
		Version: "0.1.0",
		Short:   "Acquire AWS STS credentials via Google Workspace SAML in a browser",
		RunE: func(cmd *cobra.Command, args []string) error {
			cred, err := samlAuth(awsRoleArn, profile, idpID, spID, username, clean)
			if err != nil {
				return err
			}

			fmt.Println(cred)

			return nil
		},
	}

	rootCmd.Flags().BoolVarP(&clean, "clean", "c", false, "Clean browser session")
	rootCmd.Flags().StringVarP(&awsRoleArn, "aws-role-arn", "r", "", "AWS role arn")
	rootCmd.Flags().StringVarP(&idpID, "idp-id", "i", "", "Google SSO IdP identifier")
	rootCmd.Flags().StringVarP(&profile, "profile", "p", "", "AWS profile")
	rootCmd.Flags().StringVarP(&spID, "sp-id", "s", "", "Google SSO SP identifier")
	rootCmd.Flags().StringVarP(&username, "username", "u", "", "Google Email address")

	if err := rootCmd.MarkFlagRequired("aws-role-arn"); err != nil {
		return err
	}
	if err := rootCmd.MarkFlagRequired("idp-id"); err != nil {
		return err
	}
	if err := rootCmd.MarkFlagRequired("profile"); err != nil {
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
