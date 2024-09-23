package sts

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
)

type STS struct {
	PrincipalArn  string
	Profile       string
	RoleArn       string
	SAMLAssertion string
}

type Response struct {
	sdksts.AssumeRoleWithSAMLOutput
}

func New(principalArn, profile, roleArn, samlAssertion string) *STS {
	return &STS{
		PrincipalArn:  principalArn,
		Profile:       profile,
		RoleArn:       roleArn,
		SAMLAssertion: samlAssertion,
	}
}

func (s *STS) AssumeRoleWithSAML() (*Response, error) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithSharedConfigProfile(s.Profile),
	)
	if err != nil {
		return nil, fmt.Errorf("could not load default config: %w", err)
	}

	stsCli := sdksts.NewFromConfig(cfg)

	input := &sdksts.AssumeRoleWithSAMLInput{
		PrincipalArn:  &s.PrincipalArn,
		RoleArn:       &s.RoleArn,
		SAMLAssertion: &s.SAMLAssertion,
	}

	output, err := stsCli.AssumeRoleWithSAML(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("could not assume role with SAML: %w", err)
	}

	return &Response{AssumeRoleWithSAMLOutput: *output}, nil
}
