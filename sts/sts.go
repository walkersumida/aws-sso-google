package sts

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
)

type STSer interface {
	AssumeRoleWithSAML() (*Response, error)
	SetPrincipalArn(string)
	SetSAMLAssertion(string)
}

type STS struct {
	AwsProfile    string
	AwsRoleArn    string
	Duration      int32
	PrincipalArn  string
	SAMLAssertion string
}

var _ STSer = &STS{}

type Response struct {
	sdksts.AssumeRoleWithSAMLOutput
}

func New(awsProfile, awsRoleArn string, duration int32) *STS {
	return &STS{
		AwsProfile: awsProfile,
		AwsRoleArn: awsRoleArn,
		Duration:   duration,
	}
}

func (s *STS) SetPrincipalArn(principalArn string) {
	s.PrincipalArn = principalArn
}

func (s *STS) SetSAMLAssertion(samlAssertion string) {
	s.SAMLAssertion = samlAssertion
}

func (s *STS) AssumeRoleWithSAML() (*Response, error) {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithSharedConfigProfile(s.AwsProfile),
	)
	if err != nil {
		return nil, fmt.Errorf("could not load default config: %w", err)
	}

	stsCli := sdksts.NewFromConfig(cfg)

	input := &sdksts.AssumeRoleWithSAMLInput{
		DurationSeconds: &s.Duration,
		PrincipalArn:    &s.PrincipalArn,
		RoleArn:         &s.AwsRoleArn,
		SAMLAssertion:   &s.SAMLAssertion,
	}

	output, err := stsCli.AssumeRoleWithSAML(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("could not assume role with SAML: %w", err)
	}

	return &Response{AssumeRoleWithSAMLOutput: *output}, nil
}
