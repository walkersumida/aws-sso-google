package sts

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
)

type STSer interface {
	AssumeRoleWithSAML() (*Response, error)
	SetAwsPrincipalArn(string)
	SetSAMLAssertion(string)
}

type STS struct {
	AwsProfile         string
	AwsRegion          string
	AwsRoleArn         string
	AwsSessionDuration int32
	AwsPrincipalArn    string
	SAMLAssertion      string
}

var _ STSer = &STS{}

type Response struct {
	sdksts.AssumeRoleWithSAMLOutput
}

func New(profile, region, roleArn string, duration int32) *STS {
	return &STS{
		AwsProfile:         profile,
		AwsRegion:          region,
		AwsRoleArn:         roleArn,
		AwsSessionDuration: duration,
	}
}

func (s *STS) SetAwsPrincipalArn(principalArn string) {
	s.AwsPrincipalArn = principalArn
}

func (s *STS) SetSAMLAssertion(samlAssertion string) {
	s.SAMLAssertion = samlAssertion
}

func (s *STS) AssumeRoleWithSAML() (*Response, error) {
	opts := []func(*config.LoadOptions) error{
		config.WithSharedConfigProfile(s.AwsProfile),
	}
	if s.AwsRegion != "" {
		opts = append(opts, config.WithRegion(s.AwsRegion))
	}

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(
		ctx,
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("could not load default config: %w", err)
	}

	stsCli := sdksts.NewFromConfig(cfg)

	input := &sdksts.AssumeRoleWithSAMLInput{
		DurationSeconds: &s.AwsSessionDuration,
		PrincipalArn:    &s.AwsPrincipalArn,
		RoleArn:         &s.AwsRoleArn,
		SAMLAssertion:   &s.SAMLAssertion,
	}

	output, err := stsCli.AssumeRoleWithSAML(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("could not assume role with SAML: %w", err)
	}

	return &Response{AssumeRoleWithSAMLOutput: *output}, nil
}
