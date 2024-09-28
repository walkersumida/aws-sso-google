package sts

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
)

type STSer interface {
	SetPrincipalArn(string)
	SetProfile(string)
	SetRoleArn(string)
	SetSAMLAssertion(string)
	AssumeRoleWithSAML() (*Response, error)
}

type STS struct {
	PrincipalArn  string
	Profile       string
	RoleArn       string
	SAMLAssertion string
}

var _ STSer = &STS{}

type Response struct {
	sdksts.AssumeRoleWithSAMLOutput
}

func New() *STS {
	return &STS{}
}

func (s *STS) SetPrincipalArn(principalArn string) {
	s.PrincipalArn = principalArn
}

func (s *STS) SetProfile(profile string) {
	s.Profile = profile
}

func (s *STS) SetRoleArn(roleArn string) {
	s.RoleArn = roleArn
}

func (s *STS) SetSAMLAssertion(samlAssertion string) {
	s.SAMLAssertion = samlAssertion
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
