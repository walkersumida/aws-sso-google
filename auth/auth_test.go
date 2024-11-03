package auth_test

import (
	"encoding/json"
	"testing"
	"time"

	sdksts "github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/google/go-cmp/cmp"
	"github.com/walkersumida/aws-sso-google/auth"
	cmock "github.com/walkersumida/aws-sso-google/credential/mock"
	"github.com/walkersumida/aws-sso-google/saml"
	smock "github.com/walkersumida/aws-sso-google/saml/mock"
	"github.com/walkersumida/aws-sso-google/sts"
	stsmock "github.com/walkersumida/aws-sso-google/sts/mock"
)

func TestSAMLAuth(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		giveIsExpired        bool
		wantSAMLAuthResponse string
		wantSigninCalls      int
	}{
		"when credential is expired": {
			giveIsExpired:        true,
			wantSAMLAuthResponse: toOutput("access-key", "2024-01-01T00:00:00Z", "secret", "session"),
			wantSigninCalls:      1,
		},
		"when credential is not expired": {
			giveIsExpired:        false,
			wantSAMLAuthResponse: toOutput("access-key", "2024-01-01T00:00:00Z", "secret", "session"),
			wantSigninCalls:      0,
		},
	}
	for name, tt := range tests {
		tt, name := tt, name
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cred := newCredentialMock()
			cred.IsExpiredFunc = func() bool {
				return tt.giveIsExpired
			}
			cred.OutputFunc = func() (string, error) {
				return toOutput("access-key", "2024-01-01T00:00:00Z", "secret", "session"), nil
			}
			saml := newSAMLMock()
			sts := newSTSMock()

			a := auth.New(cred, saml, sts)

			got, err := a.SAMLAuth()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if diff := cmp.Diff(tt.wantSAMLAuthResponse, got); diff != "" {
				t.Errorf("mismatch (-want +got): ¥n%s", diff)
			}

			if diff := cmp.Diff(tt.wantSigninCalls, len(saml.SigninCalls())); diff != "" {
				t.Errorf("mismatch (-want +got): ¥n%s", diff)
			}
		})
	}
}

func newCredentialMock() *cmock.CredentialerMock {
	return &cmock.CredentialerMock{
		LoadFunc: func() error {
			return nil
		},
		IsExpiredFunc: func() bool {
			return false
		},
		OutputFunc: func() (string, error) {
			return "", nil
		},
		SetAccessKeyIDFunc:     func(s *string) {},
		SetExpirationFunc:      func(t *time.Time) {},
		SetSecretAccessKeyFunc: func(s *string) {},
		SetSessionTokenFunc:    func(s *string) {},
		SaveFunc: func() error {
			return nil
		},
	}
}

func newSAMLMock() *smock.SAMLerMock {
	return &smock.SAMLerMock{
		SigninFunc: func() (*saml.Response, error) {
			return &saml.Response{
				PrincipalArn: "arn:aws:iam::123456789012:role/role-name",
				SAMLResponse: "saml",
			}, nil
		},
	}
}

func newSTSMock() *stsmock.STSerMock {
	return &stsmock.STSerMock{
		SetAwsPrincipalArnFunc: func(s string) {},
		SetSAMLAssertionFunc:   func(s string) {},
		AssumeRoleWithSAMLFunc: func() (*sts.Response, error) {
			return &sts.Response{
				AssumeRoleWithSAMLOutput: sdksts.AssumeRoleWithSAMLOutput{
					Credentials: &types.Credentials{
						AccessKeyId:     toPointer("access-key-id"),
						Expiration:      toPointer(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
						SecretAccessKey: toPointer("secret-access-key"),
						SessionToken:    toPointer("session-token"),
					},
				},
			}, nil
		},
	}
}

func toPointer[T comparable](v T) *T {
	return &v
}

func toOutput(accessKeyID, expiration, secretAccessKey, sessionToken string) string {
	type output struct {
		AccessKeyID     string `json:"AccessKeyId"`
		Expiration      string `json:"Expiration"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken"`
		Version         int    `json:"Version"`
	}

	o := output{
		AccessKeyID:     accessKeyID,
		Expiration:      expiration,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Version:         0,
	}

	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return ""
	}

	return string(b)
}
