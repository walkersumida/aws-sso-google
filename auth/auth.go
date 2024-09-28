package auth

import (
	"github.com/walkersumida/aws-sso-google/credential"
	"github.com/walkersumida/aws-sso-google/saml"
	"github.com/walkersumida/aws-sso-google/sts"
)

type Auth struct {
	Credential credential.Credentialer
	SAML       saml.SAMLer
	STS        sts.STSer
}

func New(cred credential.Credentialer, saml saml.SAMLer, sts sts.STSer) *Auth {
	return &Auth{
		Credential: cred,
		SAML:       saml,
		STS:        sts,
	}
}

func (a *Auth) SAMLAuth(awsRoleArn, profile, idpID, spID, username string, clean bool) (string, error) {
	if err := a.Credential.Load(); err != nil {
		return "", err
	}
	if !a.Credential.IsExpired() {
		out, err := a.Credential.Output()
		if err != nil {
			return "", err
		}

		return out, nil
	}

	samlRes, err := a.SAML.Signin()
	if err != nil {
		return "", err
	}

	a.STS.SetPrincipalArn(samlRes.PrincipalArn)
	a.STS.SetProfile(profile)
	a.STS.SetRoleArn(awsRoleArn)
	a.STS.SetSAMLAssertion(samlRes.SAMLResponse)
	stsRes, err := a.STS.AssumeRoleWithSAML()
	if err != nil {
		return "", err
	}

	a.Credential.SetAccessKeyId(stsRes.Credentials.AccessKeyId)
	a.Credential.SetExpiration(stsRes.Credentials.Expiration)
	a.Credential.SetProfile(profile)
	a.Credential.SetSecretAccessKey(stsRes.Credentials.SecretAccessKey)
	a.Credential.SetSessionToken(stsRes.Credentials.SessionToken)
	if err := a.Credential.Save(); err != nil {
		return "", err
	}

	out, err := a.Credential.Output()
	if err != nil {
		return "", err
	}

	return out, nil
}
