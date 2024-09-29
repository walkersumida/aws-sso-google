package credential

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"github.com/walkersumida/aws-sso-google/path"
	"gopkg.in/ini.v1"
)

type Credentialer interface {
	SetAccessKeyID(*string)
	SetExpiration(*time.Time)
	SetAwsProfile(string)
	SetSecretAccessKey(*string)
	SetSessionToken(*string)
	Load() error
	IsExpired() bool
	Save() error
	Output() (string, error)
}

type Credential struct {
	AccessKeyID     *string
	Expiration      *time.Time
	AwsProfile      string
	SecretAccessKey *string
	SessionToken    *string
}

var _ Credentialer = &Credential{}

func New(awsProfile string) *Credential {
	return &Credential{
		AwsProfile: awsProfile,
	}
}

func (c *Credential) SetAccessKeyID(accessKeyID *string) {
	c.AccessKeyID = accessKeyID
}

func (c *Credential) SetExpiration(expiration *time.Time) {
	c.Expiration = expiration
}

func (c *Credential) SetAwsProfile(awsProfile string) {
	c.AwsProfile = awsProfile
}

func (c *Credential) SetSecretAccessKey(secretAccessKey *string) {
	c.SecretAccessKey = secretAccessKey
}

func (c *Credential) SetSessionToken(sessionToken *string) {
	c.SessionToken = sessionToken
}

func (c *Credential) Load() error {
	p, err := path.CredentialsFile()
	if err != nil {
		return err
	}

	exists, err := path.Exists(p)
	if err != nil {
		return err
	}

	if !exists {
		_, err = os.Create(p)
		if err != nil {
			return err
		}

		return nil
	}

	cfg, err := ini.Load(p)
	if err != nil {
		return err
	}

	section, err := cfg.GetSection(c.AwsProfile)
	if err != nil {
		return err
	}

	c.SetAccessKeyID(ptrString(section.Key("aws_access_key_id").Value()))
	c.SetSecretAccessKey(ptrString(section.Key("aws_secret_access_key").Value()))
	c.SetSessionToken(ptrString(section.Key("aws_session_token").Value()))

	exp := section.Key("aws_session_expiration").Value()
	if exp == "" {
		return nil
	}

	parsedExp, err := time.Parse(time.RFC3339, exp)
	if err != nil {
		return err
	}

	c.SetExpiration(&parsedExp)

	return nil
}

func (c *Credential) IsExpired() bool {
	if c.Expiration == nil {
		return true
	}

	return time.Now().After(*c.Expiration)
}

func (c *Credential) Save() error {
	err := c.validate()
	if err != nil {
		return err
	}

	p, err := path.CredentialsFile()
	if err != nil {
		return err
	}

	cfg, err := ini.Load(p)
	if err != nil {
		return err
	}

	cfg.Section(c.AwsProfile).Key("aws_access_key_id").SetValue(*c.AccessKeyID)
	cfg.Section(c.AwsProfile).Key("aws_secret_access_key").SetValue(*c.SecretAccessKey)
	cfg.Section(c.AwsProfile).Key("aws_session_token").SetValue(*c.SessionToken)
	cfg.Section(c.AwsProfile).Key("aws_session_expiration").SetValue(c.Expiration.Format(time.RFC3339))

	err = cfg.SaveTo(p)
	if err != nil {
		return err
	}

	return nil
}

func (c *Credential) Output() (string, error) {
	err := c.validate()
	if err != nil {
		return "", err
	}

	type output struct {
		AccessKeyID     string `json:"AccessKeyId"`
		Expiration      string `json:"Expiration"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken"`
		Version         int    `json:"Version"`
	}

	o := output{
		AccessKeyID:     *c.AccessKeyID,
		Expiration:      c.Expiration.Format(time.RFC3339),
		SecretAccessKey: *c.SecretAccessKey,
		SessionToken:    *c.SessionToken,
		Version:         1,
	}

	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func ptrString(s string) *string {
	return &s
}

func (c *Credential) validate() error {
	if c.AccessKeyID == nil {
		return errors.New("access key id must be set")
	}

	if c.SecretAccessKey == nil {
		return errors.New("secret access key must be set")
	}

	if c.SessionToken == nil {
		return errors.New("session token must be set")
	}

	if c.Expiration == nil {
		return errors.New("expiration must be set")
	}

	return nil
}
