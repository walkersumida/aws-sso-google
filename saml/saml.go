package saml

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/playwright-community/playwright-go"
	"github.com/walkersumida/aws-sso-google/path"
)

type SAMLer interface {
	Signin() (*Response, error)
}

type SAML struct {
	AwsRoleArn string // required
	Clean      bool
	IDPID      string // required
	SpID       string // required
	Username   string
}

var _ SAMLer = &SAML{}

type Response struct {
	PrincipalArn string
	SAMLResponse string
}

type XMLSAMLResponse struct {
	Assertion struct {
		AttributeStatement struct {
			Attribute []struct {
				Name           string `xml:"Name,attr"`
				AttributeValue []struct {
					Type     string `xml:"type,attr"`
					Xsd      string `xml:"xsd,attr"`
					Xsi      string `xml:"xsi,attr"`
					CharData string `xml:",chardata"`
				} `xml:"AttributeValue"`
			} `xml:"Attribute"`
		} `xml:"AttributeStatement"`
	} `xml:"Assertion"`
}

const (
	AwsSAMLSigninURL = "https://signin.aws.amazon.com/saml"
	GoogleAccountURL = "https://accounts.google.com"

	RegexpPrincipalArn = `(arn:aws:iam:[^:]*:[0-9]+:saml-provider\/[0-9a-zA-Z-_.]+)`
)

func New(awsRoleArn, idpID, spID, username string, clean bool) *SAML {
	return &SAML{
		AwsRoleArn: awsRoleArn,
		Clean:      clean,
		IDPID:      idpID,
		SpID:       spID,
		Username:   username,
	}
}

func (s *SAML) Signin() (*Response, error) {
	err := playwright.Install()
	if err != nil {
		return nil, fmt.Errorf("could not install playwright: %w", err)
	}

	pw, err := playwright.Run()
	if err != nil {
		return nil, fmt.Errorf("could not start playwright: %w", err)
	}

	userDataDir, err := path.UserDataDirForApp()
	if err != nil {
		return nil, fmt.Errorf("could not get user data dir: %w", err)
	}

	if s.Clean {
		if err := os.RemoveAll(userDataDir); err != nil {
			return nil, fmt.Errorf("could not remove user data dir: %w", err)
		}
	}

	context, err := pw.Chromium.LaunchPersistentContext(
		userDataDir,
		playwright.BrowserTypeLaunchPersistentContextOptions{
			Headless: playwright.Bool(false),
		},
	)
	if err != nil {
		return nil, fmt.Errorf("could not launch browser: %w", err)
	}

	page, err := context.NewPage()
	if err != nil {
		return nil, fmt.Errorf("could not create page: %w", err)
	}

	page.SetDefaultTimeout(0)
	page.SetDefaultNavigationTimeout(0)

	var samlResponse string
	var errInRoute error
	err = page.Route("**/*", func(route playwright.Route) {
		err = route.Continue()
		if err != nil {
			errInRoute = fmt.Errorf("could not continue: %w", err)
			return
		}

		if route.Request().URL() == AwsSAMLSigninURL {
			req, err := route.Request().PostData()
			if err != nil {
				errInRoute = fmt.Errorf("could not get postData: %w", err)
				return
			}

			resRemovedKey := strings.ReplaceAll(req, "SAMLResponse=", "")
			samlResponse, err = url.QueryUnescape(resRemovedKey)
			if err != nil {
				errInRoute = fmt.Errorf("could not unescape: %w", err)
				return
			}
		}
	})
	if err != nil {
		return nil, fmt.Errorf("could not route: %w", err)
	}

	_, err = page.Goto(
		s.buildSamlURL(),
		playwright.PageGotoOptions{
			WaitUntil: playwright.WaitUntilStateDomcontentloaded,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("could not goto: %w", err)
	}

	if s.Username != "" {
		cnt, err := page.Locator("input[type=\"email\"]").Count()
		if err != nil {
			return nil, fmt.Errorf("could not count: %w", err)
		}

		if cnt > 0 {
			if err := page.Locator("input[type=\"email\"]").First().Fill(s.Username); err != nil {
				return nil, fmt.Errorf("could not fill username: %w", err)
			}
		}
	}

	err = page.WaitForURL(AwsSAMLSigninURL, playwright.PageWaitForURLOptions{
		WaitUntil: playwright.WaitUntilStateLoad,
	})
	if err != nil {
		return nil, fmt.Errorf("could not wait for URL: %w", err)
	}

	err = page.WaitForLoadState(playwright.PageWaitForLoadStateOptions{
		State: playwright.LoadStateLoad,
	})
	if err != nil {
		return nil, fmt.Errorf("could not wait for load state: %w", err)
	}
	if errInRoute != nil {
		return nil, fmt.Errorf("could not route: %w", errInRoute)
	}

	arns, err := findRoleArns(page)
	if err != nil {
		return nil, fmt.Errorf("could not find arns: %w", err)
	}
	if !validateArn(arns, s.AwsRoleArn) {
		return nil, fmt.Errorf("could not find arn: %s", s.AwsRoleArn)
	}

	if err := stopPlaywright(pw, context); err != nil {
		return nil, fmt.Errorf("could not stop Playwright: %w", err)
	}

	if s.Clean {
		if err := os.RemoveAll(userDataDir); err != nil {
			return nil, fmt.Errorf("could not remove user data dir: %w", err)
		}
	}

	decodedSAMLRes, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("could not decode SAMLResponse: %w", err)
	}

	xmlSAMLRes := XMLSAMLResponse{}
	err = xml.Unmarshal(decodedSAMLRes, &xmlSAMLRes)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal SAMLResponse: %w", err)
	}

	principalArn := findPrincipalArn(s.AwsRoleArn, xmlSAMLRes)
	if principalArn == "" {
		return nil, fmt.Errorf("could not find principalArn")
	}

	return &Response{
		SAMLResponse: samlResponse,
		PrincipalArn: principalArn,
	}, nil
}

func (s *SAML) buildSamlURL() string {
	return fmt.Sprintf("%s/o/saml2/initsso?idpid=%s&spid=%s&forceauthn=false", GoogleAccountURL, s.IDPID, s.SpID)
}

func findPrincipalArn(roleArn string, xmlSAMLRes XMLSAMLResponse) string {
	for _, attr := range xmlSAMLRes.Assertion.AttributeStatement.Attribute {
		if attr.Name == "https://aws.amazon.com/SAML/Attributes/Role" {
			for _, attrVal := range attr.AttributeValue {
				if strings.Contains(attrVal.CharData, roleArn) {
					re := regexp.MustCompile(RegexpPrincipalArn)
					principalArn := re.FindString(attrVal.CharData)
					return principalArn
				}
			}
		}
	}

	return ""
}

func findRoleArns(page playwright.Page) ([]string, error) {
	loc := page.Locator("label[for*=\"arn\"]")
	arns, err := loc.All()
	if err != nil {
		return nil, fmt.Errorf("could not get arns: %w", err)
	}

	var arnValues []string
	for _, arn := range arns {
		value, err := arn.GetAttribute("for")
		if err != nil {
			return nil, fmt.Errorf("could not get text content: %w", err)
		}
		arnValues = append(arnValues, value)
	}

	return arnValues, nil
}

func validateArn(allArns []string, arn string) bool {
	for _, a := range allArns {
		if a == arn {
			return true
		}
	}

	return false
}

func stopPlaywright(pw *playwright.Playwright, browserCtx playwright.BrowserContext) error {
	if err := browserCtx.Close(); err != nil {
		return err
	}
	if err := pw.Stop(); err != nil {
		return err
	}

	return nil
}
