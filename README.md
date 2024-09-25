<p align="center">
  <p align="center">aws-sso-google</p>
  <p align="center">AWS STS credentials via Google Workspace</p>
</p>

#### Features:

- Seamless integration with the `aws` cli for secure, continuous and non-interactive STS session renewals.
- Support for all 2FA methods as provided by Google

## Installation

### Build from source

```bash
go install github.com/walkersumida/aws-sso-google@latest
```

### Install executable binary

TODO

### Install via Homebrew

TODO

## Usage

Add the following settings to `~/.aws/config`.

ref: [Source credentials with an external process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html)

```ini
[profile example]
credential_process = aws-sso-google -c -u user@example.com -p example -i XXXXXXXXX -s 888888888888 -r arn:aws:iam::999999999999:role/RoleName
```

```bash
$ aws-sso-google -h
Acquire AWS STS credentials via Google Workspace SAML in a browser

Usage:
  aws-sso-google [flags]

Flags:
  -r, --aws-role-arn string   AWS role arn
  -c, --clean                 Clean browser session
  -h, --help                  help for aws-sso-google
  -i, --idp-id string         Google SSO IdP identifier
  -p, --profile string        AWS profile
  -s, --sp-id string          Google SSO SP identifier
  -u, --username string       Google Email address
  -v, --version               version for aws-sso-google
```
