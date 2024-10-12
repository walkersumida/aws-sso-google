<p align="center">
  <p align="center">aws-sso-google</p>
  <p align="center">AWS STS credentials via Google Workspace</p>
</p>

[![](https://github.com/walkersumida/aws-sso-google/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/walkersumida/aws-sso-google/actions)

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
credential_process = aws-sso-google -c -u user@example.com -p example -i XXXXXXXXX -s 888888888888 --aws-region ap-northeast-1 --aws-role-arn arn:aws:iam::999999999999:role/RoleName
```

Then run the `aws` command as usual.
```bash
$ aws s3 ls
```

If the authentication has expired, the browser will start and the Google authentication screen will appear. If the authentication is successful, the result of the aws command will be displayed.

## Help

```bash
$ aws-sso-google -h
Acquire AWS STS credentials via Google Workspace SAML in a browser

Usage:
  aws-sso-google [flags]

Flags:
  -p, --aws-profile string    AWS profile
  -e, --aws-region string     AWS region
  -r, --aws-role-arn string   AWS role arn
  -c, --clean                 Clean browser session
  -d, --duration int32        Credential duration in seconds (default 3600)
  -h, --help                  help for aws-sso-google
  -i, --idp-id string         Google SSO IdP identifier
  -s, --sp-id string          Google SSO SP identifier
  -u, --username string       Google Email address
  -v, --version               version for aws-sso-google
```
