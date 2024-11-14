package path

import (
	"fmt"
	"os"
)

const AppName = "aws-sso-google"

func UserDataDirForApp() (string, error) {
	p, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/%s", p, AppName), nil
}

func CreateCacheDirForApp() error {
	p, err := CacheDirForApp()
	if err != nil {
		return err
	}

	return os.MkdirAll(p, 0700)
}

func CacheDirForApp() (string, error) {
	p, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/%s", p, AppName), nil
}

func CredentialsFile() (string, error) {
	p, err := CacheDirForApp()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s/%s", p, "credentials"), nil
}

func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}
