package utils

import (
	"os"

	"github.com/joho/godotenv"
)

func GetAuth() (*AuthDetails, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, err
	}

	auth := AuthDetails{
		AccountID: os.Getenv("ACCOUNT_ID"),
		APIToken:  os.Getenv("API_TOKEN"),
	}

	return &auth, nil
}
