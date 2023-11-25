// Copyright (c) 2023, Benjamin Darnault <daniel.jantrambun@pm.me>
// Copyright (c) 2019, Daniel Martí <mvdan@mvdan.cc>
// See LICENSE for licensing information

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"runtime"
)

type preLoginRequest struct {
	Email string `json:"email"`
}

type preLoginResponse struct {
	KDF            int
	KDFIterations  int
	KDFMemory      int
	KDFParallelism int
}

type tokLoginResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	Key          string `json:"key"`
}

const (
	// deviceName should probably be like "Linux", "Android", etc, but this
	// helps the human user differentiate bitw logins from those made by the
	// official clients.
	deviceName       = "bitw"
	loginScope       = "api offline_access"
	loginAPIKeyScope = "api"
)

func deviceType() string {
	// The enum strings come from https://github.com/bitwarden/server/blob/b19628c6f85a2cd5f1950ac222ba14840a88894d/src/Core/Enums/DeviceType.cs.
	switch runtime.GOOS {
	case "linux":
		return "8" // Linux Desktop
	case "darwin":
		return "7" // MacOS Desktop
	case "windows":
		return "6" // Windows Desktop
	default:
		return "14" // Unknown Browser, since we don't have a better fallback
	}
}

func loginToVault(ctx context.Context, retryWithAPIKey bool) error {
	email, err := secrets.email()
	if err != nil {
		return err
	}

	var preLogin preLoginResponse
	if err := jsonPOST(ctx, apiURL+"/accounts/prelogin", &preLogin, preLoginRequest{
		Email: email,
	}); err != nil {
		return fmt.Errorf("could not pre-login: %v", err)
	}
	globalData.KDF = KDFType(preLogin.KDF)
	globalData.KDFIterations = preLogin.KDFIterations
	globalData.KDFMemory = preLogin.KDFMemory
	globalData.KDFParallelism = preLogin.KDFParallelism

	var values url.Values
	if !retryWithAPIKey {
		return fmt.Errorf("not implemented")
	}
	clientID, err := secrets.clientID()
	if err != nil {
		return err
	}

	clientSecret, err := secrets.clientSecret()
	if err != nil {
		return err
	}

	values = urlValues(
		"client_id", string(clientID[:]),
		"client_secret", string(clientSecret[:]),
		"scope", loginAPIKeyScope,
		"grant_type", "client_credentials",
		"deviceType", deviceType(),
		"deviceName", deviceName,
		"deviceIdentifier", globalData.DeviceID,
	)

	var tokLogin tokLoginResponse
	err = jsonPOST(ctx, idtURL+"/connect/token", &tokLogin, values)
	if err != nil {
		return fmt.Errorf("could not login via password: %v", err)
	}
	globalData.AccessToken = tokLogin.AccessToken
	return nil
}

func urlValues(pairs ...string) url.Values {
	if len(pairs)%2 != 0 {
		panic("pairs must be of even length")
	}
	vals := make(url.Values)
	for i := 0; i < len(pairs); i += 2 {
		vals.Set(pairs[i], pairs[i+1])
	}
	return vals
}

var b64enc = base64.StdEncoding.Strict()
