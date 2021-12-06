// Copyright 2021 MongoDB Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package store

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"okta-hosted-login/m/rbac"
	"os"

	"github.com/casbin/casbin/v2"
)

const (
	readOnlyGroup = "10gen-cloud-rate-limiting-read-only"
	adminGroup    = "10gen-cloud"
)

type Store struct {
	Session *Session
	TPL     *template.Template
	RBAC    *rbac.RBAC
	Nonce   string
	State   string
}

type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}

type Profile struct {
	Sub               string `json:"sub,omitempty"`
	Name              string `json:"name,omitempty"`
	Locale            string `json:"locale,omitempty"`
	Email             string `json:"email,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	ZoneInfo          string `json:"zoneinfo,omitempty"`
	UpdatedAt         int    `json:"updated_at,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	LastName          string `json:"lastName,omitempty"`
	FirstName         string `json:"firstName,omitempty"`
	Test              string `json:"test,omitempty"`
	Login             string `json:"login,omitempty"`
	PrimaryEmail      string `json:"primaryEmail,omitempty"`
}

func New() *Store {
	e, _ := casbin.NewEnforcer("/Users/andrea.angiolillo/workspace/poc/rate-limiting-oidc/rbac/model.conf", "/Users/andrea.angiolillo/workspace/poc/rate-limiting-oidc/rbac/policy.csv")
	return &Store{
		Session: NewSession(),
		TPL:     template.Must(template.ParseGlob("templates/*")),
		RBAC: &rbac.RBAC{
			Enforcer: e,
		},
		Nonce: "NonceNotSetYet",
		State: generateState(),
	}
}

func generateState() string {
	// Generate a random byte array for state parameter
	b := make([]byte, 16)
	return hex.EncodeToString(b)
}

func (s *Store) AuthorizationCodeRequest(r *http.Request) string {
	// Endpoint: https://developer.okta.com/docs/reference/api/oidc/#authorize
	q := r.URL.Query()
	q.Add("client_id", os.Getenv("CLIENT_ID"))
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("scope", "openid profile email")
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")
	q.Add("state", s.State)
	q.Add("nonce", s.Nonce)
	return os.Getenv("ISSUER") + "/v1/authorize?" + q.Encode()
}

func (s *Store) ExchangeCodeRequest(code string, r *http.Request) (*Exchange, error) {
	// Endpoint https://developer.okta.com/docs/reference/api/oidc/#token
	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(os.Getenv("CLIENT_ID") + ":" + os.Getenv("CLIENT_SECRET")))

	q := r.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Set("code", code)
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")

	url := os.Getenv("ISSUER") + "/v1/token?" + q.Encode()

	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Basic "+authHeader)
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Printf("error closing source: %s", err)
		}
	}(resp.Body)

	var exchange Exchange
	err := json.Unmarshal(body, &exchange)
	if err != nil {
		return nil, err
	}

	return &exchange, nil
}

func (s *Store) ProfileDataRequest(r *http.Request) (*Profile, error) {
	// Endpoint: https://developer.okta.com/docs/reference/api/oidc/#userinfo
	var profile *Profile

	session, err := s.Session.Session(r)

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" || session.Values["globalGroups"] == nil {
		return profile, nil
	}

	groups := session.Values["globalGroups"]
	if isAllowed := s.RBAC.Enforce(groups.([]interface{}), "profile", "read"); !isAllowed {
		return profile, fmt.Errorf("you are not allowed to access the resource %s", "profile")
	}

	reqUrl := os.Getenv("ISSUER") + "/v1/userinfo"
	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Printf("error closing source: %s", err)
		}
	}(resp.Body)

	err = json.Unmarshal(body, &profile)
	if err != nil {
		return nil, err
	}

	return profile, nil
}

func (s *Store) IsAdmin(r *http.Request) bool {
	return s.hasGroup(r, adminGroup)
}

func (s *Store) IsReadOnly(r *http.Request) bool {
	return s.hasGroup(r, readOnlyGroup)
}

func (s *Store) hasGroup(r *http.Request, g string) bool {
	session, err := s.Session.Session(r)
	if err != nil {
		return false
	}

	groups := session.Values["globalGroups"]
	if groups == nil {
		return false
	}

	for _, group := range groups.([]interface{}) {
		if group == g {
			return true
		}
	}
	return false
}
