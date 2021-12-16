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

package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"okta-hosted-login/m/store"
	"os"
	"strings"
	"time"

	verifier "github.com/okta/okta-jwt-verifier-golang"
)

const charset = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand = rand.New(
	rand.NewSource(time.Now().UnixNano()))
var s = store.New()

type customData struct {
	Profile         *store.Profile
	APIToken        string
	IsAuthenticated bool
	IsAdmin         bool
	IsReadOnly      bool
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	profile, err := s.ProfileDataRequest(r)
	if err != nil {
		log.Print(err.Error())
	}

	data := customData{
		Profile:         profile,
		APIToken:        newAPIToken(r),
		IsAuthenticated: isAuthenticated(r),
		IsAdmin:         s.IsAdmin(r),
		IsReadOnly:      s.IsReadOnly(r),
	}

	err = s.TPL.ExecuteTemplate(w, "home.gohtml", data)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20
	http.Redirect(w, r, s.AuthorizationCodeRequest(r), http.StatusFound)
}

func AuthCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Check the state that was returned to the query string is the same as the above state
	if r.URL.Query().Get("state") != s.State {
		fmt.Println(w, "The state was not as expected")
		http.Error(w, "The state was not as expected", http.StatusInternalServerError)
	}
	// Make sure the code was provided
	if r.URL.Query().Get("code") == "" {
		fmt.Println(w, "The code was not returned or is not accessible")
		http.Error(w, "The code was not returned or is not accessible", http.StatusInternalServerError)
	}

	exchange, err := s.ExchangeCodeRequest(r.URL.Query().Get("code"), r)
	if exchange.Error != "" || err != nil {
		fmt.Println(exchange.Error)
		fmt.Println(exchange.ErrorDescription)
		http.Error(w, exchange.ErrorDescription, http.StatusInternalServerError)
	}

	idToken, verificationError := verifyToken(exchange.IdToken)

	if verificationError != nil {
		fmt.Println(verificationError)
	}

	session, err := s.Session.Session(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if verificationError == nil {
		apiToken := generateAPIToken(22)
		s.Users[apiToken] = idToken.Claims["globalGroups"]
		session.Values["id_token"] = exchange.IdToken
		session.Values["access_token"] = exchange.AccessToken
		session.Values["globalGroups"] = idToken.Claims["globalGroups"]
		session.Values["apiToken"] = apiToken

		err := s.Session.Save(r, w, session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	profile, err := s.ProfileDataRequest(r)
	if err != nil {
		log.Print(err.Error())
	}

	data := customData{
		Profile:         profile,
		APIToken:        newAPIToken(r),
		IsAuthenticated: isAuthenticated(r),
		IsAdmin:         s.IsAdmin(r),
		IsReadOnly:      s.IsReadOnly(r),
	}

	err = s.TPL.ExecuteTemplate(w, "profile.gohtml", data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := s.Session.Session(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	delete(session.Values, "id_token")
	delete(session.Values, "access_token")
	delete(session.Values, "email")
	delete(session.Values, "apiToken")

	err = s.Session.Save(r, w, session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func ProgrammaticProfileHandler(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(strings.Replace(r.Header.Get("Authorization"), "Bearer ", "", 1))
	if token == "" {
		http.Error(w, "Missing API Token", http.StatusBadRequest)
		return
	}

	groups := s.Users[token]
	if groups == nil {
		http.Error(w, "Not Valid API Token", http.StatusBadRequest)
		return
	}

	profile := store.Profile{
		Name:   token,
		Groups: groups,
	}

	err := json.NewEncoder(w).Encode(profile)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func isAuthenticated(r *http.Request) bool {
	session, err := s.Session.Session(r)
	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}
	return true
}

func newAPIToken(r *http.Request) string {
	session, err := s.Session.Session(r)
	if err != nil || session.Values["apiToken"] == nil || session.Values["apiToken"] == "" {
		return ""
	}

	return session.Values["apiToken"].(string)
}

func verifyToken(t string) (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["nonce"] = s.Nonce
	tv["aud"] = os.Getenv("CLIENT_ID")
	jv := verifier.JwtVerifier{
		Issuer:           os.Getenv("ISSUER"),
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)

	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified: %s", "")
}

func stringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func generateAPIToken(length int) string {
	return stringWithCharset(length, charset)
}
