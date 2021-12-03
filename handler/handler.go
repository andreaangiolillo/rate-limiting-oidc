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
	"fmt"
	"net/http"
	"okta-hosted-login/m/store"
	"os"

	verifier "github.com/okta/okta-jwt-verifier-golang"
)

var s = store.New()

type customData struct {
	Profile         *store.Profile
	IsAuthenticated bool
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	profile, err := s.ProfileDataRequest(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	data := customData{
		Profile:         profile,
		IsAuthenticated: isAuthenticated(r),
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
		session.Values["id_token"] = exchange.IdToken
		session.Values["access_token"] = exchange.AccessToken
		session.Values["email"] = idToken.Claims["primaryEmail"]

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
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	data := customData{
		Profile:         profile,
		IsAuthenticated: isAuthenticated(r),
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

	err = s.Session.Save(r, w, session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func isAuthenticated(r *http.Request) bool {
	session, err := s.Session.Session(r)
	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}
	return true
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
