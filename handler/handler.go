package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	verifier "github.com/okta/okta-jwt-verifier-golang"
	"okta-hosted-login/m/store"
)


var s = store.New()

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

type customData struct {
	Profile         *Profile
	IsAuthenticated bool
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {

	profile, err := profileData(r)
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

	var redirectPath string

	q := r.URL.Query()
	q.Add("client_id", os.Getenv("CLIENT_ID"))
	q.Add("response_type", "code")
	q.Add("response_mode", "query")
	q.Add("scope", "openid profile email")
	q.Add("redirect_uri", "http://localhost:8080/authorization-code/callback")
	q.Add("state", s.State)
	q.Add("nonce", s.Nonce)

	redirectPath = os.Getenv("ISSUER") + "/v1/authorize?" + q.Encode()

	http.Redirect(w, r, redirectPath, http.StatusFound)
}

func AuthCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Check the state that was returned in the query string is the same as the above state
	if r.URL.Query().Get("state") != s.State {
		fmt.Println(w, "The state was not as expected")
		http.Error(w, "The state was not as expected", http.StatusInternalServerError)
	}
	// Make sure the code was provided
	if r.URL.Query().Get("code") == "" {
		fmt.Println(w, "The code was not returned or is not accessible")
		http.Error(w, "The code was not returned or is not accessible", http.StatusInternalServerError)
	}

	exchange, err := exchangeCode(r.URL.Query().Get("code"), r)
	if exchange.Error != "" || err != nil {
		fmt.Println(exchange.Error)
		fmt.Println(exchange.ErrorDescription)
		http.Error(w, exchange.ErrorDescription, http.StatusInternalServerError)
	}

	_, verificationError := verifyToken(exchange.IdToken)

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

		err := s.Session.Save(r, w, session)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	profile, err := profileData(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	data := customData{
		Profile:         profile,
		IsAuthenticated: isAuthenticated(r),
	}
	err = s.TPL.ExecuteTemplate(w, "profile.gohtml", data)
	if err != nil {
		return
	}
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := s.Session.Session(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	delete(session.Values, "id_token")
	delete(session.Values, "access_token")

	err = s.Session.Save(r, w, session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func exchangeCode(code string, r *http.Request) (*Exchange, error) {
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

		}
	}(resp.Body)

	var exchange Exchange
	err := json.Unmarshal(body, &exchange)
	if err != nil {
		return nil, err
	}

	return &exchange, nil
}

func isAuthenticated(r *http.Request) bool {
	session, err := s.Session.Session(r)

	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}

	return true
}

func profileData(r *http.Request) (*Profile, error) {
	var m *Profile
	session, err := s.Session.Session(r)

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m, nil
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

		}
	}(resp.Body)

	err = json.Unmarshal(body, &m)
	if err != nil {
		return nil, err
	}

	return m, nil
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
