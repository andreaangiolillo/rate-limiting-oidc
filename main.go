package main

import (
	"log"
	"net/http"
	"okta-hosted-login/m/handler"
	"os"

	oktaUtils "github.com/okta/samples-golang/okta-hosted-login/utils"
)

func main() {
	oktaUtils.ParseEnvironment()

	http.HandleFunc("/", handler.HomeHandler)
	http.HandleFunc("/login", handler.LoginHandler)
	http.HandleFunc("/authorization-code/callback", handler.AuthCodeCallbackHandler)
	http.HandleFunc("/profile", handler.ProfileHandler)
	http.HandleFunc("/logout", handler.LogoutHandler)

	log.Print("server starting at localhost:8080 ... ")
	err := http.ListenAndServe("localhost:8080", nil)
	if err != nil {
		log.Printf("the HTTP server failed to start: %s", err)
		os.Exit(1)
	}
}
