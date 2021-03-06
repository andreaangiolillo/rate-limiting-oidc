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

package main

import (
	"fmt"
	"log"
	"net/http"
	"okta-hosted-login/m/handler"
	"okta-hosted-login/m/utils"
	"os"

	"github.com/gorilla/mux"
)

func main() {
	utils.ParseEnvironment()
	host, port := utils.HostnameAndPort()
	router := mux.NewRouter().StrictSlash(true)

	// Web APIs
	router.HandleFunc("/", handler.HomeHandler)
	router.HandleFunc("/login", handler.LoginHandler)
	router.HandleFunc("/authorization-code/callback", handler.AuthCodeCallbackHandler)
	router.HandleFunc("/profile", handler.ProfileHandler)
	router.HandleFunc("/logout", handler.LogoutHandler)

	// Programmatic APIs
	router.HandleFunc("/api/profile", handler.ProgrammaticProfileHandler).Methods("GET")

	log.Printf("server starting at %s:%s ...", host, port)
	err := http.ListenAndServe(fmt.Sprintf("%s:%s", host, port), router)
	if err != nil {
		log.Printf("the HTTP server failed to start: %s", err)
		os.Exit(1)
	}
}
