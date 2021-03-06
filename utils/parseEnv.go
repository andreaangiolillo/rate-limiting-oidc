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

package utils

import (
	"bufio"
	"log"
	"os"
	"strings"
)

func ParseEnvironment() {
	// useGlobalEnv := true
	if _, err := os.Stat(".env"); os.IsNotExist(err) {
		log.Printf("Environment Variable file (.env) is not present.  Relying on Global Environment Variables")
		// useGlobalEnv = false
	}

	setEnvVariable("CLIENT_ID", os.Getenv("CLIENT_ID"))
	setEnvVariable("CLIENT_SECRET", os.Getenv("CLIENT_SECRET"))
	setEnvVariable("ISSUER", os.Getenv("ISSUER"))

	if os.Getenv("CLIENT_ID") == "" {
		log.Printf("Could not resolve a CLIENT_ID environment variable.")
		os.Exit(1)
	}

	if os.Getenv("CLIENT_SECRET") == "" {
		log.Printf("Could not resolve a CLIENT_SECRET environment variable.")
		os.Exit(1)
	}

	if os.Getenv("ISSUER") == "" {
		log.Printf("Could not resolve a ISSUER environment variable.")
		os.Exit(1)
	}
}

func setEnvVariable(env string, current string) {
	if current != "" {
		return
	}

	file, _ := os.Open(".env")
	defer file.Close()

	lookInFile := bufio.NewScanner(file)
	lookInFile.Split(bufio.ScanLines)

	for lookInFile.Scan() {
		parts := strings.Split(lookInFile.Text(), "=")
		key, value := parts[0], parts[1]
		if key == env {
			os.Setenv(key, value)
		}
	}
}

func HostnameAndPort() (string, string) {
	hostname := "localhost"
	port := "8080"
	args := os.Args[1:]

	if len(args) > 0 {
		hostname = args[0]
	}

	if len(args) > 1 {
		port = args[1]
	}

	return hostname, port
}
