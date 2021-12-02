// Copyright 2020 MongoDB Inc
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
	"encoding/hex"
	"html/template"
)

type Store struct {
	Session *Session
	TPL     *template.Template
	Nonce   string
	State   string
}

func New() *Store {
	return &Store{
		Session: NewSession(),
		TPL:     template.Must(template.ParseGlob("templates/*")),
		Nonce:   "NonceNotSetYet",
		State:   generateState(),
	}
}

func generateState() string {
	// Generate a random byte array for state parameter
	b := make([]byte, 16)
	return hex.EncodeToString(b)
}
