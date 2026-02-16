/*
kubekey is a client-go credentials plugin for kubectl
Copyright (C) 2019 - 2026 Meteorologisk Institutt (MET Norway)
Postboks 43 Blindern, 0313 OSLO, Norway - www.met.no

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

//
// The idea here is to spawn up a short lived http server on localhost and spin up the users browser for login through SSO.
// See https://auth0.com/blog/oauth-2-best-practices-for-native-apps/
//

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/pkg/browser"
	"golang.org/x/oauth2"
)

type OIDC struct {
	ClientID     string
	ClientSecret string
	IDPIssuerURL string
}

func newState() string {
	random := make([]byte, 32)
	_, err := rand.Read(random)
	if err != nil {
		log.Fatal(err)
	}
	return base64.URLEncoding.EncodeToString(random)
}

// Authorization Code Flow with Proof Key for Code Exchange (PKCE)
func pkceCredentials() (oauth2.AuthCodeOption, oauth2.AuthCodeOption, oauth2.AuthCodeOption) {
	// URLEncoding provides: A-Z, a-z, 0-9, -=_   ref: https://tools.ietf.org/html/rfc4648#section-5
	// PKCE allowed chars  : A-Z, a-z, 0-9, -._~  ref: https://www.oauth.com/oauth2-servers/pkce/authorization-request/
	// => needs to replace                   = with .
	plainCodeChallenge := strings.ReplaceAll(newState(), "=", ".")

	s256 := sha256.New()
	s256.Write([]byte(plainCodeChallenge))
	codeChallenge := oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(s256.Sum(nil)))
	codeChallengeMethod := oauth2.SetAuthURLParam("code_challenge_method", "S256")

	codeVerifier := oauth2.SetAuthURLParam("code_verifier", plainCodeChallenge)

	return codeChallenge, codeChallengeMethod, codeVerifier
}

func (cfg *OIDC) Authenticate(tokenChan chan<- string) {
	mux := &http.ServeMux{}
	srv := &http.Server{
		Handler: mux,
	}

	closeSrv := func(token string, err error) {
		tokenChan <- token
		if err != nil {
			log.Print(err)
		}
		time.Sleep(2 * time.Second)
		srv.Close()
	}

	// Listen to random port on localhost
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	baseURL := fmt.Sprintf("http://%s", listener.Addr())

	// OIDC Client
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, cfg.IDPIssuerURL)
	if err != nil {
		log.Fatal(err)
	}
	oidcConfig := &oidc.Config{
		ClientID: cfg.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)

	// Configure oAuth2
	config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  baseURL + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	state := newState()
	codeChallenge, codeChallengeMethod, codeVerifier := pkceCredentials()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, config.AuthCodeURL(state, codeChallenge, codeChallengeMethod), http.StatusFound)
	})

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		var token string
		var err error

		fail := func(msg string) {
			failMsg := failMsg{Msg: msg}
			w.WriteHeader(http.StatusInternalServerError)
			tmpl, err := parseTmplFiles("html_fail.tmpl")
			if err != nil {
				log.Fatal(err)
			}
			tmpl.Execute(w, failMsg)
			go closeSrv(token, err)
		}

		if r.URL.Query().Get("state") != state {
			fail("OAuth2 error: state did not match")
			return
		}

		oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"), codeVerifier)
		if err != nil {
			fail("Failed to exhange token: " + err.Error())
			return
		}
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			fail("No id_token field in oauth2 token.")
			return
		}
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			fail("Failed to verify ID Token: " + err.Error())
			return
		}
		token = fmt.Sprintf("%s.%d", rawIDToken, idToken.Expiry.Unix())

		var claims struct {
			Name    string `json:"name"`
			Picture string `json:"picture"`
		}
		err = idToken.Claims(&claims)
		if err != nil {
			fail("Obtained IDToken, but some info seems to be missing. (Might still be working.)" + err.Error())
			return
		}
		tmpl, err := parseTmplFiles("html_ok.tmpl")
		if err != nil {
			log.Fatal(err)
		}
		tmpl.Execute(w, claims)
		go closeSrv(token, nil)
	})

	browser.Stdout = os.Stderr
	browser.OpenURL(baseURL + "/")
	srv.Serve(listener)
}
