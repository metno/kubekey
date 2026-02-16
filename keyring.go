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
package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zalando/go-keyring"
)

/*
Cache IDToken in the operating system keyring together with .expiry in seconds since epoch
Return OIDC IDToken, and expiry time on success
*/
func (cfg *OIDC) GetToken() (string, time.Time) {
	token, err := keyring.Get("github.com/metno/kubekey", cfg.ClientID + "@" + cfg.IDPIssuerURL)
	if err == keyring.ErrNotFound {
		token = "...0" // Expired token => revalidate later
	} else if err != nil {
		log.Fatal(err)
	}
	parts := strings.Split(token, ".")
	expireSeconds, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		log.Fatal(err)
	}
	expire := time.Unix(expireSeconds, 0).UTC()
	// Check if we have less than 10s to expiry => refresh
	if time.Now().Add(time.Second * 10).After(expire) {
		tokenCh := make(chan string)
		go cfg.Authenticate(tokenCh)
		token = <-tokenCh
		if strings.Count(token, ".") < 3 {
			log.Println("Failed to aquire vaild credentials")
			time.Sleep(1 * time.Second) // Allow user to read error message in browser
			os.Exit(1)
		}
		parts = strings.Split(token, ".")
	}
	keyring.Set("github.com/metno/kubekey", cfg.ClientID + "@" + cfg.IDPIssuerURL, token)
	return strings.Join(parts[0:3], "."), expire
}
