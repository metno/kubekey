/*
kubekey is a client-go credentials plugin for kubectl
Copyright (C) 2019 - 2025 Meteorologisk Institutt (MET Norway)
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
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
)

const Version = "1.0.20250110"

func main() {
	getVersionPtr := flag.Bool("v", false, "version")
	flag.Parse()
	if *getVersionPtr {
		fmt.Printf("kubekey v%s\n", Version)
		os.Exit(0)
	}

	changeToTemplateDirectory()

	oidc := &OIDC{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		IDPIssuerURL: os.Getenv("IDP_ISSUER_URL"),
	}
	ec := ExecCredential(oidc.GetToken())
	enc, err := json.Marshal(ec)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%v\n", string(enc))
}
