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

//
// Format output according to spec for kubernetes's client-go credential plugin
// https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins
// See API-spec: https://kubernetes.io/docs/reference/config-api/client-authentication.v1beta1/
//

package main

import (
	"time"
)

type Status struct {
	Token               string `json:"token"`
	ExpirationTimestamp string `json:"expirationTimestamp"`
}

type execCredential struct {
	ApiVersion string  `json:"apiVersion"`
	Kind       string  `json:"kind"`
	Status     *Status `json:"status"`
}

func ExecCredential(tk string, expire time.Time) *execCredential {
	return &execCredential{
		ApiVersion: "client.authentication.k8s.io/v1beta1",
		Kind:       "ExecCredential",
		Status: &Status{
			Token:               tk,
			ExpirationTimestamp: expire.Format(time.RFC3339),
		},
	}
}
