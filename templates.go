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
	"embed"
	"fmt"
	"html/template"
	"log"
	"os"
)

//go:embed templates/*
var embeddedTemplates embed.FS
var useEmbeddedTemplates bool

func parseTmplFiles(filename string) (*template.Template, error) {
	if useEmbeddedTemplates {
		return template.ParseFS(embeddedTemplates, fmt.Sprintf("templates/%v", filename))
	}
	return template.ParseFiles(filename)
}

type failMsg struct {
	Msg string
}

func changeToTemplateDirectory() {
	var err error
	templateDir := make([]string, 0, 5)

	templateDirectoryFromEnv := os.Getenv("KUBEKEY_TEMPLATEDIR")
	if templateDirectoryFromEnv != "" {
		templateDir = append(templateDir, templateDirectoryFromEnv)
	}

	templateDir = append(templateDir, "/etc/kubekey")
	templateDir = append(templateDir, "/usr/local/share/kubekey")
	templateDir = append(templateDir, "/usr/share/kubekey")
	templateDir = append(templateDir, "templates")

	// Try to change to directories in the order defined above
	// Return from this function on success
	for len(templateDir) > 0 {
		tryDirectory := templateDir[0]
		templateDir = templateDir[1:] // remove the first index from array
		err = os.Chdir(tryDirectory)
		if err == nil {
			useEmbeddedTemplates = false
			return
		} else if tryDirectory == templateDirectoryFromEnv {
			log.Println("Environment variable KUBEKEY_TEMPLATEDIR is set, but couldn't change to that directory")
			log.Fatal(err)
		}
	}

	useEmbeddedTemplates = true
	return
}
