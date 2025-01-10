# kubekey

kubekey is a [client-go credentials plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins) for kubectl

* Compile with make
* Optionally make html templates for OK and failure available, e.g. in /etc/kubekey/html_fail.tmpl and /etc/kubekey/html_ok.tmpl
* Configure your OIDC issuer - you need to get
  * `CLIENT_ID`: A client id that all tokens must be issued for.
  * `CLIENT_SECRET`: Empty if supported by your issuer, or if needed just set this to what you receive when configuring the issuer.
  * `IDP_ISSUER_URL`: If the issuer's OIDC discovery URL is https://accounts.provider.example/.well-known/openid-configuration, the value should be https://accounts.provider.example
* Configure your kubernetes cluster to trust an OIDC issuer, see https://kubernetes.io/docs/reference/access-authn-authz/authentication/#configuring-the-api-server
* See [example configuration](./examples/.kube/config) for more instruction on how to configure kubekey for usage with kubectl for your users

## Copyright and license

Copyright (C) 2019 - 2025 MET Norway. kubekey is licensed under [GPL version 2](https://github.com/metno/kubekey/blob/master/LICENSE) or (at your option) any later version.
