# kubekey

kubekey is a [client-go credentials
plugin](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins)
for kubectl and other applications using the [kubernetes client-go SDK](https://github.com/kubernetes/client-go).
kubekey implements [OAuth 2.0 for Native
Apps](https://auth0.com/blog/oauth-2-best-practices-for-native-apps/) using
Authorization Code Flow with Proof Key for Code Exchange (PKCE) and spawns a
short-lived http-server on localhost, before redirecting the users browser
for login via OpenIDConnect(OIDC) protocol, so that kubectl/client-go can
aquire an autentication token from the OIDC provider and pass it to the kubernetes API.

## How it works

kubekey does the job of fetching an access token from your OIDC provider, so that kubectl/client-go can use the token for authentication on your kubernetes API.

![kubekey-flow](https://github.com/user-attachments/assets/a79b9464-dc26-4ad9-9472-5a7428cc0c81)

1. User tries to issue a kubectl command on the commandline/terminal
2. kubectl/client-go reads it configuration file and executes kubekey
3. kubekey checks with the [operating system keyring](https://en.wikipedia.org/wiki/GNOME_Keyring) if kubekey has cached a non-expired access token, if it has, it provides the token immedeately (go to step 10)
4. kubekey launches a short lived local http server and asks the operating system to bring up the browser, instructing the browser to redirect to the OIDC provider
5. The OIDC provider asks the user to log in (could be performed as SSO, if the OIDC provider recognizes the user as already logged in, or if kerberos login is enabled, or...)
6. User provides login credentials
7. The browser forwards the credentials to the OIDC provider
8. The OIDC provides issues an access token and sends it back to the browser
9. The browser redirects to kubekey's short lived local http server with the OIDC access token, kubekey stores the token in the operating system keyring
10. kubekey provides kubectl/client-go with the access token
11. kubectl/client-go sends API-requests to kube-apiserver with the access token. kube-apiserver then validates the signature and extracts information about the user

## Getting started

1. Download kubekey for your architecture from the latest release, or build with golang and make.
2. Optionally: Customize the [templates](templates) and save them to /etc/kubekey/ on the users workstation (fallback will be to use the compiled in templates)
3. Configure your OIDC issuer - you need to get
  * `CLIENT_ID`: A client id that all tokens must be issued for.
  * `CLIENT_SECRET`: Empty if supported by your issuer, or if needed just set this to what you receive when configuring the issuer.
  * `IDP_ISSUER_URL`: If the issuer's OIDC discovery URL is https://accounts.provider.example/.well-known/openid-configuration, the value should be https://accounts.provider.example
4. Configure your kubernetes cluster to trust an OIDC issuer, see https://kubernetes.io/docs/reference/access-authn-authz/authentication/#configuring-the-api-server
5. See [example configuration](./example/.kube/config) for more instruction on how to configure kubekey for usage with [kubectl](https://kubernetes.io/docs/reference/kubectl/quick-reference/#kubectl-context-and-configuration) for your users. Tailor your kubectl configuration file and put it in $HOME/.kube/config (or another place if you have set your `KUBECONFIG` environment variable.)

Now you are ready to use kubectl and authenticate your session with via OIDC.

## Copyright and license

Copyright (C) 2019 - 2025 MET Norway. kubekey is licensed under [GPL version 2](https://github.com/metno/kubekey/blob/master/LICENSE) or (at your option) any later version.
