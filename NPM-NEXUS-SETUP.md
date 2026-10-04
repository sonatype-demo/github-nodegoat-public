# Configure local npm access through Nexus Repository

This guide configures a developer workstation so that npm downloads packages through a central, authenticated Sonatype Nexus Repository npm group.

The examples use this repository's npm group:

```text
https://nexus.wn.leyux.de/repository/npm-group/
```

Replace that URL with your organization's npm group URL when using this guide elsewhere. A repository group is preferred because one endpoint can aggregate public proxy repositories and private hosted repositories.

## Prerequisites

Obtain the following from the Nexus Repository administrator:

- the HTTPS URL of the npm group;
- a Nexus username and password, or a two-part Nexus user token;
- permission to read the npm group;
- the organization's CA certificate if Nexus uses a private certificate authority.

Do not put a password, user-token password, or encoded authentication value in this repository, a shell command argument, or shell history.

## Create a local environment file

The repository provides `.env.example` with non-sensitive defaults and an explicit authentication placeholder. Create a private working copy:

```bash
cp .env.example .env
chmod 600 .env
```

Replace `REPLACE_WITH_BASE64_AUTH_VALUE` only in `.env`. The real `.env` file is ignored by Git; `.env.example` must always remain secret-free.

Neither npm nor NodeGoat automatically loads this file. Export it into the current shell before running npm or the application:

```bash
set -a
. ./.env
set +a
```

## Option 1: Log in through the npm Bearer Token Realm

Use this method when the Nexus administrator has enabled the **npm Bearer Token Realm** and normal username/password login is supported.

Configure the group as the default registry:

```bash
npm config set registry "https://nexus.wn.leyux.de/repository/npm-group/"
```

Then authenticate interactively:

```bash
npm login \
  --auth-type=legacy \
  --registry="https://nexus.wn.leyux.de/repository/npm-group/"
```

Enter the username, password, and email address only at npm's prompts. npm 9 and newer require `--auth-type=legacy` for this Nexus login flow. npm writes the resulting registry-scoped credential to the user configuration, normally `~/.npmrc`.

Do not also configure Basic `_auth` for the same registry. Use only one authentication method at a time.

## Option 2: Use Basic authentication or a Nexus user token

Use this method when:

- the npm Bearer Token Realm is not enabled;
- the username contains uppercase characters; or
- Nexus user tokens are required.

Nexus user tokens are two-part credentials. Use the token name in place of the username and the token password in place of the password.

### Create the user-level npm configuration

Create or edit `~/.npmrc`:

```ini
registry=https://nexus.wn.leyux.de/repository/npm-group/
//nexus.wn.leyux.de/repository/npm-group/:_auth=${NPM_AUTH_TOKEN}
always-auth=true
audit=false
```

Then restrict access to the file:

```bash
chmod 600 "$HOME/.npmrc"
```

Important details:

- The authentication key must omit `https:` and must include the complete repository path and trailing slash.
- `_auth` expects the Base64 representation of `username:password`. For a Nexus user token, encode `token-name:token-password` instead.
- `${NPM_AUTH_TOKEN}` is expanded by npm from the environment. The secret is therefore not stored directly in `~/.npmrc`.
- `always-auth=true` sends authentication for every request to this registry.
- `audit=false` matches this repository's CI configuration and prevents npm audit requests. Remove it if the Nexus endpoint is configured to support the audit operation and local audits are required.

### Prepare the authentication value without shell-history exposure

The following uses silent interactive input. Neither password is placed in the command text:

```bash
read -r -p "Nexus username or user-token name: " NEXUS_USERNAME
read -r -s -p "Nexus password or user-token password: " NEXUS_PASSWORD
printf '\n'

NPM_AUTH_TOKEN="$(
  printf '%s' "${NEXUS_USERNAME}:${NEXUS_PASSWORD}" | base64 | tr -d '\n'
)"
export NPM_AUTH_TOKEN
unset NEXUS_PASSWORD
```

Keep the environment variable only for as long as it is needed, load it from the ignored mode-`0600` `.env`, or retrieve it from an approved password manager when starting a development session. Remove it afterward:

```bash
unset NPM_AUTH_TOKEN NEXUS_USERNAME
```

Do not add the exported value to a tracked shell profile or to `.env.example`. Never force-add the ignored `.env` file to Git.

## Verify the configuration

With `NPM_AUTH_TOKEN` exported when using Option 2, verify the endpoint and authenticated identity:

```bash
npm config get registry
npm ping
npm whoami
```

Expected results:

- `npm config get registry` prints the Nexus npm group URL;
- `npm ping` succeeds against that URL;
- `npm whoami` returns the expected Nexus identity.

Finally, test a package lookup without installing it:

```bash
npm view lodash version
```

For this repository, install the lockfile-pinned dependencies with:

```bash
npm ci --no-audit
```

## Use an isolated npm configuration instead

To avoid changing the default `~/.npmrc`, place the same configuration in a separate mode-`0600` file and select it for the current shell:

```bash
mkdir -p "$HOME/.config/npm"
chmod 700 "$HOME/.config/npm"
touch "$HOME/.config/npm/npmrc-nexus"
chmod 600 "$HOME/.config/npm/npmrc-nexus"
export NPM_CONFIG_USERCONFIG="$HOME/.config/npm/npmrc-nexus"
```

Add the configuration from Option 2 to `npmrc-nexus`. All subsequent npm commands in that shell will use the selected file. Unset the override to return to npm's normal user configuration:

```bash
unset NPM_CONFIG_USERCONFIG
```

The GitHub Actions workflows in this repository use this isolated-file pattern under `RUNNER_TEMP`, apply mode `0600`, and delete the file during cleanup.

## Private certificate authorities

If Nexus uses a certificate signed by a private CA, configure the CA file rather than disabling TLS verification:

```bash
npm config set cafile "/path/to/organization-ca.pem"
```

Do **not** solve certificate failures with `strict-ssl=false`.

## Troubleshooting

### `E401` or `ENEEDAUTH`

- Confirm that the credential is valid and has read permission for the npm group.
- Confirm that `_auth` contains Base64 of the complete `username:password` or `token-name:token-password` pair.
- Ensure the authentication key's host, repository path, and trailing slash exactly match the registry URL.
- Do not mix the Bearer Token Realm login method with Basic `_auth` configuration.

### `E404`

Confirm that the requested package exists in a member of the npm group and that the account can browse and read that member repository.

### npm still uses the public registry

Check the effective registry:

```bash
npm config get registry
```

Also check whether a project-level `.npmrc`, `NPM_CONFIG_REGISTRY`, or `NPM_CONFIG_USERCONFIG` overrides the user configuration.

## References

- [Sonatype: Configuring npm](https://help.sonatype.com/en/configuring-npm.html)
- [Sonatype: npm Security](https://help.sonatype.com/en/npm-security.html)
- [Sonatype: User Tokens](https://help.sonatype.com/en/user-tokens.html)
- [npm: `.npmrc`](https://docs.npmjs.com/configuring-npm/npmrc.html)
