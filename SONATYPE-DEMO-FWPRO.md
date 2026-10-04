# Demo of Sonatype Firewall Pro - npm

## TLDR
Sonatype Repository [Firewall Pro](https://firewall.sonatype.app) is a cloud-based service that protects your software supply chain by blocking malicious open-source packages before they reach your artifact repository.

Firewall Pro sits between your repository manager and the public internet. When a developer or CI pipeline requests a package, Firewall Pro evaluates it against Sonatype Research threat intelligence and blocks any package identified as potentially malicious — before it is cached or served by your repository manager.

No additional software needs to be installed. This demo is using [git-pkgs proxy](https://github.com/git-pkgs/proxy#git-pkgs-proxy) as a 3rd party repository manager.

## npm demo

### Clean npm cache first:
- `npm cache clean --force`
- `rm -fr ./node_modules`

### Regular `npm install`

- `npm_config_registry=https://proxy.wn.leyux.de/npm/ npm install`
  
`npm_config_registry=https://proxy.wn.leyux.de/npm/` is used to make sure, that the 3rd party registry is used.

### Blocking of malicious package

Sonatype's [Sample Malicious Components](https://help.sonatype.com/en/release-integrity.html#sample-malicious-components) are used to show blocking.

- `npm_config_registry=https://proxy.wn.leyux.de/npm/ npm i @sonatype/policy-demo@2.1.0`

Version 2.1.0, 2.2.0 and 2.3.0 will be blocked, 2.0.0 is fine and will not be blocked. 