![groom](https://github.com/pyke369/groom/blob/master/groom.png?raw=true)


# Presentation
`groom` is a self-hosted HTTPS reverse-proxy written in Go, used to expose local private services to the public internet over secure
websocket tunnels. It works by multiplexing clients requests from a "public" server over agent-established websocket tunnels, using a
packet-framing mechanism similar to what's being done in [RTMP](https://en.wikipedia.org/wiki/Real-Time_Messaging_Protocol) or
[HTTP/2](https://en.wikipedia.org/wiki/HTTP/2) protocols. Any number of agents may be connected to a single server, and any number of
services (or "domains" in `groom` parlance) may be exposed through a single agent tunnel.

The same `groom` binary can run in 2 different modes (depending on the `mode` configuration directive value, see below):

- `server`: central instance receiving external clients requests, managing TLS termination and waiting for agents to connect
to map their exported private services under "domains".

- `agent`: distributed instances connecting to a central instance (`server` above) to make their private services accessible remotely.

`groom` is ideally suited for the following scenarii, when a pervasise communication system is most needed:

- team members or clients need to QA your current developments from anywhere, without you having to deploy to a cloud provider.

- you want to securely expose webservices running on your home server, without the hassle of TLS certificates management.

- you need to code and debug webhook workers on your development machine, but the network you're connected to is heavily firewalled.

- any situation where relentlessly deploying in-development webservices is proving painful and time-consuming.

`groom` comes with the following features out-of-the-box, completely free-of-charge when self-hosted:

- HTTPS-only in server mode for maximum security, always-on TLS termination.

- SNI support in server mode for multi-tenants/multi-certificates installations.

- "stealth" mode for clients and agents (server always return 404 statuses, whatever the encountered issue, but real HTTP statuses
  are written in logs).

- compatible with [Server-Sent Events](https://en.wikipedia.org/wiki/Server-sent_events) (Comet/long-poll) and [WebSocket](https://en.wikipedia.org/wiki/WebSocket) clients requests.

- dynamic domains configuration files changes detection / hot-reload (for a simple configuration webui integration for instance, not provided in this repository).

- @IP-ranges and secret-based agents authentication.

- @IP-ranges, credentials and time-ranges clients filtering.

- extensive structured logging (on standard-output/error, but also in auto-rotating files and syslog) for both system activity events and clients requests.


# Architecture
As mentionned above, `groom` may first be seen as a traditionnal reverse-proxy, but there's a twist: instead of issuing direct
requests to network-accessible backends (like a classical load-balancer does), a `groom` server instance will wait for `groom`
agent instances to establish websocket connections for particular domains, and only then will it accept to process (multiplex)
clients requests over these connections. Until an agent is connected to an authorized domain (therefore "activating/mapping"
the potential local services under it), all clients requests will end up returning a 404 HTTP status (not found).

This is better schematized below:

![architecture](https://github.com/pyke369/groom/blob/master/architecture.png?raw=true)

- step 1: a `groom` server instance is started and configured to handle requests for a variety of domains (among them is the
`www.domain.com` domain in this example).

- step 2: a `groom` agent instance establishes a secure authenticated websocket connection to the server, activating the tunneling
of all requests for the `www.domain.com` domain (but not for the `api.domain.com` domain in this example).

- step 3: clients issue requests for the `www.domain.com` domain, which are forwarded to the connected agent over the websocket
connection. requests for the `api.domain.com` domain are ignored (because no agent registered to handle them) and return 404.

- step 4: the agent forwards the received requests to some locally-running services, and convey the responses back to the server
over the same websocket connection. since there is a small HTTP routing engine embedded in the `groom` agent configuration, it's
entirely possible to map incoming requests to different local services (based on methods and URL paths filtering, see the "Agent
domain configuration" section below).


# Build and installation
Binaries for Windows, macOS and Linux are automatically build whenever a new release is available (using GitHub Actions). You can
download the latest `groom` version from the [releases](https://github.com/pyke369/groom/releases) page. 2 artefacts are automatically
generated with each release:

- a "universal binary" archive in `groom_<revision>.zip`
(suitable for running in agent mode, but can also be used in "on-the-go server" mode if needed)

- a Debian package in `groom_<revision>_amd64.deb`
(suitable for a fixed-installation server mode instance, comes with a systemd unit file with auto-restart)

In case you want to build the artefacts above yourself, you will need a recent version of the Golang compiler (>= 1.15) installed on
your machine. Then just invoke the following commands to build everything from scratch:
```
git clone https://github.com/pyke369/groom   # fetches the groom source code
cd groom
make portable                                # generates the groom.zip archive in the current folder
make deb                                     # generates the groom_<revision>_amd64.deb debian package in the parent folder
```

(the `devscripts`, `debhelper` and `dh-exec` packages are needed for the last part)

Example:
```
$ git clone https://github.com/pyke369/groom
Cloning into 'groom'...
Receiving objects: 100% (39/39), 196.02 KiB | 225.00 KiB/s, done.
Resolving deltas: 100% (1/1), done.

$ cd groom

$ make portable
                       Ultimate Packer for eXecutables
        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   5964664 ->   2310752   38.74%   linux/amd64   groom-linux

Packed 1 file.
                       Ultimate Packer for eXecutables
        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   8325632 ->   4414976   53.03%    win64/pe     groom.exe

Packed 1 file.
  adding: groom/ (stored 0%)
  adding: groom/conf/ (stored 0%)
  adding: groom/conf/agent.conf (deflated 44%)
  adding: groom/conf/server/ (stored 0%)
  adding: groom/conf/server/www.domain.com (deflated 49%)
  adding: groom/conf/server.conf (deflated 54%)
  adding: groom/conf/agent/ (stored 0%)
  adding: groom/conf/agent/www.domain.com (deflated 54%)
  adding: groom/groom-darwin (deflated 48%)
  adding: groom/groom-linux (deflated 2%)
  adding: groom/groom (deflated 9%)
  adding: groom/groom.exe (deflated 2%)

$ ls -al groom.zip
-rw-r--r-- 1 nobody nogroup 10899128 Jul 28 17:33 groom.zip

$ make deb
 dpkg-buildpackage -rfakeroot -us -uc -ui -i -b
dpkg-buildpackage: info: source package groom
dpkg-buildpackage: info: source version 1.2.0
dpkg-buildpackage: info: source distribution stable
 dpkg-source -i --before-build groom
dpkg-buildpackage: info: host architecture amd64
 fakeroot debian/rules clean
dh clean --with systemd
   dh_auto_clean
	make -j1 distclean
   dh_clean
 debian/rules build
dh build --with systemd
   dh_update_autotools_config
   dh_auto_configure
   dh_auto_build
	make -j1
                       Ultimate Packer for eXecutables
        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   5964664 ->   2310752   38.74%   linux/amd64   groom

Packed 1 file.
   dh_auto_test
 fakeroot debian/rules binary
dh binary --with systemd
   dh_testroot
   dh_prep
   dh_auto_install
   dh_install
   dh_installdocs
   dh_installchangelogs
   debian/rules override_dh_systemd_enable
dh_systemd_enable --no-enable
   dh_installinit
   debian/rules override_dh_systemd_start
dh_systemd_start --no-start
   dh_perl
   dh_link
   dh_compress
   dh_fixperms
   dh_missing
   dh_makeshlibs
   dh_shlibdeps
   dh_installdeb
   dh_gencontrol
   dh_md5sums
   dh_builddeb
dpkg-deb: building package 'groom' in '../groom_1.2.0_amd64.deb'.
 dpkg-genbuildinfo --build=binary
 dpkg-genchanges --build=binary >../groom_1.2.0_amd64.changes
dpkg-genchanges: info: binary-only upload (no source code included)
 dpkg-source -i --after-build groom
dpkg-buildpackage: info: binary-only upload (no source included)

$ ls -al ../groom_1.2.0_amd64.deb
-rw-r--r-- 1 nobody nogroup 2268276 Jul 28 17:34 ../groom_1.2.0_amd64.deb
```

Once downloaded, you can unzip the universal binary archive anywhere and start using `groom` right-away without installing anything
beforehand (hence the "portable/universal" qualifier):
```
$ unzip /mnt/hgfs/Downloads/groom_1.2.0.zip
Archive:  /mnt/hgfs/Downloads/groom_1.2.0.zip
   creating: groom/
  inflating: groom/groom-darwin
  inflating: groom/groom.exe
   creating: groom/conf/
   creating: groom/conf/server/
  inflating: groom/conf/server/www.domain.com
  inflating: groom/conf/agent.conf
  inflating: groom/conf/server.conf
   creating: groom/conf/agent/
  inflating: groom/conf/agent/www.domain.com
  inflating: groom/groom
  inflating: groom/groom-linux

$ cd groom

$ ./groom
usage: groom <configuration> | password [<secret> [<salt>]]

$ ./groom conf/agent.conf
2019-07-28 18:15:29 INFO {"config":"conf/agent.conf","event":"start","mode":"agent","pid":127857,"version":"1.2.0"}

PS C:\groom> .\groom .\conf\agent.conf
2019-07-28 18:42:37 INFO {"config":".\\conf\\agent.conf","event":"start","mode":"agent","pid":6328,"version":"1.2.0"}
```
We recommend adding the current folder to your PATH environment variable to allow starting `groom` from anywhere.

On a `groom` server instance, you may alternatively deploy the Debian package with the following command:
```
# dpkg -i groom_1.2.0_amd64.deb
Selecting previously unselected package groom.
Preparing to unpack groom_1.2.0_amd64.deb ...
Unpacking groom (1.2.0) ...
Setting up groom (1.2.0) ...
```

Note that the `groom` server does not start right away, and that the corresponding systemd service is not enabled by default
(to give you an opportunity to edit the configuration files before the first run):
```
$ systemctl status groom
   Loaded: loaded (/lib/systemd/system/groom.service; disabled; vendor preset: enabled)
   Active: inactive
```

To start (and enable) the `groom` service, use the following commands on a systemd-enabled system:
```
# systemctl enable groom
Created symlink /etc/systemd/system/multi-user.target.wants/groom.service -> /lib/systemd/system/groom.service.

# systemctl start groom

$ systemctl status groom
   Loaded: loaded (/lib/systemd/system/groom.service; enabled; vendor preset: enabled)
 Main PID: 121895 (groom)
    Tasks: 5 (limit: 7014)
   CGroup: /system.slice/groom.service
           `-121895 /usr/bin/groom /etc/groom/groom.conf
```


# Configuration
`groom` relies on "JSON-alike" text files for its configuration, and each file must contain a top-level `groom` section to be properly
parsed, i.e. all configuration files must be in the following form:
```
groom
{
   // directives...
}
```
The `#`, `//` and `/* */` constructs may be used for commenting or disabling parts of the configuration. Most of the configuration
files directives have sensible defaults - suitable for a production environment - and should probably not be changed unless instructed
to.  As mentionned in the presentation, domains configuration files changes (in server or agent mode) are automatically detected and
there's no need to restart the `groom` instances (the same mechanism also applies to TLS certificates rotation in server mode).


## Server main configuration
`groom` will start in server mode if its main configuration file contains a `mode = server` directive. The main configuration file path
must be specified as the only command-line argument when invoking the `groom` binary. The other directives available in server mode are
described below:

- **`mode`** (no default)

  explicitely set to `server` to run `groom` in server mode.

- **`listen`** (no default)

  listening addresses to accept clients (and agents) requests on; any number of addresses (+ associated TLS cert/key pairs)
  may be specified; a special syntax is used to reference TLS certificates in SNI mode (see the example below).

  a typical multi-domains/multi-tenants setup is obtained by using a wildcard TLS certificate associated with a wildcard DNS
  entry for the corresponding top domain: for instance, having a TLS certificate and an A DNS record for `*.dev.domain.com`
  will allow for auto-domains activation by just dropping sub-domain configuration files (like `fred.dev.domain.com`,
  `alice.dev.domain.com`, etc.) in the appropriate folder (see the `domains` directive below).

- **`headers_size`** (default **`64kB`**, valid value from **`1kB`** to **`1MB`**)

  maximum authorized size of clients requests HTTP headers.

- **`idle_timeout`** (default **`15s`**, valid value from **`5s`** to **`60s`**)

  maximum time before actively closing idle clients connections.

- **`read_timeout`** (default **`10s`**, valid value from **`5s`** to **`60s`**)

  maximum time spent reading clients requests headers (extended to **`60s`** for the body for POST/PUT requests).

- **`write_timeout`** (default **`20s`**, valid value from **`5s`** to **`60s`**)

  maximum time spent sending tunneled responses to clients.

- **`body_size`** (default **`8MB`**, valid value from **`64kB`** to **`1GB`**)

  maximum body size for POST/PUT clients requests.

- **`service`** (default **`/.well-known/groom-agent`**)

  URL path used by agents to connect domains (should not be changed unless you plan to chain `groom` instances).

- **`domains`** (default **`/etc/groom/domains`**)

  folder containing the `domain` configuration files (see next documentation section).

- **`unavailable`** (default **`404`**)

  the default HTTP status code to use when a domain is not accessible (either because it's not connected to any agent or because
  the client does not match the proper access conditions).

- **`transaction`** (default **`true`**)

  whether to return the request transaction id to the client (in the X-Transaction-Id response header) or not.

The following directives used in the `log` sub-section control the server logging (see example below):

- **`system`** (default **`console(output=stdout)`**)

  system activity structured log configuration (see the example below for syntax details).

- **`access`** (no default)

  clients requests structured log configuration (see the example below for syntax details).

- **`disconnected`** ((default **`false`**)

  clients requests to disconnected or inactive domains will not be loggued in the access log above, unless this directive is
  set to **`true`** (it can get very verbose, especially when using a widlcard DNS entry (see below)).

Below is a commented example of a server main configuration file:
```
groom
{
    // mandatory directive to run groom in server mode
    mode = server

    log
    {
        // log all system activity messages into an auto-rotating file, and also into syslog for good measure
        system = "file(path=/var/log/groom/public1-%Y%m%d.log) syslog(facility=local4,name=public1)"

        // log all clients requests into an auto-rotating file
        access = "file(path=/var/log/groom/public1-clients-%Y%m%d.log,time=no,severity=no)"
    }

    // - listen privately on the default HTTPS port (TCP 443), using a dummy self-signed certificate
    // - also listen publically on the same port, using an array of certificates (selected by regexes on SNI)
    listen
    [
        "10.11.12.13:443,/etc/groom/cert.pem,/etc/groom/key.pem"
        "4.3.2.1:443,groom.certificates" // <-- path to certificates array in this configuration file
    ]
    certificates
    [
        "^.dev\\.domain\\.com$ /etc/certs/wildcard-dev-domain-com-cert.pem /etc/certs/wildcard-dev-domain-com-key.pem"
        "^api\\.domain2\\.com$ /usr/share/certs/api-domain2-com-cert.pem /usr/share/certs/api-domain2-com-key.pem""
        "* /etc/groom/cert.pem /etc/groom/key.pem" // <-- dummy certificate fallback, probably won't work as expected
    ]

    // the rest is left with default values
}
```


## Server domain configuration
Server domain configuration files placed in the appropriate folder (and named after the FQDN of the corresponding domains) will
allow agents to expose their private endpoints by securely back-connecting to this `groom` server instance. The available
configuration directives are described below:

- **`active`** (default **`false`**)

  whether this domain is active or not (explicitely set to **`true`** to authorize agent connections).

- **`secret`** (no default)

  the agent authentication shared secret for this domain (non-empty to authorize agent connections). use hard-to-guess
  random strings for this (the output of `openssl rand -base64 48` or similar is deemed acceptable) and send it to the
  `groom` agent operator through a secure channel. the secret may also be encrypted with `groom passwd ...` (or
  `mkpasswd -m sha-512 ...`) before being stored in this file.

- **`concurrency`** (default **`20`**, valid value from **`3`** to **`100`**)

  the maximum number of concurrent clients requests for this domain; extra clients requests will yield 429 (Too Many Requests)
  responses.

- **`body_size`** (default **`8MB`**, valid value from **`64kB`** to **`1GB`**)

  maximum body size for POST/PUT clients requests. supersedes the corresponding global value from the server main configuration
  file if set at domain level.

- **`transaction`** (default **`true`**)

  whether to return the request transaction id to the client (in the X-Transaction-Id response header) or not. supersedes the
  corresponding global value from the server main configuration file if set at domain level.

- **`forward`** (no default)

  the list of networks (@IP blocks in CIDR format) trusted to forward the X-Forwarded-For header to agents.

- **`networks`** (no default)

  the list of networks (@IP blocks in CIDR format) agents are authorized to connect from for this domain.

The following directives used in the `clients` sub-section control clients accesses more granularily (see example below):

- **`networks`** (no default)

  the list of networks (@IP blocks in CIDR format) clients are authorized to issue requests from for this domain.

- **`ranges`** (no default)

  the list of time-ranges clients are authorized to issue requests within for this domain (hours are in UTC).

- **`credentials`** (no default)

  the list of credentials (login:password pairs) clients need to provide to issue requests to this domain. the passwords may
  also be encrypted with `groom passwd ...` (or `mkpasswd -m sha-512 ...`) before being stored in this file.

- **`banner`** (default **`groom`**)

  the message displayed to the user when prompted for credentials (i.e. if the list above is not empty).

Below is a commented example of a server domain configuration file (in `/etc/groom/domains/www.domain.com`):
```
groom
{
    // mandatory directive to activate this domain
    active = true

    // shared secret with the agent
    secret = "super-secret"

    // agent connections are authorized from these @IP blocks only
    networks = [ "190.27.3.0/24", "4.3.62.0/18" ]

    clients
    {
        // clients requests are authorized from these @IP blocks only (from anywhere if empty)
        networks = [ "174.17.24.0/24", "4.3.2.1/32" ]

        // clients requests are accepted within these time-ranges (anytime if empty)
        ranges = [ "2019-10-01-2019-10-31 tue-fri 08:00-19:00", "2020-01-01 sat- 13:00-17:00" ]

        // clients are prompted for one of the following credentials (no prompt if empty)
        credentials = [ "user1:password1", "user2:password2" ]

        // the following message is used in the credentials prompt above
        banner = "www.domain.com realm"
    }
}

```


## Agent main configuration
`groom` will start in agent mode if its main configuration file contains a `mode = agent` directive. The main configuration file path
must be specified as the only command-line argument when invoking the `groom` binary. The other directives available in agent mode are
described below:

- **`mode`** (no default)

  `agent` to run `groom` in agent mode.

- **`connect_timeout`** (default **`5s`**, valid value from **`5s`** to **`60s`**)

  maximum time spent connecting to local backends.

- **`read_timeout`** (default **`10s`**, valid value from **`5s`** to **`60s`**)

  maximum time spent reading tunneled clients requests headers (extended to **`60s`** for the body of POST/PUT requests).

- **`write_timeout`** (default **`20s`**, valid value from **`5s`** to **`60s`**)

  maximum time spent sending local backends responses to clients.

- **`domains`** (default **`/etc/groom/domains`**)

  folder containing the `domain` configuration files (see next documentation section).

The following directive used in the `log` sub-section controls the agent logging (see example below):

- **`system`** (default **`console(output=stdout)`**)

  system activity structured log configuration (see the example below for syntax details).

Below is a commented example of an agent main configuration file:
```
groom
{
    // mandatory directive to run groom in agent mode
    mode = "agent"

    // log system activity messages into a file (in addition to program standard-error)
    log
    {
        system = "file(path=agent.log) console()"
    }

    // the rest is left with default values
}
```


## Agent domain configuration
Agent domain configuration files placed in the appropriate folder (and named after the FQDN of the corresponding domains) will
instruct agents to try back-connecting to the corresponding `groom` server instance. The available configuration directives are
described below:

- **`active`** (default **`false`**)

  whether this domain is active or not (explicitely set to true to have the agent proactively attempt connections).

- **`secret`** (no default)

  the agent authentication shared secret for this domain (non-empty and matching the server's to successfully connect).

- **`concurrency`** (default **`20`**, valid value from **`3`** to **`100`**)

  the maximum number of concurrent tunneled clients requests for this domain; extra clients requests will yield 502
  (Bad Gateway) responses.

- **`remote`** (default **`<domain configuration file name>:443`**)

  if the `groom` server is not listening on HTTPS default TCP port (443) or is not configured to accept agents connections
  to the default FQDN, you may used this directive to specify a different connection address and/or port.

- **`service`** (default **`/.well-known/groom-agent`**)

  URL path used by agents to connect domains (should not be changed unless you plan to chain `groom` instances).

- **`insecure`** (default **`false`**)

  allow agent connection even if the server TLS certificate is invalid (or self-signed). ignoring server certificate validity
  is a major security risk as it allows MITM attacks and agent <-> server secret stealing. /!\ USE WITH CAUTION /!\

The following directives used in the `targets` sub-section control the agent local requests routing (see example below):

- **`active`** (no default)

  an ordered list of backends/targets names used to forward tunneled requests to local services. the fist matching target
  wins (see the by-method/by-path filtering techniques below).

A configuration sub-section named after each target referenced in the `active` list above must be declared next, with at
least the `target` directive (if no filtering/routing is needed):

- **`method`** (no default)

  a regular-expression-based filter on tunneled requests methods (matches all requests if empty, see example below).

- **`path`** (no default)

  a regular-expression-based filter on tunneled requests paths (matches all requests if empty, see example below).

- **`host`** (default **`target`**)

  the Host header sent to local services in backend requests is the target host[:port] by default: if you use **`remote`**
  or **`forwarded`**, this header will contain the X-Forwarded-Host[:X-Forwarded-Port] value instead. you may also specify
  any arbitrary value that will then be passed as-is to the local service for vhost selection.

- **`target`** (no default)

  the full URL used to access the local services.
  // TODO document weighted load-balancing and URL overloading syntaxes

Below is a commented example of an agent domain configuration file (in `/etc/groom/domains/www.domain.com`):
```
groom
{
    // explicitely set to activate this domain
    active = true

    // shared secret with the server
    secret = "super-secret"

    // local routing section
    targets
    {
        // ordered list of routes to local backends, declared below
        active = [ static, default ]

        // retrieval of static content from this endpoint
        static
        {
            method = "^(OPTIONS|HEAD|GET)$"
            path   = "^/static/.+$"
            host   = "static.domain.com"
            target = "https://localhost:4443/bucket/statics?user=johndoe"
        }

        // all other requests directed to this endpoint
        default
        {
            host   = "www.domain.com"
            target = "http://localhost:8000"
        }
    }
}
```


# Future work
Here are some features that could make it in `groom` if there was some interest in them:

- requests/responses recording mechanism on the agent side, allowing to introspect and replay any traffic through a simple web interface.

- mTLS agents authentication (instead of just secrets), using an automated internal PKI (the distribution of the generated agents
key/certificate pairs is left to the system administrator).

- mTLS clients authentication (in addition to basic-auth credentials) using an automated internal PKI (the distribution of the generated
clients key/certificate pairs is left to the system administrator).

- SSO clients authentication through integration with popular IdP such as Google or Okta.

- \< your proposal here \>


# Projects with similar goals/features
- [Ngrok](https://ngrok.com/) (closed-source, commercial product with a free tiers)
- [Teleport](https://goteleport.com/) (now closed-source, commercial product with a free tiers, nice SSO/IDP integrations)
- Cloudflare [Argo Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps) (commercial product, part of Cloudflare offer)
- [Inlets](https://github.com/inlets/inlets) (open-sourced, but most interesting features (like always-on websocket tunnel encryption) seem to be only available through the PRO version)


# License
MIT - Copyright (c) 2019-2021 Pierre-Yves Kerembellec
