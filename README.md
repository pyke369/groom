![groom](https://github.com/pyke369/groom/blob/master/groom.png?raw=true)

(this documentation is still a work-in-progress, but the code has been used and battle-tested for the last 2 years)


# Presentation
`groom` is a self-hosted HTTPS reverse-proxy written in Go, used to expose local private services to the public internet over secure
websocket tunnels. It works by multiplexing clients requests from a "public" server over agent-established websocket tunnels, using a
packet-framing mechanism similar to what's being done in [RTMP](https://en.wikipedia.org/wiki/Real-Time_Messaging_Protocol) or
[HTTP/2](https://en.wikipedia.org/wiki/HTTP/2) protocols. Any number of agents may be connected to a single server, and any number of
services (or "domains" in `groom` parlance) may be exposed through a single agent tunnel.

The same `groom` binary can run in 2 different modes (depending on the `mode` configuration directive value, see below):

- `server`: central instance receiving external clients requests, managing TLS termination and waiting for agents to connect
to map their exported private services under "domains".

- `agent`: distributed instances connecting to a central instance (`server` above) to make their private services accessible
remotely.

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

- extensive structured logging (on console, and in auto-rotating files and syslog) for both system events and clients requests.


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
remote: Enumerating objects: 39, done.
remote: Counting objects: 100% (39/39), done.
remote: Compressing objects: 100% (32/32), done.
remote: Total 39 (delta 1), reused 38 (delta 0), pack-reused 0
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
dpkg-buildpackage: info: source version 1.0.5
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
dpkg-deb: building package 'groom' in '../groom_1.0.5_amd64.deb'.
 dpkg-genbuildinfo --build=binary
 dpkg-genchanges --build=binary >../groom_1.0.5_amd64.changes
dpkg-genchanges: info: binary-only upload (no source code included)
 dpkg-source -i --after-build groom
dpkg-buildpackage: info: binary-only upload (no source included)

$ ls -al ../groom_1.0.5_amd64.deb
-rw-r--r-- 1 nobody nogroup 2268276 Jul 28 17:34 ../groom_1.0.5_amd64.deb
```

Once downloaded, you can unzip the universal binary archive anywhere and start using `groom` right-away without installing anything
beforehand (hence the "portable/universal" qualifier):
```
$ unzip /mnt/hgfs/Downloads/groom_1.0.5.zip
Archive:  /mnt/hgfs/Downloads/groom_1.0.5.zip
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

$ ./groom conf/agent.conf
2019-07-28 18:15:29 INFO {"config":"conf/agent.conf","event":"start","mode":"agent","pid":127857,"version":"1.0.5"}

PS C:\groom> .\groom .\conf\agent.conf
2019-07-28 18:42:37 INFO {"config":".\\conf\\agent.conf","event":"start","mode":"agent","pid":6328,"version":"1.0.5"}
```
We recommend adding the current folder to your PATH environment variable to allow starting `groom` from anywhere.

On a `groom` server instance, you may alternatively deploy the Debian package with the following command:
```
# dpkg -i groom_1.0.5_amd64.deb
Selecting previously unselected package groom.
Preparing to unpack groom_1.0.5_amd64.deb ...
Unpacking groom (1.0.5) ...
Setting up groom (1.0.5) ...
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
`groom` relies on "JSON-syntax-alike" text files for its configuration, and each file must contain a top-level `groom` section to be
properly parsed, i.e. all configuration files must be in the following form:
```
groom
{
   // directives...
}
```
The #, // and /* */ may be used for commenting or disabling some parts of the configuration. Most of the configuration files directives
have sensible defaults - suitable for a production environment - and should not be changed unless instructed to. As mentionned in the
presentation, domains configuration files changes (in server or agent mode) are automatically detected and there's no need to restart
the `groom` instances


## Server main configuration
`groom` will start in server mode if its main configuration file contains a `mode = server` directive. The main configuration file path
must be specified as the only command-line argument when invoking the `groom` binary. The other directives available in server mode are
described below:

- **`mode`** (no default)

  must be `server` to run `groom` in server mode.

- **`log`** (default **`console(output=stdout)`**)

  TODO

- **`access_log`** (no default)

  TODO

- **`listen`** (no default)

  TODO

- **`headers_size`** (default **`64kB`**)

  TODO

- **`idle_timeout`** (default **`15s`**)

  TODO

- **`read_timeout`** (default **`10s`**)

  TODO

- **`write_timeout`** (default **`20s`**)

  TODO

- **`body_size`** (default **`8MB`**)

  TODO

- **`service`** (default **`/.well-known/groom-agent`**)

  TODO

- **`domains`** (default **`/etc/groom/domains`**)

  TODO


Commented example of a server main configuration file:
```
groom
{
    mode   = server
    log    = "file(path=) syslog()"
    listen = [ "*:443,/etc/groom/cert.pem,/etc/groom/key.pem"" ]
}

```


## Server domain configuration
TODO

- **`active`** (default **`false`**)

  TODO

- **`secret`** (no default)

  TODO

- **`concurrency`** (default **`20`**)

  TODO

- **`networks`** (no default)

  TODO

clients sub-section

- **`networks`** (no default)

  TODO

- **`ranges`** (no default)

  TODO

- **`credentials`** (no default)

  TODO

- **`banner`** (default **`groom`**)

  TODO

Commented example of a server domain configuration file:
```
groom
{
}

```


## Agent main configuration
`groom` will start in aget mode if its main configuration file contains a `mode = agent` directive. The main configuration file path
must be specified as the only command-line argument when invoking the `groom` binary. The other directives available in agent mode are
described below:

- **`mode`** (no default)

  must be `agent` to run `groom` in agent mode.

- **`log`** (default **`console(output=stdout)`**)

  TODO

- **`connect_timeout`** (default **`5s`**)

  TODO

- **`read_timeout`** (default **`10s`**)

  TODO

- **`write_timeout`** (default **`20s`**)

  TODO

- **`domains`** (default **`/etc/groom/domains`**)

  TODO

Commented example of an agent main configuration file:
```
groom
{
}

```


## Agent domain configuration
TODO

- **`active`** (default **`false`**)

  TODO

- **`secret`** (no default)

  TODO

- **`concurrency`** (default **`20`**)

  TODO

- **`remote`** (default **`<filename>:443`**)

  TODO

- **`service`** (default **`/.well-known/groom-agent`**)

  TODO

- **`insecure`** (default **`false`**)

  TODO

(`targets` sub-section)

- **`active`** (no default)

  TODO

(`<target>` sub-section)

- **`method`** (no default)

  TODO

- **`path`** (no default)

  TODO

- **`target`** (no default)

  TODO

Commented example of an agent domain configuration file:
```
groom
{
}
```


# Future work
Here are some features that could make it in `groom` if there was some interest in them:

- requests/responses recording mechanism on the agent side, allowing to introspect and replay any traffic through a simple web interface.

- mTLS agents authentication (instead of just secrets), using an automated internal PKI (the distribution of the generated agents
key/certificate pairs would be left to the implentation).

- mTLS clients authentication (in addition to basic auth credential) using an automated internal PKI (the distribution of the generated
clients key/certificate pairs would be left to the implementation).

- SSO clients authentication through integration with popular IdP such as Google or Okta.

- \< your proposal here \>


# Projects with similar goals/features
- [Ngrok](https://ngrok.com/) (closed-source, commercial product with a free tiers)
- [Teleport](https://goteleport.com/) (now closed-source, commercial product with a free tiers, nice SSO/IDP integrations)
- Cloudflare [Argo Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps) (commercial product, part of Cloudflare offer)
- [Inlets](https://github.com/inlets/inlets) (open-sourced, but most interesting features (like always-on websocket tunnel encryption) seem to be only available through the PRO version)


# License
MIT - Copyright (c) 2019-2021 Pierre-Yves Kerembellec
