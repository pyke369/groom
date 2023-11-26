package main

import (
	"crypto/tls"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uconfig"
	"github.com/pyke369/golang-support/uws"
)

type HOST struct {
	host   string
	weight int
}
type TARGET struct {
	protocol string
	hosts    []*HOST
	weights  int
	path     string
	host     string
	rmethod  *regexp.Regexp
	rpath    *regexp.Regexp
}
type DOMAIN struct {
	Name        string
	Remote      string
	Service     string
	Insecure    bool
	Secret      string
	Concurrency int
	Size        int
	Transaction bool
	Sources     []string
	Forward     []string
	Networks    []string
	Ranges      []string
	Credentials []string
	Banner      string
	hash        string
	seen        time.Time
	modified    time.Time
	lock        sync.RWMutex
	active      bool
	connecting  bool
	connected   bool
	agent       *uws.Socket
	id          int
	streams     map[int]*STREAM
	targets     []*TARGET
}
type DOMAINS struct {
	lock sync.RWMutex
	list map[string]*DOMAIN
}

func NewDomains() *DOMAINS {
	return &DOMAINS{list: map[string]*DOMAIN{}}
}

func (d *DOMAINS) Update() {
	root := Config.GetString(Config.Path(PROGNAME, "domains"), "/etc/"+PROGNAME+"/domains")
	if entries, err := os.ReadDir(root); err == nil {
		for _, entry := range entries {
			name, modified := entry.Name(), time.Now()
			if info, err := entry.Info(); err == nil {
				modified = info.ModTime()
			}
			if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || strings.Contains(name, "dpkg-") {
				continue
			}
			d.lock.Lock()
			if domain := d.list[name]; domain == nil || (domain.modified.Sub(modified) < 0 && time.Since(modified) >= 5*time.Second) {
				if dconfig, err := uconfig.New(filepath.Join(root, name)); err == nil {
					hash := dconfig.Hash()
					if domain == nil {
						domain = &DOMAIN{Name: name, modified: modified, streams: map[int]*STREAM{}}
						d.list[domain.Name] = domain
						Logger.Info(map[string]interface{}{"mode": Mode, "event": "domain", "domain": name, "action": "load"})
					} else {
						domain.modified = modified
					}
					if domain.hash != "" && domain.hash != hash {
						Logger.Info(map[string]interface{}{"mode": Mode, "event": "domain", "domain": name, "action": "update"})
					}
					if domain.hash != hash {
						domain.hash = hash
						domain.lock.Lock()
						domain.active = dconfig.GetBoolean(dconfig.Path(PROGNAME, "active"))
						domain.lock.Unlock()
						domain.Secret = strings.TrimSpace(dconfig.GetString(dconfig.Path(PROGNAME, "secret")))
						domain.Concurrency = int(dconfig.GetIntegerBounds(dconfig.Path(PROGNAME, "concurrency"), 20, 3, 1000))
						domain.Size = int(dconfig.GetSizeBounds(dconfig.Path(PROGNAME, "body_size"), Config.GetSizeBounds(Config.Path(PROGNAME, "body_size"), 8<<20, 64<<10, 1<<30), 64<<10, 1<<30))
						domain.Transaction = dconfig.GetBoolean(dconfig.Path(PROGNAME, "transaction"), Config.GetBoolean(Config.Path(PROGNAME, "transaction"), true))

						if Mode == "server" {
							domain.Sources, domain.Forward, domain.Networks, domain.Ranges, domain.Credentials = []string{}, []string{}, []string{}, []string{}, []string{}
							for _, path := range dconfig.GetPaths(Config.Path(PROGNAME, "forward")) {
								if value := strings.TrimSpace(dconfig.GetString(path)); value != "" {
									domain.Forward = append(domain.Forward, value)
								}
							}
							for _, path := range dconfig.GetPaths(dconfig.Path(PROGNAME, "networks")) {
								if value := strings.TrimSpace(dconfig.GetString(path)); value != "" {
									domain.Sources = append(domain.Sources, value)
								}
							}
							for _, path := range dconfig.GetPaths(dconfig.Path(PROGNAME, "clients", "networks")) {
								if value := strings.TrimSpace(dconfig.GetString(path)); value != "" {
									domain.Networks = append(domain.Networks, value)
								}
							}
							for _, path := range dconfig.GetPaths(dconfig.Path(PROGNAME, "clients", "ranges")) {
								if value := strings.TrimSpace(dconfig.GetString(path)); value != "" {
									domain.Ranges = append(domain.Ranges, value)
								}
							}
							for _, path := range dconfig.GetPaths(dconfig.Path(PROGNAME, "clients", "credentials")) {
								if value := strings.TrimSpace(dconfig.GetString(path)); value != "" {
									domain.Credentials = append(domain.Credentials, value)
								}
							}
							domain.Concurrency = int(dconfig.GetIntegerBounds(dconfig.Path(PROGNAME, "concurrency"), 20, 3, 1000))
							domain.Banner = strings.TrimSpace(dconfig.GetString(dconfig.Path(PROGNAME, "clients", "banner"), PROGNAME))
						}

						if Mode == "agent" {
							domain.Remote = strings.TrimSpace(dconfig.GetString(dconfig.Path(PROGNAME, "remote"), name+":443"))
							domain.Service = strings.TrimSpace(dconfig.GetString(dconfig.Path(PROGNAME, "service"), "/.well-known/"+PROGNAME+"-agent"))
							domain.Insecure = dconfig.GetBoolean(dconfig.Path(PROGNAME, "insecure"))
							targets := []*TARGET{}
							for _, path := range dconfig.GetPaths(dconfig.Path(PROGNAME, "targets", "active")) {
								name := dconfig.GetString(path)
								if value := strings.TrimSpace(dconfig.GetString(dconfig.Path(PROGNAME, "targets", name, "target"))); value != "" {
									if captures := rcache.Get(`^(https?://)([^/]+)(.*)$`).FindStringSubmatch(value); captures != nil {
										hosts, weights := []*HOST{}, 0
										for _, host := range strings.Split(captures[2], "|") {
											if host = strings.TrimSpace(host); host != "" {
												weight := 1
												if parts := strings.Split(host, "@"); len(parts) > 1 {
													host = strings.TrimSpace(parts[1])
													weight, _ = strconv.Atoi(strings.TrimSpace(parts[0]))
													weight = int(math.Min(100, math.Max(1, float64(weight))))
												}
												hosts = append(hosts, &HOST{host: host, weight: weight})
												weights += weight
											}
										}
										if len(hosts) != 0 {
											target := &TARGET{protocol: captures[1], hosts: hosts, weights: weights, path: strings.TrimSpace(captures[3])}
											target.host = strings.ToLower(strings.TrimSpace(dconfig.GetString(dconfig.Path(PROGNAME, "targets", name, "host"), "target")))
											if value := strings.TrimSpace(strings.ToUpper(dconfig.GetString(dconfig.Path(PROGNAME, "targets", name, "method")))); value != "" {
												if matcher := rcache.Get(value); matcher != nil {
													target.rmethod = matcher
												} else {
													continue
												}
											}
											if value := strings.TrimSpace(dconfig.GetString(dconfig.Path(PROGNAME, "targets", name, "path"))); value != "" {
												if matcher := rcache.Get(value); matcher != nil {
													target.rpath = matcher
												} else {
													continue
												}
											}
											targets = append(targets, target)
										}
									}
								}
							}

							domain.lock.Lock()
							domain.targets = targets
							domain.lock.Unlock()
						}
					}
				} else {
					Logger.Warn(map[string]interface{}{"mode": Mode, "event": "error", "domain": filepath.Join(root, name), "error": fmt.Sprintf("domain syntax error: %v", err)})
				}
			}
			if domain := d.list[name]; domain != nil {
				domain.seen = time.Now()
			}
			d.lock.Unlock()
		}
	}
	d.lock.RLock()
	for _, domain := range d.list {
		if time.Since(domain.seen) >= 15*time.Second {
			domain.lock.Lock()
			domain.active = false
			domain.lock.Unlock()
		}
		domain.lock.RLock()
		if domain.active {
			domain.lock.RUnlock()
			if Mode == "agent" {
				domain.Connect(func(ws *uws.Socket, mode int, data []byte) bool {
					length := len(data)
					if mode == uws.WEBSOCKET_OPCODE_BLOB && length >= 4 {
						domain, flags, id := ws.Context.(*DOMAIN), int(data[length-4]), (int(data[length-3])<<16)+(int(data[length-2])<<8)+int(data[length-1])
						if stream := domain.Stream(id, false); stream != nil {
							if flags&FLAG_ABRT != 0 {
								stream.Shutdown(false, true)
								return false
							}
							stream.Queue(flags, data[:length-4])
							return true
						}
						if flags&FLAG_START != 0 {
							if stream := domain.Stream(id, true); stream != nil {
								go AgentRequest(domain, stream)
								stream.Queue(flags, data[:length-4])
								return true
							}
						}
					}
					return false
				})
			}
		} else if domain.connected {
			domain.lock.RUnlock()
			domain.agent.Close(0)
		} else {
			domain.lock.RUnlock()
		}
	}
	d.lock.RUnlock()
}

func (d *DOMAINS) Get(name string) (domain *DOMAIN) {
	d.lock.RLock()
	domain = d.list[name]
	d.lock.RUnlock()
	return
}

func (d *DOMAIN) HandleConnect(response http.ResponseWriter, request *http.Request, handler func(*uws.Socket, int, []byte) bool) {
	d.lock.Lock()
	if d.connecting || d.connected {
		d.lock.Unlock()
		response.WriteHeader(http.StatusNotFound)
		Logger.Warn(map[string]interface{}{"mode": Mode, "event": "error", "domain": d.Name, "remote": request.RemoteAddr, "error": "agent already connected"})
		return
	}
	d.connecting = true
	d.lock.Unlock()
	if handled, _ := uws.Handle(response, request, &uws.Config{
		Protocols:    []string{PROGNAME},
		NeedProtocol: true,
		FragmentSize: 64 << 10,
		ReadSize:     16 << 10,
		OpenHandler: func(ws *uws.Socket) {
			domain := ws.Context.(*DOMAIN)
			domain.lock.Lock()
			domain.Remote = request.RemoteAddr
			domain.connecting = false
			domain.connected = true
			domain.agent = ws
			domain.lock.Unlock()
			Logger.Info(map[string]interface{}{"mode": Mode, "event": "domain", "domain": domain.Name, "remote": domain.Remote, "action": "connect"})
		},
		CloseHandler: func(ws *uws.Socket, code int) {
			domain := ws.Context.(*DOMAIN)
			domain.lock.Lock()
			for id, stream := range domain.streams {
				stream.Shutdown(false, false)
				delete(domain.streams, id)
			}
			domain.connected = false
			domain.lock.Unlock()
			Logger.Info(map[string]interface{}{"mode": Mode, "event": "domain", "domain": domain.Name, "remote": domain.Remote, "action": "disconnect"})
		},
		MessageHandler: handler,
		Context:        d,
	}); !handled {
		d.lock.Lock()
		d.connecting = false
		d.lock.Unlock()
		response.WriteHeader(http.StatusNotFound)
		Logger.Warn(map[string]interface{}{"mode": Mode, "event": "error", "domain": d.Name, "remote": request.RemoteAddr, "error": "websocket upgrade failed"})
	}
}

func (d *DOMAIN) Connect(handler func(*uws.Socket, int, []byte) bool) {
	d.lock.Lock()
	if !d.connecting && !d.connected {
		d.connecting = true
		d.lock.Unlock()
		if _, err := uws.Dial(fmt.Sprintf("wss://%s%s", d.Remote, d.Service), "", &uws.Config{
			Headers:      map[string]string{"Authorization": fmt.Sprintf("Bearer %s", d.Secret)},
			TLSConfig:    &tls.Config{InsecureSkipVerify: d.Insecure},
			Protocols:    []string{PROGNAME},
			FragmentSize: 64 << 10,
			ReadSize:     16 << 10,
			OpenHandler: func(ws *uws.Socket) {
				domain := ws.Context.(*DOMAIN)
				domain.lock.Lock()
				domain.connecting = false
				domain.connected = true
				domain.agent = ws
				domain.lock.Unlock()
				Logger.Info(map[string]interface{}{"mode": Mode, "event": "domain", "domain": domain.Name, "remote": domain.Remote, "action": "connect"})
			},
			CloseHandler: func(ws *uws.Socket, code int) {
				domain := ws.Context.(*DOMAIN)
				domain.lock.Lock()
				for id, stream := range domain.streams {
					stream.Shutdown(false, false)
					delete(domain.streams, id)
				}
				domain.connected = false
				domain.lock.Unlock()
				Logger.Info(map[string]interface{}{"mode": Mode, "event": "domain", "domain": domain.Name, "remote": domain.Remote, "action": "disconnect"})
			},
			MessageHandler: handler,
			Context:        d,
		}); err != nil {
			d.lock.Lock()
			d.connecting = false
			d.lock.Unlock()
			Logger.Warn(map[string]interface{}{"mode": Mode, "event": "error", "domain": d.Name, "remote": d.Remote, "error": fmt.Sprintf("%v", err)})
		}
	} else {
		d.lock.Unlock()
	}
}

func (d *DOMAIN) IsActive() (active bool) {
	d.lock.RLock()
	active = d.active
	d.lock.RUnlock()
	return
}

func (d *DOMAIN) IsConnected() (connected bool) {
	d.lock.RLock()
	connected = d.active && d.connected
	d.lock.RUnlock()
	return
}

func (d *DOMAIN) Stream(id int, create bool) (stream *STREAM) {
	d.lock.Lock()
	if id >= 0 || (id < 0 && len(d.streams) < d.Concurrency) {
		if id < 0 {
			for {
				d.id++
				d.id %= (1 << 24)
				if d.streams[d.id] == nil {
					id = d.id
					break
				}
			}
		}
		if stream = d.streams[id]; stream == nil {
			if create {
				stream = &STREAM{domain: d, id: id, queue: make(chan *FRAME, 256)}
				d.streams[id] = stream
				Logger.Debug(map[string]interface{}{"mode": Mode, "event": "stream", "domain": d.Name, "stream": id, "action": "activate"})
			}
		}
	}
	d.lock.Unlock()
	return
}

func (d *DOMAIN) Target(method, path string) (target, host string) {
	d.lock.RLock()
	for _, value := range d.targets {
		if (value.rmethod != nil && !value.rmethod.MatchString(method)) || (value.rpath != nil && !value.rpath.MatchString(path)) {
			continue
		}
		host = value.host
		index, weight := 0, rand.Intn(value.weights)
		for _, host := range value.hosts {
			index += host.weight
			if weight < index {
				if value.rpath != nil {
					path = value.rpath.ReplaceAllString(path, value.path)
				} else {
					path = value.path
				}
				target = fmt.Sprintf("%s%s%s", value.protocol, host.host, path)
				break
			}
		}
		break
	}
	d.lock.RUnlock()
	return
}
