package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
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

type RANGE struct {
	Dates [2]time.Time
	Days  [2]int
	Times [2]int
}
type TARGET struct {
	Target string
	Method *regexp.Regexp
	Path   *regexp.Regexp
}
type DOMAIN struct {
	Name        string
	Remote      string
	Service     string
	Insecure    bool
	Secret      string
	Concurrency int
	Sources     []*net.IPNet
	Networks    []*net.IPNet
	Ranges      []*RANGE
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

func Domains() *DOMAINS {
	return &DOMAINS{list: map[string]*DOMAIN{}}
}

func (this *DOMAINS) Update() {
	root := config.GetString(progname+".domains", "/etc/"+progname+"/domains")
	if entries, err := ioutil.ReadDir(root); err == nil {
		for _, info := range entries {
			name, modified := info.Name(), info.ModTime()
			if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
				continue
			}
			this.lock.Lock()
			if domain := this.list[name]; domain == nil || (domain.modified.Sub(modified) < 0 && time.Now().Sub(modified) >= 5*time.Second) {
				if dconfig, err := uconfig.New(filepath.Join(root, name)); err == nil {
					hash := dconfig.Hash()
					if domain == nil {
						domain = &DOMAIN{Name: name, modified: modified, streams: map[int]*STREAM{}}
						this.list[domain.Name] = domain
						logger.Info(map[string]interface{}{"mode": mode, "event": "domain", "domain": name, "action": "load"})
					} else {
						domain.modified = modified
					}
					if domain.hash != "" && domain.hash != hash {
						logger.Info(map[string]interface{}{"mode": mode, "event": "domain", "domain": name, "action": "update"})
					}
					if domain.hash != hash {
						domain.hash = hash
						domain.lock.Lock()
						domain.active = dconfig.GetBoolean(progname+".active", false)
						domain.lock.Unlock()
						domain.Secret = strings.TrimSpace(dconfig.GetString(progname+".secret", ""))
						domain.Concurrency = int(dconfig.GetIntegerBounds(progname+".concurrency", 20, 3, 100))

						if mode == "server" {
							networks := []*net.IPNet{}
							for _, path := range dconfig.GetPaths(progname + ".networks") {
								if _, entry, err := net.ParseCIDR(strings.TrimSpace(dconfig.GetString(path, ""))); err == nil {
									networks = append(networks, entry)
								}
							}
							domain.Sources = networks

							networks = []*net.IPNet{}
							for _, path := range dconfig.GetPaths(progname + ".clients.networks") {
								if _, entry, err := net.ParseCIDR(strings.TrimSpace(dconfig.GetString(path, ""))); err == nil {
									networks = append(networks, entry)
								}
							}
							domain.Networks = networks
							domain.Concurrency = int(dconfig.GetIntegerBounds(progname+".concurrency", 20, 3, 100))

							ranges, matcher1, matcher2, matcher3, days := []*RANGE{},
								rcache.Get(`^(\d{4}-\d{2}-\d{2})?-(\d{4}-\d{2}-\d{2})?$`),
								rcache.Get(`^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)?-(Mon|Tue|Wed|Thu|Fri|Sat|Sun)?$`),
								rcache.Get(`^(?:(\d{2}):(\d{2})(?::(\d{2}))?)?-(?:(\d{2}):(\d{2})(?::(\d{2}))?)?$`),
								map[string]int{"Mon": 1, "Tue": 2, "Wed": 3, "Thu": 4, "Fri": 5, "Sat": 6, "Sun": 7}
							for _, path := range dconfig.GetPaths(progname + ".clients.ranges") {
								entry := &RANGE{}
								for _, value := range strings.Split(dconfig.GetString(path, ""), " ") {
									if captures := matcher1.FindStringSubmatch(value); len(captures) == 3 {
										if value, err := time.Parse("2006-01-02", captures[1]); err == nil {
											entry.Dates[0] = value
										}
										if value, err := time.Parse("2006-01-02", captures[2]); err == nil {
											entry.Dates[1] = value.Add(86399 * time.Second)
										}
									} else if captures := matcher2.FindStringSubmatch(value); len(captures) == 3 {
										entry.Days[0], entry.Days[1] = days[captures[1]], days[captures[2]]
									} else if captures := matcher3.FindStringSubmatch(value); len(captures) == 7 {
										hour, _ := strconv.ParseInt(captures[1], 10, 64)
										minute, _ := strconv.ParseInt(captures[2], 10, 64)
										second, _ := strconv.ParseInt(captures[3], 10, 64)
										entry.Times[0] = int(hour)*3600 + int(minute)*60 + int(second)
										hour, _ = strconv.ParseInt(captures[4], 10, 64)
										minute, _ = strconv.ParseInt(captures[5], 10, 64)
										second, _ = strconv.ParseInt(captures[6], 10, 64)
										entry.Times[1] = int(hour)*3600 + int(minute)*60 + int(second)
									}
								}
								ranges = append(ranges, entry)
							}
							domain.Ranges = ranges

							credentials, matcher := []string{}, rcache.Get(`^\s*([^:\s]+)\s*:\s*([^:\s]+)\s*$`)
							for _, path := range dconfig.GetPaths(progname + ".clients.credentials") {
								if captures := matcher.FindStringSubmatch(dconfig.GetString(path, "")); len(captures) == 3 {
									credentials = append(credentials, fmt.Sprintf("%s:%s", captures[1], captures[2]))
								}
							}
							domain.Credentials = credentials
							domain.Banner = strings.TrimSpace(dconfig.GetString(progname+".clients.banner", progname))
						}

						if mode == "agent" {
							domain.Remote = strings.TrimSpace(dconfig.GetString(progname+".remote", name+":443"))
							domain.Service = strings.TrimSpace(dconfig.GetString(progname+".service", "/.well-known/"+progname+"-agent"))
							domain.Insecure = dconfig.GetBoolean(progname+".insecure", false)
							targets := []*TARGET{}
							for _, path := range dconfig.GetPaths(progname + ".targets.active") {
								name := dconfig.GetString(path, "")
								if value := strings.TrimSpace(dconfig.GetString(progname+".targets."+name+".target", "")); value != "" {
									target := &TARGET{Target: value}
									if value := strings.TrimSpace(strings.ToUpper(dconfig.GetString(progname+".targets."+name+".method", ""))); value != "" {
										if matcher := rcache.Get(value); matcher != nil {
											target.Method = matcher
										} else {
											continue
										}
									}
									if value := strings.TrimSpace(dconfig.GetString(progname+".targets."+name+".path", "")); value != "" {
										if matcher := rcache.Get(value); matcher != nil {
											target.Path = matcher
										} else {
											continue
										}
									}
									targets = append(targets, target)
								}
							}
							domain.lock.Lock()
							domain.targets = targets
							domain.lock.Unlock()
						}
					}
				} else {
					logger.Warn(map[string]interface{}{"mode": mode, "event": "error", "domain": filepath.Join(root, name), "error": fmt.Sprintf("domain syntax error: %v", err)})
				}
			}
			if domain := this.list[name]; domain != nil {
				domain.seen = time.Now()
			}
			this.lock.Unlock()
		}
	}
	this.lock.RLock()
	for _, domain := range this.list {
		if time.Now().Sub(domain.seen) >= 15*time.Second {
			domain.lock.Lock()
			domain.active = false
			domain.lock.Unlock()
		}
		domain.lock.RLock()
		if domain.active {
			domain.lock.RUnlock()
			if mode == "agent" {
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
								go agent_request(domain, stream)
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
	this.lock.RUnlock()
}

func (this *DOMAINS) Get(name string) (domain *DOMAIN) {
	this.lock.RLock()
	domain = this.list[name]
	this.lock.RUnlock()
	return
}

func (this *DOMAIN) HandleConnect(response http.ResponseWriter, request *http.Request, handler func(*uws.Socket, int, []byte) bool) {
	this.lock.Lock()
	if this.connecting || this.connected {
		this.lock.Unlock()
		response.WriteHeader(http.StatusNotFound)
		logger.Warn(map[string]interface{}{"mode": mode, "event": "error", "domain": this.Name, "remote": request.RemoteAddr, "error": "agent already connected"})
		return
	}
	this.connecting = true
	this.lock.Unlock()
	if handled, _ := uws.Handle(response, request, &uws.Config{
		Protocols:    []string{progname},
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
			logger.Info(map[string]interface{}{"mode": mode, "event": "domain", "domain": domain.Name, "remote": domain.Remote, "action": "connect"})
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
			logger.Info(map[string]interface{}{"mode": mode, "event": "domain", "domain": domain.Name, "remote": domain.Remote, "action": "disconnect"})
		},
		MessageHandler: handler,
		Context:        this,
	}); !handled {
		this.lock.Lock()
		this.connecting = false
		this.lock.Unlock()
		response.WriteHeader(http.StatusNotFound)
		logger.Warn(map[string]interface{}{"mode": mode, "event": "error", "domain": this.Name, "remote": request.RemoteAddr, "error": "websocket upgrade failed"})
	}
}

func (this *DOMAIN) Connect(handler func(*uws.Socket, int, []byte) bool) {
	this.lock.Lock()
	if !this.connecting && !this.connected {
		this.connecting = true
		this.lock.Unlock()
		if _, err := uws.Dial(fmt.Sprintf("wss://%s%s", this.Remote, this.Service), "", &uws.Config{
			Headers:      map[string]string{"Authorization": fmt.Sprintf("Bearer %s", this.Secret)},
			Insecure:     this.Insecure,
			Protocols:    []string{progname},
			FragmentSize: 64 << 10,
			ReadSize:     16 << 10,
			OpenHandler: func(ws *uws.Socket) {
				domain := ws.Context.(*DOMAIN)
				domain.lock.Lock()
				domain.connecting = false
				domain.connected = true
				domain.agent = ws
				domain.lock.Unlock()
				logger.Info(map[string]interface{}{"mode": mode, "event": "domain", "domain": domain.Name, "remote": domain.Remote, "action": "connect"})
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
				logger.Info(map[string]interface{}{"mode": mode, "event": "domain", "domain": domain.Name, "remote": domain.Remote, "action": "disconnect"})
			},
			MessageHandler: handler,
			Context:        this,
		}); err != nil {
			this.lock.Lock()
			this.connecting = false
			this.lock.Unlock()
			logger.Warn(map[string]interface{}{"mode": mode, "event": "error", "domain": this.Name, "remote": this.Remote, "error": fmt.Sprintf("%v", err)})
		}
	} else {
		this.lock.Unlock()
	}
}

func (this *DOMAIN) IsActive() (active bool) {
	this.lock.RLock()
	active = this.active
	this.lock.RUnlock()
	return
}

func (this *DOMAIN) IsConnected() (connected bool) {
	this.lock.RLock()
	connected = this.active && this.connected
	this.lock.RUnlock()
	return
}

func (this *DOMAIN) Stream(id int, create bool) (stream *STREAM) {
	this.lock.Lock()
	if id >= 0 || (id < 0 && len(this.streams) < this.Concurrency) {
		if id < 0 {
			for {
				this.id++
				this.id %= (1 << 24)
				if this.streams[this.id] == nil {
					id = this.id
					break
				}
			}
		}
		if stream = this.streams[id]; stream == nil {
			if create {
				stream = &STREAM{domain: this, id: id, queue: make(chan *FRAME, 256)}
				this.streams[id] = stream
				logger.Debug(map[string]interface{}{"mode": mode, "event": "stream", "domain": this.Name, "stream": id, "action": "activate"})
			}
		}
	}
	this.lock.Unlock()
	return
}

func (this *DOMAIN) Target(method, path string) (target string) {
	this.lock.RLock()
	for _, value := range this.targets {
		if (value.Method != nil && !value.Method.MatchString(method)) || (value.Path != nil && !value.Path.MatchString(path)) {
			continue
		}
		target = value.Target
		break
	}
	this.lock.RUnlock()
	return
}
