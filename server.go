package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/pyke369/golang-support/acl"
	"github.com/pyke369/golang-support/bslab"
	"github.com/pyke369/golang-support/dynacert"
	"github.com/pyke369/golang-support/rcache"
	"github.com/pyke369/golang-support/uuid"
	"github.com/pyke369/golang-support/uws"
)

func ServerRun() {
	handler := http.NewServeMux()
	handler.HandleFunc(strings.TrimSpace(Config.GetString(Config.Path(PROGNAME, "service"), "/.well-known/"+PROGNAME+"-agent")), serverAgent)
	handler.HandleFunc("/", serverRequest)
	for _, path := range Config.GetPaths(Config.Path(PROGNAME, "listen")) {
		if parts := strings.Split(Config.GetStringMatch(path, "_", `^.*?(:\d+)?((,[^,]+){1,2})?$`), ","); parts[0] != "_" && len(parts) > 1 {
			parts[0], parts[1] = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
			certificates := &dynacert.DYNACERT{}
			if len(parts) > 2 {
				certificates.Add("*", parts[1], strings.TrimSpace(parts[2]))
			} else if matcher := rcache.Get(`^(\S+)\s+(\S+)\s+(\S+)$`); matcher != nil {
				for _, path := range Config.GetPaths(parts[1]) {
					if captures := matcher.FindStringSubmatch(strings.TrimSpace(Config.GetString(path))); len(captures) > 3 {
						certificates.Add(captures[1], captures[2], captures[3])
					}
				}
			}
			server := &http.Server{
				Handler:           handler,
				Addr:              strings.TrimLeft(parts[0], "*"),
				ErrorLog:          log.New(io.Discard, "", 0),
				MaxHeaderBytes:    int(Config.GetSizeBounds(Config.Path(PROGNAME, "headers_size"), 64<<10, 1<<10, 1<<20)),
				IdleTimeout:       Config.GetDurationBounds(Config.Path(PROGNAME, "idle_timeout"), 15, 5, 60),
				ReadHeaderTimeout: Config.GetDurationBounds(Config.Path(PROGNAME, "read_timeout"), 10, 5, 60),
				ReadTimeout:       Config.GetDurationBounds(Config.Path(PROGNAME, "read_timeout"), 60, 5, 60),
				TLSConfig:         dynacert.IntermediateTLSConfig(certificates.GetCertificate),
				TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
			}
			go func(server *http.Server, parts []string) {
				Logger.Info(map[string]interface{}{"mode": Mode, "event": "listen", "listen": parts[0], "certificates": strings.Join(parts[1:], ",")})
				for {
					server.ListenAndServeTLS("", "")
					time.Sleep(time.Second)
				}
			}(server, parts)
		}
	}
	Domains.Update()
	for range time.Tick(5 * time.Second) {
		Domains.Update()
	}
}

func serverAgent(response http.ResponseWriter, request *http.Request) {
	name, _, err := net.SplitHostPort(request.Host)
	if err != nil {
		name = request.Host
	}
	secret, unavailable := "", int(Config.GetIntegerBounds(Config.Path(PROGNAME, "unavailable"), http.StatusNotFound, 200, 999))
	if header := request.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") && len(header) >= 8 {
		secret = strings.TrimSpace(header[7:])
	}
	if secret == "" {
		response.WriteHeader(unavailable)
		Logger.Warn(map[string]interface{}{"mode": Mode, "event": "error", "domain": name, "remote": request.RemoteAddr, "error": "agent authentication not provided"})
		return
	}
	domain := Domains.Get(name)
	if domain == nil {
		response.WriteHeader(unavailable)
		Logger.Warn(map[string]interface{}{"mode": Mode, "event": "error", "domain": name, "remote": request.RemoteAddr, "error": "unknown domain"})
		return
	}
	if !domain.IsActive() {
		response.WriteHeader(unavailable)
		Logger.Warn(map[string]interface{}{"mode": Mode, "event": "error", "domain": name, "remote": request.RemoteAddr, "error": "inactive domain"})
		return
	}
	if match, _ := acl.Password(secret, []string{domain.Secret}, false); !match || domain.Secret == "" {
		response.WriteHeader(unavailable)
		Logger.Warn(map[string]interface{}{"mode": Mode, "event": "error", "domain": name, "remote": request.RemoteAddr, "error": "invalid agent authentication"})
		return
	}
	if ok, _ := acl.CIDR(request.RemoteAddr, domain.Sources, true); !ok {
		response.WriteHeader(unavailable)
		Logger.Warn(map[string]interface{}{"mode": Mode, "event": "error", "domain": name, "remote": request.RemoteAddr, "error": "agent connection from unauthorized network"})
		return
	}

	domain.HandleConnect(response, request, func(ws *uws.Socket, mode int, data []byte) bool {
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
		}
		return false
	})
}

func serverLog(start time.Time, reason, domain, id string, request *http.Request, status, in, out int) {
	info := map[string]interface{}{
		"start":    start.UnixNano() / 1000000,
		"domain":   domain,
		"id":       id,
		"method":   request.Method,
		"remote":   request.RemoteAddr,
		"status":   status,
		"in":       in,
		"out":      out,
		"duration": fmt.Sprintf("%v", time.Since(start).Round(time.Microsecond)),
	}
	if reason != "" {
		info["reason"] = reason
	}
	path := request.URL.Path
	if value := strings.TrimSpace(request.URL.RawQuery); value != "" {
		path += "?" + value
	}
	info["path"] = path
	if value := strings.TrimSpace(request.Header.Get("User-Agent")); value != "" {
		info["ua"] = value
	}
	if value := strings.TrimSpace(request.Header.Get("Referer")); value != "" {
		info["referer"] = value
	}
	if matcher := rcache.Get(`^bytes=(\d+)?-(\d+)?$`); matcher != nil {
		if captures := matcher.FindStringSubmatch(strings.TrimSpace(request.Header.Get("Range"))); len(captures) == 3 {
			info["range"] = fmt.Sprintf("%s-%s", captures[1], captures[2])
		}
	}
	AccessLogger.Info(info)
}

func serverRequest(response http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodConnect || request.Method == http.MethodTrace {
		response.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	name, port, err := net.SplitHostPort(request.Host)
	if err != nil {
		name, port = request.Host, "443"
	}

	start, id, in, out, domain := time.Now(), uuid.UUID(), 0, 52, Domains.Get(name)
	unavailable := int(Config.GetIntegerBounds(Config.Path(PROGNAME, "unavailable"), http.StatusNotFound, 200, 999))
	if headers, err := httputil.DumpRequest(request, false); err == nil {
		in = len(headers)
	}
	if domain == nil || !domain.IsConnected() {
		response.WriteHeader(unavailable)
		if Config.GetBoolean(Config.Path(PROGNAME, "log", "disconnected"), false) {
			serverLog(start, "disconnected domain", name, id, request, http.StatusNotFound, in, out)
		}
		return
	}

	if request.Method == http.MethodPost || request.Method == http.MethodPut {
		if request.ContentLength < 0 {
			response.WriteHeader(http.StatusLengthRequired)
			serverLog(start, "missing content length", name, id, request, http.StatusLengthRequired, in, out)
			return
		}
		if int(request.ContentLength) >= domain.Size {
			response.WriteHeader(http.StatusRequestEntityTooLarge)
			serverLog(start, "request too large", name, id, request, http.StatusRequestEntityTooLarge, int(request.ContentLength), out)
			return
		}
	}

	if ok, _ := acl.CIDR(request.RemoteAddr, domain.Networks, true); !ok {
		response.WriteHeader(unavailable)
		serverLog(start, "unauthorized network", name, id, request, http.StatusForbidden, in, out)
		return
	}

	if ok, _ := acl.Ranges(time.Now(), domain.Ranges, true); !ok {
		response.WriteHeader(unavailable)
		serverLog(start, "unauthorized timerange", name, id, request, http.StatusForbidden, in, out)
		return
	}

	if len(domain.Credentials) != 0 {
		cookie, seal := fmt.Sprintf("%s%x", PROGNAME, Instance[:4]), fmt.Sprintf("%x", sha1.Sum(append(append(Secret, Instance...), []byte(name)...)))
		if value, _ := request.Cookie(cookie); value == nil || value.Value != seal {
			login, password, _ := request.BasicAuth()
			if match, _ := acl.Password(fmt.Sprintf("%s:%s", login, password), domain.Credentials, false); !match {
				response.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, domain.Banner))
				response.WriteHeader(http.StatusUnauthorized)
				return
			}
			http.SetCookie(response, &http.Cookie{Name: cookie, Value: seal, Path: "/", MaxAge: 1200})
			request.Header.Del("Authorization")
		}
		cookies := strings.Split(request.Header.Get("Cookie"), ";")
		for index, value := range cookies {
			if strings.Contains(value, cookie+"=") {
				cookies = append(cookies[0:index], cookies[index+1:]...)
				break
			}
		}
		if len(cookies) != 0 {
			for index := range cookies {
				cookies[index] = strings.TrimSpace(cookies[index])
			}
			request.Header.Set("Cookie", strings.Join(cookies, "; "))
		} else {
			request.Header.Del("Cookie")
		}
	}

	remote, _, _ := net.SplitHostPort(request.RemoteAddr)
	if ok, _ := acl.CIDR(request.RemoteAddr, domain.Forward, false); ok {
		if value := request.Header.Get("X-Forwarded-For"); value != "" {
			remote = value
		}
	}
	request.Header.Set("X-Forwarded-For", remote)
	request.Header.Set("X-Forwarded-Host", name)
	request.Header.Set("X-Forwarded-Port", port)
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Transaction-Id", id)
	request.Header.Del("Expect")
	if domain.Transaction {
		response.Header().Set("X-Transaction-Id", id)
	}

	if stream := domain.Stream(-1, true); stream != nil {
		if headers, err := httputil.DumpRequest(request, false); err == nil {
			var errored error

			head, data := false, bslab.Get(64<<10, nil)
			for {
				data = data[:cap(data)-4]
				read, err := request.Body.Read(data)
				if read >= 0 {
					if !head {
						head = true
						if err := stream.Write(FLAG_HEAD|FLAG_START, headers); err != nil {
							errored = err
							break
						}
					}
					in += read
					data = data[:read]
					flags := FLAG_BODY
					if read == 0 || err != nil {
						flags |= FLAG_END
					}
					if err := stream.Write(flags, data); err != nil {
						errored = err
						break
					}
				}
				if err != nil {
					break
				}
			}
			if !head {
				if err := stream.Write(FLAG_HEAD|FLAG_START|FLAG_END, headers); err != nil {
					errored = err
				}
			}

			if errored != nil {
				stream.Shutdown(true, true)
				response.WriteHeader(http.StatusBadGateway)
				serverLog(start, fmt.Sprintf("%v", errored), name, id, request, http.StatusBadGateway, in, out)
			} else {
				upgraded, timeout, status := false, Config.GetDurationBounds(Config.Path(PROGNAME, "write_timeout"), 20, 5, 60), 0
				for {
					frame := stream.Read(timeout, request.Context())
					if frame == nil {
						errored = fmt.Errorf("backend timeout")
						break
					}

					if frame.Flags&FLAG_HEAD != 0 {
						aresponse, err := http.ReadResponse(bufio.NewReader(bytes.NewBuffer(frame.Data)), request)
						bslab.Put(frame.Data)
						if err != nil {
							errored = err
							break
						}
						status = aresponse.StatusCode
						if headers, err := httputil.DumpResponse(aresponse, false); err == nil {
							out += len(headers)
						}
						if frame.Flags&FLAG_UPGD != 0 {
							upgraded = true
						}
						for name := range aresponse.Header {
							if name != "Set-Cookie" && name != "Keep-Alive" && (upgraded || name != "Connection") && name != "Transfer-Encoding" {
								response.Header().Set(name, aresponse.Header.Get(name))
							}
						}
						for _, cookie := range aresponse.Cookies() {
							if cookie.Name != PROGNAME {
								http.SetCookie(response, cookie)
							}
						}
						response.WriteHeader(aresponse.StatusCode)
						aresponse.Body.Close()
						if frame.Flags&FLAG_END != 0 {
							serverLog(start, "", name, id, request, status, in, out)
							break
						}
						if upgraded {
							serverLog(start, "raw session startup", name, id, request, status, in, out)
							break
						}
					}

					if frame.Flags&FLAG_BODY != 0 {
						if frame.Data != nil && len(frame.Data) > 0 {
							_, err := response.Write(frame.Data)
							out += len(frame.Data)
							bslab.Put(frame.Data)
							if err != nil {
								errored = err
								break
							}
							if flusher, ok := response.(http.Flusher); ok {
								flusher.Flush()
							}
						}
						if frame.Flags&FLAG_END != 0 {
							serverLog(start, "", name, id, request, status, in, out)
							break
						}
					}
				}

				if errored != nil {
					stream.Shutdown(true, true)
				} else if upgraded {
					if client, _, err := response.(http.Hijacker).Hijack(); err != nil {
						stream.Shutdown(true, true)
					} else {
						go func() {
							for {
								frame := stream.Read(timeout, nil)
								if frame == nil {
									stream.Shutdown(true, false)
									break
								}
								if frame.Flags&FLAG_RAW != 0 {
									client.SetWriteDeadline(time.Now().Add(timeout))
									_, err := client.Write(frame.Data)
									out += len(frame.Data)
									bslab.Put(frame.Data)
									if err != nil {
										break
									}
								}
							}
						}()
						for {
							client.SetReadDeadline(time.Now().Add(timeout))
							data = data[:cap(data)-4]
							read, err := client.Read(data)
							if read >= 0 {
								in += read
								data = data[:read]
								flags := FLAG_RAW
								if read == 0 || err != nil {
									flags |= FLAG_END
								}
								if stream.Write(flags, data) != nil {
									break
								}
							}
							if err != nil {
								stream.Shutdown(true, false)
								break
							}
						}
						client.Close()
						serverLog(start, "raw session teardown", name, id, request, 0, in, out)
					}
				}
			}
			bslab.Put(data)
		} else {
			response.WriteHeader(http.StatusBadRequest)
			serverLog(start, "", name, id, request, http.StatusBadRequest, in, out)
		}
		stream.Shutdown(false, true)
	} else {
		response.WriteHeader(http.StatusTooManyRequests)
		serverLog(start, "", name, id, request, http.StatusTooManyRequests, in, out)
	}
}
