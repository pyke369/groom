package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/pyke369/golang-support/bslab"
)

func AgentRun() {
	Domains.Update()
	for range time.Tick(5 * time.Second) {
		Domains.Update()
	}
}

func AgentRequest(domain *DOMAIN, stream *STREAM) {
	var (
		request *http.Request
		backend net.Conn
	)

	errored, timeout := 0, Config.GetDurationBounds(Config.Path(PROGNAME, "read_timeout"), 10, 5, 60)
	for {
		frame := stream.Read(timeout, nil)
		if frame == nil {
			break
		}

		if frame.Flags&FLAG_HEAD != 0 {
			request, _ = http.ReadRequest(bufio.NewReader(bytes.NewBuffer(frame.Data)))
			bslab.Put(frame.Data)
			if request == nil {
				errored = http.StatusBadRequest
				break
			}
			target, host := domain.Target(request.Method, request.URL.Path)
			if target == "" {
				errored = http.StatusBadGateway
				break
			}
			parts, err := url.Parse(target)
			if err != nil || parts.Scheme == "" || parts.Host == "" {
				errored = http.StatusBadGateway
				break
			}
			if _, _, err := net.SplitHostPort(parts.Host); err != nil {
				if parts.Scheme == "https" {
					parts.Host += ":443"
				} else {
					parts.Host += ":80"
				}
			}
			timeout := Config.GetDurationBounds(Config.Path(PROGNAME, "connect_timeout"), 5, 5, 60)
			if parts.Scheme == "https" {
				if value, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", parts.Host, &tls.Config{InsecureSkipVerify: true}); err == nil {
					backend = net.Conn(value)
				}
			} else if value, err := net.DialTimeout("tcp", parts.Host, timeout); err == nil {
				backend = value
			}
			if backend == nil {
				errored = http.StatusBadGateway
				break
			}
			if host == "target" {
				request.Host = parts.Host
			} else if host != "remote" && host != "forwarded" {
				request.Host = host
			}
			if parts.Path != "" || len(parts.Query()) != 0 {
				if parts.Path == "" {
					parts.Path = request.URL.Path
				}
				parameters := request.URL.Query()
				for name, value := range parts.Query() {
					if len(value) == 0 || value[0] == "" {
						parameters.Del(name)
					} else {
						parameters.Set(name, value[0])
					}
				}
				query, separator := parameters.Encode(), ""
				if query != "" {
					separator = "?"
				}
				request.URL, _ = url.ParseRequestURI(parts.Path + separator + query)
				request.RequestURI = request.URL.String()
			}
			if strings.ToLower(request.Header.Get("Connection")) != "upgrade" {
				request.Header.Del("Connection")
				request.Header.Del("Upgrade")
			}
			request.ProtoMinor = 1
			headers, err := httputil.DumpRequest(request, false)
			if err != nil {
				errored = http.StatusBadRequest
				break
			}
			backend.SetWriteDeadline(time.Now().Add(Config.GetDurationBounds(Config.Path(PROGNAME, "read_timeout"), 10, 5, 60)))
			if _, err := backend.Write(headers); err != nil {
				errored = http.StatusBadGateway
				break
			}
		}

		if frame.Flags&FLAG_BODY != 0 {
			if frame.Data != nil && len(frame.Data) > 0 {
				backend.SetWriteDeadline(time.Now().Add(Config.GetDurationBounds(Config.Path(PROGNAME, "read_timeout"), 10, 5, 60)))
				_, err := backend.Write(frame.Data)
				bslab.Put(frame.Data)
				if err != nil {
					errored = http.StatusBadGateway
					break
				}
			}
			if frame.Flags&FLAG_END != 0 {
				break
			}
		}
	}

	if errored != 0 {
		stream.Status(errored)
		stream.Shutdown(false, true)
		if backend != nil {
			backend.Close()
		}
	} else if backend != nil {
		timeout := Config.GetDurationBounds(Config.Path(PROGNAME, "write_timeout"), 20, 5, 60)
		backend.SetReadDeadline(time.Now().Add(timeout))
		if response, err := http.ReadResponse(bufio.NewReader(backend), request); err == nil {
			if headers, err := httputil.DumpResponse(response, false); err == nil {
				head, upgraded, flags, data := false, false, FLAG_HEAD|FLAG_START, bslab.Get(64<<10, nil)
				if response.StatusCode == http.StatusSwitchingProtocols {
					upgraded = true
					flags |= FLAG_UPGD
				}
				for {
					backend.SetReadDeadline(time.Now().Add(timeout))
					data = data[:cap(data)-4]
					read, err := response.Body.Read(data)
					if read >= 0 {
						if !head {
							head = true
							if stream.Write(flags, headers) != nil {
								break
							}
						}
						data, flags = data[:read], FLAG_BODY
						if read == 0 || err != nil {
							flags |= FLAG_END
						}
						if stream.Write(flags, data) != nil {
							break
						}
					}
					if err != nil {
						if err == io.ErrUnexpectedEOF {
							stream.Shutdown(true, false)
						}
						break
					}
				}
				if !head {
					if !upgraded {
						flags |= FLAG_END
					}
					stream.Write(flags, headers)
				}
				response.Body.Close()

				if upgraded {
					go func() {
						for {
							frame := stream.Read(timeout, nil)
							if frame == nil {
								stream.Shutdown(false, false)
								break
							}
							if frame.Flags&FLAG_RAW != 0 {
								backend.SetWriteDeadline(time.Now().Add(timeout))
								if _, err := backend.Write(frame.Data); err != nil {
									break
								}
							}
						}
					}()
					for {
						backend.SetReadDeadline(time.Now().Add(timeout))
						data = data[:cap(data)-4]
						read, err := backend.Read(data)
						if read >= 0 {
							data, flags = data[:read], FLAG_RAW
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
				}
				bslab.Put(data)
			} else {
				stream.Status(http.StatusBadGateway)
			}
		} else {
			stream.Status(http.StatusGatewayTimeout)
		}
		backend.Close()
	}

	stream.Shutdown(false, true)
}
