package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/pyke369/golang-support/bslab"
	"github.com/pyke369/golang-support/uws"
)

const (
	FLAG_HEAD  = 0x01
	FLAG_BODY  = 0x02
	FLAG_RAW   = 0x04
	FLAG_ABRT  = 0x08
	FLAG_UPGD  = 0x20
	FLAG_START = 0x40
	FLAG_END   = 0x80
)

type FRAME struct {
	Flags int
	Data  []byte
}
type STREAM struct {
	domain *DOMAIN
	id     int
	lock   sync.RWMutex
	shut   bool
	queue  chan *FRAME
}

func (s *STREAM) Queue(flags int, data []byte) (err error) {
	s.lock.RLock()
	if !s.shut {
		s.queue <- &FRAME{flags, data}
	} else {
		err = fmt.Errorf("shut")
	}
	s.lock.RUnlock()
	return
}

func (s *STREAM) Read(timeout time.Duration, ctx context.Context) (frame *FRAME) {
	s.lock.RLock()
	if s.shut {
		s.lock.RUnlock()
		return nil
	}
	s.lock.RUnlock()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case frame = <-s.queue:
	case <-time.After(timeout):
	case <-ctx.Done():
	}
	return
}

func (s *STREAM) Write(flags int, data []byte) (err error) {
	s.lock.RLock()
	if s.shut {
		s.lock.RUnlock()
		err = fmt.Errorf("shut")
	} else {
		s.lock.RUnlock()
		s.domain.lock.RLock()
		if s.domain.connected {
			s.domain.lock.RUnlock()
			err = s.domain.agent.Write(uws.WEBSOCKET_OPCODE_BLOB, append(data, []byte{byte(flags), byte(s.id >> 16), byte(s.id >> 8), byte(s.id)}...))
		} else {
			s.domain.lock.RUnlock()
			err = fmt.Errorf("disconnected")
		}
	}
	return
}

func (s *STREAM) Status(code int) {
	headers := fmt.Sprintf("HTTP/1.1 %d %s\r\nDate: %s\r\n\r\n", code, http.StatusText(code), time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	s.Write(FLAG_HEAD|FLAG_START|FLAG_END, []byte(headers))
}

func (s *STREAM) Shutdown(abort bool, remove bool) {
	s.lock.RLock()
	if !s.shut {
		s.lock.RUnlock()
		if abort {
			s.Write(FLAG_ABRT, nil)
		}
		s.lock.Lock()
		s.shut = true
		s.lock.Unlock()
	flushed:
		for {
			select {
			case frame := <-s.queue:
				if frame != nil {
					bslab.Put(frame.Data)
				}
			default:
				break flushed
			}
		}
		s.lock.Lock()
		close(s.queue)
		s.lock.Unlock()
		if remove {
			s.domain.lock.Lock()
			delete(s.domain.streams, s.id)
			s.domain.lock.Unlock()
		}
		logger.Debug(map[string]interface{}{"mode": mode, "event": "stream", "domain": s.domain.Name, "stream": s.id, "action": "shutdown"})
	} else {
		s.lock.RUnlock()
	}
}
