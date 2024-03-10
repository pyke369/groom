package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/pyke369/golang-support/bslab"
	"github.com/pyke369/golang-support/uws"

	_ "encoding/hex"
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
	sync.RWMutex
	shut  bool
	queue chan *FRAME
}

func (s *STREAM) Queue(flags int, data []byte) (err error) {
	s.RLock()
	if !s.shut {
		s.queue <- &FRAME{flags, data}
	} else {
		err = fmt.Errorf("shut")
	}
	s.RUnlock()
	return
}

func (s *STREAM) Read(timeout time.Duration, ctx context.Context) (frame *FRAME) {
	s.RLock()
	if s.shut {
		s.RUnlock()
		return nil
	}
	s.RUnlock()
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
	// fmt.Printf("stream-write (%d)\n%s", len(data), hex.Dump(data))
	s.RLock()
	if s.shut {
		s.RUnlock()
		err = fmt.Errorf("shut")
	} else {
		s.RUnlock()
		s.domain.RLock()
		if s.domain.connected {
			s.domain.RUnlock()
			err = s.domain.agent.Write(uws.WEBSOCKET_OPCODE_BLOB, append(data, []byte{byte(flags), byte(s.id >> 16), byte(s.id >> 8), byte(s.id)}...))
		} else {
			s.domain.RUnlock()
			err = fmt.Errorf("disconnected")
		}
	}
	return
}

func (s *STREAM) Status(code int) {
	headers := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nDate: %s\r\n\r\n",
		code, http.StatusText(code),
		time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"),
	)
	s.Write(FLAG_HEAD|FLAG_START|FLAG_END, []byte(headers))
}

func (s *STREAM) Shutdown(abort bool, remove bool) {
	s.RLock()
	if !s.shut {
		s.RUnlock()
		if abort {
			s.Write(FLAG_ABRT, nil)
		}
		s.Lock()
		s.shut = true
		s.Unlock()
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
		s.Lock()
		close(s.queue)
		s.Unlock()
		if remove {
			s.domain.Lock()
			delete(s.domain.streams, s.id)
			s.domain.Unlock()
		}
		Logger.Debug(map[string]interface{}{"mode": Mode, "event": "stream", "domain": s.domain.Name, "stream": s.id, "action": "shutdown"})
	} else {
		s.RUnlock()
	}
}
