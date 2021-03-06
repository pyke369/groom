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

func (this *STREAM) Queue(flags int, data []byte) (err error) {
	this.lock.RLock()
	if !this.shut {
		this.queue <- &FRAME{flags, data}
	} else {
		err = fmt.Errorf("shut")
	}
	this.lock.RUnlock()
	return
}

func (this *STREAM) Read(timeout time.Duration, ctx context.Context) (frame *FRAME) {
	this.lock.RLock()
	if this.shut {
		this.lock.RUnlock()
		return nil
	}
	this.lock.RUnlock()
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case frame = <-this.queue:
	case <-time.After(timeout):
	case <-ctx.Done():
	}
	return
}

func (this *STREAM) Write(flags int, data []byte) (err error) {
	this.lock.RLock()
	if this.shut {
		this.lock.RUnlock()
		err = fmt.Errorf("shut")
	} else {
		this.lock.RUnlock()
		this.domain.lock.RLock()
		if this.domain.connected {
			this.domain.lock.RUnlock()
			err = this.domain.agent.Write(uws.WEBSOCKET_OPCODE_BLOB, append(data, []byte{byte(flags), byte(this.id >> 16), byte(this.id >> 8), byte(this.id)}...))
		} else {
			this.domain.lock.RUnlock()
			err = fmt.Errorf("disconnected")
		}
	}
	return
}

func (this *STREAM) Status(code int) {
	headers := fmt.Sprintf("HTTP/1.1 %d %s\r\nDate: %s\r\n\r\n", code, http.StatusText(code), time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))
	this.Write(FLAG_HEAD|FLAG_START|FLAG_END, []byte(headers))
}

func (this *STREAM) Shutdown(abort bool, remove bool) {
	this.lock.RLock()
	if !this.shut {
		this.lock.RUnlock()
		if abort {
			this.Write(FLAG_ABRT, nil)
		}
		this.lock.Lock()
		this.shut = true
		this.lock.Unlock()
	flushed:
		for {
			select {
			case frame := <-this.queue:
				if frame != nil {
					bslab.Put(frame.Data)
				}
			default:
				break flushed
			}
		}
		this.lock.Lock()
		close(this.queue)
		this.lock.Unlock()
		if remove {
			this.domain.lock.Lock()
			delete(this.domain.streams, this.id)
			this.domain.lock.Unlock()
		}
		logger.Debug(map[string]interface{}{"mode": mode, "event": "stream", "domain": this.domain.Name, "stream": this.id, "action": "shutdown"})
	} else {
		this.lock.RUnlock()
	}
}
