#!/bin/sh

PROGNAME=groom

# build targets
$(PROGNAME): *.go
	@go get -d && env GOPATH=/tmp/go CGO_ENABLED=0 go build -trimpath -o $(PROGNAME)
	@-strip $(PROGNAME) 2>/dev/null || true
	@-#upx -q9 $(PROGNAME) >/dev/null 2>&1 || true
clean:
distclean:
	@rm -f $(PROGNAME) $(PROGNAME)-* $(PROGNAME).exe *.zip *.upx
deb:
	@debuild -e GOROOT -e GOPATH -e PATH -i -us -uc -b
debclean:
	@debuild -- clean
	@rm -f ../$(PROGNAME)_*

$(PROGNAME)-linux-x86_64: *.go
	@echo '- linux amd64'
	@env GOPATH=/tmp/go CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o $(PROGNAME)-linux-x86_64
	@-strip $(PROGNAME)-linux-x86_64 2>/dev/null || true
	@-upx -q9 $(PROGNAME)-linux-x86_64 >/dev/null 2>&1 || true
$(PROGNAME)-linux-aarch64: *.go
	@echo '- linux arm64'
	@env GOPATH=/tmp/go CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o $(PROGNAME)-linux-aarch64
	@-strip $(PROGNAME)-linux-aarch64 2>/dev/null || true
	@-upx -q9 $(PROGNAME)-linux-aarch64 >/dev/null 2>&1 || true
$(PROGNAME)-darwin-amd64: *.go
	@echo '- macos amd64'
	@env GOPATH=/tmp/go CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -o $(PROGNAME)-darwin-amd64
	@-upx -q9 $(PROGNAME)-darwin-amd64 >/dev/null 2>&1 || true
$(PROGNAME)-darwin-arm64: *.go
	@echo '- macos arm64'
	@env GOPATH=/tmp/go CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -o $(PROGNAME)-darwin-arm64
$(PROGNAME).exe: *.go
	@echo '- windows amd64'
	@env GOPATH=/tmp/go CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o $(PROGNAME).exe
	@-upx -q9 $(PROGNAME).exe >/dev/null 2>&1 || true
portable: $(PROGNAME)-linux-x86_64 $(PROGNAME)-linux-aarch64 $(PROGNAME)-darwin-amd64 $(PROGNAME)-darwin-arm64 $(PROGNAME).exe
	@rm -rf build && mkdir build && cd build && \
	mkdir -p $(PROGNAME)/conf/agent $(PROGNAME)/conf/server && \
	cp ../$(PROGNAME)-linux-x86_64 ../$(PROGNAME)-linux-aarch64 ../$(PROGNAME)-darwin-amd64 ../$(PROGNAME)-darwin-arm64 ../$(PROGNAME).exe $(PROGNAME) && \
	cp ../$(PROGNAME).sh $(PROGNAME)/$(PROGNAME) && \
	cp ../conf/agent.conf ../conf/server.conf $(PROGNAME)/conf && \
	cp ../conf/agent/www.domain.com $(PROGNAME)/conf/agent && \
	cp ../conf/server/www.domain.com $(PROGNAME)/conf/server && \
	zip -9r ../$(PROGNAME).zip $(PROGNAME) && cd .. && rm -rf build

# run targets
server: $(PROGNAME)
	@./$(PROGNAME) conf/server.conf
agent: $(PROGNAME)
	@./$(PROGNAME) conf/agent.conf
