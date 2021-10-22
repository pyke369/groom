#!/bin/sh

# build targets
groom: *.go
	@env GOPATH=/tmp/go CGO_ENABLED=0 go get && go build -trimpath -o groom
	@-strip groom 2>/dev/null || true
	@-upx -9 groom 2>/dev/null || true
clean:
distclean:
	@rm -f groom groom-* groom.exe *.zip *.upx
deb:
	@debuild -e GOROOT -e GOPATH -e PATH -i -us -uc -b
debclean:
	@debuild -- clean
	@rm -f ../groom_*

groom-linux: *.go
	@env GOPATH=/tmp/go CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o groom-linux
	@-strip groom-linux 2>/dev/null || true
	@-upx -9 groom-linux 2>/dev/null || true
groom-darwin: *.go
	@env GOPATH=/tmp/go CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -o groom-darwin
groom.exe: *.go
	@env GOPATH=/tmp/go CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -o groom.exe
	@-upx -9 groom.exe 2>/dev/null || true
portable: groom-linux groom-darwin groom.exe
	@rm -rf build && mkdir build && cd build && \
	mkdir -p groom/conf/agent groom/conf/server && \
	cp ../groom-linux ../groom-darwin ../groom.exe groom && \
	cp ../groom.sh groom/groom && \
	cp ../conf/agent.conf ../conf/server.conf groom/conf && \
	cp ../conf/agent/www.domain.com groom/conf/agent && \
	cp ../conf/server/www.domain.com groom/conf/server && \
	zip -9r ../groom.zip groom && cd .. && rm -rf build

# run targets
server: groom
	@./groom conf/server.conf
agent: groom
	@./groom conf/agent.conf
