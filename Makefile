
NPM_INSTALLS := node_modules

$(NPM_INSTALLS):
	npm install

.PHONY: run
run: $(NPM_INSTALLS) $(TA_BIN)
	cp -f $(TA_BIN) TAs || true
	node app.js

.PHONY: clean
clean:
	rm -fr $(NPM_INSTALLS)

.PHONY: push-docker
push-docker:
	docker build -t trasioteam/tamproto:teep-device-interop .
	docker push trasioteam/tamproto:teep-device-interop
