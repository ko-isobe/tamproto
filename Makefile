
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
