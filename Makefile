
NPM_INSTALLS := node_modules

$(NPM_INSTALLS):
	npm install

.PHONY: run
run: $(NPM_INSTALLS)
	node app.js

.PHONY: clean
clean:
	rm -fr $(NPM_INSTALLS)
