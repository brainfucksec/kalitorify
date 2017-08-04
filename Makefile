PROGRAM_NAME=kalitorify
VERSION=1.8.2

LICENSE_DIR=/usr/share/licenses
DOCS_DIR=/usr/share/doc
PROGRAM_DIR=/usr/local/bin

install:
	install -Dm644 LICENSE $(LICENSE_DIR)/$(PROGRAM_NAME)/LICENSE
	install -Dm644 README.md $(DOCS_DIR)/$(PROGRAM_NAME)/README.md
	install -Dm755 kalitorify.sh $(PROGRAM_DIR)/$(PROGRAM_NAME)

uninstall:
	rm -Rf $(LICENSE_DIR)/$(PROGRAM_NAME)
	rm -Rf $(DOCS_DIR)/$(PROGRAM_NAME)
	rm -Rf $(PROGRAM_DIR)/$(PROGRAM_NAME)
