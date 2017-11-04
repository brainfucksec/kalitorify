PROGRAM_NAME=kalitorify
VERSION=1.10.1

DOCS_DIR=/usr/share/doc
PROGRAM_DIR=/usr/local/bin
CONFIG_DIR=/opt

install:
	install -Dm644 LICENSE $(DOCS_DIR)/$(PROGRAM_NAME)/LICENSE
	install -Dm644 README.md $(DOCS_DIR)/$(PROGRAM_NAME)/README.md
	install -Dm755 kalitorify.sh $(PROGRAM_DIR)/$(PROGRAM_NAME)
	mkdir -p $(CONFIG_DIR)/$(PROGRAM_NAME)/backups
	cp -R cfg $(CONFIG_DIR)/$(PROGRAM_NAME)

uninstall:
	rm -Rf $(DOCS_DIR)/$(PROGRAM_NAME)
	rm -Rf $(PROGRAM_DIR)/$(PROGRAM_NAME)
	rm -Rf $(CONFIG_DIR)/$(PROGRAM_NAME)
