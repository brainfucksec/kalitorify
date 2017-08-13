PROGRAM_NAME=kalitorify
VERSION=1.9.0

DOCS_DIR=/usr/share/doc
PROGRAM_DIR=/usr/local/bin
BACKUP_DIR=/opt

install:
	install -Dm644 LICENSE $(DOCS_DIR)/$(PROGRAM_NAME)/LICENSE
	install -Dm644 README.md $(DOCS_DIR)/$(PROGRAM_NAME)/README.md
	install -Dm755 kalitorify.sh $(PROGRAM_DIR)/$(PROGRAM_NAME)
	mkdir -p $(BACKUP_DIR)/$(PROGRAM_NAME)/backups

uninstall:
	rm -Rf $(DOCS_DIR)/$(PROGRAM_NAME)
	rm -Rf $(PROGRAM_DIR)/$(PROGRAM_NAME)
	rm -Rf $(BACKUP_DIR)/$(PROGRAM_NAME)
