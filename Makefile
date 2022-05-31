PROGRAM_NAME=kalitorify
VERSION=1.29.0

DATA_DIR=/usr/share
BACKUP_DIR=/var/lib
DOC_DIR=$(DATA_DIR)/doc
PROGRAM_DIR=/usr/bin


install:
	install -Dm644 README.md $(DOC_DIR)/$(PROGRAM_NAME)/README.md
	install -Dm755 kalitorify.sh $(PROGRAM_DIR)/$(PROGRAM_NAME)
	mkdir -p $(DATA_DIR)/$(PROGRAM_NAME)/data
	mkdir -p $(BACKUP_DIR)/$(PROGRAM_NAME)/backups
	install -Dm644 data/* $(DATA_DIR)/$(PROGRAM_NAME)/data

uninstall:
	rm -Rf $(PROGRAM_DIR)/$(PROGRAM_NAME)
	rm -Rf $(DATA_DIR)/$(PROGRAM_NAME)
	rm -Rf $(DOC_DIR)/$(PROGRAM_NAME)
	rm -Rf $(BACKUP_DIR)/$(PROGRAM_NAME)
