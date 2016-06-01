.PHONY: clr orca-outliers orca-malic orca-clean orca-clean-all orca-clean-m orca-clean-all-m

.SECONDARY: 
.SUFFIXES:
ROOT = ${CURDIR}
TCONF:=$(subst .R,,$(CONF))
TCONF:=$(subst .r,,$(TCONF))
#CONF = $(ROOT)/../scripts/conf.R
ORCA_CONF := $(ROOT)/../scripts/orca_$(TCONF)
R_CONF := $(ROOT)/../scripts/$(TCONF).R
#orca.conf

DATA?=$(shell cat $(ORCA_CONF))

ORCA_DIR = $(ROOT)/scripts

WEIGHTS = $(DATA)/bin
USE_WEIGHTS = -won
#-won
#weights file is rewritten to this destination on dprep stage from ORCA_EXEC
SCALE=-snone
#-snone -s01 -sstd
FRAC=1
KNN=$(shell grep 'orca_knn=' $(R_CONF) | sed -E 's/^orca_knn=(.*)/\1/g')
ISAVG=$(shell grep 'orca_AVERAGE=' $(R_CONF) | sed -E 's/^orca_AVERAGE=(.*)/\1/g')
ifeq ($(ISAVG),T)
	TYPE=-avg
else
	TYPE=-kth
endif

RSCRIPTS=$(ROOT)/scripts

DIST_TYPE=$(shell grep 'orca_disttype=' $(R_CONF) | sed -E 's/^orca_disttype="(.*)"/\1/g')
#-euclid -jaccard -Fjaccard

ORCA_EXEC=orca-linux
DPREP_EXEC=dprep-linux

UNAME_S=$(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	ORCA_EXEC=orca-mac
	DPREP_EXEC=dprep-mac
endif

l=$(shell ls $(DATA)/pre/*train.data)
NN=$(notdir $(l))
NUMBERS=$(shell echo $(NN)| sed -E "s/chabada-//g;s/_train.data//g")	
JOBS = $(addprefix $(DATA)/outliers-, $(NUMBERS))
JOBS := $(addsuffix .txt, $(JOBS))


test:
	echo $(CONF)
	echo $(ORCA_CONF)
	echo $(JOBS)

orca-outliers: clr $(ORCA_CONF) $(JOBS)

clr:
	rm -f $(DATA)/scores-all.csv

$(DATA)/bin/group-%.bin: 
	test -d $(DATA)/bin || mkdir -p $(DATA)/bin
	cd $(ORCA_DIR); ./$(DPREP_EXEC) \
		$(DATA)/pre/$*_train.data \
		$(DATA)/pre/$*_train.fields \
		$(subst .bin,,$@)_train.bin \
		$(SCALE) > dprep_train.log
	cd $(ORCA_DIR); ./$(DPREP_EXEC) \
		$(DATA)/pre/$*_test.data \
		$(DATA)/pre/$*_test.fields \
		$(subst .bin,,$@)_test.bin \
		$(SCALE) >dprep_test.log
	mv $(ORCA_DIR)/weights $(WEIGHTS)/group-$*.weights
	cd $(ROOT)/../scripts/ && Rscript $(ROOT)/../scripts/make_weights.R $(CONF) $(WEIGHTS)/group-$*.weights

$(DATA)/wide/outliers-group-%-wide.txt: $(DATA)/bin/group-%.bin
	test -d $(DATA)/wide || mkdir -p $(DATA)/wide
	cd $(ORCA_DIR); ./$(ORCA_EXEC) \
		$(DATA)/bin/group-$*_test.bin \
		$(DATA)/bin/group-$*_train.bin \
		$(WEIGHTS)/group-$*.weights \
		$(TYPE) \
		-k $(KNN) \
		-n $(shell echo $(shell wc -l < $(DATA)/pre/$*_test.data)\*$(FRAC) | bc) \
		$(DIST_TYPE) \
		$(USE_WEIGHTS) \
		> $@
#-rn
#use -rn to output neighbors of outliers
$(DATA)/outliers-%.txt: $(DATA)/wide/outliers-group-%-wide.txt
	python $(RSCRIPTS)/extract_outliers.py \
		$^ \
		$(DATA)/pre/$*_test.data \
		$@ \
		$(DATA)/scores-all.csv

clean:
	rm -fr $(DATA)/wide
	rm -f $(DATA)/scores-all.csv
	rm -f $(JOBS)

clean-all: clean
	rm -fr $(DATA)/pre
	rm -fr $(DATA)/bin
	rm -fr $(DATA)/wide
