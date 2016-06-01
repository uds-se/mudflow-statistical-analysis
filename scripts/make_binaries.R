rm(list = ls())
options(stringsAsFactors=F)
args = commandArgs(trailingOnly = T)
if (is.na(args[1])) {
	cat("WARNING - no config file specified, using default\n")
	source("conf.R")
} else {
	conf_name=args[1]
	if (any(grep("*\\.R$",conf_name,ignore.case=T))){
		conf_name=sub("(*)\\.R$","\\1",conf_name)
	}
	source(paste0(conf_name,".R"))
}
source("shared.R")
data_file=get_dfile()
dfile_rds=to_rds(data_file)
susi_sources_name=get_susi_sources()
susi_sources_rds=to_rds(susi_sources_name)
data = read.csv(file=data_file, head=TRUE, sep=";",check.names=F)
saveRDS(data,file=dfile_rds)
susi_sources = read.csv(file=susi_sources_name, head=TRUE, sep=";")
saveRDS(susi_sources,file=susi_sources_rds)
