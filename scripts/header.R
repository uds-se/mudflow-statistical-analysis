args = commandArgs(trailingOnly = T)
if (is.na(args[1])) {
	cat("WARNING - no config file specified, using default\n")
	conf_name="conf"
   #orca_conf="orca_conf"
} else {
	conf_name=args[1]
	conf_name=sub("*\\.R$","",conf_name,ignore.case = T)
#orca_conf=paste0("orca_",conf_name,"")
}
cat("INFO - config loaded",conf_name,"\n")
source(paste0(conf_name,".R"))
options(stringsAsFactors=F)

source("shared.R")