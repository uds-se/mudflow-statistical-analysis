rm(list = ls())

args = commandArgs(trailingOnly = T)
if (is.na(args[1])) {
	cat("WARNING - no config file specified, using default\n")
	source("conf.R")
	orca_conf="orca_conf"
} else {
	conf_name=args[1]
	if (any(grep("*\\.R$",conf_name,ignore.case=T))){
		conf_name=sub("(*)\\.R$","\\1",conf_name)
	}
	source(paste0(conf_name,".R"))
	orca_conf=paste0("orca_",conf_name,"")
}
if (is.na(args[2])) {
	stop("no weight file")
}else{
	fname=args[2]
}
source("shared.R")

#dir=paste(get_orca_dir(),"bin",sep="/")
#files=list.files(path = dir, pattern = "*.weights", full.names = TRUE)

#for (fname in files){
	data=read.table(file=fname,sep=" ")
	rows=grep(paste(minor_features,collapse="|"),data[,1])
	data[rows,2]<-minor_features_weight
	write.table(data,file=fname,sep=" ",col.names=F,row.names=F,quote=F)
#}