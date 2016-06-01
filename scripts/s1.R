rm(list = ls())
source("header.R")
library("logging")
library("stringr")
#TODO: add extended support of logging
basicConfig()

#write(get_orca_dir(),file=paste0(orca_conf))
if (Sys.info()[["sysname"]]=="Darwin"){
    orca_exec= orca_exec_mac
    dprep_exec = dprep_exec_mac
}else if(Sys.info()[["sysname"]]=="Linux"){
    orca_exec=orca_exec_linux
    dprep_exec=dprep_exec_linux
}else{
    stop("Unsupported OS")
}

#get features where sources belong to particular susi category
get_susi_features_id<-function(features,susi){
    susi_api = paste0("",susi_map[susi_map$susi==susi,]$api)
    s=strsplit(features," -> ")
    ss=do.call(cbind,s)
    sources_api=ss[1,]
    res=which(sources_api %in% susi_api)
    #cat(sources_api,"\n")
    return(res)
}

make_for_cluster<-function(data,fname,category)
{
    meta_col_id = c(grep("^name", names(data)))
    if (WITHIN){
        features_id = get_susi_features_id(names(data),category)
    }else{
        features_id = get_features_id(data)
    }
    cluster_set = data
    data_result = cluster_set[,c(meta_col_id, features_id)]
    data_file  = paste0(fname, ".data")
    write.table(data_result, file = data_file, quote = F, row.names = F, col.names = F, sep=",")
    meta_col = sapply(names(cluster_set)[meta_col_id], function(x)paste0(gsub('[\\.: ,]', '_', x),':','ignore.'))
    features_col = sapply(names(cluster_set)[features_id], function(x)paste0(gsub('[\\.: ,]', '_', x),':',orca_col_type))# column names
    fields_result = c(meta_col, features_col)
    fields_file  = paste0(fname, ".fields")
    write.table(fields_result, file = fields_file, quote = F, row.names = F, col.names = F)


}#end make_

split_data_train_test <- function(n, traindata,testdata) {
    results = list()
    if (n==1){
        results[[1]] = list(trainset=traindata,testset=rbind(traindata,testdata))
        return(results)
    }   
    parts = split(traindata, sample(rep(1:n, nrow(traindata)/n)))
    fold = 0
    for (part in parts){
        fold = fold + 1
        testset = part
        testset = rbind(testset, testdata)
        trainset = traindata[!rownames(traindata) %in% rownames(part),]
        results[[fold]] = list(trainset=trainset,testset=testset)
    }
    return(results)
}


prepare_folder<-function(dest) {
    #FIXME: 
    dir.create(dest,recursive=TRUE)
    file.copy(from=paste0(path_orca,dprep_exec),to=dest)
    file.copy(from=paste0(path_orca,orca_exec),to=dest)
    if(!file.exists(paste0(dest,"pre"))) dir.create(paste0(dest,"pre"),recursive=TRUE)
    if(!file.exists(paste0(dest,"bin"))) dir.create(paste0(dest,"bin"),recursive=TRUE)
    #dir.create(paste0(dest,"ext"),recursive=TRUE)
    #dir.create(paste0(dest,"res"),recursive=TRUE)
}

split_data_features_metadata <- function(data){
  meta_features_col = c(grep("name|malicious|train", names(data),fixed = F))
  data_is_metadata <- 1:ncol(data)
  features <- (data[, -meta_features_col])
  metadata <- data[, meta_features_col]
  return(list(features=features,metadata=metadata))
} 

########################

dfile=get_dfile()
susi_sources_name=get_susi_sources()
base_dir=paste0(get_base_dir())#FIXME:
if(!file.exists(base_dir)) dir.create(base_dir,recursive=TRUE)
print(base_dir)
orca_col_type = "continuous."

if (WITHIN){
    susi_map_file=paste0(path,'mapping_',f_type,'.txt')# used only for within mode FIXME: move to shared
    susi_map=read.csv(file=susi_map_file, head=F, sep=";")
    names(susi_map)<-c("api","susi")
}

if (loadRDS){
    susi_sources = readRDS(file=to_rds(susi_sources_name))
    data = readRDS(file=to_rds(dfile))
    vt_data=readRDS(file=to_rds(get_virustotal()))
}else{
    susi_sources = read.csv(file=susi_sources_name, head=T, sep=";")
    data = read.csv(file=dfile, head=TRUE, sep=";",check.names=F)
    vt_data=read.csv(file=get_virustotal(), head=TRUE, sep=";",check.names=F, stringsAsFactors=F)
}
cat("vt: ",nrow(vt_data),"\n")

#data$malicious<-data$malicious/malic_type

if (doJOIN){
    join_file=paste0(path,get_join_table(),".csv")
    join_data=read.csv(file=join_file, head=TRUE, sep=";",check.names=F)
    data=join_data(data,join_data)
}

#make some apps from google play malicious
if (doMAKEMALIC){
    malic_file=paste0(path,get_malic_table(),".csv")
    malic_data=read.csv(file=malic_file, head=TRUE, sep=";",check.names=F)
    data = make_malic_data(data,malic_data)
}

cat("file name:",dfile,"\n")
cat("data",dim(data),"\n")
cat("m: ",nrow(data[data$malicious==1,]),"b: ",nrow(data[data$malicious==0,]),"\n")
names(susi_sources)<-c("name","s")
sources_list=unique(susi_sources$s)
gdata=list()#for future use

if (noSUSI){
    sources_list=c('ALL')
}
if (doBFILTER){
    fdata=vt_bfilter(cldata, vt_data)
    trainset=fdata$trainset
    testset=fdata$testset
}else{
    trainset=data[data$malicious==0,]
    testset=data[data$malicious==1,]
}

data_set = split_data_train_test(n.parts, trainset, testset)

per_source=list()
for(source in sources_list){
    per_source[[source]]=susi_sources[susi_sources$s == source,]$name
}

#saveRDS(data,file=dfile_rds)
#TODO: make in parallel
#prepare data
for (fold in 1:n.folds){
    dest=get_orca_dir(paste0(base_dir,fold))
    prepare_folder(dest)
    train=data_set[[fold]]$trainset
    test=data_set[[fold]]$testset
    for(source in sources_list){
        if (noSUSI){
            strain=train
            stest=test
        }else{
            strain=train[train$name %in% per_source[[source]],]
            stest=test[test$name %in% per_source[[source]],]
        }
        destfile=paste0(dest,"pre/",source)
        cat("fold ", fold," ", source," train:", nrow(strain)," test:",nrow(stest),"\n")
        if (nrow(strain)>minSamples){
            make_for_cluster(strain, paste0(destfile,"_train"),source)
            make_for_cluster(stest, paste0(destfile,"_test"),source)
            #TODO: use rds instead csv
            ref_train_file=paste0(destfile,"_train.ref")
            write.table(strain[,c("name","malicious"),drop=F], file = ref_train_file, quote = F, row.names = F, col.names = T,sep=";")
            ref_test_file=paste0(destfile,"_test.ref")
            write.table(stest[,c("name","malicious"),drop=F], file = ref_test_file, quote = F, row.names = F, col.names = T,sep=";")
        }
    }
}
save_config(get_base_dir())
