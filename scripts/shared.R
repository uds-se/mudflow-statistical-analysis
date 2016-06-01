#deprecated
# if (mutated){
#   malic_type=2
#   prefix="Mutation"
#   f_type="class_method_URI"
#   mix=F
#   mutated_type=paste0(m_type,"Sources")
# }
get_features_id<-function(data){
  mf=c(grep("^name|^cl|^malic", names(data)))
  f=setdiff(1:length(names(data)),mf)
  return(f)
}

join_data<-function(d1,d2){
  mf=c(grep("^cl|^malic", names(d2)))
  if (length(mf)==0){
    jdata=merge(d1,d2, by="name")
  }else{
    jdata=merge(d1,d2[,-mf], by="name")
  }
  return(jdata)
}

erf_ <- function(x){
	2 * pnorm(x * sqrt(2)) - 1
}

gaussian_cutoff <- function(data, base_data){
  o_mean = mean(base_data$score)
  o_sd = sd(base_data$score) 
  prob = sapply(data$score,function(x)max(0,erf_((x-o_mean)/(o_sd*sqrt(2)))))
  return(prob)
}

make_malic_data<-function(data,malic) {
  data[data$name %in% malic$name,]$malicious<-1
  return(data)
}

#get malic with low vt detection rate
vt_mfilter<-function(data,vt) {  
  temp=data[data$name %in% vt[vt$detection<=vt_malic_threshold,]$name,]
  test=temp[temp$malicious==1,]
  return(list(test=test))
}
#get benign with low vt detection rate; all others as test
vt_bfilter<-function(data,vt) {  
  temp=data[data$name %in% vt[vt$detection<=vt_benign_threshold,]$name,]
  train=temp[temp$malicious==0,]
  test=data[!data$name %in% train$name]
  return(list(train=train,test=test))
}

to_rds<-function(name) {
  return(gsub("\\.(csv|txt)$",".rds",name))
}

get_base_dir<-function() {
  name=sub("[.][^.]*$","",basename(main_data))
  # if (doJOIN){
  #   join_table_name=sub("[.][^.]*$","",basename(join_table))
  #   name=paste0(name,"_",join_table_name,"_joined")
  # }
  # if(WITHIN){
  #   name=paste0(name,"_within")
  # }
  # if (mutated){
  #   name=paste0(name,"_",mutated_type)
  # }
  if (gid!="") gid=paste0("_",gid)
  return(paste0(dest_dir,name,gid,"/"))
}

get_orca_dir<-function(parentdir) {
  #if (id_orca!="") id_orca=paste0("_",id_orca)
  orca_dir=paste0(parentdir,"/orca/")
  return(orca_dir)
}

get_maliciogram_dir<-function(parentdir){
  if (id_orca!="") id=paste0("/",id_orca)
  maliciogram_dir=paste0(parentdir,"/maliciogram",id,"/")
  if (!file.exists(maliciogram_dir))
    dir.create(maliciogram_dir,recursive = T)
  return(maliciogram_dir)
}

get_classification_dir<-function(parentdir){
  id=get_ids()
  if (id!="") id=paste0("/",id)
  classification_dir=paste0(parentdir,"/classification",id,"/")
  if (!file.exists(classification_dir))
    dir.create(classification_dir,recursive = T)

  return(classification_dir)
}

get_ids<-function() {
  id=""
  if (id_cl!="" || id_orca!="")
    id=paste0("",id_orca,id_cl)
  if (id_cl!="" && id_orca!="")
    id=paste0("",id_orca,"_",id_cl)
  return(id)
}

save_config<-function(dest) {
  id=get_ids()
  if (id!="") id=paste0("_",id)
  file.copy(from=normalizePath(paste0(conf_name,".R")),to=paste0(dest,basename(conf_name),id,".R"))
}
get_classification_file<-function() {
  id=get_ids()
  if (id!="") id=paste0("_",id)
  result_file=paste0(get_base_dir(),"classification",id,".txt")
  return(result_file)
}
get_result_file<-function() {
  result_file=paste0(root_dir,"report.txt")
  return(result_file)
}
###

get_normalized_file<-function(file) {
  if (file==basename(file)){
    return(paste0(data_dir,file))
  }else{
    return(file)
  }
}

get_malic_table<-function() {
  return(get_normalized_file(malic_table))
}

get_join_table<-function() {
  return(get_normalized_file(join_table))
}

get_virustotal<-function() {
  return(get_normalized_file(virustotal_all))
}

get_susi_sources<-function() {
  return(get_normalized_file(susi_list))
}

get_susi_mapping<-function() {
  return(get_normalized_file(susi_mapping))
}

get_dfile<-function() {
  return(get_normalized_file(main_data))
}

get_repack_file<-function() {
  return(get_normalized_file(repack_file))
}

###
#FIXME
get_file_name<-function() {
  name=main
  if (doJOIN){
    name=paste0(name,"_",join_table,"_joined")
  }
  if(WITHIN){
    name=paste0(name,"_within")
  }
  if (mutated){
    name=paste0(name,"_",mutated_type)
  }
  return(name)
}

#deprecated
get_score_file<-function() {
  name=get_file_name()
  score_file=paste0(prefix,"/orca_scores_",name)

  if(toPROBABILITY){
    score_file=paste0(score_file,"_prob")
  }
  score_file=paste0(path,score_file,"_",id,".csv")
  return(score_file)
}

#deprecated
get_full_name<-function() {
  name=get_file_name()
  if(toPROBABILITY){
    name=paste0(name,"_prob")
  }
  name=paste0(name,"_",gid)
  return(name)
}

get_fp_dir<-function() {
  dir=paste0(path,"fp_",get_full_name())
  if (!file.exists(dir)){
    dir.create(dir,recursive=TRUE)
  }
  return(dir)
}
