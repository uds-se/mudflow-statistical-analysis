rm(list = ls())

args = commandArgs(trailingOnly = T)
if (is.na(args[1])) {
 cat("WARNING - no config file specified, using default\n")
 source("conf.R")
} else {
  conf_name=args[1]
  if (!any(grep("*\\.R$",conf_name,ignore.case=T))){
    conf_name=paste0(conf_name,".R")
  }
  source(conf_name)
}

source("shared.R")
library("e1071")

n.runs=10
scale=F

score_file=get_score_file()
output=get_full_name()
results_file=get_results_file()

split_data_train_test <- function(data, n, traindata,testdata) {

  # if (doBFILTER){
  #   malicious = testdata
  #   non_malicious = traindata
  # }else{
  #   malicious = subset(data, data$malicious == 1)
  #   non_malicious = subset(data, data$malicious == 0)
  # }
  results = list()
  if (n==1){
    results[[1]] = list(trainset=traindata,testset=data)
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

split_data_features_metadata <- function(data, outF="null"){
  #outF is for future experiments, not used
  meta_features_col = c(grep(paste0("^name|^cl|^malic|^",outF), names(data)))
  data_is_metadata <- 1:ncol(data)
  features <- (data[, -meta_features_col])
  metadata <- data[, meta_features_col]
  return(list(features=features,metadata=metadata))
}
############
if (loadRDS){
  data = readRDS(file=to_rds(score_file))
  vt_data=readRDS(file=to_rds(get_virustotal()))
}else{
  data = read.csv(file=score_file, head=TRUE, sep=";")
  vt_data=read.csv(file=get_virustotal(), head=TRUE, sep=";",check.names=F, stringsAsFactors=F)
}
print("data loaded")

sink(paste0(path,output,".txt"))
print(score_file)

rownames(data)<-data$name
data$malicious<-data$malicious/malic_type

if (doBFILTER){
  fdata=vt_filter(data, vt_data)
  #data=rbind(fdata$train,fdata$test)
  trainset=fdata$train
  testset=fdata$test
  cat("train: ",nrow(fdata$train)," test: ",nrow(fdata$test),"\n")
}

mdata=data
malic = mdata[mdata$malicious == 1,]
benign = mdata[mdata$malicious == 0,]
cat("m:",nrow(malic),"b:",nrow(benign),"\n")
cat("size: ",dim(mdata),"\n")
run_res=list()
for (iter in 1:n.runs) {
  if (doBFILTER){
    data_set = split_data_train_test(mdata, n.folds, trainset, testset)
  }else{
    data_set = split_data_train_test(mdata, n.folds, benign, malic)
  }
  results_fold = list()
  cat("run: ",iter,"\n")
  for(fold in 1:n.folds){
    sfdata = data_set[[fold]]
    sfmdata_train = split_data_features_metadata(sfdata$trainset)
    sfmdata_test = split_data_features_metadata(sfdata$testset)

    test.data=sfmdata_test$features
    training.data = sfmdata_train$features

    test.metadata=sfmdata_test$metadata
    require("kernlab")
    sigdata=as.matrix(training.data)
    gamma=sigest(sigdata,scaled=scale)
    gamma=mean(gamma)
    if (is.na(gamma)){
      gamma=0.1
      cat("\n.\n")
    }
    model = svm(training.data, type="one-classification",nu=nu, scale=scale, gamma=gamma)
    predict_data = predict(model, test.data, decision.values = TRUE)
    decision_values = attributes(predict_data)$decision.values

    merged_results = cbind(test.metadata,predict_data,decision_values)
    colnames(merged_results)[ncol(merged_results)-1] <- "predicted"
    colnames(merged_results)[ncol(merged_results)] <- "decision_values"
    #add detection rate from virus total

    merged_results = merge(merged_results,vt_data[,c("name","detection")], by="name",all.x=T)
  # mispredicted means that the app is Malicious, but the classifier returned TRUE (i.e. it belongs to the distribution of the good apps) 
  # or the app is not Malicious, but the clasifier returnes FALSE (i.e. it does not belong to the distibution)
    mispredicted = merged_results[(merged_results$malicious == 0 & merged_results$predicted == FALSE) | (merged_results$malicious == 1 & merged_results$predicted == TRUE),]
    false_positives = merged_results[(merged_results$malicious == 0 & merged_results$predicted == FALSE),]
    false_negatives = merged_results[(merged_results$malicious == 1 & merged_results$predicted == TRUE),]
    true_positives = merged_results[(merged_results$malicious == 1 & merged_results$predicted == FALSE),]
    true_negatives = merged_results[(merged_results$malicious == 0 & merged_results$predicted == TRUE),]

    results_fold[[fold]] = list(model=model,
     predict_data=predict_data, 
     mispredicted=mispredicted, 
     false_positives=false_positives,
     false_negatives=false_negatives,
     true_positives=true_positives,
     true_negatives=true_negatives,
     neg_count=length(which(test.metadata$malicious==0)),
     all_test_values=merged_results
     )

    cat("FP ", nrow(results_fold[[fold]]$false_positives), " ")
    cat("FN ", nrow(results_fold[[fold]]$false_negatives), " ")
    cat("TP ", nrow(results_fold[[fold]]$true_positives), " ")
    cat("TN ", nrow(results_fold[[fold]]$true_negatives), " \n")
  }

  pos=nrow(malic)
  neg=nrow(benign)/n.folds
  tpos=mean(sapply(results_fold, function(x) nrow(x$true_positives)))
  tneg=mean(sapply(results_fold, function(x) nrow(x$true_negatives)))
  fpos=mean(sapply(results_fold, function(x) nrow(x$false_positives)))
  fneg=mean(sapply(results_fold, function(x) nrow(x$false_negatives)))

  if (printFP){
    fp_dir=get_fp_dir()
    for(fold in 1:n.folds){
      rfold=results_fold[[fold]]
      fplist=rfold$false_positives
      write.table(fplist$name,file=paste0(fp_dir,"/f_",fold,"_false_positives.txt"),quote=F,row.names=F,col.names=F)
    }

    fp_all=unlist(sapply(results_fold, function(x) x$false_positives$name))
    write.table(fp_all,file=paste0(fp_dir,"/all_false_positives.txt"),quote=F,row.names=F,col.names=F)
  }
  g=sqrt(tpos/pos*tneg/neg)
  acc=(tpos+tneg)/(pos+neg)
  tpr=tpos/pos
  tnr=tneg/neg

  cat(output,"knn",orca_knn,"nu",nu,"g",g,"acc",acc,"tpr",tpr,"tnr",tnr,"\n")
  
  run_res[[iter]]=list(
    tpos=tpos,
    tneg=tneg,
    fpos=fpos,
    fneg=fneg,
    g=sqrt(tpos/pos*tneg/neg),
    acc=(tpos+tneg)/(pos+neg),
    tpr=tpos/pos,
    tnr=tneg/neg
    )
}
sink()
pos=nrow(malic)
neg=nrow(benign)/n.folds

tposvec=sapply(run_res,function(x)x$tpos)
tnegvec=sapply(run_res,function(x)x$tneg)
fposvec=sapply(run_res,function(x)x$fpos)
fnegvec=sapply(run_res,function(x)x$fneg)

gvec=sapply(run_res,function(x)x$g)
qrange = c(0.2,0.8)

# qtpos = quantile(tposvec, qrange)
# qtneg = quantile(tnegvec, qrange)
# qfpos = quantile(fposvec, qrange)
# qfneg = quantile(fnegvec, qrange)
qg = quantile(gvec, qrange)
qidx=findInterval(gvec,qg)

# tpos=mean(tposvec[findInterval(tposvec,qtpos)==1])
# tneg=mean(tnegvec[findInterval(tnegvec,qtneg)==1])
# fpos=mean(fposvec[findInterval(fposvec,qfpos)==1])
# fneg=mean(fnegvec[findInterval(fnegvec,qfneg)==1])

tpos=mean(sapply(run_res,function(x)x$tpos))
tneg=mean(sapply(run_res,function(x)x$tneg))
fpos=mean(sapply(run_res,function(x)x$fpos))
fneg=mean(sapply(run_res,function(x)x$fneg))

#g=median(sapply(run_res,function(x)x$g))
#acc=median(sapply(run_res,function(x)x$acc))
#tpr=median(sapply(run_res,function(x)x$tpr))
#tnr=median(sapply(run_res,function(x)x$tnr))
# tpos=mean(tposvec[qidx])
# tneg=mean(tnegvec[qidx])
# fpos=mean(fposvec[qidx])
# fneg=mean(fnegvec[qidx])

# g=mean(gvec[qidx])

g=sqrt(tpos/pos*tneg/neg)
acc=(tpos+tneg)/(pos+neg)
tpr=tpos/pos
tnr=tneg/neg

sink(results_file,append=TRUE)
cat(output,"knn",orca_knn,"nu",nu,"g",g,"acc",acc,"tpr",tpr,"tnr",tnr,"\n")
sink()
cat(output,"knn",orca_knn,"nu",nu,"g",g,"acc",acc,"tpr",tpr,"tnr",tnr,"\n")
###########################

if (checkREPACKS){
  repacks_file=get_repack_file()
  repacks=read.table(paste0(path,"chabada_repack_full.txt"),head=T,sep=";",stringsAsFactors=F)
  repack.data=mdata[mdata$name %in% repacks$name,]
  #train using all except repackaged apps
  ex_repack.data=mdata[!mdata$name %in% repacks$name,]
  repack_train=split_data_features_metadata(ex_repack.data)
  repack_test=split_data_features_metadata(repack.data)
  sigdata=as.matrix(repack_train$features)
  gamma=sigest(sigdata,scaled=scale)
  gamma=mean(gamma)
  model = svm(repack_train$features, type="one-classification",nu=nu, scale=scale, gamma=gamma)
  predict_data = predict(model, repack_test$features, decision.values = TRUE)
  merged_results = cbind(repack_test$metadata,predict_data)
  false_negatives = merged_results[(merged_results$malicious == 1 & merged_results$predict_data == TRUE),]
  true_positives = merged_results[(merged_results$malicious == 1 & merged_results$predict_data == FALSE),]
  cat("repacks true positiives:",nrow(true_positives)," false negatives",nrow(false_negatives),"\n")
}
