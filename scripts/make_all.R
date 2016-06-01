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
    if(length(features_id)==0)return()
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
        results[[1]] = list(trainset=traindata,testset=testdata)
        #rbind(traindata,testdata))
        return(results)
    }   
    parts = split(traindata, sample(rep(1:n, nrow(traindata)/n)))
    fold = 0
    for (part in parts){
        fold = fold + 1
        testset = part
        testset = rbind(testset, testdata)
        trainset = traindata[!traindata$name %in% part$name,]
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
        if(!file.exists(paste0(dest,"bin")))dir.create(paste0(dest,"bin"),recursive=TRUE)
    #dir.create(paste0(dest,"ext"),recursive=TRUE)
    #dir.create(paste0(dest,"res"),recursive=TRUE)
    }

split_data_features_metadata <- function(data){
  meta_features_col = c(grep("^name|^malicious|^train", names(data),fixed = F))
  data_is_metadata <- 1:ncol(data)
  features <- (data[, -meta_features_col])
  metadata <- data[, meta_features_col]
  return(list(features=features,metadata=metadata))
} 

parse_orca_output<-function(data, refdata, category, getweight=F, traindata=NA) {
    record_id="Record:"
    records=grep(record_id,data,value=T)
    #f_records=str_match_all(records,".*Record:\\s+(\\d+)\\s+Score:\\s+([0-9\\.]+)\\s+Neighbors:\\s((?:[0-9]+\\s*)+)")#(?:\\+e)?
    f_records=str_match_all(records,".*Record:\\s+(\\d+)\\s+Score:\\s+([0-9\\.]+)")
    #items=regmatches(t,gregexpr("[0-9]*\\.?[0-9]+(?:\\+e)*",t))
    records_frame=do.call(rbind.data.frame, f_records)
    records_frame=records_frame[,-1]
    if(nrow(records_frame)==0){
        records_frame=data.frame(matrix(nrow=0,ncol=2))
    }
    colnames(records_frame)<-c("id","score")
    records_frame$score<-as.numeric(records_frame$score)
    scores=merge(records_frame,refdata,by.x="id",by.y="row.names", all.y=T)    
    if (any(is.na(scores$id))){
        logerror("merge of orca scores and ref data was wrong")
    }
    
    #add missing values
    scores$score[is.na(scores$score)]=0
    if (any(scores$score>10000)){
        logwarn("smth wrong with orca, we have scores out of range OR it's euclidean")
        scores$score[scores$score>10000]<-orca_knn
    }
    #if (orca_AVERAGE){
        #scores$score<-scores$score/orca_knn# orca outputs sum of distances instead of average
        #scores$score<-scores$score#^(1/orca_knn)
    #}
    # if (toPROBABILITY){
    #     if (traindata==NA) traindata=scores$score
    #     scores$score<-gaussian_cutoff(scores$score,traindata)
    # }
    scores=cbind(scores,category=rep(category,nrow(scores)))
    scores=scores[order(scores$score,decreasing = T),]
    #barplot(sort(scores$score),main=category,ylim=c(0,1)) #if we want to plot scores
    if (getweight){
        res=scores[,c("name","category","score")]
        svar=var(scores$score)
        smean=mean(scores$score)
        weight=exp(1/smean)
        #auc=trapz(1:nrow(refdata),sort(bn[bn$malicious==0,]$score))/nrow(bn[bn$malicious==0,])
        attr(res,which="weight")<-weight
        return(res)
    } else{
        return(scores[,c("name","category","score")])
    }
}

########################

dfile=get_dfile()
susi_sources_name=get_susi_sources()
base_dir=get_base_dir()
if(!file.exists(base_dir)) {dir.create(base_dir,recursive=TRUE)}
print(base_dir)
orca_col_type = "continuous."
library(doParallel)
cl = makeCluster(n_cores)
registerDoParallel(cl)
if(0 %in% stage){
    if (WITHIN){
        susi_map_file=get_susi_mapping()# used only for within mode
        susi_map=read.csv(file=susi_map_file, head=F, sep=";",strip.white=TRUE)
        names(susi_map)<-c("api","susi")
    }
    if (loadRDS){
        susi_sources = readRDS(file=to_rds(susi_sources_name))
        data = readRDS(file=to_rds(dfile))
        if(doBFILTER || doMFILTER){
            vt_data=readRDS(file=to_rds(get_virustotal()))
        }
    }else{
        susi_sources = read.csv(file=susi_sources_name, head=T, sep=";")
        data = read.csv(file=dfile, head=TRUE, sep=";",check.names=F)
        if(doBFILTER || doMFILTER){
            vt_data=read.csv(file=get_virustotal(), head=TRUE, sep=";",check.names=F, stringsAsFactors=F)
        }
    }
    ##cat("vt: ",nrow(vt_data),"\n")
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
#prepare data
    for(fold in 1:n.folds){
        dest=get_orca_dir(paste0(base_dir,fold))
        prepare_folder(dest)
    }
    tmp1<-
    foreach(fold=1:n.folds) %:%
    foreach(source = sources_list) %dopar% {
        dest=get_orca_dir(paste0(base_dir,fold))
        train=data_set[[fold]]$trainset
        test=data_set[[fold]]$testset
        if (noSUSI){
            strain=train
            stest=test
        }else{
            strain=train[train$name %in% per_source[[source]],]
            stest=test[test$name %in% per_source[[source]],]
        }
        destfile=paste0(dest,"pre/",source)
        cat("fold ", fold," ", source," train:", nrow(strain)," test:",nrow(stest),"\n")
        if (nrow(strain)>minSamples && nrow(stest)>0){
            make_for_cluster(strain, paste0(destfile,"_train"),source)
            make_for_cluster(stest, paste0(destfile,"_test"),source)
            #TODO: use rds instead csv
            ref_train_file=paste0(destfile,"_train.ref")
            write.table(strain[,c("name","malicious"),drop=F], file = ref_train_file, quote = F, row.names = F, col.names = T,sep=";")
            ref_test_file=paste0(destfile,"_test.ref")
            write.table(stest[,c("name","malicious"),drop=F], file = ref_test_file, quote = F, row.names = F, col.names = T,sep=";")
        }
    }
    save_config(get_base_dir())
}
#orca stage

# curr_wd=getwd()
# tmp_dir=paste0(base_dir,"/tmp")
# dir.create(tmp_dir)
# launch dprep
if (1 %in% stage){
    cat("*dprep*\n")
    tmp<-
    foreach(fold=1:n.folds)%dopar%{
        orca_dir=get_orca_dir(paste0(base_dir,fold))
        command=paste0(orca_dir,dprep_exec)
        out_all=list()
        for(data_file in dir(path=paste0(orca_dir,"pre"),pattern="\\.data$",full.names=T)){
            fields_file=sub("data$","fields",data_file)
            category=sub("\\.data","",basename(data_file))
            bin_file=sub("/pre/","/bin/",sub("data$","bin",data_file))
            orca_args=c("cd",orca_dir,"&&",command,data_file,fields_file,bin_file, orca_scale)
            out=system(paste0(orca_args,collapse=" "),ignore.stdout=F,intern=T,wait=T)
            weights_file=sub("((_train)|(_test))\\.","\\.",sub("/pre/","/bin/",sub("data$","weights",data_file)))
            file.rename(from=paste0(orca_dir,"weights"),to=weights_file)
                # weights_data=read.table(file=weights_file,sep=" ")
                # weights_rows=grep(paste(minor_features,collapse="|"),data[,1])
                # weights_data[weights_rows,2]<-minor_features_weight
                # write.table(weights_file,file=fname,sep=" ",col.names=F,row.names=F,quote=F)

            #res=list(cat=out)
            #names(res)<-category
            #out_all=append(out_all,res)
        }
        #res=list(fold=out_all)
        #names(res)<-fold
        #res  
    }
    #sink("debug_dprep.txt")
    #print(tmp)
    #sink()
}

if (12 %in% stage){
    cat("*weights*\n")
    tmp<-
    foreach(fold=1:n.folds)%dopar%{
        orca_dir=get_orca_dir(paste0(base_dir,fold))
        command=paste0(orca_dir,dprep_exec)
        out_all=list()
        for(data_file in dir(path=paste0(orca_dir,"pre"),pattern="\\.data$",full.names=T)){
            weights_file=sub("((_train)|(_test))\\.","\\.",sub("/pre/","/bin/",sub("data$","weights",data_file)))
            weights_data=read.table(file=weights_file,sep=" ")
            weights_rows=1:nrow(weights_data)#grep(paste(minor_features,collapse="|"),weights_data[,1])
            weights_data[weights_rows,2]<-minor_features_weight
            write.table(weights_data,file=weights_file,sep=" ",col.names=F,row.names=F,quote=F)
        }
    }
}


if (2 %in% stage){
    cat("*orca*\n")
    if(orca_AVERAGE){
        dtype="-avg"#FIXME: move to config
    }else{
        dtype="-kth"
    }
    orca_use_weights ="-won"#-won FIXME: move to config
# launch orca, we should do it twice: for train and test sets separately
# log.socket <- make.socket(port=4000)
# write.socket(log.socket, "$$")
    options(stringsAsFactors=F)
#foreach(fold=1:n.folds,.packages=c("stringr"))%:%{
    weights=list()
    #cat(paste0(orca_dir,"bin"))
    maliciogram_list=
    foreach(fold=1:n.folds,.packages=c("stringr"))%:%
    foreach(train_file = dir(path=paste0(get_orca_dir(paste0(base_dir,fold)),"bin"),pattern="train\\.bin$",full.names=T),.packages=c("stringr"))%dopar%{
        orca_dir=get_orca_dir(paste0(base_dir,fold))
        maliciogram_dir=get_maliciogram_dir(paste0(base_dir,fold))
        maliciogram_file=paste0(maliciogram_dir,"maliciogram.csv")
        command=paste0(path_orca,orca_exec)
            #paste0(orca_dir,orca_exec)
            #sink("debug.txt", append=TRUE)
        options(stringsAsFactors=F)
        scores_all=data.frame(matrix(nrow=0,ncol=3))            
        test_file=sub("train","test",train_file)
        weights_file=sub("bin$","weights",sub("_train","",train_file))
        category=sub("_train\\.bin","",basename(train_file))
            #cat(category,"&\n")
        #out_file=sub("/bin/","/ext/",sub("bin$","txt",train_file))
        #get train data scores
        ref_train_file=sub("/bin/","/pre/",sub("bin$","ref",train_file))
        ref_train=read.table(file=ref_train_file,head=T,sep=";")            
        orca_args=c(command,train_file,train_file,weights_file,orca_disttype,"-k",orca_knn,"-n",nrow(ref_train),dtype,orca_use_weights)
            #orca_args=c("cd",orca_dir,"&&",command,train_file,train_file,weights_file,orca_disttype,"-k",orca_knn-1,"-n",nrow(ref_train),dtype,orca_use_weights)
            #print(orca_args)
        out=system(paste0(orca_args,collapse=" "),intern=T,wait=T)
        train_scores=parse_orca_output(out,ref_train,category,getweight=T)
        weights[[category]]=attr(train_scores,"weight")
        scores_all=setNames(rbind(scores_all,train_scores),c("name","category","score"))
            #cat(category,"=1\n")
        ref_test_file=sub("_train\\.","_test\\.",sub("/bin/","/pre/",sub("bin$","ref",train_file)))
        ref_test=read.table(file=ref_test_file,head=T,sep=";")
        orca_args=c(command,test_file,train_file,weights_file,orca_disttype,"-k",orca_knn,"-n",nrow(ref_test),dtype,orca_use_weights)
            #orca_args=c("cd",orca_dir,"&&",command,test_file,train_file,weights_file,orca_disttype,"-k",orca_knn,"-n",nrow(ref_test),dtype,orca_use_weights)
        out=system(paste0(orca_args,collapse=" "),intern=T,wait=T)
        test_scores=parse_orca_output(out,ref_test,category, traindata=train_scores$score)
        scores_all=rbind(scores_all,test_scores)
            #cat(category,"=2\n")

            #scores_all$score<-scores_all$score*weights[[category]]
        res=list(category=scores_all[,c("name","score")])
        names(res)<-category
        scores_file=paste0(maliciogram_dir,category,"_scores.csv")
        write.table(scores_all, file=scores_file,quote=F,col.names=F,row.names=F,sep=";")
            #cat(category,"=3\n")
        sink()
        res
    #     #cat(category,"train", nrow(ref_train), "test", nrow(fer_test) "weight ",weights[[category]],"\n")
    #     #row.names(scores_all)<-scores_all$name
    #     #scores_vector=scores_all[,"score",drop=F]
    #     #scores_vector=scores_vector*weights[[type]]
        #maliciogram[scores_all$name,category]<-scores_all$score*weights[[category]]
        #maliciogram[ref_train$name,"malicious"]<-ref_train$malicious
        #maliciogram[ref_test$name,"malicious"]<-ref_test$malicious
        #maliciogram[ref_train$name,"train"]<-1
        #maliciogram[ref_test$name,"train"]<-0
    }

}
if(3 %in% stage){
    for(fold in 1:n.folds){
        maliciogram=data.frame()
        orca_dir=get_orca_dir(paste0(base_dir,fold))
        maliciogram_dir=get_maliciogram_dir(paste0(base_dir,fold))
        maliciogram_file=paste0(maliciogram_dir,"maliciogram.csv")
        for(train_file in dir(path=paste0(orca_dir,"bin"),pattern="train\\.bin$",full.names=T)){
            category=sub("_train\\.bin","",basename(train_file)) 
            scores_file=paste0(maliciogram_dir,category,"_scores.csv")
            scores=read.table(file=scores_file,head=F,sep=";",stringsAsFactors=F)
            names(scores)<-c("name","category","score")
            scores=scores[scores$category==category,]  
            cat(category," ",dim(scores),"\n")
            ref_test_file=sub("_train\\.","_test\\.",sub("/bin/","/pre/",sub("bin$","ref",train_file)))
            ref_test=read.table(file=ref_test_file,head=T,sep=";",stringsAsFactors=F)
            ref_train_file=sub("/bin/","/pre/",sub("bin$","ref",train_file))
            ref_train=read.table(file=ref_train_file,head=T,sep=";",stringsAsFactors=F)
            #FIXME:
            #now moved from parse_
            if (toPROBABILITY){
                base_scores=scores[scores$name %in% ref_train$name,]
                scores$score<-gaussian_cutoff(scores,base_scores)
            }
            train_scores=scores[scores$name %in% ref_train$name,]
            smean=mean(train_scores$score)
            weight=exp(1/smean)
            #scores=maliciogram_list[[category]]
            if(orca_AVERAGE){
                scores$score<-scores$score/orca_knn
            }
            maliciogram[scores$name,category]<-scores$score*weight
            maliciogram[ref_train$name,"malicious"]<-ref_train$malicious
            maliciogram[ref_test$name,"malicious"]<-ref_test$malicious
            maliciogram[ref_test$name,"train"]<-0
            maliciogram[ref_train$name,"train"]<-1
        }
        maliciogram[is.na(maliciogram)]<-0
        maliciogram$name<-row.names(maliciogram)
    #TODO: add rds
        #write.table(scores_all, file=scores_file,quote=F,col.names=F,row.names=F,sep=";")
        write.table(maliciogram, file=maliciogram_file,quote=F,row.names=F,sep=";")
    }
}

if (4 %in% stage){
    print("*classification*")
#TODO: clean orca and dpred executables
#TODO: add separate maliciogram construction from scores_all file
#do classification
#library("kernlab")
#library("e1071")
    result<-
    foreach(fold=1:n.folds,.combine=rbind,.packages=c("kernlab","e1071","logging"))%dopar%{
        maliciogram_dir=get_maliciogram_dir(paste0(base_dir,fold))
        maliciogram_file=paste0(maliciogram_dir,"maliciogram.csv")
        maliciogram = read.csv(file=maliciogram_file, head=TRUE, sep=";")
        #ff=!colnames(maliciogram) %in% c("NO_SENSITIVE_SOURCE", "","","")#ACCOUNT_INFORMATION
        #print(ff)
        #maliciogram=maliciogram[,ff]
            #print(dim(maliciogram))
        train = split_data_features_metadata(maliciogram[maliciogram$train==1,])
        test = split_data_features_metadata(maliciogram[maliciogram$train==0,])
        train.data = train$features
        #cat(names(maliciogram))
        test.data=test$features
        test.metadata=test$metadata
        gamma_quantile=sigest(as.matrix(train.data),scaled=doScale,frac=1)
        gamma=mean(gamma_quantile)#gamma_quantile[[1]]#
        print(gamma)
        if (is.na(gamma)){
            gamma=0.1
            logerror(paste0("sigest got wrong values: ",paste0(gamma_quantile,collapse=" ")))
        }
        if (TRUE){
            #svm from e1071
            model = svm(train.data, tolerance=0.000001,epsilon=0.0001,type="one-classification",nu=nu, scale=doScale, gamma=gamma,kernel="radial")
            #print(model)
            predict_data = predict(model, test.data, decision.values = TRUE)
            decision_values = attributes(predict_data)$decision.values
            merged_results = cbind(test.metadata,predicted=predict_data,decision_values=decision_values)

        #add detection rate from virus total
        #merged_results = merge(merged_results,vt_data[,c("name","detection")], by="name",all.x=T)
            mispredicted = merged_results[(merged_results$malicious == 0 & merged_results$predicted == FALSE) | (merged_results$malicious == 1 & merged_results$predicted == TRUE),]
            false_positives = merged_results[(merged_results$malicious == 0 & merged_results$predicted == FALSE),]
            false_negatives = merged_results[(merged_results$malicious == 1 & merged_results$predicted == TRUE),]
            true_positives = merged_results[(merged_results$malicious == 1 & merged_results$predicted == FALSE),]
            true_negatives = merged_results[(merged_results$malicious == 0 & merged_results$predicted == TRUE),]
        }else{
            #svm from kernlab
            model = ksvm(as.matrix(train.data), kernel="rbfdot", nu=nu, scales=doScale, type="one-svc",kpar=list(sigma=gamma))
            #print(model)
            predict_data = predict(model, test.data)
            merged_results = cbind(test.metadata,predicted=predict_data)
            mispredicted = merged_results[(merged_results$malicious == 0 & merged_results$predicted == FALSE) | (merged_results$malicious == 1 & merged_results$predicted == TRUE),]
            false_positives = merged_results[(merged_results$malicious == 0 & merged_results$predicted == FALSE),]
            false_negatives = merged_results[(merged_results$malicious == 1 & merged_results$predicted == TRUE),]
            true_positives = merged_results[(merged_results$malicious == 1 & merged_results$predicted == FALSE),]
            true_negatives = merged_results[(merged_results$malicious == 0 & merged_results$predicted == TRUE),]
        }


        classification_dir=get_classification_dir(paste0(base_dir,fold))
        fp_file=paste0(classification_dir,"false_positives.csv")
        fn_file=paste0(classification_dir,"false_negatives.csv")
        write.table(false_positives[,names(test.metadata)],file=fp_file,row.names=F)
        write.table(false_negatives[,names(test.metadata)],file=fn_file,row.names=F)
        classification_file=paste0(classification_dir,"classification.txt")

        tp=nrow(true_positives)
        tn=nrow(true_negatives)
        fp=nrow(false_positives)
        fn=nrow(false_negatives)

        pos=tp+fn#length(which(test.metadata$malicious==0))
        neg=tn+fp#length(which(test.metadata$malicious==1))

        g=sqrt(tp/pos*tn/neg)
        acc=(tp+tn)/(pos+neg)
        tpr=tp/pos
        tnr=tn/neg

    #TODO: save 1) fp fn    
    #           2) g acc tpr tnr
    #           3)
        fileConn=file(classification_file)
        writeLines(c("g",g,"acc",acc,"tpr",tpr,"tnr",tnr,"TP", tp,"TN", tn, "FP", fp,"FN", fn), fileConn, sep=" ")
        close(fileConn)
        res=c(g,acc,tpr,tnr,tp,tn,fp,fn)
    #TODO: add writing of fpositives and fnegatives
    #TODO: create .combine function
    # list(model=model,
    #  predict_data=predict_data, 
    #  mispredicted=mispredicted, 
    #  false_positives=false_positives,
    #  false_negatives=false_negatives,
    #  true_positives=true_positives,
    #  true_negatives=true_negatives,
    #  neg_count=length(which(test.metadata$malicious==0)),
    #  pos_count=length(which(test.metadata$malicious==1)),
    #  all_test_values=merged_results
    #  )
        res
    }
    result=as.data.frame(result)
    if(ncol(result)==1)result=data.frame(t(result))
    #if (is.null(dim(result)))result=data.frame(t(result))
        colnames(result)<-c("g","acc","tpr","tnr","tp","tn","fp","fn")
    tp=mean(result$tp)
    tn=sum(result$tn)
    fp=sum(result$fp)
    fn=mean(result$fn)

    pos=tp+fn
    neg=tn+fp
    g=sqrt(tp/pos*tn/neg)
    acc=(tp+tn)/(pos+neg)
    tpr=tp/pos
    tnr=tn/neg

#aggregate cross-validation
    classification_file=get_classification_file()
    fileConn=file(classification_file)
    writeLines(c("g",g,"acc",acc,"tpr",tpr,"tnr",tnr,"TP", tp,"TN", tn, "FP", fp,"FN", fn), fileConn, sep=" ")
#TODO: write all params?
    close(fileConn)

    all_res_file=get_result_file()
    sink(all_res_file, append=T)
    cat(gid,get_ids(),"knn",orca_knn,"nu",nu,"g",g,"acc",acc,"tpr",tpr,"tnr",tnr,"\n")
    sink()
    cat(gid,get_ids(),"knn",orca_knn,"nu",nu,"g",g,"acc",acc,"tpr",tpr,"tnr",tnr,"\n")
}
