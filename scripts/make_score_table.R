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
require(pracma)

score_file_name=get_score_file()
input_file_name=get_orca_dir()
##############
input_file=paste0(input_file_name,"/scores-all.csv")
res_file=score_file_name
data_file=get_dfile()
print(input_file)
print(res_file)
print(data_file)

outl=read.csv(file=input_file, head=F, sep=";", stringsAsFactors=F)
names(outl)<-c("name","s","score")

susi_sources_file=get_susi_sources()
print(susi_sources_file)
if (loadRDS){
    data = readRDS(file=to_rds(data_file))
    susi_sources = readRDS(file=to_rds(susi_sources_file))
    vt_data=readRDS(file=to_rds(get_virustotal()))
}else{
    data = read.csv(file=data_file, head=TRUE, sep=";")
    susi_sources = read.csv(file=susi_sources_file, head=T, sep=";" ,stringsAsFactors=F)
    vt_data=read.csv(file=get_virustotal(), head=TRUE, sep=";",check.names=F, stringsAsFactors=F)
}

print(dim(data))
data=data[,c("name","malicious")]
data$malicious<-data$malicious/malic_type
susi_sources=unique(susi_sources)
names(susi_sources)<-c("name","s")

#susi_so = read.csv(file="/home/konst/LAB/ndss2015-flowminer/DATA/NO_SENSITIVE_SINK/Sources_list_signatures_NO_SENSITIVE_SOURCE.txt", head=T, sep=";" ,stringsAsFactors=F)
#susi_so=unique(susi_so)
#names(susi_so)<-c("name","s")
#susi_sources$s<-paste0("SI_",susi_sources$s)
#susi_sources=rbind(susi_sources,susi_so)
#

susi=unique(outl$s)
if (noSUSI){
    susi=c("ALL")#FIXME
}

scores=data.frame(row.names=data$name,stringsAsFactors=F)
scores=cbind(scores,data[,c("name","malicious")])
#dev.new()
#par(mfrow=c(4,4),mar=c(1,1,1,1))
weights=list()
for (type in susi){
    soutl=outl[outl$s==type,]
    sdata=susi_sources[susi_sources$s==type,]
    if (noSUSI){
        smdata=data
    }else{
        smdata=data[data$name %in% sdata$name,,drop=F]
    }
    msoutl=merge(soutl[,c("name","score")],smdata,by="name",all.y=T)
    msoutl$score[is.na(msoutl$score)]=0
    msoutl$score[msoutl$score>10000]<-orca_knn  #FIXIT

    if (orca_AVERAGE){
        msoutl$score<-msoutl$score/orca_knn# orca outputs sum of distances instead of average
    }
    if (toPROBABILITY){
        msoutl$score<-gaussian_cutoff(msoutl)
    }

    if (doBFILTER){
        fdata=vt_filter(data, vt_data)
        #data=rbind(fdata$train,fdata$test)
        #cat("train: ",nrow(fdata$train)," test: ",nrow(fdata$test),"\n")
        trainset=msoutl[msoutl$name %in% fdata$train,]
    }else{
        trainset=msoutl
        #trainset=msoutl[msoutl$name %in% data$name,]#msoutl[msoutl$name %in% data$name,]
    }

    #barplot(sort(bn[bn$malicious==0,]$score),main=type,ylim=c(0,1))
    #bn[bn$malicious==0,]
    svar=var(trainset$score)#var(trainset$score) #check
    smean=mean(trainset$score)
    
    scores=cbind(scores,rep(0,nrow(data)))
    colnames(scores)[ncol(scores)]<-type
    scores[msoutl[,1],type]<-msoutl[,2]#
    weights[[type]]=exp(1/(smean+svar))

    cat(type,nrow(msoutl)," all var ",var(scores[,type])," ")
    #auc=trapz(1:nrow(bn[bn$malicious==0,]),sort(bn[bn$malicious==0,]$score))/nrow(bn[bn$malicious==0,])
    #scores[,type]<-scores[,type] * var(scores[,type]) #CHECK variance of the whole data including not presented in susi category
    cat("var ",svar," mean ",smean,"w ",1/(smean+svar),"expw ",exp(1/(smean+svar)),"\n")

    
    #some kind of classifier evaluation
    if (FALSE){
        require("ROCR")
        pred=prediction(msoutl$score,msoutl$malicious,label.ordering=c(0,1))
        perf=performance(pred,measure="auc")    #measure="aucpr" can be used only for modified ROCR package https://github.com/ipa-tys/ROCR/pull/1
        cat("auc ",type,perf@y.values[[1]],"\n")
    }
    
    if(FALSE){
        malic=msoutl[msoutl$malicious==1,]
        benign=msoutl[msoutl$malicious==0,]
        malic_n=nrow(malic)
        benign_n=nrow(benign)
    #Cantelli inequality, doesn't work well here
        as_in_paper=FALSE #The Odd One Out
        if (as_in_paper){
            model_confidence=0.5
            model_k=sqrt(1/model_confidence-1)
            model_mean=mean(benign$score)
            model_sd=sd(benign$score)
            score_threshold=model_mean+model_k*model_sd
        }else{
            #as in code of krimp
            false_pos_rate=0.05
            obenign=benign[order(benign$score, decreasing=T),]
            # consider some part of benign apps as ground truth
            score_threshold=obenign[false_pos_rate*benign_n,]$score
            model_mean=mean(benign$score)
            model_sd=sd(benign$score)
            model_k=(score_threshold-model_mean)/model_sd
            model_confidence=1/(1+model_k^2)
            pred_conf=1/(1+((msoutl$score-model_mean)/model_sd)^2)
        }
        if (toPROBABILITY){
            score_threshold=0    
        }
        cat("score threshold: ",score_threshold,"\n")
        cat("confidence: ",model_confidence,"\n")

        decision=msoutl$score<=score_threshold

        res=cbind(msoutl,decision=decision)
        tp = length(which(res$malicious==1 & res$decision==FALSE))
        fp = length(which(res$malicious==0 & res$decision==FALSE))
        tn = length(which(res$malicious==0 & res$decision==TRUE))
        fn = length(which(res$malicious==1 & res$decision==TRUE))
        cat(type," tp:",tp," out of:",malic_n," fn:",fn," tn:",tn," out of:",benign_n," fp:",fp,"\n")
        cat(type," tpr:",tp/malic_n," tnr:",tn/benign_n," acc:",(tp+tn)/(malic_n+benign_n)," g:",sqrt(tp/(tp+fn)*tn/(tn+fp)),"\n")
    }
}
#normalize weights
sumweights=Reduce("+",weights)
#rank as weight
wd=data.frame(row.names=susi,stringsAsFactors=F)
for(type in susi){
    wd[type,"w"]=weights[[type]]
}
wd=wd[order(wd$w),,drop=F]
wd=cbind(wd,r=1:length(susi))
for(type in susi){
    scores[,type]<-scores[,type] *weights[[type]]#/sumweights
    #scores[,type]<-scores[,type] * wd[type,"r"]
}
saveRDS(scores, file = to_rds(res_file))
write.table(scores, file = res_file, quote = F, row.names = F, col.names = T,sep=";")
