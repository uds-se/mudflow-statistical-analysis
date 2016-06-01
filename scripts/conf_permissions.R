#set root path
path=""
root_dir=paste0(normalizePath(paste0(getwd(),"/..")),"/")
path_orca=paste0(root_dir,"orca/scripts/")

data_dir=root_dir
dest_dir=root_dir

#data folder
# 0 make CV split
# 1 do dprep
# 12 apply weights
# 2 do orca
# 3 make maliciogram
# 4 do classification
stage=c(0,1,12,2,3,4)
#stage=c(4)
gid="10parts"
id_orca="k5"
id_cl="svm"

loadRDS=T
f_type="paper"
main_sfx=""
main_data=paste0(root_dir, "data/mudflow_",f_type,".csv")
susi_list=paste0(root_dir, "data/permissions_list_",f_type,".csv")
susi_mapping=paste0('mapping_',f_type,'.txt')

n_cores=4

n.folds=10
n.parts=10

virustotal_all="virustotal_all.csv"

doBFILTER=F
vt_benign_threshold=5
doMFILTER=F
vt_malic_threshold=5

doMAKEMALIC=F
malic_table="google_malic10"

minor_features=c("Log")
minor_features_weight=0.5#weight for minor dflow features

nu=0.17
doScale=F

toPROBABILITY=F
printFP=F

noSUSI=F

WITHIN=F

checkREPACKS=F
repacks_file="chabada_repack_full.txt"

#reserved#
malic_type=1

orca_exec_mac="orca-mac"
dprep_exec_mac="dprep-mac"
orca_exec_linux="orca-linux"
dprep_exec_linux="dprep-linux"

orca_disttype="-jaccard"
orca_knn=5
orca_AVERAGE=T
orca_scale="-snone"
#-snone , -s01, -sstd
doJOIN=F
join_table=paste0("unique_sources",f_type,".csv")
#min number of apps in susi category to be processed
minSamples = orca_knn
