#set root path
path="/Users/kuznetsov/LAB/workspace/mudflow-scripts/"

options(stringsAsFactors=F)

f_type="signatures"

#data folder
prefix=""

suffix=""
#main_sfx="_nosource_nosink"
main_sfx=""
main=paste0("mudflow_bati_",f_type,main_sfx)

susi_list=paste0("Sources_list_",f_type,"_bati.txt")
#"Sources_list_",f_type,"_NO_SENSITIVE_SOURCE.txt"
#"Sources_list_",f_type,"_bati.txt")

doJOIN=F
join_table="unique_sources"
join_name_complete=F

doMAKEMALIC=F
malic_table="google_malic10"

nu=0.12

orca_knn=5
orca_AVERAGE=T

mutated=F
m_type="No"
#No, Same

toPROBABILITY=F
printFP=F

noSUSI=F

WITHIN=F

#min number of apps in susi category to be processed
minSamples = 4

checkREPACKS=F
repacks_file="chabada_repack_full.txt"

#reserved#
malic_type=1
#not used
outF_id=1
