# Statistical Analysis Scripts of a MUDFLOW prototype

The repository contains scripts that are needed for statistical analysis of data flows


These scripts implement MUDFLOW approach.

* Modify `scripts/conf.R` such that `<main_data>` and `<susi_list>` point to your data. Use only base names. All paths are relative to the root application folder.
* Use `<suffix>` to set an id for a particular classification (can be empty).
* `<susi_mapping>` file is optional. It is used only when a set of features used in maliciogram construction is being restricted to data flows belonging to a particular susi category.
* Try running `Rscript scripts/make_all.R`

* You need the following R libraries: 
  * e1071, 
  * kernlab, 
  * ROCR(optionally),
  * parallel,
  * iterators,
  * foreach
* These scripts were tested with R 3.1.1
* You can make several configurations and launch Mudflow using particular one via `Rscript make_all.R <conf_file>`
* It's possible to launch stages step by step. Please see `stage` variable in the `conf.R`
* If you have a lot of data it's reasonable to convert CSV files to RDS at first (like RDS files in `data` folder). Then you can use `<loadRDS=T>` flag to increase the speed of data loading
* You can find sample data files in `data` folder. Main file contains number of flows found in each application in rows. Currently Mudflow accepts only nonnegative integers as feature values. Though, for jaccard distance only binary values are considered (i.e. zero and nonzero)
* Each pair `name;category` in `<susi_list>` file means that an app `name` has a source associated with susi category `category`.
* It's better to surround each value in files with double quotes.
* Classification results are stored in file `Results.txt`.

The Mudflow process consists of the following stages:
* Prepare data for orca. For each susi category it constitutes training and testing sets from apps having at least one flow from a source that belongs to this category. Depending on settings all data flows or only ones from sources associated with a category are considered.
* Perform outlierness score calculation with help of orca;
* Aggregate scores into a maliciogram and calculate feature weights;
* Do one-class SVM classification using maliciograms as features.
