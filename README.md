# Sensitive Checker

### Introduction
Script based on AWS Boto3 SDK which analyzes S3 buckets in order to find sensitive information storage on there. It has been devoloped to be included within a pipeline and can be executed on demand as well. By default, the script analyzes all S3 buckets within an account (a single bucket can be reviewed isolated using "-b" parameter), and as result of it a group of risks are raised and a csv report is created.
Below it is shown the different checks executed by the tool:
<em>
* Presence of key store files.
* Suspicius file names.
* Spanish PII (personal data) within the content of structured files.
* Credentials within the content of structured files.
* DNI (spanish national ID) within the content of structured files.
</em>
