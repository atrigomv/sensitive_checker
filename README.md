# Sensitive Checker

### Introduction
Script based on AWS Boto3 SDK which analyzes S3 buckets in order to find sensitive information storage on it. It has been devoloped to be included within a pipeline and can be executed on demand as well. By default, the script analyzes all S3 buckets within an account (a single bucket can be reviewed isolated using "-b" parameter), and as result of it a group of risks are raised and a csv report is created.
Below it is shown the different checks executed by the tool:
<em>
* Presence of key store files.
* Suspicius file names.
* Spanish PII (personal data) within the content of structured files.
* Credentials within the content of structured files.
* DNI (spanish national ID) within the content of structured files.
* Credit cards number within the content of structured files.
</em>

### Installation and environment configuration
To use the tool, first of all you have to clone the git repository or download the Python script from [here](https://github.com/atrigomv/sensitive_checker/blob/master/sensitive_checker.py):

```
git clone git://github.com/atrigomv/sensitive_checker.git
```
To execute the tool it is necessary to cover the steps below:
* Download the tool
* Create a programmatic user in AWS account in which there are the S3 to analyze (extract from it their secret and access keys)
* Install Python
* Install [Boto3](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/quickstart.html) for Python:
```
pip install boto3
```
* Install [AWS CLI](https://aws.amazon.com/cli/?nc1=h_ls) and configure it with the access key and the secret access key of the user previously created:
```
pip install awscli
aws configure
```
* Put execution permissions:
```
chmod +x sensitive_checker.py
```
