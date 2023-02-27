#!/bin/bash
#this script gets new aws sts by mfa token and inject it to aws credentials
mfaDevice=$(aws iam list-mfa-devices | grep SerialNumber | awk '{print $2}' | sed 's/"//g' | sed 's/,//g')
echo "MFA Device: $mfaDevice"
echo "Enter MFA Token:"
read mfaToken
echo "MFA Token entered: $mfaToken"
stsData=$(aws sts get-session-token --serial-number $mfaDevice --token-code $mfaToken --duration-seconds 129600)
if [ $? -ne 0 ]; then
    echo "Failed to get sts token"
    exit 1
fi
echo "Updating AWS Credentials file with mfa profile (valid for 3 days)"
export AWS_ACCESS_KEY_ID=$(echo $stsData | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $stsData | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $stsData | jq -r '.Credentials.SessionToken')
# aws configure set aws_access_key_id $(echo $stsData | jq -r '.Credentials.AccessKeyId') --profile mfa
# aws configure set aws_secret_access_key $(echo $stsData | jq -r '.Credentials.SecretAccessKey') --profile mfa
# aws configure set aws_session_token $(echo $stsData | jq -r '.Credentials.SessionToken') --profile mfa
echo "Successfully updated your AWS Credentials with mfa profile\nPlease use --profile mfa with your aws cli commands"