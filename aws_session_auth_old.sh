echo "please insert an up to date token for aws:"
read token
echo "getting credentials for aws"
credentials=$(aws sts get-session-token --serial-number arn:aws:iam::515619314315:mfa/guy_iphone --token-code $token)
echo "credentials received"
echo $credentials
# key_id, secret_key, session_token = $(echo $credentials | jq -r '.Credentials.AccessKeyId, .Credentials.SecretAccessKey, .Credentials.SessionToken')
read key_id secret_key session_token <<< $(echo $credentials | jq -r '.Credentials.AccessKeyId, .Credentials.SecretAccessKey, .Credentials.SessionToken')
echo $secret_key

export AWS_ACCESS_KEY_ID=$key_id
export AWS_SECRET_ACCESS_KEY=$secret_key
export AWS_SESSION_TOKEN=$session_token
echo 'done setting AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN'