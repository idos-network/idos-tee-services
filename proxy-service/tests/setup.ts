process.env.NODE_ENV ??= "test";
process.env.DYNAMODB_ARMED_TABLE ??= "test-armed";
process.env.AWS_REGION ??= "eu-central-1";
process.env.AWS_KMS_ARMED_ARN ??= "arn:aws:kms:eu-central-1:000000000000:key/test";
process.env.ARM_TOKENS ??= "arm-token-one, arm-token-two";
