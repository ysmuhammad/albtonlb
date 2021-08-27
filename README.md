# Populate AWS Network Load Balancer (NLB) with Application Load Balancer (ALB) IP

This is modified function from the original one: 
https://aws.amazon.com/blogs/networking-and-content-delivery/using-aws-lambda-to-enable-static-ip-addresses-for-application-load-balancers/

If on some point you want to publish your app using static IP address, you will need NLB.
Function will populate 2 NLB's Target Group (Target Group with HTTP listener and HTTPS listener) with IP address from ALB. With this function run regularly, it will update NLB to have the same IP address as listed on ALB.

Set these environment variable accordingly:

- ALB_LISTENER = The traffic listener port of the ALB
- CW_METRIC_FLAG_IP_COUNT = The controller flag that enables the CloudWatch metric of the IP address count. The default value is “True” in the CloudFormation template.
- INVOCATIONS_BEFORE_DEREGISTRATION = Then number of required Invocations before an IP address is deregistered. The default value is 3 in the CloudFormation template.
- MAX_LOOKUP_PER_INVOCATION = The max times of DNS look per invocation. The default value is 50 in the CloudFormation template.
- NLB_TG_ARN = The ARN of the NLBs target group
- NLB_TLS_TG_ARN =  The ARN of the NLBs target group (HTTPS)
- S3_BUCKET = Bucket to track changes between Lambda invocations
- FIRST_INGRESS_NAME = Name of the first ingress on Kubernetes
- SECOND_INGRESS_NAME = Name of the second ingress on Kubernetes

Format of the ingress name is:
`<namespace_name>/<ingress_name>`
