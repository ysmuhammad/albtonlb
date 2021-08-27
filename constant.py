import os
import boto3
import sys
from botocore.exceptions import ClientError
from datetime import datetime


class LambdaEnv:
    """
    Constant extracted from Lambda environment variables
    """
    ALB_LISTENER = int(os.environ["ALB_LISTENER"])
    S3_BUCKET = os.environ["S3_BUCKET"]
    NLB_TG_ARN = os.environ["NLB_TG_ARN"]
    NLB_TLS_TG_ARN = os.environ["NLB_TLS_TG_ARN"]
    MAX_LOOKUP_PER_INVOCATION = int(os.environ["MAX_LOOKUP_PER_INVOCATION"])
    INVOCATIONS_BEFORE_DEREGISTRATION = int(
        os.environ["INVOCATIONS_BEFORE_DEREGISTRATION"]
    )
    CW_METRIC_FLAG_IP_COUNT = os.environ["CW_METRIC_FLAG_IP_COUNT"]
    REGION = os.environ["AWS_REGION"]
    ACTIVE_FILENAME = "active_ip.json"
    PENDING_DEREGISTRATION_FILENAME = "pending_ip.json"
    ACTIVE_FILENAME_TLS = "active_ip_tls.json"
    PENDING_DEREGISTRATION_FILENAME_TLS = "pending_ip_tls.json"
    TIME = datetime.strftime((datetime.utcnow()), "%Y-%m-%d %H:%M:%S")
    FIRST_INGRESS_NAME = os.environ["FIRST_INGRESS_NAME"]
    SECOND_INGRESS_NAME = os.environ["SECOND_INGRESS_NAME"]

    try:
        tag = boto3.client('resourcegroupstaggingapi')
    except ClientError as e:
        print(e.response['Error']['Message'])
        sys.exit(1)

    try:
        ec2client = boto3.client('ec2')
    except ClientError as e:
        print(e.response['Error']['Message'])
        sys.exit(1)
    resource_list = tag.get_resources(
        TagFilters=[
            {
                'Key': 'ingress:owner',
                'Values': [
                    FIRST_INGRESS_NAME,
                ]
            },
        ],
        ResourceTypeFilters=[
            'elasticloadbalancing:loadbalancer'
        ]
    )
    if len(resource_list['ResourceTagMappingList']) == 0:
        resource_list = tag.get_resources(
            TagFilters=[
                {
                    'Key': 'ingress:owner',
                    'Values': [
                        SECOND_INGRESS_NAME,
                    ]
                },
            ],
            ResourceTypeFilters=[
                'elasticloadbalancing:loadbalancer'
            ]
        )
        try:
            ARN_NAME = resource_list['ResourceTagMappingList'][0]['ResourceARN'].rsplit(
                '/', 3)
        except IndexError:
            print(
                'Cannot find ALB neither with first ingress name and second ingress name!')
            sys.exit(1)
        ACTIVE_IP_LIST_KEY = f"{ARN_NAME[2]}/{ACTIVE_FILENAME}"
        PENDING_IP_LIST_KEY = f"{ARN_NAME[2]}/{PENDING_DEREGISTRATION_FILENAME}"
        ACTIVE_IP_LIST_KEY_TLS = f"{ARN_NAME[2]}/{ACTIVE_FILENAME_TLS}"
        PENDING_IP_LIST_KEY_TLS = f"{ARN_NAME[2]}/{PENDING_DEREGISTRATION_FILENAME_TLS}"
    else:
        ARN_NAME = resource_list['ResourceTagMappingList'][0]['ResourceARN'].rsplit(
            '/', 3)
        ACTIVE_IP_LIST_KEY = f"{ARN_NAME[2]}/{ACTIVE_FILENAME}"
        PENDING_IP_LIST_KEY = f"{ARN_NAME[2]}/{PENDING_DEREGISTRATION_FILENAME}"
        ACTIVE_IP_LIST_KEY_TLS = f"{ARN_NAME[2]}/{ACTIVE_FILENAME_TLS}"
        PENDING_IP_LIST_KEY_TLS = f"{ARN_NAME[2]}/{PENDING_DEREGISTRATION_FILENAME_TLS}"
