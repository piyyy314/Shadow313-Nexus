import boto3

def quarantine_instance(instance_id, region='us-east-1'):
    ec2 = boto3.client('ec2', region_name=region)
    ec2.modify_instance_attribute(InstanceId=instance_id, Groups=['sg-for-quarantine'])