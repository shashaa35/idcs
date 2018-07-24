
import boto3
import hashlib
import json
import urllib2
import operator

def lambda_handler(event, context):
    print("Received event: " + json.dumps(event, indent=2))
    ip = event['ip']
    
    subnet_id = get_subnet_id(event['instance_id'])
    print subnet_id
    
    acl = get_acl(subnet_id)
    print acl
    
    response = update_acl(acl, ip)
    return acl

def update_acl(acl_id, ip):
    ec2 = boto3.resource('ec2')
    acl = ec2.NetworkAcl(acl_id)
    entries = sorted(acl.entries,key=sortFunc)
    smallest_rule_number = entries[0]['RuleNumber']
    print "smallest rule number is "+ str(smallest_rule_number)
    if smallest_rule_number < 20 :
        response = "Rule cannot be added"
        print response
    else:
        response = acl.create_entry(
            CidrBlock = ip,
            DryRun=False,
            Egress=False,
            PortRange={
                 'From': 0,
                 'To': 65535
            },
            Protocol ='-1',
            RuleAction ='deny',
            RuleNumber=smallest_rule_number - 5
        )
        print response
    return response

def get_subnet_id(instance_id):
    ec2 = boto3.resource('ec2')
    instance = ec2.Instance(instance_id)
    subnet = instance.subnet_id
    return subnet
    
def get_acl(subnet_id):
    client = boto3.client('ec2')
    response = client.describe_network_acls(
        Filters=[
            {
                'Name': 'association.subnet-id',
                'Values': [subnet_id]
            }
            ]
        )
    acl_id = response['NetworkAcls'][0]['Associations'][0]['NetworkAclId']
    return acl_id
    
def sortFunc(item):
    return item['RuleNumber']
