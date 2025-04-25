import boto3
import json
import hashlib
import os
import requests
import pytz
from datetime import datetime, timedelta

#Slack
WEBHOOK_URL = '<WEBHOOK_URL>'

# File to track and store the last state of security group
HASH_FILE = '/home/ubuntu/sg_snapshot.hash'

# AWS settings
REGION = '<REGION>'

def get_security_groups():
    session = boto3.Session()  # Removed profile_name
    ec2 = session.client('ec2', region_name=REGION)
    response = ec2.describe_security_groups()

    # Extract only relevant rule information
    filtered_sgs = []
    for sg in response['SecurityGroups']:
        filtered_sgs.append({
            'GroupId': sg['GroupId'],
            'GroupName': sg['GroupName'],
            'IpPermissions': sg.get('IpPermissions', []),
            'IpPermissionsEgress': sg.get('IpPermissionsEgress', [])
        })

    # Sort keys to make hash consistent
    sg_data = json.dumps(filtered_sgs, sort_keys=True)
    return sg_data

def get_hash(data):
    return hashlib.md5(data.encode('utf-8')).hexdigest()

def get_recent_sg_events():
    session = boto3.Session()  # Removed profile_name
    cloudtrail = session.client('cloudtrail', region_name=REGION)

    now = datetime.utcnow()
    start_time = now - timedelta(minutes=10)  # Check last 10 minutes of activity

    event_names = [
        'AuthorizeSecurityGroupIngress',
        'RevokeSecurityGroupIngress',
        'AuthorizeSecurityGroupEgress',
        'RevokeSecurityGroupEgress',
        'UpdateSecurityGroupRuleDescriptionsIngress',
        'UpdateSecurityGroupRuleDescriptionsEgress',
        'ModifySecurityGroupRules'
    ]

    events = []
    for event_name in event_names:
        response = cloudtrail.lookup_events(
            LookupAttributes=[{'AttributeKey': 'EventName', 'AttributeValue': event_name}],
            StartTime=start_time,
            EndTime=now,
            MaxResults=5
        )
        for event in response['Events']:
            evt = json.loads(event['CloudTrailEvent'])
            user = evt.get('userIdentity', {}).get('arn', 'Unknown')
            ip = evt.get('sourceIPAddress', 'Unknown')
            changes = evt.get('requestParameters', {})
            events.append({
                'eventName': event_name,
                'user': user,
                'ip': ip,
                'changes': changes,
                'time': event['EventTime'].strftime('%Y-%m-%d %H:%M:%S UTC')
            })
    return events

def send_alert(message):
    payload = {"text": message}  # Slack expects "text" instead of "content"
    headers = {'Content-Type': 'application/json'}
    response = requests.post(WEBHOOK_URL, data=json.dumps(payload), headers=headers)
    print(f"Notification sent to Slack: {response.status_code} - {response.text}")

def format_event_summary(events):
    if not events:
        return ":warning: No recent changes to security groups detected."

    lines = [":mag: *Details are as below:*\n"]

    # Define IST timezone
    IST = pytz.timezone('Asia/Kolkata')

    for evt in events:
        changes = evt.get('changes', {})
        event_name = evt['eventName']

        # Convert UTC time to IST
        event_time_utc = evt['time']
        event_time_utc = datetime.strptime(event_time_utc, "%Y-%m-%d %H:%M:%S UTC")
        event_time_ist = event_time_utc.replace(tzinfo=pytz.utc).astimezone(IST)
        formatted_time = event_time_ist.strftime("%Y-%m-%d %H:%M:%S IST")

        # ✅ Updated Event Type Handling
        if event_name == 'ModifySecurityGroupRules':
            emoji = ":wrench:"  # 🔧 Rule modified
            action = "Rule Modified"
        elif event_name.startswith('Authorize') or event_name.startswith('Update'):
            emoji = ":white_check_mark:"  # ✅ Rule added/updated
            action = "Rule Added/Updated"
        elif event_name.startswith('Revoke'):
            emoji = ":x:"  # ❌ Rule deleted
            action = "Rule Removed"
        else:
            emoji = ":grey_question:"
            action = event_name

        lines.append(f"{emoji} **{action}** at `{formatted_time}`")
        lines.append(f"  - User: `{evt.get('user', 'Unknown')}`")
        lines.append(f"  - IP: `{evt.get('ip', 'Unknown')}`")

        # ModifySecurityGroupRules structure is different
        if event_name == 'ModifySecurityGroupRules':
            modify_req = changes.get('ModifySecurityGroupRulesRequest', {})
            group_id = modify_req.get('GroupId', 'Unknown')
            lines.append(f"  - Group ID: `{group_id}`")

            rule = modify_req.get('SecurityGroupRule', {}).get('SecurityGroupRule', {})
            proto = rule.get('IpProtocol', 'any')
            from_port = rule.get('FromPort', 'all')
            to_port = rule.get('ToPort', 'all')
            cidr = rule.get('CidrIpv4', 'N/A')
            desc = rule.get('Description', '—')

            lines.append(f"    - Protocol: `{proto}` | Ports: `{from_port}` - `{to_port}`")
            lines.append(f"    - CIDR: `{cidr}` | Desc: _{desc}_")
        
        else:
            group_id = changes.get('groupId', 'Unknown')
            lines.append(f"  - Group ID: `{group_id}`")

            ip_permissions = changes.get('ipPermissions', {}).get('items', [])
            if ip_permissions:
                for perm in ip_permissions:
                    proto = perm.get('ipProtocol', 'any')
                    from_port = perm.get('fromPort', 'all')
                    to_port = perm.get('toPort', 'all')
                    lines.append(f"    - Protocol: `{proto}` | Ports: `{from_port}` - `{to_port}`")

                    for ip_range in perm.get('ipRanges', {}).get('items', []):
                        cidr = ip_range.get('cidrIp', 'N/A')
                        desc = ip_range.get('description', '—')
                        lines.append(f"      - CIDR: `{cidr}` | Desc: _{desc}_")
            else:
                lines.append("    - No IP permissions found.")

        lines.append("\n")  # Spacing between entries

    # Add a separator line at the end for easy differentiation
    lines.append("\n" + "="*40 + "\n")  # 40 dashes for separation

    return "\n".join(lines)

def main():
    sg_data = get_security_groups()
    current_hash = get_hash(sg_data)

    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, 'r') as f:
            old_hash = f.read().strip()
    else:
        old_hash = None

    if old_hash != current_hash:
        print("Security Group change detected. Checking CloudTrail for events...")
        events = get_recent_sg_events()

        if events:
            event_summary = format_event_summary(events)
            send_alert(f"⚠️  AWS Security Group Change Detected!\n\n{event_summary}")
        else:
            print("Hash changed, but no CloudTrail events found. Skipping alert.")

        # ✅ Always update hash to avoid duplicate alerts
        with open(HASH_FILE, 'w') as f:
            f.write(current_hash)
    else:
        print("No changes in Security Groups.")

if __name__ == "__main__":
    main()
if __name__ == "__main__":
    while True:
        main()
        time.sleep(300)
