# AWS Security Group Change Monitoring with Slack Alerts

This project is designed to monitor AWS Security Group changes and send Slack alerts when changes are detected. It uses AWS CloudTrail logs to track security group changes and Python to process these logs. The Python script runs as a systemd service on an EC2 instance.

## Objective

- Monitor AWS Security Group changes.
- Send Slack notifications when changes are detected.
- Run a Python script as a systemd service on an EC2 instance.
- Able to run automatically for changes using CloudTrail logs.

---

## Implementation Steps

### 1. Enable CloudTrail

1. Sign in to the AWS Management Console.
2. Go to the **CloudTrail** service.
3. Create or use an existing trail:
   - The trail must track **Management Events** (not just data events).
   - Ensure "Read/Write events" includes **Write-only** or **All**.
   - Enable the trail for all regions (recommended).
4. Save the trail.

CloudTrail is required for tracking security group changes such as `AuthorizeSecurityGroupIngress`, `RevokeSecurityGroupEgress`, etc.

---

### 2. Create IAM Role

1. Go to **IAM > Roles**.
2. Click **Create Role**.
3. Select **EC2** as the trusted entity type.
4. Attach the following custom policy to the role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

5. Name the role: SecurityGroupMonitorRole.
6. Attach this role to your EC2 instance.

### 3. Prepare the EC2 Instance
1. Launch an Ubuntu EC2 instance (or any Linux-based instance).
2. Ensure the instance has internet access (for Slack webhook).
3. Update system packages:
```bash
sudo apt update && sudo apt install -y python3-pip
```
4. Install Python libraries from requirements.txt:
```bash
pip install -r requirements.txt
```

### 4. Create the Python Script
1. Create the script 'sg-monitoring.py' that checks for security group changes using CloudTrail logs and sends Slack alerts.
2. Note: 🔁 You can includes "while True:" to run continuously every 5 minutes at the end of the code.
3. If you're creating the service in systemd (GONNA PERFORM THE 5th STEP), kindly ignore adding the "while true:" at the end of the code.
4. IMPORTANT: Create your slack channel and generate the 'Webhook' for the same and mention in the script. 

### 5.  Create systemd Service
1. Create file: 
```bash
sudo nano /etc/systemd/system/sg-monitoring.service
```

```ini
#Please take care of the given paths. 
[Unit]
Description=AWS Security Group Monitoring Service
After=network.target

[Service]
User=ubuntu
Group=ubuntu
WorkingDirectory=/home/ubuntu/sg-monitoring
Environment="PATH=/home/ubuntu/sg-monitoring/sg-venv/bin"
ExecStart=/home/ubuntu/sg-monitoring/sg-venv/bin/python /home/ubuntu/sg-monitoring/sg-monitoring.py

[Install]
WantedBy=multi-user.target
```
NOTE: If you’re not using ‘while True’ in the script, then you must create a ‘.timer’ file in systemd to run the service continuously. 

2. Once you create the service file, run the commands given below.
```bash
sudo chmod 644 /etc/systemd/system/sg-monitoring.service
sudo systemctl daemon-reload
sudo systemctl enable sg-monitoring.service
sudo systemctl start sg-monitoring.service
sudo systemctl status sg-monitoring.service
```

### 6.  Create systemd Timer for Service
1. Create file:
```bash
sudo nano /etc/systemd/system/sg-monitoring.timer
```

```ini
[Unit]
Description=AWS Security Group Monitoring Timer
Requires=sg-monitoring.service

[Timer]
OnBootSec=60
OnUnitActiveSec=60
Unit=sg-monitoring.service
Persistent=true

[Install]
WantedBy=timers.target
```

2. Once you create the service file, run the commands given below.
```bash
sudo chmod 644 /etc/systemd/system/sg-monitoring.timer
sudo systemctl daemon-reload
sudo systemctl enable sg-monitoring.timer
sudo systemctl start sg-monitoring.timer
sudo systemctl status sg-monitoring.timer
```

3. Verify Timer Schedule
```bash
systemctl list-timers
```

4. Now you can modify the security group and run the script. You will be able to get alert notification in the Slack channel.
```bash
python3 sg-monitoring.py
```
