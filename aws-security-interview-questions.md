# AWS Security Interview Questions

1. How would you find evidence of malicious activity within the services like AWS EBS, Application using Lambda etc.
    
    This is to check if the person have experience with GuardDuty, CloudTrail, Config and have worked on any such malicious activities in past. If so, what all he/she did.

2. CloudTrail vs CloudWatch and explain in depth from security perspective. 

    Person has to work on CloudTrail functionalities more often and has to be good at incident/event analysis. Also, to check whether an interviewee is aware about CloudWatch.
3. How IMDSv1 is vulnerable to SSRF, explain. 

There are many org wide admins, developers of whoever launch instance, by default AWS creates v1 reference.
This can lead to key stealing, privilege escalation etc. through SSRF or sometimes even through curl commands.
Is person aware of IMDSv1 and how IMDSv2 solves SSRF issue.

4. Did you implement IMDSv2 and how it fixed SSRF? 
References:
    1. https://medium.com/@shurmajee/aws-enhances-metadata-service-security-with-imdsv2-b5d4b238454b 
    2. https://www.cyberbit.com/blog/uncategorized/aws-imds-v2-secures-ssrf-vulnerability/ 
    3. https://www.accurics.com/blog/security-blog/aws-cloud-security-protect-ssrf/ 
    4. https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html 
    5. https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/ 
    6. https://blog.appsecco.com/an-ssrf-privileged-aws-keys-and-the-capital-one-breach-4c3c2cded3af 
    7. https://www.youtube.com/watch?v=2B5bhZzayjI (re:Invent SEC310)
5. How logs are stored in AWS and how you can monitor those?
6. Can you analyse and explain risk and security issues for ElasticSearch services?
7. When should you use TGW? is there any security improvement for using this?
8. Should we expose Database access publicly or to web application directly?
9. Can you help me to understand the security posture for Wordpress site being hosted in AWS?
10. Do you have experience in AWS services security design and enforcement review or documentation?
11. What issue you see when any API endpoint is exposed to public?
12. There is a security group names as default and have port 22, 25, 53, 80,443, 3679, 3306, 9001. Do you see any issue here?
13. Have you worked on Backup security and monitoring. Can you explain?
14. We want to enable SSO and integrate a tool call Trello in our AWS environment where other applications are hosted. What security posture you think we should work on to keep everything secured?
15. How the security alerts of AWS resources being captured and sent to security people automatically?
16. Have you worked on GuardDuty? It has lots of false positives. Do you have any suggestions to reduce false positives.
17. Can you explain how to use and when to use Access key id and Principal id with one example?
18. What are the different data sources for GuardDuty?
19. What are the various options/features you have worked in GuardDuty?
20. I need to get an alert to slack/mail, whenever my backend APIs start giving 5xx in CloudWatch, how would you achieve that?
21. RTO (Recovery Time Objective) vs RPO (Recovery Point Objective)
22. [You are trying to SSH into an EC2 instance but it is failing.](https://aws.plainenglish.io/i-have-asked-this-ssh-question-in-every-aws-interview-and-heres-the-catch-ee2013a83e99)

## IAM
1. Explain below IAM policy: 

As a Cloud Security Engineer, you would need to work on reviewing and inspecting IAM policies time to time.
Main idea behind asking such question is to check if you are ok with IAM policies and know the basic idea about effect, resource, condition etc.

```json
{
    "Version": "2012-10-17",
    "Statement": [{
        "Sid": "DenyAllUsersNotUsingMFA",
        "Effect": "Deny",
        "NotAction": "iam:*",
        "Resource": "*",
        "Condition": {"BoolIfExists": 
                        {"aws:MultiFactorAuthPresent": "false"}
                    }
    }]
}
```
2. Explain below policy. What's wrong with this policy
```json
{
    "Version": "2012-10-17",
    "Statement": {
    "Effect": "Deny",
    "Action": "s3:*",
    "NotResource": [
      "arn:aws:s3:::HRBucket/Payroll",
      "arn:aws:s3:::HRBucket/Payroll/*"
    ]
    }
}
```

3. What comes in your mind when a service need cross account access?

## Data Security
1. How do you secure data transfer in transit?
2. Do you agree that we need to enable data encryption at rest by default?

## Scenario Based questions:
###Scenario 1 (Lambda, SES and config rules) :
Task is to create lambda function for config rules and send email using SES.
I have multi account and one of the account is for organization level aggregator. Using that org aggregator account write a lambda function to retrieve all non-compliant config rules based on each aggregator. I wanted to have a list which has the following results 

Aggregator name = AggregatorTest
OrgConfigRule – VPCFlowlog-o30sfig, Non_complaint, Acc No: 23135134235
		Account id, Resource id, Resource type, AWS Region	
		Account id, Resource id, Resource type, AWS Region

So above we have an email configured for aggregator test and then got the list of all OrgConfigRule then after that whatever resources are there for that org config rule you need to list out and then send email to users using SES.

### Logging and Monitoring
1. Data integrity for cloudtrail logs 
2. How to get unencrypted EBS volume(s) in an easy way: config -> filter
3. cloudwatch -> metrics filter

### Infrastructure security
1. EC2 vulnerability patch management in automated way
2. What checks AWS Inspector does to figure out instance vulnerabilities

### Data protection
1. KMS key usage: s3 bucket, file download but can’t see the object. what solution do you propose
2. CMK keys auto-renew solution after 3 month (key rotation): cloudwatchevent to check it
3. What comes to your mind when you have to secure RDS instance?
4. When encryption by default is not enough?
5. Would you suggest key rotation? why and what should be the rotation period? Justify.

### IAM
1. Let's say an event is triggered and lambda does something. To make sure it works what you check in IAM

### Programming question (Depends on the role)
A non-decreasing number list is given and a target number. You need to print if target number exists in the list or print the most nearest number to the target number

## Some more Questions, if you still have time and out of quesitons
1. What are the top 3 things you would do if you are working on CSPM tool from the scratch.
2. What and how you check if AWS resource is deployed/implemented over encrypted communication/channel.
3. How do you make sure everyone in the organisation follow AWS security guideline while working with AWS Services?


**_You can help us to add more questions or even suggest any edits. Kind gesture to help the community is always welcome._**
