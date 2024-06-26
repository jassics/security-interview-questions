# Application Security Interview Questions

## Setting up the context
You can assess yourself by checking how many of these application security interview questions are easy for you, how many need finetuning and how many are yet to learn and master. Remember, every one of us is learning and a question is easy for you doesn’t mean it’s the same for everyone. However, it depends upon the role, and expectations set by the hiring manager and the interviewer.

The question might look straightforward but your answer speaks more about your experience and hands-on in this domain. Try to analyze the question and answer honestly. 

Many questions might not be for your experience or role as I am sharing mixed questions asked for various roles in the Application Security domain. 

Also, I am not sharing questions on any programming language-specific or even programming-based security questions. That can possibly be another series of questions in my next release.

### First thing first
This interview question set is mostly for defensive roles as compared to offensive roles which are mainly called “Penetration Testing or Web Security (sometimes it’s used interchangeably) ”. I will concentrate more on how an application is developed, maintained, and deployed and how as a security engineer you would help an engineering team to overcome security challenges.


### Second important note
I am listing questions based on a few criteria:

1. Common to everyone who is in this domain or trying to enter this domain.
2. Some questions would be theoretical and you can consider those questions as a starting point to check the candidate’s overall knowledge
3. Some questions are for senior professionals
4. Some questions may have different answers depending on seniority level
5. Some questions can be to check your domain and leadership skills in this domain

**_One more thing_**

If you are new to this domain or planning to make a career in cybersecurity. You should see the study plan before delving into interview questions.

__They are:__

1. Common Skills Study Plan that you can finish within 3 months
2. 20 Essential books that you should read from security world
3. Application Security Study Plan (You must go through it before trying for appsec interviews)
4. You can’t ignore API security at present. So, here is your API Security Study Plan
5. Knowledge of Pentest will be an added advantage for you. Check this out: Web Pentest Study Plan
6. You can star or bookmark Security Study Plan which will give you an insight into what to study for various security domains.

## This space will focus more on:

1. Secure Code Review
2. Threat Modeling
3. Secure Coding
4. Secure Development
5. And anything that is defensive in nature and developer centric. For everything else related to [web security we have another page](web-security-interview-questions.md).

If you are interviewing someone for Application Security Engineer role, could be juinor, senior or architect level.
You can always start questions based on the person's experience in AppSec. However, below questions can be always interesting and will help you to understand the candidate better technically.
Soft skills, team player, presentation skills, communication skills are out of the scope of this space.

### Application Security Basics Questions
1. Explain your top 3 favorite OWASP Top 10 vulnerabilities and why
2. How does TCP 3-way handshake work?
3. Why is TLS important in cybersecurity and can you explain the use of TLS in detail for a website?
4. How SSL/TLS makes my content secured over the internet?
5. What happens when you type google.com in your browser?
6. What’s the difference between SAST and SCA?
7. What is SQLi and how would you prevent/mitigate it?
8. Explain XSS with a few examples and how it can be avoided in the current software world.
9. How to avoid brute-force attacks on an application. Let’s say the login page. Explain everything that comes to your mind.
10. Tell us about a time when you had to learn something new really quickly and how did you go about it?

### Application Security Role-based questions
1. Explain CORS, SOP, and CSP from security point of view
2. How is CSRF dangerous for an application and what must be done to prevent CSRF in an application?
3. Explain the concept of input validation and why it is crucial for secure coding. Provide examples.
4. How do you approach secure error handling and logging in an application?
5. Discuss the role of encryption in secure coding and some best practices for implementing it.
6. What are some best practices for managing secrets and sensitive information in code?
7. How do you ensure the security of third-party libraries and dependencies in your code?
8. What are the key differences between manual code review and automated static analysis?
9. Describe your approach to conducting a secure code review. What do you look for first?
10. Can you give an example of a security vulnerability you discovered during a code review and how you addressed it?
11. Which secure coding standards do you follow during a code review (e.g., OWASP, CERT)?
12. How do you balance between finding security issues and maintaining development velocity during a secure code review?
13. Describe the STRIDE threat modeling methodology and provide examples of each threat type.
14. How do you prioritize threats identified during a threat modeling exercise?
15. How would you integrate threat modeling into an Agile development process?

### Overall Application Security Assessment-based Questions
1. Where do we need security in the SDLC phase?
2. What would you suggest for input sanitization?
3. What should a developer do for secrets management?
4. What are some strategies for ensuring secure session management in web applications?
5. How do you handle security misconfigurations in development and production environments?
6. Discuss the importance of least privilege and role-based access control in application security.
7. How do you ensure that logging and monitoring are implemented securely and do not expose sensitive information?
8. What are the challenges of implementing SDL in a fast-paced development environment, and how do you overcome them?
9. Describe the various phases of SDL and the security activities involved in each phase.
10. How can an attacker exploit SSRF and what an application developer must do to prevent SSRF? This medium article might help you to understand how to bypass SSRF protection.

### Some common “test your problem-solving skills” Application Security questions (mostly for senior roles)
1. What step would you plan to ensure developers follow secure coding practices?
2. How would you make developers aware and involved in secure code development?
3. How do you handle typical developer and security clash situations?
4. What were your interesting findings in the secure code review?
5. What are the common vulnerabilities you have experienced so far?
6. How would you approach identifying and mitigating security risks in a large, legacy codebase that hasn’t been regularly maintained for security?
7. Describe a strategy to ensure secure coding practices in a multi-team development environment, especially when teams are working on interdependent components.
8. How would you implement and enforce a secure coding standard in a globally distributed development team?
9. How would you design a security strategy to protect a microservices architecture from both external and internal threats? What are the challenges you might face while designing and implementing it?
10. Describe how you would conduct threat modeling for a cloud-native application. What specific security concerns are most critical in any cloud native application?
11. Can you provide an example of how you have implemented SDL in a past project?
12. What are some key metrics you would track to measure the effectiveness of an SDL program?

### Application Security Scenario-based interview questions
Consider this section as the toughest one and mainly for senior appsec professional.

1. How would you design a safe and secure password mechanism?
2. Can you explain the password hashing function and the importance of salt? Also, how salting and hashing passwords are used in this domain?
3. You use the SCA tool to find vulnerabilities in 3rd party libraries. How would you mitigate those vulnerabilities found and risks associated with third-party libraries and frameworks?
4. Your company is developing a new financial application that handles sensitive customer data, including banking information. Describe how you would approach threat modeling for this application. What specific threats would you consider, and how would you prioritize and mitigate them?
5. You are tasked with performing a secure code review for a web application that has been recently developed. During the review, you find several instances where user inputs are directly concatenated into SQL queries. Explain how you would address this issue and guide the development team to implement a secure solution.
6. A development team is working on a new feature that requires handling and storing user passwords. They plan to use a simple hash function (e.g., MD5) to store these passwords. As a security architect, how would you advise them on securely handling and storing passwords? Provide a detailed explanation of best practices.
7. During a code review, you discover that the application does not properly handle errors and exceptions. For example, stack traces are exposed to end users, which could potentially reveal sensitive information. Describe how you would rectify this situation and implement secure error handling and logging practices.
8. A critical vulnerability is discovered in a third-party library used extensively in your company’s application. Explain the process you would follow to assess the impact, communicate with stakeholders, and implement a fix. How would you prevent similar issues in the future?
9. You are designing the architecture for a new e-commerce platform that includes a web application, mobile application, and backend APIs. Outline the security architecture you would propose, including key components and technologies to ensure robust security across all layers.
10. How would you review an architecture to prevent an automated brute force attack or dictionary attack (think of different brute force attack techniques)?

### Secure Code Review round with code snippets
Many companies won’t have this round, but I feel one should involve a few code snippets in an interview to check the candidate’s indirect coding knowledge from security point of view, at least for a senior role like a lead or staff role. 

Insecure code snippets can be on a tougher note. However, I am adding a few easy ones for practice and to give an idea of how this round can be prepared well as per the JD.

I would give you a hint for your practice, but in an interview, you won’t be given any hint.

1. Identify the security issue in this code snippet and explain how you would fix it. [Hint: Can you spot the CSRF issue here?]
```php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userId = $_POST['userId'];
    $newEmail = $_POST['newEmail'];
    updateEmail($userId, $newEmail);
}
```

2. Identify the security issue in this code snippet and explain how you would fix it. [Hint: Insecure desrialization]

```java
ObjectInputStream in = new ObjectInputStream(new FileInputStream("data.ser"));
Object obj = in.readObject();
in.close();
```
3. Identify the security issue in this code snippet and explain how you would fix it. [Hint: password hashing issue]

```python
import hashlib
def store_password(password):
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    save_to_database(hashed_password)
```    
4. Which security issue it can cause? [Hint: XSS]

```typescript
const userInput = request.query.userInput;
const output = "<div>" + userInput + "</div>";
response.send(output);
```
5. Most common question asked in a secure coding round. It doesn’t need a hint I suppose. What issue this code snippet would cause and how would you help the developer in fixing it?

```javascript
String userId = request.getParameter("userId");
String query = "SELECT * FROM users WHERE user_id = '" + userId + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```

## Topics or concepts that are subjective and can check your in-depth knowledge regarding that area
### 1. What do you think about the good password?
    
This question looks very similar, but can help the interviewer to understand if the person has experience with password management related skills or not. 
    
This question will help you to drill down to more specific questions to understand the competence of the candidate:
   1. What is complex password
   2. Should the password complexity be same for admin and user
   3. How do you save the password in Database, encrypted or hashed or plain text
   4. Do you use salt? Is it same for all the password? is it random in nature per user?
   5. How do you make your code safe for password attacks?

### 2. How do you stop bruteforce attack on login/signup/forgot password page(s)?
This question helps you to understand if the person is aware of secure code development and secure design for such features and how far he/she can think.
Check if the person talks about:

1. Captcha 
2. CSRF token
3. Rate Limiting
4. MFA
5. Alert and Monitor for such anomalous behavior
6. Account Lockout after n failed attempts

### 3. What happens when you type google.com on browser
This question is just to check if the person understands the behind the curtain scene like url to IP conversion, DNS involvement, server response and so on.
Listen the interviewee and see if he/she mentions below things:
1. How DNS resolves the url 
2. TCP 3 way handshake
3. How HTTPS work and what's its advantages
4. How to prevent the application from MiTM (Man in The Middle Attack)

### 4. How SSL/TLS actually makes my content secured over the internet
This question is the extension of previous question to understand if the person understands:

1. How client server hello established
2. How key exchange happens i.e. public key or certificate
3. Is it symmetric or asymmetric encryption or both and when it is used 
4. Talks about Certificate Signing Request (CSR)
5. What are weak ciphers and what are good SSL Cipher Suites
6. Able to use openssl command to see the details of ssl information
7. Can explain ssl format like this: **TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256**
8. TLS 1.2 or TLS 1.3 and why? 
9. What is PFS (Perfect Forward Secrecy) and why it is used?
10. Why https enabled website still gets hacked?

### 5. How you would make developers aware and involved for secure code development?
This question would help you to understand if the person has delivered any training, presentaed slides, gave demo, delivered secure coding practices workshops.
See if person talks about:

1. OWASP ASVS (Application Security Verification Standard)
2. OWASP Top 10 2017/2021
3. OWASP Secure Review with some examples
4. Secure Design Principles
5. Then you can go little deeper like what difficulties you faced while giving training to them on secure code design, principles etc.
6. How do you make sure developers follow what you taught or made aware? IDE plugin, git actions, SAST tools etc?

### 6. Which one would you prefer and why? Manual secure code review or automated or both ?

### 7. Which tools have you used for SAST?

### 8. What is the difference between SAST and SCA?

### 9. How well you understand SQLi (SQL Injection)?
See if the person is able to explain:

1. When data becomes code and how to test it
2. Any specific tool to fasten SQL Injection
3. Can you spot SQLi from code review
4. Experience of any SAST tool through which you can verify and validate SQLi
5. Mitigation for SQLi
6. Prepared statement in sql injection

### 10. Do you understand the key difference between encryption, hashing, salt, obfuscation and encoding?

### 11. What you should check if the website is damn slow suddenly?

### 12. Explain how do you handle AuthN and AuthZ?
An interviewer can assess whether the candidate has a robust and comprehensive understanding of both authentication and authorization, as well as their practical application in ensuring application security.

#### Depth of Understanding:

Does the candidate understand the fundamental differences and purposes of authentication and authorization?
Are they able to explain common methods and protocols for both AuthN and AuthZ?

#### Practical Knowledge:

1. Can the candidate discuss specific implementations and technologies (e.g., OAuth, SAML, RBAC)?
2. Do they mention industry best practices and why they are important?

#### Security Focus:

1. Is the candidate aware of common security risks and how to mitigate them in both AuthN and AuthZ?
2. Do they highlight the importance of monitoring and logging?

#### Experience:

1. Can the candidate provide examples from past experience where they have implemented or improved AuthN and AuthZ mechanisms?
2. Are they able to discuss challenges faced and how they overcame them?

#### Current Trends:

1. Is the candidate up-to-date with current trends and emerging technologies in authentication and authorization?
2. Do they mention advanced methods like biometrics, adaptive authentication, or zero trust models?

### 13. How do you implement CSP? Do you think it adds extra security for a web application? How?
Go as much deep as you can.
Use this article to [understand details of CSP](https://hackernoon.com/everything-you-need-to-know-about-content-security-policy-csp-qt2g37wv)

### 14. Benefits of using SoP, CORS and CSP? 
Explain the basics of these concepts with one or two real world examples.
Also, explain why to use these and where with few scenarios.

### 15. How do you handle typical developer and security clash situation?

### 16. List out the techniques used to prevent web server attacks
Check what all points one can cover and then you can deep dive based on the answer:

1. Patch management
2. Web Server hardening
3. Scanning system vulnerability
4. Custom vs default port
5. Firewall and other server setting avoiding default settings
6. Proper alerting and monitoring mechanism
7. Server log settings

### 17. List out the steps to successful data loss prevention controls.
See if the interviewee is able to explain below points:

1. Information risk profile 
2. Assign roles and responsibilities to the technical administrator, incident analyst, auditor and forensic investigator 
3. Develop the technical risk framework 
4. Expand the coverage of DLP controls 
5. Monitor the results of risk reduction
6. Incident Response, risk severity, playbook etc.

### 18. Where do we need security in SDLC phase?

### 19. What would do you suggest for input sanitization?

### 20. What have you done so far for API Security?
You can't think of application security without API security at present. However, I will cover more on [API security Interview Questions](/api-security-interview-questions.md) in another page.

### 21. Why XoR is very important in Crypto world?
It's basic of Cryptography but untouched topic and I would recommend every AppSec engineer to go through basics of Cryptography.

### 22. How OAuth works?

### 23. What is SCA and how do you perform SCA?

### 24. What should a developer do for secrets management?

### 25. What is your interesting finding in secure code review?

## Summary
I have tried to cover all the possible questions from basics to advanced from various topics under the AppSec domain like Threat Modeling, Secure Code Review, OWASP Top 10, Secure Design, Cryptography (basics), Overall understanding of application from a security perspective, dealing few scenarios with agile development, developers etc. All the best for your bright future and hope this set of questions would help you to excel in an interview.

I will try to add more security interview questions for specific role as well. Please share in the comments which one you want to see next. Some examples are Sr. or Lead AppSec Engineer, AppSec Architect, DevSecOps engineer, and Product Security Engineer role.