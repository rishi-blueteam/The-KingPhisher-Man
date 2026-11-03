# The Kingphisher-Man SOC Lab For Windows


## Architecture of SOC-Lab for Windows


Github (Phishing Pot)[Phishing .EML files Selection] -> Sent to Code for Analysis -> .eml file analysis > Output > Send to Gmail Inbox  

Architecture Image: 



## Workflow, Delievery and Handling of Malcious EML Files.


```
[ Incoming Personalized Email / .eml Injection ] ➔ ➔ ➔ [ Enters @gmail.com Inbox ]
                                                   │
                                                   ▼ (Triggered Instantly)
                                         [ GMAIL API EVENT LISTENER ]
                                                   │
 ┌─────────────────────────────────────────────────┴─────────────────────────────────────────────────┐
 ▼ (Step 1: Immediate Quarantine Simulation)                                                          ▼ (Step 2: Analysis)
[ Remove 'INBOX' Label ] ➔ [ Apply 'TEMPORARY_HOLD' Label ]                                   [ Download Message Data as .eml String ]
              │
                                                                                                     ▼
                                                                                              [ RUN CODE ANALYSIS CHAIN ]
                                                                                                     │
 ┌───────────────────────────────────────────────────────────────────────────────────────────────────┴──────────────────────────────────┐
 ▼ IF VERDICT = CLEAN (Step 3A)                                                                                                         ▼ IF VERDICT = MALICIOUS (Step 3B)
1. Inject HTML Verdict Banner to Email Body String.                                                                                    1. Apply 'QUARANTINE' / Trash Label.
2. Send updated email copy back to Inbox via SMTP/API.                                                                                 2. Permanently delete/archive the original message.
3. Trash/Delete the original un-analyzed email from 'TEMPORARY_HOLD'.                                                                   3. Alert admin/console of blocked thread.
```


### Phase 1: Github .eml Extraction and Gmail Inbox (Version-1.0) (No Update Needed)

**Section 1: Gmail Inbox Security Code** 

Go to the app authentication for Gmail so that we can fetch the 16 bit code SO, that I can use this to send any eml files to the Inbox.

**URL:** https://myaccount.google.com/apppasswords

![APP Code Email](image.png)

Now we will copy the code but we have to be sure to note down the code so that we can enter in the code and the code can then recieve the eml file.

**Section 2: Eml Fetching from Github to Inbox**

- Now, our code second main function working is, 5 Random .eml files are picked and sent to the users email inbox, all of them gets delivered. 

- None of the content of the eml file will ever be touched in this scenario (Body, Recipient, sender, reciever, metadata), only it shall be taggin the external user in this case which will be me in their BCC.

![alt text](image-1.png)

**Section 3:** Sending Personalized Mail from a Attacker account to user target

This section briefs on how an Attacker (Personalized Attacker) will try to send Phishing Emails to our (user Account). This involve only small configuration needed but this is attached as a different section of code itself. 

![alt text](image-3.png)


### Phase 2: Email Analysis for .eml Files (Version-1.0)

**Part 1:** All .eml files will first be sent to the Email Analyzer Code first for analysis that does the analysis properly.

The Phishing Email analysis will be done for all important phases: 

#### Section-1: Header Analysis (Version-1.0)

Helps to extract key meta data as shown from this image:

![alt text](image-2.png)

From, TO, Reply To, Delivered To, Subject, File attachments, Ip address (Defanged), Header Authentication Details, and Originating IP Details. 

#### Section-2: Domain Analysis 

Domain Analysis is crucial aspect for analyzing potential phishing emails because there are various potential phishes out there 
that tries to represent an organization and end up tricking the user to click and interact with the contents of the phishing email.

Fetching domains to conduct manual phishing analysis is time consuming and takes in a lot of amount of effort, since for a phishing there is more than just a phishing email, this is where Domain Analysis must be run against a set of rules and tool to ensure that we get a clear verdict of known and unknown domains. 

More can be read from the **Domain Analysis Directory**: <ENTER URL HERE>

#### Section-3: Attachment Analysis 

Cannot be ignored ever, any given file that seems legtimate may not be the best file to be trusted and used just because it has a friendly name. Proper analysis must be done for files, by collecting their hashes and verifying if they are safe or no. Deeper analysis must be conducted specially files that have a suspicious hash, or a malcious reading must ran in sandbox so that we can know the output of how exactly files behave, and what is their affect on the system.

More will be given over here: <enter url here>

As of now basic file analysis is covered in the project.

#### Section-4: URL Analysis

This goes without saying one of the most powerful, weapon used by any attacker to trick users into click onto a link that is potentially suspicious, and malacious too. Testing of these links, with each click and redirect is espcially if these domains, website age, and many other factors do not mactch creates a serious red flag that URL attached in the email is malacious. 

More of the URL Analysis will be mentioned here: <enter url here>

#### Section-5 IP Address

This section involves doing IP address look

#### The JSON Verdict (Output only)

After all of these layers of Phishing Analysis is ran, our verdict is just not a terminal output it is a whole process defined in a json output by correlating these scores together to give a strong foundation as to why this particular Phishing Email is a malcious one. These can be used to import it to Wazuh alerts, so that the dashboard can give precise data towards the gmail file on the client's endpoint

> Note: The JSON alert details on dashabord are yet to be tested.

Phase-1-(Version-1.0) working mentioned here: <Enter URL Here>

### Phase 3: Hand Crafted Email Analysis

#### Section-1 The Phisherman's Big Phish 

This phase invloves the inbox actively waiting for any kind of email delivery from the attacker's domain. The attackers send email to the user, the email reaches the users inbox. Our code run in the backend waiting for the Gmail's inbox for any unread email. 

It keeps polling awaiting for any kind of response from the inbox for any incoming email. As the email reaches the inbox. The poll gets the information of the new .eml file received, eml file gets downloaded. 

#### Section-2 The Phishers Phish Verdict

Now the downloaded file will be a part of the tmp.log file and will go for analysis. As the new received file will be gettting analyzed from one end, on the other end from the inbox for a temporary time it will be going to archieve. As the verdict comes out as a safe or malacious accordingly a banner will be added. 

If the file is malcious it will be sent to trash, if it is safe, then it will be resent to the inbox with the updated verdict banner seen on top.

> Note: In this particular case since we are doing this from a specific attacker (who we totally control), that means we keep this duration for a short span of 2 mintues so that if 2 minutes timer is up then the code execution ends and further emails from this attacker won't be analyzed.

-----
### Phase 2 : Sub-Tool Strengthening

####  Section 2 (Version 1.1) : Domain Analysis for .eml Files Updated


> We create a stronger domain analysis update where it follows huerstic behavior towards any incoming email file from the attacker to the user.

Read more about the co-relation rules, the tools and how domain analysis strenthens over here to ensure a verdict given by the domain analysis is precise and not just consisting too much of noise.  

Domain Analysis Readme.md: <\eNTER URL HERRESACACSSA/> 


## Maintaining This README

Update this overview when the project's **current working capabilities or version status change**.

- **Project Overview:** Update if the project's main purpose or scope changes.
- **Current Workflow:** Update when a workflow is added, removed, or materially changed.
- **Current Version:** Update the version number and summarize the latest functional changes.
- **Known Limitations and Planned Work:** Remove completed items and add newly identified limitations or planned enhancements.
- **Repository Structure:** Update if major components or directories are added, removed, or reorganized.

Keep detailed implementation notes, setup instructions, configuration, and component-specific changes in their respective README files. This file should remain a concise overview of the project's current state.




