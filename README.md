# Phishing-Analysis-Tools-Phishing-Case-2

![image](https://github.com/user-attachments/assets/8372df34-406b-4656-86c4-182b8d3c8fbe)


## Project Report: Phishing Case 2 - Suspicious Email Analysis

### Introduction

As a Level 1 SOC Analyst, it's crucial to be vigilant when dealing with suspicious emails, as they can often be indicators of phishing attempts or more severe cyber threats. In this scenario, several suspicious emails were forwarded by coworkers, necessitating a thorough analysis to identify and mitigate potential risks. This report outlines the investigation carried out using Any Run, a tool for dynamic malware analysis, and details the findings to help the team implement the appropriate security measures.
Investigation and Findings

### 1. Classification of the Email

![image](https://github.com/user-attachments/assets/cf775208-4321-44b3-b687-a3b0bfaf1712)

#### Tool Used: Any Run.

Result: The email was classified as involving suspicious activity.

#### Analysis: 

The suspicious activity classification by Any Run indicates that the email contains elements that could potentially be malicious, such as dangerous attachments or suspicious links. This requires further scrutiny to prevent possible exploitation.

#### 2. Name of the Malicious PDF File

![image](https://github.com/user-attachments/assets/82a36ef7-04e1-4926-a150-b6c9dc9acb68)

Tool Used: Any Run (Text Report)


![image](https://github.com/user-attachments/assets/b4c6fd85-1cdd-4b37-97b0-892e931824bd)

Result: The PDF file associated with the email was named CC6F1A04B10BCB168AEEC8D870B97BD7C20FC161E8310B5BCE1AF8ED420E2C24.

##### Analysis: 

The file name, a long hash-like string, is typical of malware-laden files designed to obscure their true nature. Recognizing such file names can help in identifying potential threats quickly.

### 3. Malicious IP Addresses

![image](https://github.com/user-attachments/assets/50e8c7eb-20f3-4918-9cff-f9f65bd846e4)

Tool Used: Any Run (Text Report) and CyberChef for Defanging

![image](https://github.com/user-attachments/assets/19437ba9-1311-4044-9aac-2bb48653a28c)

Result: The two IP addresses identified as malicious were 2[.]16[.]107[.]24 and 2[.]16[.]107[.]83.

##### Analysis: 

These IP addresses were flagged due to their association with malicious activity. By defanging the IP addresses (replacing periods with brackets), they can be safely shared and analyzed without the risk of accidental connection.

#### 4. Windows Process Flagged as Potentially Bad Traffic

#### Tool Used: Any Run

![image](https://github.com/user-attachments/assets/8cd7de6b-5a4f-4a94-8e6b-a1c535c238db)


Result: The Windows process svchost.exe was flagged as generating potentially bad traffic.

##### Analysis: 

The svchost.exe process is a legitimate Windows process that can be exploited by malware to perform unauthorized actions. Detecting this process in a suspicious context often indicates that it has been compromised or is being misused by malicious software.


### Benefits and Experience Gained

#### Enhanced Analytical Skills

This investigation provided valuable experience in analyzing phishing emails using advanced tools like Any Run. It enhanced my ability to scrutinize suspicious emails, identify malicious elements, and determine the appropriate response.

#### Improved Threat Detection

The exercise improved my ability to detect and understand various indicators of compromise (IoCs), such as suspicious file names, malicious IP addresses, and exploited processes. Recognizing these IoCs is critical in early detection and prevention of cyber threats.

P#### ractical Experience with Malware Analysis Tools

I gained hands-on experience with Any Run, a dynamic malware analysis tool, which allowed me to visualize the behavior of potentially malicious files in real-time. This practical knowledge will be instrumental in future investigations and threat analyses.

#### Strengthened Security Posture

By identifying and understanding the threat vectors associated with these phishing emails, I am better equipped to recommend and implement security measures that will prevent similar attacks from affecting the organization.

#### Documentation and Reporting Skills

This project reinforced the importance of clear and thorough documentation when reporting findings from a cybersecurity investigation. The ability to document and communicate the results effectively ensures that the team can take informed actions based on the analysis.

#### Preparedness for Future Incidents

The knowledge and experience gained from this project have increased my preparedness for handling similar incidents in the future, particularly in the areas of phishing detection and malware analysis. This will enable me to respond swiftly and effectively to potential threats.

This report encapsulates the key findings from the investigation of the phishing emails and reflects on the benefits and experiences gained throughout the process. The insights and skills acquired will contribute significantly to ongoing and future cybersecurity efforts.

### Conclusion

The analysis of the suspicious emails using Any Run revealed critical information about the nature of the threat. The classification of the email as suspicious, the identification of a malicious PDF file, the discovery of malicious IP addresses, and the flagging of the svchost.exe process as potentially bad traffic were key findings. These insights will inform the necessary steps to strengthen defenses, including the implementation of security rules to block similar threats in the future.
