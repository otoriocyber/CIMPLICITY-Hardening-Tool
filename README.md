# General Electric CIMPLICITY Hardening Tool
Version 1.0
## Overview
Powershell script for assessing the security configurations of windows machines in the CIMPLICITY environment.

## Dependencies
None! The script is Powershell 2.0 compatible. 
Powershell >=2.0 is pre-installed on every Windows since Windows 7 and Windows Server 2008R2.
The tool was tested on:
* Windows 7
* Windows 10
* Windows Server 2008 R2
* Windows Server 2012 R2
* Windows Server 2016

## Usage
Run the script as an administrator.

## Description
Collects data from the following sources:
* Windows Management Instrumentation (WMI)
* Windows registry
* Security Policy
* Netstat
* Dirlist
* Net and Netsh Commands

Analyzes the collected data according to OTORIO's profound research on CIMPLICITY security and hardening.
The security recommendations are based on the CIMPLICITY's "Secure Deployment Guide" and the attached "Windows Hardening Guide".
* https://www.ge.com/digital/sites/default/files/download_assets/cimplicity-secure-deployment-guide.pdf
* https://digitalsupport.ge.com/communities/en_US/Documentation/WINDOWS-HARDENING-GUIDE-and-RECOMMENDATIONS-WINDOWS-SERVER-2012-R2

You should refer to those documents for further instructions and security recommendations.

The research was based on the latest CIMPLICITY 11 version but is relevant for earlier versions as well.
                                              
## Insights

| #  | Insight                                                   | Data source                     | Details                                                                                              | Recommended state                                                                                                               |
|----|-----------------------------------------------------------|---------------------------------|------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| 1  | Password minimum length                                   | Security Policy                 | The policy determines the minimum length of the password                                             | The password should be at least 14 characters                                                                                   |
| 2  | Password complexity                                       | Security Policy                 | The policy determines a complexity policy for passwords                                              | Password complexity policy should be enforced                                                                                   |
| 3  | Password cleartext                                        | Security Policy                 | The policy prevents password from being stored as cleartext or in reversible encryption              | The policy should be enforced                                                                                                   |
| 4  | Account lockout policy                                    | Security Policy                 | The policy determines a maximum number of failed login attempts, after it the account will be locked | The maximum number should be at least 5                                                                                         |
| 5  | Audit policies                                            | Security Policy                 | The policies determine which actions will be audited                                                 | See GE's recommendations in the table below                                                                                     |
| 6  | Default Guest and Admin accounts are disabled             | Security Policy                 | Checks if the default Guest and Admin accounts are enabled, usually unnecessary users                | The accounts should be disabled                                                                                                 |
| 7  | Number of administrator users                             | WMI                             | The number of administrator users should be restricted                                               | The maximum number is configured to 2 users                                                                                     |
| 8  | Windows logging policies                                  | Registry                        | Checks if windows logs are enabled                                                                   | Verify that windows "Application", "Security" and "System" logs are enabled                                                     |
| 9  | Screen saver configuration                                | Registry                        | Checks if a screen saver is enabled and if is secure with a password                                 | If screen saver is enabled it should be secure with a password                                                                  |
| 10 | Unnecessary open ports                                    | Netstat Command                 | Check unnecessary open ports on the computer                                                         | The TCP port 135,139,445 and the UDP ports 135,137,138,445 should be closed if not used                                         |
| 11 | Shares that allow access to "Everyone"                    | WMI                             | Checks if there are shares that allow access to "Everyone"                                           | Access to all of the shares should be restricted only to necessary users                                                        |
| 12 | Anonymous access to computer shares and named pipes       | Registry                        | Checks if there any shares or named pipes that anonymous access is allowed to                        | Anonymous access should be completely restricted                                                                                |
| 13 | Debugging privileges                                      | Security Policy & WMI           | This policy determines which users will have permissions to debug programs                           | This policy should be restricted to administrators only                                                                         |
| 14 | Remote desktop settings                                   | Registry                        | Checks if RDP is enabled and if it will always prompt for password upon connections                  | If not used RDP should be disabled, if enabled it should always prompt for password                                             |
| 15 | IPsec communication                                       | Netsh Command                   | Checks if IPsec communication is configured to encrypt CIMPLICITY communication                      | Communication in all of the defined ports should be encrypted, Refer to the IPsec section below for more relevant information   |
| 16 | CIMPLICITY files in open shares                           | Net Command + Dirlist on Shares | Checks if there are any CIMPLICITY projects (.gef) or screens (.cim) in any shares                   | It is recommended to not store any CIMPLICITY files in shares                                                                   |

## Audit policies - Insight #5
| #  | Policy                     | Recommended state         |
|----|----------------------------|---------------------------|
| 1  | AuditLogonEvents           | Success and Failure       |
| 2  | AuditAccountLogon          | Success and Failure       |
| 3  | AuditObjectAccess          | Success and Failure       |
| 4  | AuditPrivilegeUse          | Failure	                  |
| 5  | AuditAccountManage         | Success and Failure       |
| 6  | AuditPolicyChange          | Success and Failure       |
| 7  | AuditSystemEvents          | Success and Failure       |
| 8  | AuditProcessTracking       | Success and Failure       |
| 9  | AuditDSAccess              | No Auditing               |

## IPsec rules - Insight #15
The test in the script ensures that CIMPLICITY client-server communication in the default ports is included in the firewall rules that defines IPsec protection.
If the current machine has another rule, such as Historian, additional network functionality, such as communication with a secondary server, or the machine doesn't use default ports, there are different or additional ports that will need to be protected by IPsec.
You can improve the test by adding those ports to the variable $IPSEC_PORTS in the beginning of the script. 
For information about the used ports and instruction for IPsec correct configuration refer to the Windows Hardening Guide (Link above).    

## Authors
Yuval Ardon, Amit Porat, Roman Dvorkin from OTORIO's Research Team.


For any questions/suggestions feel free to contact us at <matan.dobr@otorio.com>
