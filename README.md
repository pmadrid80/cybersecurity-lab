# cybersecurity-lab
IAM &amp; SOC Security Lab - Identity Management, SIEM, and Automated Security Operations
# IAM & SOC Security Lab

**Identity and Access Management | Security Operations | Threat Detection**

A comprehensive hands-on cybersecurity lab demonstrating enterprise IAM administration, SIEM deployment, and automated security operations workflows.

---

## 🎯 Project Overview

This lab replicates real-world enterprise security infrastructure to develop and demonstrate practical skills in:
- Identity and Access Management (IAM)
- Security Information and Event Management (SIEM)
- Security Operations Center (SOC) workflows
- Threat intelligence integration
- Security automation and orchestration

**Purpose:** Maintain and expand technical proficiency in modern cybersecurity tools while transitioning back to full-time information security work.

---

## 🏗️ Architecture

```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│  Kali Linux │────────▶│    Ubuntu    │────────▶│   Wazuh     │
│   (Attack)  │         │   (Target)   │         │   (SIEM)    │
└─────────────┘         └──────────────┘         └─────────────┘
                                                         │
                                                         ▼
                                                  ┌─────────────┐
                                                  │     n8n     │
                                                  │ (Automation)│
                                                  └─────────────┘
                                                         │
                                                         ▼
                                                  ┌─────────────┐
                                                  │ AbuseIPDB   │
                                                  │(Threat Intel)│
                                                  └─────────────┘

┌─────────────────────────────────────────────────────────────┐
│              Microsoft Azure AD / Entra ID                  │
│  (Identity Governance | User Lifecycle | Security Groups)   │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     Splunk Enterprise                       │
│        (Log Analysis | Identity Monitoring | SIEM)          │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔐 Identity and Access Management (IAM) Lab

### Microsoft Azure AD / Entra ID

**Tenant Configuration:**
- Cloud-based identity platform (Microsoft Azure)
- Global Administrator role
- Security Defaults enabled for baseline MFA enforcement
- US datacenter region

**User Lifecycle Management:**
- Created and managed 5+ user accounts with proper UPN conventions
- Configured Member vs Guest account types
- Implemented onboarding and offboarding workflows
- Managed user properties, licenses, and authentication methods

**Group-Based Access Control:**
- Deployed 3 Security Groups with role-based membership:
  - `Finance-Team` - Financial systems access
  - `Engineering-Team` - Development resources access
  - `IT-Admins` - Privileged administrative access
- Configured group properties and assignment rules
- Implemented least-privilege access principles

**Security Controls Implemented:**
- Multi-factor Authentication (MFA) enforcement via Security Defaults
- Conditional Access policy framework evaluation
- Sign-in logs monitoring for authentication anomalies
- Audit logs for change tracking and compliance
- Provisioning logs for lifecycle event tracking

**Identity Governance:**
- Explored Azure AD Identity Governance capabilities
- Reviewed access review processes
- Evaluated privileged identity management (PIM) concepts

**Key Concepts Demonstrated:**
- Role-Based Access Control (RBAC)
- Least Privilege Access
- Separation of Duties (SoD)
- User Lifecycle (Joiner/Mover/Leaver processes)
- Zero Trust security model foundations
- Compliance audit support (access documentation)

---

### Okta Identity Platform

**Tenant Configuration:**
- Cloud-based identity management (Okta trial tenant)
- Administrator role with full IAM privileges
- Multi-factor authentication enabled

**User Lifecycle Management:**
- Created and managed 6 user accounts
- Configured user activation and password policies
- Implemented onboarding workflows

**Group-Based Access Control:**
- Deployed 3 custom security groups:
  - `Finance-Team` - Financial systems access
  - `Engineering-Team` - Development resources access
  - `IT-Admins` - Privileged administrative access
- Configured group descriptions and membership rules

**Authentication & Security:**
- Multi-factor authentication with multiple factors:
  - Email authentication
  - Google Authenticator
  - Okta Verify (mobile app)
- Password policies and account lockout protection

**Key Concepts Demonstrated:**
- User lifecycle (activation, provisioning, deprovisioning)
- Role-Based Access Control (RBAC) via groups
- Multi-Factor Authentication (MFA) configuration
- Identity provider administration
- Okta Admin Console navigation and management

---
## 🛡️ Security Operations Center (SOC) Lab

### Detection Pipeline Architecture

**Attack Simulation:**
- **Kali Linux** virtual machine for controlled penetration testing
- Simulates realistic attack vectors:
  - Brute force authentication attempts
  - Port scanning and service enumeration
  - Privilege escalation attempts
  - Lateral movement scenarios

**Target Environment:**
- **Ubuntu Linux** server as attack target
- Configured with intentional services for monitoring
- Logs forwarded to SIEM for analysis
- Network traffic captured for forensic analysis

**SIEM Deployment:**
- **Wazuh** open-source SIEM platform
- Real-time log collection and correlation
- Custom detection rules for:
  - Failed authentication attempts
  - Unauthorized access attempts
  - Privilege escalation indicators
  - Suspicious network activity
  - File integrity monitoring events

**Security Automation:**
- **n8n** workflow automation platform
- Automated alert triage workflows
- Integration with threat intelligence feeds
- Automated IOC (Indicator of Compromise) enrichment
- Response orchestration capabilities

**Threat Intelligence Integration:**
- **AbuseIPDB** API integration
- Automatic IP reputation lookups
- Known malicious actor identification
- Context enrichment for security alerts
- Threat scoring and prioritization

**Splunk SIEM:**
- Splunk Enterprise deployment
- Identity-focused use cases:
  - Authentication event monitoring
  - Failed login pattern detection
  - Privileged account activity tracking
  - Impossible travel detection scenarios
- Dashboard creation for security metrics
- SPL (Search Processing Language) query development

---

## 🎓 Skills Demonstrated

### Identity and Access Management
- Enterprise IAM administration
- User lifecycle management (provisioning/deprovisioning)
- Role-Based Access Control (RBAC) implementation
- Multi-Factor Authentication (MFA) configuration
- Conditional Access policy design
- Security group management
- Access review and audit processes
- Identity governance principles
- Privileged Access Management (PAM) concepts

### Security Operations
- SIEM deployment and administration (Wazuh, Splunk)
- Log collection and correlation
- Security event detection and analysis
- Custom detection rule creation
- Alert triage and investigation
- Incident response workflows
- Threat intelligence integration
- Security automation (SOAR concepts)

### Technical Platforms
- **Cloud:** Microsoft Azure, Azure AD/Entra ID
- **SIEM:** Wazuh, Splunk, OSSIM (previous experience)
- **Automation:** n8n workflow engine
- **Operating Systems:** Linux (Ubuntu, Kali), Windows
- **Scripting:** Bash, basic Python
- **Networking:** SNMP, log forwarding, network monitoring

### Compliance and Governance
- Understanding of compliance frameworks (PCI-DSS, NERC/CIP)
- Audit log management
- Access control documentation
- Security policy enforcement
- Change management processes

---

## 📊 Use Cases and Scenarios

### IAM Security Scenarios

**1. User Onboarding:**
- Create new user account in Azure AD
- Assign to appropriate security group based on role
- Configure MFA requirements
- Provision access to necessary resources
- Document access grants for compliance

**2. Privileged Access Management:**
- Identify privileged accounts requiring additional controls
- Implement MFA for administrative access
- Monitor privileged account activity through SIEM
- Create alerts for suspicious admin behavior

**3. Access Review:**
- Periodic review of group memberships
- Identify and remediate excessive permissions
- Document access decisions for audit
- Implement least-privilege principles

### SOC Detection Scenarios

**1. Brute Force Attack Detection:**
- Kali generates multiple failed SSH login attempts
- Wazuh detects pattern of failures from single source IP
- Alert triggers n8n automation workflow
- AbuseIPDB confirms IP reputation
- Automated response: temporary IP block + alert escalation

**2. Privilege Escalation Attempt:**
- Attacker attempts unauthorized sudo command
- Wazuh correlates with user account and access level
- Alert generated for privilege boundary violation
- Investigation workflow triggered
- Incident logged for security review

**3. Impossible Travel:**
- User login from Location A
- Second login from distant Location B within unrealistic timeframe
- Alert generated based on geolocation correlation
- Investigation triggered for potential credential compromise
- MFA enforcement verification

---

## 🏆 Certifications

**Current:**
- CompTIA Security+ (2025)
- Splunk: Intro to Splunk (eLearning) - February 2025
- Splunk: Using Fields (eLearning) - February 2025

**Professional Background:**
- Information Security Administrator - NextEra Energy Resources (2012-2014)
  - Enterprise IAM using SAP CUP/GRC and Active Directory
  - RSA SecurID two-factor authentication administration
  - NERC/CIP compliance and security audits
- SOC Security Analyst - ECIJA USA (2009-2011)
  - SIEM operations with OSSIM/AlienVault
  - Security incident investigation and response
  - Vulnerability assessment and threat analysis

---

## 🚀 Future Enhancements

**Planned Additions:**

**IAM:**
- [ ] Integrate Azure AD with on-premises Active Directory (hybrid identity)
- [ ] Implement Single Sign-On (SSO) with SAML applications
- [ ] Create automated user provisioning workflows with API integration
- [ ] Deploy Privileged Access Management (PAM) controls
- [ ] Implement Just-In-Time (JIT) access workflows

**SOC:**
- [ ] Add EDR (Endpoint Detection and Response) capabilities
- [ ] Implement SOAR playbooks for common incident types
- [ ] Integrate additional threat intelligence feeds (VirusTotal, OTX)
- [ ] Create custom Splunk dashboards for executive reporting
- [ ] Deploy honeypot for attacker behavior analysis

**Integration:**
- [ ] Forward Azure AD sign-in logs to Splunk/Wazuh
- [ ] Create correlation rules between IAM events and network activity
- [ ] Implement automated account lockout on suspicious activity
- [ ] Build compliance reporting dashboards (SOX, HIPAA, PCI-DSS)

---

## 📚 Technical Documentation

### Key Learnings

**IAM Administration:**
- User Principal Name (UPN) formatting and domain management
- Difference between Member and Guest account types in Azure AD
- Security Groups vs Microsoft 365 Groups (use cases and architecture)
- Security Defaults vs Conditional Access (capabilities and licensing)
- Identity lifecycle stages (Joiner/Mover/Leaver)
- Audit log interpretation for access governance

**SIEM Operations:**
- Log normalization and field extraction
- Event correlation techniques
- Alert tuning to reduce false positives
- Threat intelligence contextualization
- Investigation workflow optimization

**Security Automation:**
- Workflow design for repeatable security processes
- API integration for data enrichment
- Alert prioritization algorithms
- Automated vs manual response decision trees

---

## 🔗 Related Resources

**Microsoft Azure AD / Entra ID:**
- [Microsoft Entra ID Documentation](https://learn.microsoft.com/en-us/entra/identity/)
- [Azure AD Security Operations Guide](https://learn.microsoft.com/en-us/security/)

**Wazuh SIEM:**
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Wazuh Use Cases](https://wazuh.com/use-cases/)

**Splunk:**
- [Splunk Documentation](https://docs.splunk.com/)
- [Splunk Security Essentials](https://splunkbase.splunk.com/app/3435/)

**Security Frameworks:**
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

---

## 👤 About

**Penelope Madrid**  
Identity & Access Management Professional | Security Operations | Compliance

- 📍 Doral, FL | Open to Remote Opportunities
- 🌐 LinkedIn: [linkedin.com/in/penelope-madrid-152070324](https://linkedin.com/in/penelope-madrid-152070324)
- 📧 pmadrid80@gmail.com
- 🗣️ Bilingual: English & Spanish

**Professional Focus:**  
Returning to full-time cybersecurity with specialization in Identity and Access Management. Combining enterprise IAM experience (SAP CUP/GRC, Active Directory, RSA SecurID) with modern cloud platforms (Azure AD/Entra ID) and current SIEM capabilities (Wazuh, Splunk). Strong background in compliance (PCI-DSS, NERC/CIP) and security operations.

**Seeking:** IAM Analyst, IAM Administrator, or Security Engineer roles where I can apply proven identity governance expertise with updated technical skills.

---

## 📝 License

This project is for educational and portfolio demonstration purposes.

---

**Last Updated:** February 2025  
**Status:** Active Development
