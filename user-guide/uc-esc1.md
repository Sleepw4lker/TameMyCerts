### How TameMyCerts can reduce severity of attacks against the ESC1 attach vector {#uc-esc1}

Attacks on Microsoft certification authorities include the abuse of permissions on certificate templates. In many cases, certificate templates must be configured to allow the enrollee request any kind of identity, which can lead to account impersonation and elevation of privileges. These kinds of attacks are known as ESC1 (<https://posts.specterops.io/certified-pre-owned-d95910965cd2>) in the security scene.

ESC1 abuses a certificate template that is configured with the "Enrollee supplies subject" setting enabled (also called an "offline" certificate template, because the identity is provided by the enrollee, as opposed to an "online" certificate template where the certificate identity is built from Active Directory based on the enrollee's logon information). The adversary would have to submit a certificate request containing a "malicious" Subject Alternative Name certificate extension.

![A certificate template that allows the enrollee to supply the identity of the issued certificate in the certificate request](resources/offline-template.png)

TameMyCerts can contain the damage done in such a case, and in even prevent the attack in many cases:

- TameMyCerts can [enforce identity types](#subject-rules) and thus ensure that only definiec certificate fields are allowed to get issued.
- TameMyCerts can [apply syntax rules](#subject-rules) to certificate requests and thus ensure that certificates only get issued if the certificate content matched defined naming conventions.
- TameMyCerts can [map requested identities](#ds-mapping) back to the according object in Active Directory and apply rules bases on accont status, security group or organizational unit membership.

Rule violations [are being logged](#logs) and thus allow alerting on policy violations.

![A certificate request not containing required fields and containing forbidden fields was denied by TameMyCerts](resources/deny-fields-missing.png)

![A certificate request triggering blacklisted words was denied by TameMyCerts](resources/deny-syntax-blacklist.png)

![A certificate request violating syntax rules was denied by TameMyCerts](resources/deny-syntax-violation.png)

![A certificate request for a user not being member of any allowed group was denied by TameMyCerts](resources/deny-not-member.png)

![A certificate request for a non-existing user was denied by TameMyCerts](resources/deny-nonexisting-user.png)

![A certificate request for an account residing in the wrong OU was denied by TameMyCerts](resources/deny-wrong-ou.png)

![A certificate request for a disabled account was denied by TameMyCerts](resources/deny-disabled-account.png)

![A certificate request containing a forbidden extension was denied by TameMyCerts](resources/deny-sid-extension.png)