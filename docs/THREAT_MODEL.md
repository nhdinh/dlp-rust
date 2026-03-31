# Threat Model (STRIDE)

## Spoofing

- Risk: AD credential theft
- Mitigation: MFA, conditional access

## Tampering

- Risk: File modification
- Mitigation: NTFS ACL + integrity monitoring

## Repudiation

- Mitigation: Central logging

## Information Disclosure

- Mitigation: ABAC + DLP enforcement

## DoS

- Mitigation: rate limiting

## Privilege Escalation

- Mitigation: strict RBAC + ABAC
