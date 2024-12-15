# Sample Phishing Investigation — Sanitized Lab Scenario

> This is a fictional portfolio example. All indicators are placeholders and are not intended to represent a real incident.

## Alert
A user reports an unexpected account-verification email containing a link.

## Triage
The analyst records the sender, recipient, subject, timestamp, and message identifiers, then reviews the message headers and authentication results.

## IOC Analysis
The URL is extracted without visiting it from the analyst workstation. The domain and URL are checked using approved reputation sources. Available organizational telemetry is searched to determine whether any users interacted with the destination.

## Assessment
Multiple contextual and technical indicators support a malicious phishing disposition in this fictional scenario.

## Response
The analyst documents the IOCs, searches for related messages, follows authorized quarantine/blocking procedures, identifies potentially affected users, and escalates any evidence of credential or endpoint compromise.

## Lessons Learned
The investigation demonstrates the importance of combining reputation data with email authentication, message context, user-interaction telemetry, and controlled analysis rather than relying on a single detection result.
