# Alpha policy pages

The monolith serves `/privacy` and `/terms` from versioned, dependency-free
templates compiled into the binary. Operator name and contact addresses come
from the same validated metadata shown before login and in **Privacy &
interface**. The pages contain no JavaScript, external assets, cookies,
analytics, or user-controlled template input.

The templates describe the behavior implemented in this repository:

- email/password or Apple identity, one-way password and recovery-code hashes,
  sessions, device records, and server/chat metadata;
- plaintext versus MLS-encrypted content and the remaining metadata boundary;
- Exocord-hosted attachment storage, LiveKit, and optional R2/Apple processing;
- ten-minute login challenges, 15-minute orphan reservations, the 30-day
  account-deletion window, anonymized shared messages, and three-set local backup
  rotation;
- password change and one-time recovery, Apple connection/disconnection,
  account export, device revocation, deletion, support, and abuse contacts;
- deliberate one-message report disclosure, operator review, sanitized
  evidence storage, and disposal of the franking opening after verification;
- platform account suspension, immediate session/gateway/voice cutoff,
  reinstatement without session restoration, and durable enforcement history;
- no advertising or behavioral analytics in the current client.

They are an operationally honest alpha starting point, not a substitute for
advice about the operator, tester locations, international transfers,
contract formation, taxes, consumer warranties, law-enforcement procedures,
or public-launch obligations. The operator must review them before deployment
and obtain counsel before open signup.

The structure follows the transparency categories in
[GDPR Article 13](https://eur-lex.europa.eu/eli/reg/2016/679/art_13/oj) and the
FTC’s guidance to disclose collection, use, sharing, choices, and material
changes clearly:

- <https://www.ftc.gov/business-guidance/resources/marketing-your-mobile-app-get-it-right-start>
- <https://oag.ca.gov/privacy/ccpa>

Re-run `scripts/alpha-preflight.ps1` after changing the templates. A release
must keep operator metadata, the linked policy URLs, and the actual deployment
behavior consistent.
