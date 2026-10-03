# Screening policy

Cyphras private payments take deposits through an entry gate. A deposit waits in a
queue, is screened, and then either enters the shielded pool or goes back in full to
the account it came from. This policy states what is checked and when, what each
decision means, how refunds and reports work, what Cyphras keeps, and what it
publishes. It applies to every v2 vault on mainnet and to the relayer that Cyphras
runs.

The vault's entry queue is specified in [vault.md](vault.md) and the screening
service in [services.md](services.md).

Status: draft, version 1. It is reviewed by Indonesian counsel before the mainnet
launch.

## Principles

- Cyphras never holds, moves or redirects anyone's funds. The vault returns a refused
  deposit to its depositor and nowhere else.
- Screening happens at entry. A deposit is screened before it can be used, and a
  refused deposit is returned in full.
- Every decision is recorded, and every refusal is public on chain with a reason code.
- Screening fails closed: without an answer, nothing is admitted.
- Cyphras keeps as little data as it can: public addresses and its own decisions.

## What is checked, and when

| When | What | Result |
| --- | --- | --- |
| Within 10 minutes of the deposit | the depositor and its funders, against the sources below | cleared, or refused with a reason code |
| During the deposit's delay | a person reviews every deposit at or above the large-deposit threshold, and every deposit an automated rule refers | cleared, or refused with reason 5 |
| In the last 10 minutes before the deposit can be admitted | the automated checks again, with current sources | attested, or refused |
| When the Cyphras relayer is asked to relay an unshield | the destination and its funders, one hop back | relayed, or refused with a reason code |

- At launch the delay is 1 hour, or 24 hours for a deposit of 500 XLM or more, which
  is also the large-deposit threshold ([vault.md](vault.md), Limits).
- **Funders** are the accounts that sent value to the depositor in the 30 days before
  the deposit: one hop back, and two hops for a large deposit. For USDC that reached
  the depositor through CCTP, the sender on the source chain is screened as a funder.
- Refusing a deposit means flagging it on the vault; attesting it lets it be admitted
  once its delay has passed ([vault.md](vault.md), Entry queue).
- A review not finished before the final check counts as a refusal with reason 5.
- If a source is unreachable or out of date, nothing is attested until it is back.
  Deposits wait, and their depositors can cancel at any time.
- An attestation covers every deposit up to a given ID, so a deposit can be attested
  before its own final check. If that final check cannot run in time, the deposit is
  refused with reason 5. Nothing is admitted unchecked.

### Sources

- The list of ledger keys that validators have frozen under CAP-77.
- Sanctions lists that carry digital-currency addresses, including the OFAC SDN list.
  For bridged USDC, the sender on the source chain is checked against them as well.
- Addresses published as holding exploit or theft proceeds, from incident reports and
  security advisories.
- stellar.expert directory tags that mark an account as malicious or fraudulent.
- Self-reports and fraud reports received under this policy.
- A KYT vendor, once its coverage of Stellar is verified.

Some lists, such as Indonesia's DTTOT, name people and carry no addresses. Cyphras
cannot match them against accounts it knows nothing about, and applies them when a
report links a listed person to an address.

## Reason codes

The vault publishes the code of every refusal in its `deposit_flagged` and
`deposit_refunded` events.

| Code | Meaning |
| --- | --- |
| 0 | Cancelled by the depositor. Used in refund events only. |
| 1 | Sanctions list: the depositor, a funder or a bridged source address is on a sanctions list. |
| 2 | Exploit or theft proceeds: the funds come from addresses published as holding stolen funds. |
| 3 | Frozen by validators: the depositor or a funder is on the CAP-77 frozen list. |
| 4 | Fraud report: a credible report by a victim, with evidence, or a self-report of a compromised address. |
| 5 | Manual review: refused by a reviewer, or not cleared in time. |
| 99 | Other: the private record holds the details. |

A code keeps its meaning forever. A new reason gets a new code.

## Refunds

- A refused deposit is refunded in full to the account that made it. The vault allows
  no other destination, and Cyphras has no way to hold or keep it.
- The depositor can claim the refund of a refused deposit at any time, and can cancel
  any deposit that is not yet admitted, whether refused or not.
- The Cyphras keeper refunds a deposit that has stayed refused for 24 hours, so the
  funds go back even if the depositor does nothing. The 24 hours leave room to correct
  a mistaken refusal.
- A mistaken refusal is corrected while the deposit is still pending. The correction is
  recorded and visible on chain.
- When a written order from an Indonesian court, prosecutor or police concerns a
  pending deposit, Cyphras refuses it with reason 99 if it is not yet admitted, and its
  keeper does not refund it. The depositor can still claim the refund: the vault gives
  Cyphras no way to hold funds.

## Compromised addresses

A person whose Stellar key was stolen can stop deposits from that address from
entering the pool. They sign this message with the compromised key under SEP-53:

```
Cyphras compromised address report
Network: mainnet
Address: <the address, G...>
Date: <YYYY-MM-DD>
```

and submit it to the screening service's `/v1/self-report` endpoint, or by email to
the contact below.
- Cyphras checks the signature, then refuses every pending deposit from that address,
  and every later one, with reason 4. The block is permanent for that address on that
  network.
- The refunds still go to the compromised address. A report keeps stolen funds from
  entering the pool, where they would be harder to follow; it does not stop the thief
  from using the address.
- A report cannot affect notes already in the pool.

## Fraud reports

A victim, or someone acting for one, can report an address that holds stolen or
defrauded funds, with evidence such as transaction hashes or a police report. Cyphras
reviews every report and refuses matching pending deposits with reason 4 when the
evidence is credible. Reports and decisions are recorded.

## Requests from law enforcement

**What Cyphras holds:**
- the screening record of each deposit: public addresses, amounts, decisions, reason
  codes and the sources consulted;
- relay records: transaction hashes, fees, unshield destinations and their screening
  results;
- self-reports, fraud reports and correspondence.

**What Cyphras does not hold:**
- IP addresses or request logs of any service;
- accounts or identity data, since there is no sign-up and no KYC;
- seeds, keys or viewing keys;
- which notes belong to whom, any balance, or any link between deposits, payments and
  unshields.

**What Cyphras can do:** refuse a deposit that is still pending, which returns it to
its depositor; refuse to relay to an address; and disclose the records it holds.

**What Cyphras cannot do:** freeze, seize or redirect funds; reverse an admitted
deposit; or identify who sent, received or unshielded a note. A user can prove their
own payments with a payment disclosure or a viewing key
([encryption.md](encryption.md)); Cyphras cannot do it for them.

**How requests are handled:**
- Requests come in writing from a competent authority, to the contact below. Cyphras
  confirms each request through a contact for that authority that it finds
  independently before it answers.
- Requests are handled under Indonesian law. A request from abroad goes through the
  channels Indonesian law provides.
- An answer covers only what the request names.
- Every request is recorded. The number received and answered is published every six
  months.
- Where a refusal rests on strong evidence of a crime, such as a published exploit,
  Cyphras may also report it to PPATK on its own initiative.

**Contact:** `<compliance mailbox, published before the mainnet launch>`

## Records

- Kept for at least five years after the decision they concern: screening records,
  relay records, self-reports, fraud reports, and law-enforcement requests with their
  answers.
- They never include IP addresses, device data or anything this policy does not list.
- They are stored encrypted, readable only by the person responsible for this policy,
  and backed up encrypted away from the service host.
- They are deleted when the retention period ends, unless a legal hold applies.

## Public statistics

Published at the screening service's `/v1/stats` endpoint and summarized each month:
- deposits admitted, refused by reason code, refunded and cancelled, with counts and
  total values;
- the median and longest time from deposit to admission;
- unshields the Cyphras relayer refused, by reason code;
- self-reports and fraud reports received;
- law-enforcement requests received and answered, every six months.

Every deposit figure can be recomputed by anyone from the vault's public events.

## Scope and limits

- Screening works at the entry gate only. Funds found to be dirty after admission
  cannot be traced or blocked inside the pool.
- The vault applies the same gate to every deposit, whatever software makes it. This
  policy binds only the services Cyphras runs; a third-party relayer applies its own
  rules to unshields.
- Cyphras's terms of service exclude sanctioned persons and the comprehensively
  sanctioned jurisdictions from the services it hosts.

## Changes

- One named person at Cyphras is responsible for this policy and signs off every
  manual decision.
- The policy is reviewed at least once a year and after every incident.
- Each change gets a new version number. A change that tightens screening applies
  when published; any other change applies 7 days after publication.
