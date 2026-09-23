# MySQL Database Ransomware — Honeynet Incident Investigation

An investigation into real intrusion activity captured by a honeynet I built and instrumented.
An internet-reachable MySQL service was deliberately exposed and fully logged. Within days,
automated actors found it, brute-forced the `root` account, enumerated every schema, destroyed
three databases, and left a Bitcoin ransom demand in a table named `RECOVER_YOUR_DATA`.

The whole point of standing this up was to work an incident against telemetry that nobody
authored for a lesson — real internet background radiation, real credential attacks, real
destructive extortion tooling, and the real evidence gaps that come with them.

**That last part is the reason this write-up is worth reading.** The logs prove privileged access
and destruction beyond argument. They do **not** prove exfiltration, malware execution, or host
persistence — and the ransom note's claim that data was "backed up" is an attacker assertion, not
evidence. Throughout the report I state what the telemetry establishes and mark everything else
*not determined from available logs*. Writing "no evidence of exfiltration" when you mean "no
visibility into exfiltration" is how an incident gets closed at the wrong severity.

## Tools used

| Tool | Role |
|---|---|
| MySQL audit plugin | Authentication and full query logging |
| Microsoft Sentinel / Azure Log Analytics (KQL) | Correlation and hunting across sources |
| Microsoft Defender for Endpoint | Host process, file, registry, and logon telemetry |
| Azure Network Traffic Analytics | `NTANetAnalytics` flow records |
| MITRE ATT&CK | Technique classification |

## At a glance

| | |
|---|---|
| **Affected asset** | `corp-na23-fa123` (honeynet host) |
| **Evidence window** | 12 Sep 2026 23:34Z – 14 Sep 2026 04:03Z |
| **Entry vector** | Internet-reachable MySQL on TCP 3306, `root` accessible remotely |
| **Destruction window** | 06:39:38Z – 07:49:56Z on 13 Sep (~70 minutes) |
| **Databases destroyed** | `cr_corp_01`, `sakila`, `world` |
| **Destructive statements** | 35 `DROP` statements across 28 tables and 4 databases |
| **Ransom demand** | 0.0110 BTC |
| **Distinct external sources** | 12 across 4 network ranges |
| **Assessment** | Confirmed privileged access and destructive extortion; exfiltration unproven |

---

## 1. Scope the incident before interpreting anything

The first query establishes which sources exist and what the telemetry actually covers, before
forming any theory about what happened.

```kusto
let start=datetime(2026-09-12T20:30:00Z);
let end=datetime(2026-09-15T03:00:00Z);
union isfuzzy=true DeviceLogonEvents, DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents
| where TimeGenerated between (start .. end)
| where DeviceName =~ "corp-na23-fa123"
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated), Events=count() by $table
```

Coverage established: MySQL authentication (173 records) and query audit (761 queries), Windows
logon/process/file/registry telemetry, and two `NTANetAnalytics` rows. **No `DeviceNetworkEvents`
export was available** — which is precisely the table that would show outbound transfer. That gap
is recorded up front, because it determines what can and cannot be concluded later.

A timezone note that matters for the timeline: MySQL `RawData` timestamps are UTC. Defender and
network exports carry no timezone metadata, so those are labelled "export time" rather than
silently normalized to UTC.

## 2. Reconstruct the authentication attack

```kusto
MySQLAudit_CL
| where RawData contains "Connect"
| extend SourceIP=extract(@"root@([^ ]+)",1,RawData)
| summarize Failures=countif(RawData contains "Access denied"),
            Successes=countif(RawData contains "Connect root@" and RawData !contains "Access denied"),
            FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
         by SourceIP
| where Successes > 0 or Failures > 0
| order by FirstSeen asc
```

173 authentication records: **102 successes, 71 failures.** The failure-then-success pattern
repeats across every source range — automated probing of `root`, `admin`, and `sa`, followed by
a successful `root` session.

| Source range | Behavior |
|---|---|
| `64.89.163.94`, `.153`, `.164`, `.167`, `.169`, `.178` | Root failures followed by root successes; `RECOVER_YOUR_DATA` activity overlaps this range |
| `77.90.185.21`, `77.90.185.30`, `213.209.159.115` | Automated `root` / `admin` / `sa` probing, each later recording a root success |
| `45.128.199.207` | First logged successful external root authentication, over SSL/TLS |
| `195.201.175.13`, `187.188.15.93`, `193.24.211.39` | Windows network-logon sources, separate from the MySQL activity |

These are source addresses observed in my own honeynet telemetry. They are reported as observed,
without attribution — internet-facing hosts conducting this kind of scanning are frequently
compromised third parties rather than an operator's own infrastructure.

## 3. Prove the destruction from the query audit

```kusto
MySQLAudit_CL
| where RawData contains " Query "
| where RawData contains "DROP TABLE" or RawData contains "DROP DATABASE"
     or RawData contains "RECOVER_YOUR_DATA"
| extend Sql=tostring(split(RawData," Query ")[1])
| project TimeGenerated, Sql
| order by TimeGenerated asc
```

The query audit is what makes this incident provable rather than inferred. It contains the literal
SQL, in order, with connection IDs.

**Connection 38 — 06:39:38Z to 06:41:00Z.** Began schema enumeration, created ransom-note tables,
inserted "Saved file name" records, then dropped 28 tables across `cr_corp_01`, `sakila`, and
`world`. **Connection 38's source is absent from the authentication log** — a correlation gap
noted rather than papered over with a guess.

**07:49:16Z – 07:49:37Z.** `64.89.163.164` failed `root` twice, authenticated successfully, then
created the `RECOVER_YOUR_DATA` database and inserted the demand.

**Connection 83 — 07:49:54Z to 07:49:56Z.** Dropped `cr_corp_01`, `recover_your_data`, `sakila`,
and `world`, then **recreated `RECOVER_YOUR_DATA` and reinserted the ransom note.** Destroying
its own note and rewriting it is characteristic of automated tooling replaying a fixed sequence
without checking prior state — the same behavior that produced 35 `DROP` statements where a
targeted operator would have issued four.

## 4. Test the host-compromise hypothesis

Database destruction does not require host compromise. That had to be checked rather than assumed.

```kusto
let suspicious=dynamic(["45.128.199.207","64.89.163.164","64.89.163.167","64.89.163.169",
                        "64.89.163.178","64.89.163.94","77.90.185.21","77.90.185.30","213.209.159.115"]);
DeviceLogonEvents
| where DeviceName =~ "corp-na23-fa123"
| where RemoteIP in (suspicious) or AccountName in~ ("administrator","root")
| project TimeGenerated, RemoteIP, AccountName, ActionType, LogonType
| order by TimeGenerated asc
```

| Source | Evidence | Assessment |
|---|---|---|
| 676 process records | MySQL Workbench launch and extensive Defender activity | No supplied process event proves attacker code execution |
| 1,047 file records | No host ransom note, no encryption, no attacker tooling | No evidence of host-side ransomware |
| 6 registry records | Edge auto-launch, Azure agent certificate, normal service entries | No confirmed persistence |
| 29 Windows logon events | `195.201.175.13` and `187.188.15.93` recorded **successful administrator network logons** | **Unresolved — flagged for follow-up** |

The successful Windows administrator logons are the loose thread. They are real and they are
external, but the available evidence does not establish whether they were authorized. That is
carried forward as an open item rather than folded into the ransomware narrative.

**Conclusion:** the observed SQL could be executed entirely through the MySQL service. Host
compromise was not required and is not evidenced.

## 5. Extract and validate indicators

```kusto
let iocs=dynamic(["45.128.199.207","64.89.163.164","77.90.185.30",
                  "bc1q0l7hr5v220f5qlqhjhg4p3jjqfkgudazzjnlkw",
                  "ak+2xhn6@onionmail.org","cuq.in/844","2XHN6"]);
union isfuzzy=true MySQLAudit_CL, DeviceLogonEvents, DeviceProcessEvents, DeviceFileEvents, DeviceRegistryEvents
| where TimeGenerated > ago(30d)
| where tostring(pack_all()) has_any (iocs)
| project TimeGenerated, $table, DeviceName, Evidence=tostring(pack_all())
| order by TimeGenerated asc
```

| Indicator | Type | Context |
|---|---|---|
| `bc1q0l7hr5v220f5qlqhjhg4p3jjqfkgudazzjnlkw` | Bitcoin address | Observed twice in inserted ransom text |
| `ak+2xhn6@onionmail.org` | Email | Observed twice in inserted ransom text |
| `hxxps://cuq[.]in/844` | URL (defanged) | Observed twice in inserted ransom text |
| `2XHN6` | Data identifier | Victim reference in the ransom text |
| `RECOVER_YOUR_DATA`, `RECOVER_YOUR_DATA_info` | Database / table names | Created to hold extortion instructions |

I also ran a set of candidate indicators from a similar public campaign report through the same
query — `bc1qk9…apz99`, `ak+28t2@onionmail.org`, `hxxps://2no[.]co/2mysql`, `DATAID 28T2`.
**None appeared in this environment.** Recording a negative validation result matters: it
establishes that the indicator set is derived from this incident's evidence and not inherited
from someone else's report.

## 6. Determine root cause

The attack vector was direct external access to a remotely reachable MySQL service using the
`root` account. Beyond that, the evidence is honest about its limits — the audit log does not
record *how* valid credentials were obtained, and I did not claim it did.

**Not determined from available logs:** the root credential source (blank, weak, reused, or
previously exposed); the firewall/NSG and MySQL `bind-address` configuration; the date the
service became externally reachable; and connection 38's source address.

**Established:** the query sequence is consistent with automated database extortion — enumerate
schemas, inspect tables, create a recovery note, delete data, leave a payment demand.

---

## Results

| Impact area | Assessment | Basis |
|---|---|---|
| **Availability** | **Confirmed** | 35 `DROP` statements, 06:39:53Z–07:49:55Z; three databases destroyed |
| **Integrity** | **Confirmed** | Ransom records inserted; database objects altered |
| **Confidentiality** | **Potentially affected** | Schema enumeration and `SELECT` statements observed; no supplied log proves outbound transfer or a completed dump |
| **Scope** | One logged device, three databases | Broader lateral scope not determined |

### Recommendations, in priority order

| Priority | Recommendation | Verification |
|---|---|---|
| **P1** | Eliminate internet exposure of MySQL. Enforce NSG and host-firewall allowlists; prefer private endpoints or VPN administration. | External scans of TCP 3306 fail; approved private clients still connect |
| **P1** | Prohibit remote `root`. Replace `root@%` with named least-privilege accounts; rotate all secrets. | No root authentication from remote hosts; grants match documented roles |
| **P1** | Maintain tested, immutable backups with point-in-time recovery. | Restore all three databases in a recovery test; compare row and schema checks |
| **P2** | Alert on brute-force-to-success patterns and destructive DDL. | A test sequence raises an incident for failure bursts, external root success, `DROP DATABASE`, and `RECOVER_YOUR_DATA` strings |
| **P2** | Retain correlated auth and query logs with connection IDs and source addresses. | Every destructive query stream maps to a user, IP, and session |
| **P2** | Investigate the successful Windows administrator logons; extend network telemetry retention. | Each success tied to an approved owner or contained; `DeviceNetworkEvents` covers the incident window |

## Lessons learned

**Correlated logs beat verbose logs.** 761 queries proved what happened; 173 auth records proved
who connected. Neither alone was sufficient, and the one place they failed to join — connection
38 — is the one place the incident has an unattributed actor. Logging query text without a
resolvable source identity produces evidence you cannot pin to anyone.

**"No evidence of X" and "no visibility into X" are different findings.** The missing
`DeviceNetworkEvents` export meant exfiltration could not be assessed at all. Reporting that as
"no evidence of exfiltration" would have understated the incident and pointed recovery in the
wrong direction. Confidence was rated separately per conclusion: high for unauthorized privileged
access and destruction, low for exfiltration, persistence, and business impact.

**Attacker claims are not evidence.** The ransom note asserted the data was backed up before
deletion. That assertion is an extortion lever and appears in the report as a claim, not a finding.

**Automation leaves a signature.** 35 `DROP` statements for four databases, plus a sequence that
destroyed and recreated its own ransom note, says commodity tooling replaying a fixed script — not
a targeted operator. That read directly informs severity, scope, and how much to worry about
lateral movement.

**Deliberate exposure produces better training data than any lab.** Every source address, every
credential-stuffing pattern, and every evidence gap here came from real internet traffic hitting
a service I instrumented for it.

## MITRE ATT&CK mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Reconnaissance | Active Scanning | [T1595](https://attack.mitre.org/techniques/T1595/) | Automated probing across 12 sources in 4 ranges |
| Initial Access | External Remote Services | [T1133](https://attack.mitre.org/techniques/T1133/) | Internet-reachable MySQL on TCP 3306 |
| Credential Access | Brute Force: Password Guessing | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | `root` / `admin` / `sa` probing, 71 failures |
| Initial Access | Valid Accounts | [T1078](https://attack.mitre.org/techniques/T1078/) | 102 successful `root` authentications from external sources |
| Discovery | Cloud/Data Storage Object Discovery | [T1619](https://attack.mitre.org/techniques/T1619/) | Schema and table enumeration by connection 38 |
| Collection | Data from Information Repositories | [T1213](https://attack.mitre.org/techniques/T1213/) | `SELECT` statements against enumerated tables |
| Impact | Data Destruction | [T1485](https://attack.mitre.org/techniques/T1485/) | 35 `DROP` statements; 28 tables and 3 databases destroyed |
| Impact | Financial Theft | [T1657](https://attack.mitre.org/techniques/T1657/) | 0.0110 BTC demand with contact address and data identifier |
| Impact | Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) | Destruction of the databases themselves as the recovery-denial mechanism |

## Repository contents

```text
Honeynet-MySQL-Ransomware-Incident/
├── README.md
└── report/
    └── MySQL-Ransomware-Incident-Report.docx
```

The full report carries the complete timeline, per-artifact evidence table, impact assessment,
and the KQL hunt for every section.

---

*Conducted against a honeynet I designed, deployed, and instrumented. The intrusion activity and
all source addresses are real. Two of the three destroyed databases, `sakila` and `world`, are
Oracle's public MySQL sample schemas. No production system and no third-party data was involved.*
