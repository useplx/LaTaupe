# SQL injection lab

This lab runs the official Damn Vulnerable Web Application image and MariaDB.
DVWA joins a frontend network and a private backend network; MariaDB joins only
the backend. Only DVWA HTTP is published, on `127.0.0.1:3000`, so neither the
database nor the vulnerable site is reachable from the LAN.

## Vulnerability identity

| Field | Value |
|---|---|
| Product | Damn Vulnerable Web Application (DVWA) |
| Weakness | CWE-89: SQL injection |
| CVE | Not applicable: deliberately vulnerable training endpoint |
| Tested input | GET parameter `id` in `/vulnerabilities/sqli/` |

The exercised weakness is
[CWE-89](https://cwe.mitre.org/data/definitions/89.html), improper
neutralization of SQL syntax in user-controlled input. DVWA deliberately ships
this vulnerable implementation for training, so this particular endpoint does
**not** have a CVE identifier. CVEs identify vulnerabilities in released
products that were not intended as security exercises; assigning an unrelated
SQL injection CVE to DVWA would make the demonstration technically false.

This distinction is useful when evaluating LaTaupe: the test validates generic
SQL-injection detection against a deterministic vulnerable service, not a
signature specifically trained for one CVE. A future CVE regression fixture
must pin the affected product and version and reproduce that CVE's exact request
shape separately.

Start the target and initialize its database:

```bash
docker compose up -d
docker compose ps
./initialize.sh
```

DVWA is configured for its official `low` security level with authentication
disabled so automated scanners do not need a session cookie.

Run SQLMap directly against the vulnerable service:

```bash
sqlmap -u 'http://127.0.0.1:3000/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie='security=low' -p id \
  --batch --level=2 --risk=1 --flush-session
```

From the LaTaupe repository root, start LaTaupe with an explicit upstream and
proxy address:

```bash
LATAUPE_UPSTREAM_HTTP=http://127.0.0.1:3000 \
LATAUPE_PROXY_PORT=8081 \
LATAUPE_SOURCE_ROOT="$PWD/demo/sql-injection" \
lataupe
```

Then run the same scan through LaTaupe:

```bash
sqlmap -u 'http://127.0.0.1:8081/vulnerabilities/sqli/?id=1&Submit=Submit' \
  --cookie='security=low' -p id \
  --batch --level=2 --risk=1 --flush-session
```

The direct scan should identify `id` as injectable. With enforcement enabled,
the proxied scan should receive LaTaupe `403` responses and fail to exploit the
upstream endpoint. Stop and remove the isolated lab with:

```bash
docker compose down --volumes
```
