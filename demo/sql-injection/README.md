# CVE-2021-35042 lab

This fixture reproduces
[CVE-2021-35042](https://www.djangoproject.com/weblog/2021/jul/01/security-releases/),
an SQL injection in `QuerySet.order_by()` affecting Django versions before
3.2.5 and 3.1.13. User-controlled ordering text could be interpreted as SQL
when it reached an expected column position.

The fixture is adapted from
[Vulhub](https://github.com/vulhub/vulhub/tree/master/django/CVE-2021-35042).
It runs Django 3.2.4, MySQL and the official Parrot Security SQLMap image in
containers. Compose performs the migrations, loads the sample records and
starts the attack automatically.

## Network

The vulnerable service joins a frontend network and a private backend network.
MySQL joins only the backend. The only host binding is
`127.0.0.1:3000`, so neither service is exposed to the LAN.

The SQLMap container checks whether LaTaupe is available on the Docker host. It
routes the attack through the WAF when port `8081` is listening and attacks the
fixture directly otherwise. No Python attack script is used.

## Start

```bash
docker compose up -d
docker compose ps
```

Follow the prebuilt SQLMap attacker:

```bash
docker compose logs -f attacker
```

## Run LaTaupe from source

From the LaTaupe repository root:

```bash
LATAUPE_LISTEN_HOST=0.0.0.0 \
LATAUPE_UPSTREAM_HTTP=http://127.0.0.1:3000 \
LATAUPE_PROXY_PORT=8081 \
PYTHONPATH=src python -m app.main
```

This runs LaTaupe directly from `src`. Nuitka is not involved.

SQLMap switches to the WAF on its next cycle. Stop LaTaupe to let it switch
back to the vulnerable service. The log states which path is active.

Stop the isolated environment with:

```bash
docker compose down --volumes
```

Only run the payload against this local fixture or systems you are explicitly
authorized to assess.
