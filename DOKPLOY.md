# AuthForge on Dokploy

Create a **Docker Compose** service (not Application or Docker Stack) with GitHub
repository `FaruqHAO/AuthForge`, branch `main`, build path `/`, and compose path
`compose.dokploy.yml`. This stack includes PostgreSQL and Redis; do not create
additional database services for it. No host ports are published.

In Dokploy's Environment tab, provide these variables. Replace every placeholder:

```dotenv
POSTGRES_PASSWORD=GENERATE_A_RANDOM_HEX_VALUE
SECRET_KEY=GENERATE_A_DIFFERENT_RANDOM_HEX_VALUE
JWT_SECRET_KEY=GENERATE_ANOTHER_RANDOM_HEX_VALUE
CORS_ALLOWED_ORIGINS=["https://auth.baosat.dpdns.org"]
ADMIN_EMAIL=YOUR_EMAIL_ADDRESS
ADMIN_PASSWORD=YOUR_STRONG_UNIQUE_ADMIN_PASSWORD
```

Generate each of the first three values separately on Ubuntu with
`openssl rand -hex 32`. Use hex for the database password so it can safely appear
in the connection URL without URL encoding. Never commit the filled environment
file. Keep signing keys stable across deployments. Add frontend origins to the
JSON CORS list if other apps will call this API from a browser.

Add a Dokploy domain for service `api`: host `auth.baosat.dpdns.org`, container
port `8000`, path `/`, internal path `/`, HTTPS disabled. Preview the Compose
configuration to confirm proxy labels are attached to `api`, then deploy.

The single API container applies Alembic migrations and seeds roles before it
starts. Setting ADMIN_PASSWORD creates the initial administrator if the email
does not exist. Remove ADMIN_PASSWORD after the first successful bootstrap;
redeploying will retain the administrator in PostgreSQL. Existing passwords
are not changed by the seed script. Back up PostgreSQL before later schema
upgrades. Do not scale API containers without separating the migration job.

In the existing Cloudflare tunnel `baosat`, add a published hostname:

* Subdomain: `auth`
* Zone: `baosat.dpdns.org`
* Origin: `http://127.0.0.1:80`
* Path: blank

Public checks:

* `https://auth.baosat.dpdns.org/` — service information (this is an API, not a frontend)
* `https://auth.baosat.dpdns.org/api/v1/health` — verify database and Redis are healthy
* `/api/v1/auth/register` and `/api/v1/auth/login` — authentication routes

Interactive docs are deliberately disabled with DEBUG=false. For temporary
private testing, DEBUG=true enables `/docs`, `/redoc`, and `/openapi.json`;
restore DEBUG=false afterward. SMTP and verification/reset email delivery are
not provisioned by this deployment.

Enable the Ubuntu VM's Start at boot in Proxmox. In Ubuntu, enable Docker and
the already installed Cloudflare connector with
`sudo systemctl enable --now docker cloudflared`. Compose restart policies
restart the services after Docker starts. Reboots still cause temporary downtime.
Keep named volumes and schedule off-server PostgreSQL backups. Do not delete
the stack's volumes when redeploying or changing settings.
