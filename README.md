# Enterprise Zero Trust Access Control Architecture

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-009688?style=flat&logo=fastapi&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-18-4169E1?style=flat&logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=flat&logo=docker&logoColor=white)
![Tests](https://img.shields.io/badge/Test_Suite-12%2F12_Passed-brightgreen?style=flat&logo=pytest&logoColor=white)

A hardened, multi-tenant backend reference architecture engineered around Zero Trust principles, combining Role-Based Access Control (RBAC), Attribute-Based Access Control (ABAC), PostgreSQL Row-Level Security (RLS), and Asymmetric (RS256) JWT Validation.

Designed to provide defense-in-depth security, strict cryptographic tenant isolation, least-privileged runtime execution, and automated security auditing.

---

## Architectural Blueprint & Request Flow

```text
 ┌──────────────┐       Bearer Token (RS256)       ┌──────────────────────────────────────┐
 │ Client / App │ ───────────────────────────────> │  FastAPI Backend (Middleware Layer)  │
 └──────────────┘                                  └──────────────────────────────────────┘
                                                                      │
                                          1. Cryptographic Validation (RSA Public Key)
                                          2. Context Injection (Tenant ID, Roles, Attr)
                                                                      │
                                                                      ▼
                                                   ┌──────────────────────────────────────┐
                                                   │        PostgreSQL 18 (Engine)        │
                                                   │  [RLS Policy Enforced Dynamically]   │
                                                   └──────────────────────────────────────┘
```
Core Security Matrix

Permissions and boundaries are evaluated at every stage of the request lifecycle:
1. Role-Based Access Control (RBAC)

    Concept: Rights are assigned based on organizational roles embedded within verified security tokens.

    Implementation: User claims specify distinct operational roles (admin, tenant_user, auditor), gating administrative routers (routers/tenants.py) and execution paths.

2.  Attribute-Based Access Control (ABAC)

    Concept: Dynamic evaluation driven by environmental, user, and resource attributes rather than static assignments.

    Implementation: Security dependencies (security/dependencies.py) evaluate dynamic context—such as numeric clearance levels (clearance >= 2), resource tags, and tenant scopes—before permitting access.

3.  Database Row-Level Security (RLS)

    Concept: Storage-engine level firewall enforcing isolation directly at the database tier.

    Implementation: database/init_rls.sql forces FORCE ROW LEVEL SECURITY on target tables. Policies match rows against runtime session settings (current_setting('app.current_tenant', true)), transparently dropping unauthorized cross-tenant data even if application queries omit WHERE clauses.

4. Asymmetric Cryptography & Hardened JWT Parsing

    Concept: Cryptographically verifiable identity claims operating on a Zero Trust trust-boundary model.

    Implementation: Tokens are signed using an offline private key (jwt_private.pem) and verified downstream via an asymmetric public key (jwt_public.pem). Strict checks validate signature, expiration (exp), missing mandatory claims (jti, tenant_id), algorithm downgrades (alg: none), and production scheme expectations (iss/aud).

5.  Graceful Error Handling & Unhandled Exception Shielding

    Concept: Prevents worker process crashes and protocol truncation on invalid cryptographic payloads.

    Implementation: All key loader exceptions and token parsing errors in security/jwt_validator.py are wrapped in standardized HTTP exception responses (HTTP 401/400/500) to shield the Uvicorn worker process.

6.  Least-Privilege & SIEM Audit Logging

Least-Privilege Runtime: Application connection pools utilize a restricted non-superuser role (app_user), preventing schema-level privilege escalation.

Audit Telemetry: security/audit.py captures unauthorized access attempts, cross-tenant violations, and malformed payload attempts for SIEM ingestion (e.g., Wazuh/Elasticsearch).


Zero Trust Test Suite (12 Vectors)

The suites in tests/whitebox/zt_test.py and tests/blackbox/zt_test.py verify all security boundaries against automated attack simulations.

Test Matrix Summary

	Vector	Description		Target Threat / Vulnerability			Expected Response

1. Authorized Request & RLS Check	Cross-tenant data leakage			HTTP 200 + Correct Tenant Data
2. Anti-BOLA Cross-Tenant Gate		Broken Object Level Authorization (IDOR)	HTTP 403 Forbidden
3. Insufficient ABAC Clearance		Privilege Escalation (Low Clearance Tier)	HTTP 403 Forbidden
4. Temporal Claim Expiration		Replay Attacks with Expired JWTs		HTTP 401 Unauthorized
5. Cryptographic Signature Tampering	Payload Munge / Cryptographic Spoofing		HTTP 401 Unauthorized
6. Algorithm Downgrade Attack		alg: "none" Arbitrary Token Bypass		HTTP 401 Unauthorized
7. Missing Authorization Header		Unauthenticated Access				HTTP 401 / 403
8. Malformed Auth Scheme Prefix		Non-Standard Prefix Injection			HTTP 401 / 403
9. RBAC Role Evaluation			Role Mismatch (viewer accessing admin)		Controlled HTTP 403 / 200 Gate
10. Missing Mandatory Claims		Missing jti or tenant_id claims			HTTP 401 Unauthorized
11. Malformed UUID Injection		Type Injection in Path & Token UUIDs		HTTP 400 / 401
12. Issuer / Audience Mismatch		Federated Token Spoofing (iss/aud)		HTTP 401 Unauthorized

```
Project Directory Structure
.
├── .github/
│   └── workflows/         # CI/CD DevSecOps automation pipeline & security scripts
├── app/                   # Core application directory
│   ├── app.py             # FastAPI application entrypoint and middleware registration
│   ├── config/            # Environment configurations and global settings
│   ├── database/          # Database connection logic & dynamic RLS initialization scripts
│   ├── middleware/        # Tenant context injection, RBAC/ABAC enforcement, and auth hooks
│   ├── routers/           # Feature-scoped API endpoints (Tenants, Documents)
│   └── security/          # Core crypto validation, JWT parsing, and security audit loggers
├── docker-compose.yml     # Multi-container orchestration (App + Hardened Postgres Engine)
├── Dockerfile             # Non-root container build spec for the FastAPI service
├── .dockerignore          # Docker build exclusion definitions
├── .env                   # Local environment configuration variables
├── env.example            # Required environment configuration template for local setup
├── .gitignore             # Git exclusion definitions
├── jwt_private.pem        # RSA private key for token generation and signing
├── jwt_public.pem         # RSA public key for cryptographic signature validation
├── requirements.txt       # Python dependency manifest
└── tests/                 # Automated Zero Trust test suites
    ├── blackbox/
    │   ├── .env.live      # Live environment configuration for black-box penetration testing
    │   └── zt_test.py     # Production/Staging penetration suite (tests external boundaries & CORS)
    └── whitebox/
        └── zt_test.py     # 12-vector zero-trust local integration test suite
