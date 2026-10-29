# Background Image Service Module

This module provides background image management for UAA identity zones. Each zone can have one custom PNG or JPEG displayed on the login page.

## Features

- **Upload**: Zone admins can upload PNG or JPEG images; minimum and maximum sizes are configured with environment variables
- **Multi-tenant**: Every upload receives a unique S3 key scoped to its identity zone
- **S3 Storage**: The database stores a relative object reference and audit metadata; the CloudFront URL is constructed at read time
- **Zone updates**: `PUT /identity-zones/{id}` preserves all three background image fields via `restoreBrandingProperties`

## Architecture

```
UAA Web UI → POST /background_images/upload → BackgroundImageService → S3
                                                      └─> identity_zone.config.branding (relative reference + audit)
LoginInfoEndpoint ← BackgroundImageService (CloudFront URL when reference is valid)
Login page ← model URL, otherwise bundled static image
```

## REST API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/background_images/upload` | Zone admin | Upload a background image; returns `200 OK` with no body |
| `DELETE` | `/background_images` | Zone admin | Delete the zone's background image; returns `204 No Content` or `404 Not Found` |

**Authorization**: Bearer token with `zones.write`, `uaa.admin`, or `zones.{zoneId}.admin` scope.

### Upload (curl)

```bash
curl -X POST http://localhost:8080/background_images/upload \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -F "file=@/path/to/image.png"
```

The upload response has no body. The login page obtains the CloudFront URL from the service when it renders.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `AWS_REGION` | Yes | AWS region used by the S3 client |
| `BACKGROUND_IMAGE_STORAGE_BUCKET` | Yes | S3 bucket name |
| `BACKGROUND_IMAGE_BASE_PATH` | Yes | Prefix for background-image objects |
| `BACKGROUND_IMAGE_CLOUDFRONT_DOMAIN` | Yes | CloudFront hostname without scheme or path |
| `BACKGROUND_IMAGE_UPLOAD_MIN_SIZE_BYTES` | No | Minimum accepted upload size; defaults to 1 byte |
| `BACKGROUND_IMAGE_UPLOAD_MAX_SIZE_BYTES` | Yes | Maximum accepted upload size and servlet multipart limit |

AWS credentials are provided via IRSA (IAM Roles for Service Accounts) on Kubernetes.

## Storage Design

- **S3 key**: `{basePath}/{zoneId}/{timestamp}-{random}.{png|jpg}`
- **Zone config**: stores `{zoneId}/{timestamp}-{random}.{png|jpg}` plus `uploadedAt` (ISO-8601) and `uploadedBy` (principal name) at `identity_zone.config.branding`
- **CloudFront URL**: `https://{cloudFrontDomain}/{basePath}/{relativeReference}`; the direct S3 URL is not stored
- **S3 cache headers**: `Cache-Control: public, max-age=31536000`; every upload gets a unique key, so long-lived caching is safe
- **Fallback**: both login layouts use `/images/background-image.png` under `predixBaseUrl` when no provider URL is present

## Troubleshooting

### Upload fails with 413 Payload Too Large

Check `BACKGROUND_IMAGE_UPLOAD_MAX_SIZE_BYTES`; this value configures both the upload and servlet file-size limits.

### Upload fails with 415 Unsupported Media Type

Ensure the request declares `image/png` or `image/jpeg` as its `Content-Type`.

### Background image disappears after zone update

Ensure the persisted zone is being updated successfully. Background image URL and audit fields are owned by the upload/delete endpoints and are preserved across `PUT /identity-zones/{id}`.

## Pangea audit

Pangea forwarding is disabled by default. Configure `PANGEA_AUDIT_ENABLED=true` to enable it.

| Variable | Description |
|---|---|
| `PANGEA_AUDIT_URL` | Full Pangea audit endpoint URL, used as provided |
| `PANGEA_AUDIT_CONFIG_ID` | Pangea audit configuration ID |
| `PANGEA_AUDIT_TOKEN` | Static Pangea API token; secret |
| `PANGEA_AUDIT_APP_NAME` | Application name; defaults to `uaa` |
| `PANGEA_AUDIT_RETRY_COUNTER` | Maximum result-poll attempts; defaults to `5` |
| `PANGEA_AUDIT_RETRY_INTERVAL_MS` | Delay between `202` result polls; defaults to `500` ms |
| `PANGEA_AUDIT_CONNECT_TIMEOUT_MS` | HTTP connect timeout; defaults to `2000` ms |
| `PANGEA_AUDIT_READ_TIMEOUT_MS` | HTTP read timeout; defaults to `5000` ms |
| `PANGEA_AUDIT_VAULT_URI` | Vault endpoint used to retrieve the Pangea token |
| `PANGEA_AUDIT_VAULT_TOKEN` | Vault API token; secret |
| `PANGEA_AUDIT_VAULT_TOKEN_ID` | Vault item ID containing the Pangea token |
| `PANGEA_AUDIT_VAULT_TOKEN_REFRESH_MINUTES` | Cached-token refresh period; defaults to `720`, valid range `1`–`1440` |

Configure either `PANGEA_AUDIT_TOKEN` or all three Vault values: `PANGEA_AUDIT_VAULT_URI`, `PANGEA_AUDIT_VAULT_TOKEN`, and `PANGEA_AUDIT_VAULT_TOKEN_ID`. Provide both token secrets through Kubernetes Secrets or a Secrets Manager integration. Do not put either token in `values.yaml`.

## License

Apache License 2.0 (same as UAA)

