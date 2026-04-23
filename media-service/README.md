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

## License

Apache License 2.0 (same as UAA)

