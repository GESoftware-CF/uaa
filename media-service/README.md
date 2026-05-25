# Background Image Service Module

This module provides background image management for UAA identity zones. Each zone can have one custom background image displayed on the login page.

## Features

- **Upload**: Zone admins can upload PNG, JPEG, or WebP images (up to 5 MB)
- **Multi-tenant**: Fully isolated per identity zone (fixed S3 key per zone)
- **S3 Storage**: Images stored in AWS S3; public URL + audit metadata persisted in zone config
- **Race-condition-safe**: `PUT /identity-zones/{id}` preserves uploaded URL via `restoreBrandingProperties`

## Architecture

```
UAA Web UI → POST /background_images/upload → BackgroundImageService → S3
                                                      └─> identity_zone.config.branding (URL + audit)
Login page ← BackgroundImageService (implements BackgroundImageUrlProvider) ← identity_zone.config.branding.backgroundImageUrl
```

## REST API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/background_images/upload` | Zone admin | Upload a background image for the current zone |
| `DELETE` | `/background_images` | Zone admin | Delete the zone's background image |

**Authorization**: Bearer token with `zones.write`, `uaa.admin`, or `zones.{zoneId}.admin` scope.

### Upload (curl)

```bash
curl -X POST http://localhost:8080/background_images/upload \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -F "file=@/path/to/image.png"
```

Response:
```json
{
  "backgroundImageUrl": "https://your-bucket.s3.us-west-2.amazonaws.com/uaa/zone-id/background-image?v=1716048000000"
}
```

## Configuration

In `uaa.yml`:

```yaml
spring:
  servlet:
    multipart:
      max-file-size: 5MB
      max-request-size: 6MB

background-image:
  storage:
    bucket: ${BACKGROUND_IMAGE_BUCKET:fs-sec-uaa-background-image-int}
  default-url: ${BACKGROUND_IMAGE_DEFAULT_URL:https://...}
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `BACKGROUND_IMAGE_BUCKET` | Yes | S3 bucket name |
| `AWS_REGION` | Yes | AWS region (e.g. `us-west-2`) |
| `BACKGROUND_IMAGE_DEFAULT_URL` | No | Fallback URL shown before any image is uploaded |

AWS credentials are provided via IRSA (IAM Roles for Service Accounts) on Kubernetes.

## Storage Design

- **S3 key**: `uaa/{zoneId}/background-image` (fixed per zone — upload overwrites in place)
- **URL format**: `https://{bucket}.s3.{region}.amazonaws.com/uaa/{zoneId}/background-image?v={epochMillis}` — `?v=` is a cache-buster updated on each upload
- **Zone config**: URL, `uploadedAt` (ISO-8601), and `uploadedBy` (principal name) stored at `identity_zone.config.branding.backgroundImageUrl/uploadedAt/uploadedBy`
- **S3 cache headers**: `Cache-Control: public, max-age=86400` — browsers cache for 1 day; `?v=` change on new upload ensures fresh fetch

## Troubleshooting

### Upload fails with 413 Payload Too Large

Check `spring.servlet.multipart.max-file-size` (currently 5 MB).

### Upload fails with 415 Unsupported Media Type

Ensure file is PNG, JPEG, or WebP. Validation is based on the declared `Content-Type`.

### Background image disappears after zone update

Ensure server version includes `restoreBrandingProperties()` fix (PR #751). A `PUT /identity-zones/{id}` request without `backgroundImageUrl` in the body no longer clears the stored URL.

## License

Apache License 2.0 (same as UAA)

