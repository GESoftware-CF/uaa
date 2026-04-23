# Background Image Service Module

This module provides background image management for UAA identity zones. Each zone can have one custom background image displayed on the login and home pages.

## Features

- **Upload**: Zone admins can upload PNG, JPEG, or WebP images (10 KB - 10 MB)
- **Download**: Images served directly from the backend with caching headers
- **Multi-tenant**: Fully isolated per identity zone
- **S3 Storage**: Images stored in AWS S3 with metadata in PostgreSQL
- **Audit**: All uploads and deletions logged via UAA's audit system

## Architecture

```
UAA Web UI → REST API → BackgroundImageService → S3 + PostgreSQL
                                └─> AuditService (async)
```

## REST API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/background_images` | Upload a background image |
| `GET` | `/background_images` | Get background image metadata |
| `GET` | `/background_images/download` | Download the raw image bytes |
| `DELETE` | `/background_images` | Delete the zone's background image |

## Configuration

Add to `uaa.yml`:

```yaml
background-image:
  enabled: true
  storage:
    bucket: ${AWS_S3_BUCKET}
    key-prefix: media
  validation:
    min-size-bytes: 10240       # 10 KB
    max-size-bytes: 10485760    # 10 MB
    allowed-mime-types:
      - image/png
      - image/jpeg
      - image/webp

aws:
  region: ${AWS_REGION:us-east-1}
  s3:
    max-concurrency: 50
    multipart-threshold-bytes: 8388608  # 8 MB
```

## Environment Variables

- `AWS_S3_BUCKET`: S3 bucket name for background images (required)
- `AWS_REGION`: AWS region (default: `us-east-1`)
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`: AWS credentials (or use IAM roles)

## Database

The module creates a `background_images` table via Flyway migration `V4_113__Create_Background_Images_Table.sql`.

Supported databases: PostgreSQL, MySQL, HSQLDB, SQL Server

## Usage Example

### Upload (curl)

```bash
curl -X POST http://localhost:8080/background_images \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -F "file=@/path/to/image.png"
```

Response:
```json
{
  "id": "uuid-123",
  "identityZoneId": "zone-456",
  "uploadedBy": "admin",
  "originalFilename": "image.png",
  "mimeType": "image/png",
  "sizeBytes": 524288,
  "storageKey": "media/zone/zone-456/background/uuid-123/image.png",
  "created": "2026-04-13T10:30:00Z"
}
```

### Download

```bash
curl -O http://localhost:8080/background_images/download \
  -H "Authorization: Bearer $JWT_TOKEN"
```

## Security

- **Authentication**: All endpoints require a valid JWT token
- **Authorization**: Upload and delete require zone admin privileges(`zones.{zoneId}.admin`)
- **Validation**: Magic-byte MIME detection prevents header spoofing
- **Zone Isolation**: All queries scoped to `identity_zone_id`

## Testing

Run tests:
```bash
./gradlew :cloudfoundry-identity-media:test
```

Integration tests (requires Docker for localstack):
```bash
./gradlew :cloudfoundry-identity-media:integrationTest
```

## Phase 2 Enhancements (Roadmap)

- **Replace-on-upload**: Automatically delete old image when uploading new one
- **Presigned URLs**: Return time-limited S3 URLs instead of proxying bytes
- **Thumbnail generation**: Create previews for settings UI
- **CDN integration**: Serve images via CloudFront
- **Image dimension validation**: Enforce minimum resolution (e.g., 1280x720)

## Troubleshooting

### Upload fails with 413 Payload Too Large

- Check `background-image.validation.max-size-bytes` (default: 10 MB)
- Check Spring Boot `spring.servlet.multipart.max-file-size` and `max-request-size`

### Upload fails with 415 Unsupported Media Type

- Ensure file is PNG, JPEG, or WebP
- Magic-byte detection reads file signature (not just extension)

### Download returns 404 Not Found

- Verify zone has an uploaded background image
- Check S3 bucket permissions and object existence

### S3 connection errors

- Verify `AWS_REGION` and `AWS_S3_BUCKET` are set correctly
- Check AWS credentials (access key or IAM role)
- Ensure S3 bucket exists and UAA has s3:PutObject / s3:GetObject permissions

## License

Apache License 2.0 (same as UAA)
