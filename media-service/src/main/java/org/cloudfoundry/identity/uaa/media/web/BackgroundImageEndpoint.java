package org.cloudfoundry.identity.uaa.media.web;

import org.cloudfoundry.identity.uaa.media.service.BackgroundImageService;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import org.springframework.web.bind.annotation.PathVariable;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;

import javax.imageio.ImageIO;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * REST endpoint for background image upload and retrieval.
 *
 * <p>The S3 key for a zone's active image is resolved automatically from the database —
 * callers do not need to supply a key.
 *
 * <ul>
 *   <li>POST   /background_images              – upload image for current zone</li>
 *   <li>GET    /background_images              – get metadata for current zone's image</li>
 *   <li>GET    /background_images/stream       – stream raw image bytes</li>
 *   <li>GET    /background_images/stream/{zoneId} – cacheable stream with ETag + 304 support</li>
 *   <li>GET    /background_images/responsive   – stream image scaled to requested width</li>
 *   <li>GET    /background_images/presigned-url – generate a presigned S3 URL</li>
 *   <li>GET    /background_images/url          – stream raw image bytes directly from S3</li>
 *   <li>GET    /background_images/base64       – return Base64-encoded image</li>
 *   <li>DELETE /background_images              – delete the zone's background image</li>
 * </ul>
 */
@RestController
@RequestMapping("/background_images")
public class BackgroundImageEndpoint {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageEndpoint.class);

    private static final int  DEFAULT_WIDTH_PX              = 1920;
    private static final int  MIN_WIDTH_PX                  = 64;
    private static final int  MAX_WIDTH_PX                  = 3840;
    private static final long DEFAULT_PRESIGN_EXPIRY_MINUTES = 60;

    /** Cache-Control max-age: 7 days = 7 * 24 * 60 * 60 = 604800 seconds. */
    private static final long CACHE_MAX_AGE_SECONDS         = 604800L;
    private static final String CACHE_CONTROL_VALUE         = "public, max-age=" + CACHE_MAX_AGE_SECONDS;

    private final BackgroundImageService backgroundImageService;

    public BackgroundImageEndpoint(BackgroundImageService backgroundImageService) {
        this.backgroundImageService = backgroundImageService;
    }

    // -------------------------------------------------------------------------
    // POST /background_images  — upload
    // -------------------------------------------------------------------------

    /**
     * Upload a background image for the current identity zone.
     * If the zone already has a background image use {@code PATCH /background_images}
     * to atomically replace it (uploads the new image, updates the DB record, and
     * deletes the old S3 object in one operation).
     *
     * @param file multipart image file (PNG, JPEG, or WebP)
     * @return 201 Created with a presigned S3 URL and key for the uploaded image
     */
    @PostMapping(value = {"", "/upload"}, consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> uploadBackgroundImage(
            @RequestParam("file") MultipartFile file) {

        String zoneId = IdentityZoneHolder.get().getId();
        logger.info("POST /background_images: zone={}, filename={}, size={}",
                zoneId, file.getOriginalFilename(), file.getSize());

        String s3Key = backgroundImageService.uploadBackgroundImage(file, zoneId);

        long    clampedExpiry = DEFAULT_PRESIGN_EXPIRY_MINUTES;
        Instant expiresAt     = Instant.now().plusSeconds(clampedExpiry * 60);
        String  presignedUrl  = backgroundImageService.getPresignedUrl(zoneId, s3Key, clampedExpiry);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("zoneId",        zoneId);
        response.put("key",           s3Key);
        response.put("presignedUrl",  presignedUrl);
        response.put("expiryMinutes", clampedExpiry);
        response.put("expiresAt",     expiresAt.toString());

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // -------------------------------------------------------------------------
    // PATCH /background_images  — replace
    // -------------------------------------------------------------------------

    /**
     * Replace the background image for the current identity zone.
     *
     * <p>The existing S3 object is deleted <em>after</em> the new image has been
     * uploaded and the database record updated, so the zone is never left without a
     * reachable image. Returns 404 if no image has been uploaded yet (use POST instead).
     *
     * @param file multipart image file (PNG, JPEG, or WebP)
     * @return 200 OK with the new S3 URL and key, or 404 if no current image exists
     */
    @PatchMapping(value = "", consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
                  produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> replaceBackgroundImage(
            @RequestParam("file") MultipartFile file) {

        String zoneId = IdentityZoneHolder.get().getId();
        logger.info("PATCH /background_images: zone={}, filename={}, size={}",
                zoneId, file.getOriginalFilename(), file.getSize());

        try {
            String newKey = backgroundImageService.replaceBackgroundImage(file, zoneId);

            long    clampedExpiry = DEFAULT_PRESIGN_EXPIRY_MINUTES;
            Instant expiresAt     = Instant.now().plusSeconds(clampedExpiry * 60);
            String  presignedUrl  = backgroundImageService.getPresignedUrl(zoneId, newKey, clampedExpiry);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("zoneId",        zoneId);
            response.put("key",           newKey);
            response.put("presignedUrl",  presignedUrl);
            response.put("expiryMinutes", clampedExpiry);
            response.put("expiresAt",     expiresAt.toString());

            return ResponseEntity.ok(response);

        } catch (java.util.NoSuchElementException e) {
            logger.info("PATCH /background_images: no existing image for zone={}", zoneId);
            return ResponseEntity.notFound().build();
        }
    }

    // -------------------------------------------------------------------------
    // GET /background_images  — metadata
    // -------------------------------------------------------------------------

    /**
     * Return metadata for the current zone's active background image.
     *
     * @return 200 with zoneId + key, or 404 if no image has been uploaded for this zone
     */
    @GetMapping(value = "", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getMetadata() {
        String zoneId = IdentityZoneHolder.get().getId();
        Optional<String> keyOpt = backgroundImageService.findS3KeyByZone(zoneId);
        if (keyOpt.isEmpty()) {
            logger.info("GET /background_images: no image for zone={}", zoneId);
            return ResponseEntity.notFound().build();
        }
        String s3Key = keyOpt.get();
        HeadObjectResponse meta = backgroundImageService.getObjectMetadata(zoneId, s3Key);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("zoneId",        zoneId);
        response.put("key",           s3Key);
        response.put("url",           backgroundImageService.buildS3Uri(s3Key));
        response.put("contentType",   meta.contentType());
        response.put("contentLength", meta.contentLength());
        response.put("lastModified",  meta.lastModified() != null ? meta.lastModified().toString() : null);

        return ResponseEntity.ok(response);
    }

    // -------------------------------------------------------------------------
    // DELETE /background_images
    // -------------------------------------------------------------------------

    /**
     * Delete the background image for the current identity zone.
     *
     * @return 204 No Content on success, 404 if no image exists for this zone
     */
    @DeleteMapping("")
    public ResponseEntity<Void> deleteBackgroundImage() {
        String zoneId = IdentityZoneHolder.get().getId();
        logger.info("DELETE /background_images: zone={}", zoneId);
        boolean deleted = backgroundImageService.deleteBackgroundImage(zoneId);
        return deleted
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    // -------------------------------------------------------------------------
    // GET /background_images/stream
    // -------------------------------------------------------------------------

    /**
     * Stream the raw background image bytes for the current identity zone.
     *
     * @return image bytes with correct Content-Type and caching headers,
     *         or 404 if no image has been uploaded for this zone
     */
    @GetMapping(value = "/stream")
    public ResponseEntity<byte[]> streamImage() {
        String zoneId = IdentityZoneHolder.get().getId();
        Optional<String> keyOpt = backgroundImageService.findS3KeyByZone(zoneId);
        if (keyOpt.isEmpty()) {
            logger.info("GET /background_images/stream: no image for zone={}", zoneId);
            return ResponseEntity.notFound().build();
        }
        String key = keyOpt.get();
        logger.info("GET /background_images/stream: zone={}, key={}", zoneId, key);

        long start = System.currentTimeMillis();
        try (ResponseInputStream<GetObjectResponse> s3Stream =
                     backgroundImageService.downloadBackgroundImage(zoneId, key)) {

            GetObjectResponse s3Meta = s3Stream.response();
            String contentType = s3Meta.contentType() != null ? s3Meta.contentType() : "image/jpeg";
            byte[] imageBytes  = s3Stream.readAllBytes();
            long totalMs       = System.currentTimeMillis() - start;
            logger.info("Stream complete: zone={}, key={}, totalBytes={}, totalMs={}",
                    zoneId, key, imageBytes.length, totalMs);

            HttpHeaders headers = new HttpHeaders();
            headers.set(HttpHeaders.CONTENT_TYPE, contentType);
            headers.set(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL_VALUE);
            headers.setContentLength(imageBytes.length);
            return ResponseEntity.ok().headers(headers).body(imageBytes);

        } catch (IOException e) {
            logger.error("Error reading image from S3: zone={}, key={}", zoneId, key, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // -------------------------------------------------------------------------
    // GET /background_images/stream/{zoneId}
    // -------------------------------------------------------------------------

    /**
     * Stream the background image bytes for a specific zone identified by the
     * {@code zoneId} path variable.
     *
     * <p>The unique path {@code /stream/{zoneId}} makes the URL stable and zone-specific,
     * allowing the <strong>browser or CDN</strong> to cache the response using the
     * {@code Cache-Control: public, max-age=604800} (7 days) header returned.
     * No server-side ETag or conditional GET logic is applied — cache revalidation
     * is fully delegated to the client.
     *
     * <p>Compared to {@code GET /background_images/stream}:
     * <ul>
     *   <li>{@code /stream}           — zone resolved from request host via
     *       {@code IdentityZoneHolder}; URL is not zone-specific, not browser-cacheable</li>
     *   <li>{@code /stream/{zoneId}}  — zone taken from path variable; URL is unique
     *       per zone, browser/CDN cacheable</li>
     * </ul>
     *
     * @param zoneId identity zone ID from the path (e.g. {@code uaa})
     * @return raw image bytes with {@code Content-Type} and {@code Cache-Control} headers,
     *         or {@code 404} if no image has been uploaded for this zone
     */
    @GetMapping(value = "/stream/{zoneId}")
    public ResponseEntity<byte[]> streamImageByZone(
            @PathVariable("zoneId") String zoneId) {

        logger.info("GET /background_images/stream/{}: fetching image", zoneId);

        Optional<String> keyOpt = backgroundImageService.findS3KeyByZone(zoneId);
        if (keyOpt.isEmpty()) {
            logger.info("GET /background_images/stream/{}: no image found", zoneId);
            return ResponseEntity.notFound().build();
        }
        String key = keyOpt.get();

        long start = System.currentTimeMillis();
        try (ResponseInputStream<GetObjectResponse> s3Stream =
                     backgroundImageService.downloadBackgroundImage(zoneId, key)) {

            GetObjectResponse s3Meta    = s3Stream.response();
            String contentType = s3Meta.contentType() != null ? s3Meta.contentType() : "image/jpeg";
            byte[] imageBytes  = s3Stream.readAllBytes();
            long   totalMs     = System.currentTimeMillis() - start;

            logger.info("GET /background_images/stream/{}: served {} bytes, contentType={}, totalMs={}",
                    zoneId, imageBytes.length, contentType, totalMs);

            HttpHeaders headers = new HttpHeaders();
            headers.set(HttpHeaders.CONTENT_TYPE,  contentType);
            headers.set(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL_VALUE);
            headers.setContentLength(imageBytes.length);
            return ResponseEntity.ok().headers(headers).body(imageBytes);

        } catch (IOException e) {
            logger.error("Error streaming image from S3: zone={}, key={}", zoneId, key, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // -------------------------------------------------------------------------
    // GET /background_images/responsive
    // -------------------------------------------------------------------------

    /**
     * Return a viewport-adapted PNG version of the current zone's background image.
     *
     * @param width desired output width in pixels (default: 1920, range: 64–3840)
     * @return PNG bytes scaled to the requested width, or 404 if no image exists
     */
    @GetMapping(value = "/responsive", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> responsiveImage(
            @RequestParam(value = "width", defaultValue = "" + DEFAULT_WIDTH_PX) int width) {

        String zoneId = IdentityZoneHolder.get().getId();
        Optional<String> keyOpt = backgroundImageService.findS3KeyByZone(zoneId);
        if (keyOpt.isEmpty()) {
            logger.info("GET /background_images/responsive: no image for zone={}", zoneId);
            return ResponseEntity.notFound().build();
        }
        String key         = keyOpt.get();
        int    targetWidth = Math.max(MIN_WIDTH_PX, Math.min(MAX_WIDTH_PX, width));
        logger.info("GET /background_images/responsive: zone={}, key={}, requestedWidth={}, targetWidth={}",
                zoneId, key, width, targetWidth);

        long start = System.currentTimeMillis();
        try (ResponseInputStream<GetObjectResponse> s3Stream =
                     backgroundImageService.downloadBackgroundImage(zoneId, key)) {

            BufferedImage original = ImageIO.read(s3Stream);
            if (original == null) {
                logger.error("ImageIO could not decode image: zone={}, key={}", zoneId, key);
                return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).build();
            }

            int targetHeight = (int) Math.round(
                    (double) original.getHeight() / original.getWidth() * targetWidth);

            BufferedImage resized = new BufferedImage(targetWidth, targetHeight, BufferedImage.TYPE_INT_ARGB);
            Graphics2D g2d = resized.createGraphics();
            try {
                g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
                g2d.setRenderingHint(RenderingHints.KEY_RENDERING,     RenderingHints.VALUE_RENDER_QUALITY);
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING,  RenderingHints.VALUE_ANTIALIAS_ON);
                g2d.drawImage(original, 0, 0, targetWidth, targetHeight, null);
            } finally {
                g2d.dispose();
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            if (!ImageIO.write(resized, "png", baos)) {
                throw new IOException("No suitable PNG ImageWriter found");
            }
            byte[] imageBytes = baos.toByteArray();
            long totalMs = System.currentTimeMillis() - start;
            logger.info("Responsive image served: zone={}, key={}, width={}, totalMs={}",
                    zoneId, key, targetWidth, totalMs);

            HttpHeaders headers = new HttpHeaders();
            headers.set(HttpHeaders.CONTENT_TYPE, MediaType.IMAGE_PNG_VALUE);
            headers.set(HttpHeaders.CACHE_CONTROL, CACHE_CONTROL_VALUE);
            headers.set("X-Image-Width", String.valueOf(targetWidth));
            headers.setContentLength(imageBytes.length);
            return ResponseEntity.ok().headers(headers).body(imageBytes);

        } catch (IOException e) {
            logger.error("Failed to serve responsive image: zone={}, key={}, width={}",
                    zoneId, key, targetWidth, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // -------------------------------------------------------------------------
    // GET /background_images/presigned-url
    // -------------------------------------------------------------------------

    /**
     * Generate a presigned S3 GET URL for the current zone's background image.
     *
     * @param expiryMinutes URL validity window in minutes (default: 60, max: 10080 / 7 days)
     * @return JSON with presignedUrl, key, contentType, contentLength, etag, expiresAt;
     *         or 404 if no image exists for this zone
     */
    @GetMapping(value = "/presigned-url", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getPresignedUrl(
            @RequestParam(value = "expiryMinutes",
                          defaultValue = "" + DEFAULT_PRESIGN_EXPIRY_MINUTES) long expiryMinutes) {

        String zoneId = IdentityZoneHolder.get().getId();
        Optional<String> keyOpt = backgroundImageService.findS3KeyByZone(zoneId);
        if (keyOpt.isEmpty()) {
            logger.info("GET /background_images/presigned-url: no image for zone={}", zoneId);
            return ResponseEntity.notFound().build();
        }
        String key = keyOpt.get();
        logger.info("GET /background_images/presigned-url: zone={}, key={}, expiryMinutes={}",
                zoneId, key, expiryMinutes);

        try {
            HeadObjectResponse meta       = backgroundImageService.getObjectMetadata(zoneId, key);
            // Clamp BEFORE generating the URL so the URL expiry equals the reported value.
            long    clampedExpiry = Math.max(BackgroundImageService.MIN_PRESIGN_MINUTES,
                                        Math.min(BackgroundImageService.MAX_PRESIGN_MINUTES, expiryMinutes));
            String  presignedUrl  = backgroundImageService.getPresignedUrl(zoneId, key, clampedExpiry);
            Instant expiresAt     = Instant.now().plusSeconds(clampedExpiry * 60);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("zoneId",        zoneId);
            response.put("key",           key);
            response.put("presignedUrl",  presignedUrl);
            response.put("contentType",   meta.contentType());
            response.put("contentLength", meta.contentLength());
            response.put("etag",          meta.eTag());
            response.put("lastModified",  meta.lastModified() != null ? meta.lastModified().toString() : null);
            response.put("expiryMinutes", clampedExpiry);
            response.put("expiresAt",     expiresAt.toString());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Failed to generate presigned URL: zone={}, key={}", zoneId, key, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // -------------------------------------------------------------------------
    // GET /background_images/url
    // -------------------------------------------------------------------------

    /**
     * Stream the background image bytes directly from S3 for the current identity zone.
     *
     * <p>Downloads the raw image from S3 and writes the bytes directly to the HTTP response
     * with the correct {@code Content-Type} and caching headers. No presigning, URL conversion,
     * or image transformation is applied — bytes are returned exactly as stored in S3.
     *
     * <p>Suitable for direct use as an {@code <img src="...">} or CSS
     * {@code background-image: url(...)} target.
     *
     * @return raw image bytes with {@code Content-Type} and {@code Cache-Control} headers,
     *         or 404 if no image has been uploaded for this zone
     */
    @GetMapping(
            value    = "/url",
            produces = { MediaType.IMAGE_PNG_VALUE, MediaType.IMAGE_JPEG_VALUE, "image/webp" }
    )
    public ResponseEntity<byte[]> getImageDirect() {
        String zoneId = IdentityZoneHolder.get().getId();
        Optional<String> keyOpt = backgroundImageService.findS3KeyByZone(zoneId);
        if (keyOpt.isEmpty()) {
            logger.info("GET /background_images/url: no image for zone={}", zoneId);
            return ResponseEntity.notFound().build();
        }
        String key = keyOpt.get();
        logger.info("GET /background_images/url: zone={}, key={}", zoneId, key);

        try (ResponseInputStream<GetObjectResponse> s3Stream =
                     backgroundImageService.downloadBackgroundImage(zoneId, key)) {

            GetObjectResponse s3Meta      = s3Stream.response();
            String            contentType = s3Meta.contentType() != null
                    ? s3Meta.contentType() : MediaType.IMAGE_PNG_VALUE;
            byte[]            imageBytes  = s3Stream.readAllBytes();

            logger.info("GET /background_images/url: served {} bytes, contentType={}, zone={}",
                    imageBytes.length, contentType, zoneId);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.parseMediaType(contentType));
            headers.setContentLength(imageBytes.length);
            headers.set(HttpHeaders.CACHE_CONTROL,       CACHE_CONTROL_VALUE);
            headers.set(HttpHeaders.CONTENT_DISPOSITION, "inline");
            return ResponseEntity.ok().headers(headers).body(imageBytes);

        } catch (IOException e) {
            logger.error("Failed to stream image from S3: zone={}, key={}", zoneId, key, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // -------------------------------------------------------------------------
    // GET /background_images/base64
    // -------------------------------------------------------------------------

    /**
     * Return the current zone's background image as a Base64-encoded JSON payload.
     * Suitable for embedding directly as a CSS {@code background-image} data URI.
     * For large images, prefer the presigned-url endpoint to avoid the 33 % size overhead.
     *
     * @return JSON with base64Data, dataUri, contentType, originalBytes, encodedLength,
     *         encodingMs; or 404 if no image exists for this zone
     */
    @GetMapping(value = "/base64", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getImageAsBase64() {
        String zoneId = IdentityZoneHolder.get().getId();
        Optional<String> keyOpt = backgroundImageService.findS3KeyByZone(zoneId);
        if (keyOpt.isEmpty()) {
            logger.info("GET /background_images/base64: no image for zone={}", zoneId);
            return ResponseEntity.notFound().build();
        }
        String key = keyOpt.get();
        logger.info("GET /background_images/base64: zone={}, key={}", zoneId, key);

        try {
            BackgroundImageService.Base64ImageResult result =
                    backgroundImageService.getImageAsBase64(zoneId, key);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("zoneId",        zoneId);
            response.put("key",           key);
            response.put("contentType",   result.contentType());
            response.put("originalBytes", result.originalBytes());
            response.put("encodedLength", result.base64Data().length());
            response.put("encodingMs",    result.encodingMs());
            response.put("dataUri",       result.toDataUri());
            response.put("base64Data",    result.base64Data());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Failed to encode image to Base64: zone={}, key={}", zoneId, key, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}

