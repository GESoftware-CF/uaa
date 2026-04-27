package org.cloudfoundry.identity.uaa.media.web;

import org.cloudfoundry.identity.uaa.media.service.BackgroundImageService;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
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

/**
 * REST endpoint for background image upload and retrieval.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>POST  /background_images            – upload image</li>
 *   <li>GET   /background_images/stream     – return raw image bytes</li>
 *   <li>GET   /background_images/responsive – return image scaled to requested viewport width</li>
 * </ul>
 */
@RestController
@RequestMapping("/background_images")
public class BackgroundImageEndpoint {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageEndpoint.class);

    private static final int DEFAULT_WIDTH_PX = 1920;
    private static final int MIN_WIDTH_PX = 64;
    private static final int MAX_WIDTH_PX = 3840;
    private static final long DEFAULT_PRESIGN_EXPIRY_MINUTES = 60;

    private final BackgroundImageService backgroundImageService;

    public BackgroundImageEndpoint(BackgroundImageService backgroundImageService) {
        this.backgroundImageService = backgroundImageService;
    }

    // -------------------------------------------------------------------------
    // POST /background_images
    // -------------------------------------------------------------------------

    /**
     * Upload a background image for the current identity zone.
     *
     * @param file multipart image file (PNG, JPEG, or WebP)
     * @return 201 Created with the S3 URL and the S3 key needed for GET calls
     */
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> uploadBackgroundImage(@RequestParam("file") MultipartFile file) {
        String zoneId = IdentityZoneHolder.get().getId();
        logger.info("POST /background_images: zone={}, filename={}, size={}",
                zoneId, file.getOriginalFilename(), file.getSize());

        String s3Uri = backgroundImageService.uploadBackgroundImage(file, zoneId);
        String s3Key = s3Uri.replaceFirst("^s3://[^/]+/", "");

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("url", s3Uri, "key", s3Key));
    }

    // -------------------------------------------------------------------------
    // GET /background_images/stream
    // -------------------------------------------------------------------------

    /**
     * Return the raw background image bytes from S3.
     *
     * @param key the S3 object key returned by the upload endpoint
     * @return image bytes with correct Content-Type and caching headers
     */
    @GetMapping(value = "/stream")
    public ResponseEntity<byte[]> streamImage(@RequestParam("key") String key) {
        String zoneId = IdentityZoneHolder.get().getId();
        logger.info("GET /background_images/stream: zone={}, key={}", zoneId, key);

        long start = System.currentTimeMillis();
        try (ResponseInputStream<GetObjectResponse> s3Stream =
                     backgroundImageService.downloadBackgroundImage(zoneId, key)) {

            GetObjectResponse s3Meta = s3Stream.response();
            String contentType = s3Meta.contentType() != null ? s3Meta.contentType() : "image/jpeg";

            byte[] imageBytes = s3Stream.readAllBytes();
            long totalMs = System.currentTimeMillis() - start;
            logger.info("Stream complete: zone={}, key={}, totalBytes={}, totalMs={}",
                    zoneId, key, imageBytes.length, totalMs);

            HttpHeaders headers = new HttpHeaders();
            headers.set(HttpHeaders.CONTENT_TYPE, contentType);
            headers.set(HttpHeaders.CACHE_CONTROL, "public, max-age=86400");
            headers.setContentLength(imageBytes.length);

            return ResponseEntity.ok().headers(headers).body(imageBytes);

        } catch (IOException e) {
            logger.error("Error reading image from S3: zone={}, key={}", zoneId, key, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // -------------------------------------------------------------------------
    // GET /background_images/responsive
    // -------------------------------------------------------------------------

    /**
     * Return a viewport-adapted PNG version of the background image.
     *
     * @param key   the S3 object key
     * @param width desired output width in pixels (default: 1920)
     * @return PNG bytes scaled to the requested width
     */
    @GetMapping(value = "/responsive", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<byte[]> responsiveImage(
            @RequestParam("key") String key,
            @RequestParam(value = "width", defaultValue = "" + DEFAULT_WIDTH_PX) int width) {

        String zoneId = IdentityZoneHolder.get().getId();
        int targetWidth = Math.max(MIN_WIDTH_PX, Math.min(MAX_WIDTH_PX, width));
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

            int origWidth  = original.getWidth();
            int origHeight = original.getHeight();
            int targetHeight = (int) Math.round((double) origHeight / origWidth * targetWidth);

            BufferedImage resized = new BufferedImage(targetWidth, targetHeight, BufferedImage.TYPE_INT_ARGB);
            Graphics2D g2d = resized.createGraphics();
            try {
                g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
                g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
                g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
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
            headers.set(HttpHeaders.CACHE_CONTROL, "public, max-age=86400");
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
     * Generate a presigned S3 GET URL for the given key, along with object metadata.
     *
     * <p>The presigned URL allows the caller (or browser) to download the image directly
     * from S3 without proxying through UAA, improving performance for large images.
     *
     * @param key           the S3 object key returned by the upload endpoint
     * @param expiryMinutes how long the URL is valid in minutes (default: 60, max: 10080 / 7 days)
     * @return JSON with {@code presignedUrl}, {@code key}, {@code contentType},
     *         {@code contentLength}, {@code etag}, and {@code expiresAt}
     */
    @GetMapping(value = "/presigned-url", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getPresignedUrl(
            @RequestParam("key") String key,
            @RequestParam(value = "expiryMinutes", defaultValue = "" + DEFAULT_PRESIGN_EXPIRY_MINUTES) long expiryMinutes) {

        String zoneId = IdentityZoneHolder.get().getId();
        logger.info("GET /background_images/presigned-url: zone={}, key={}, expiryMinutes={}",
                zoneId, key, expiryMinutes);

        try {
            // Fetch S3 metadata (HEAD request – no data transferred)
            HeadObjectResponse meta = backgroundImageService.getObjectMetadata(zoneId, key);

            // Generate presigned URL
            String presignedUrl = backgroundImageService.getPresignedUrl(zoneId, key, expiryMinutes);

            long clampedExpiry = Math.max(1, Math.min(10080, expiryMinutes));
            Instant expiresAt = Instant.now().plusSeconds(clampedExpiry * 60);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("presignedUrl", presignedUrl);
            response.put("key", key);
            response.put("contentType", meta.contentType());
            response.put("contentLength", meta.contentLength());
            response.put("etag", meta.eTag());
            response.put("lastModified", meta.lastModified() != null ? meta.lastModified().toString() : null);
            response.put("expiryMinutes", clampedExpiry);
            response.put("expiresAt", expiresAt.toString());

            logger.info("Presigned URL generated: zone={}, key={}, contentType={}, contentLength={}, expiresAt={}",
                    zoneId, key, meta.contentType(), meta.contentLength(), expiresAt);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Failed to generate presigned URL: zone={}, key={}", zoneId, key, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // -------------------------------------------------------------------------
    // GET /background_images/base64
    // -------------------------------------------------------------------------

    /**
     * Fetch the image from S3, Base64-encode it, and return a JSON response containing the
     * encoded data and a ready-to-use HTML/CSS data URI.
     *
     * <p>This is useful when the client needs to embed the image inline (e.g. in a JSON
     * payload or as a CSS {@code background-image} value) without making a separate request
     * to S3.  For large images consider using the presigned-url endpoint instead, as Base64
     * increases payload size by ~33 %.
     *
     * <p>Response body example:
     * <pre>{@code
     * {
     *   "key":          "background_images/uaa/abc_photo.jpg",
     *   "contentType":  "image/jpeg",
     *   "originalBytes": 550540,
     *   "encodedLength": 734056,
     *   "encodingMs":   312,
     *   "dataUri":      "data:image/jpeg;base64,/9j/4AAQSkZJRg...",
     *   "base64Data":   "/9j/4AAQSkZJRg..."
     * }
     * }</pre>
     *
     * @param key the S3 object key returned by the upload endpoint
     * @return JSON with Base64 payload and performance metrics
     */
    @GetMapping(value = "/base64", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> getImageAsBase64(@RequestParam("key") String key) {
        String zoneId = IdentityZoneHolder.get().getId();
        logger.info("GET /background_images/base64: zone={}, key={}", zoneId, key);

        try {
            BackgroundImageService.Base64ImageResult result =
                    backgroundImageService.getImageAsBase64(zoneId, key);

            Map<String, Object> response = new LinkedHashMap<>();
            response.put("key", key);
            response.put("contentType", result.contentType());
            response.put("originalBytes", result.originalBytes());
            response.put("encodedLength", result.base64Data().length());
            response.put("encodingMs", result.encodingMs());
            response.put("dataUri", result.toDataUri());
            response.put("base64Data", result.base64Data());

            logger.info("Base64 response ready: zone={}, key={}, originalBytes={}, encodedLength={}, encodingMs={}",
                    zoneId, key, result.originalBytes(), result.base64Data().length(), result.encodingMs());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Failed to encode image to Base64: zone={}, key={}", zoneId, key, e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
