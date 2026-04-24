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
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;

import javax.imageio.ImageIO;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.util.Map;

/**
 * REST endpoint for background image upload and retrieval.
 *
 * <p>Endpoints:
 * <ul>
 *   <li>POST  /background_images            – upload image</li>
 *   <li>GET   /background_images/stream     – stream raw image with performance logging</li>
 *   <li>GET   /background_images/responsive – stream image scaled to requested viewport width</li>
 * </ul>
 */
@RestController
@RequestMapping("/background_images")
public class BackgroundImageEndpoint {

    private static final Logger logger = LoggerFactory.getLogger(BackgroundImageEndpoint.class);

    /** Buffer size used when piping S3 bytes to the HTTP response (32 KB). */
    private static final int BUFFER_SIZE = 32 * 1024;

    /** Default viewport width used when none is specified (desktop). */
    private static final int DEFAULT_WIDTH_PX = 1920;

    /** Minimum allowed viewport width to avoid degenerate resize requests. */
    private static final int MIN_WIDTH_PX = 64;

    /** Maximum allowed viewport width; larger values are clamped. */
    private static final int MAX_WIDTH_PX = 3840;

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

        // Derive the plain S3 key from the URI (strip "s3://bucket/")
        String s3Key = s3Uri.replaceFirst("^s3://[^/]+/", "");

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("url", s3Uri, "key", s3Key));
    }

    // -------------------------------------------------------------------------
    // GET /background_images/stream
    // -------------------------------------------------------------------------

    /**
     * Stream the raw background image directly from S3.
     *
     * <p>Performance metrics (time-to-first-byte, total transfer time, throughput) are
     * logged at INFO level for every request so they can be collected by log aggregators.
     *
     * <p>The response uses {@link StreamingResponseBody} so Spring does <em>not</em>
     * buffer the entire image in memory before sending the first byte to the client.
     *
     * @param key the S3 object key returned by the upload endpoint
     * @return streaming image response with correct Content-Type and caching headers
     */
    @GetMapping(value = "/stream")
    public ResponseEntity<StreamingResponseBody> streamImage(@RequestParam("key") String key) {
        String zoneId = IdentityZoneHolder.get().getId();
        logger.info("GET /background_images/stream: zone={}, key={}", zoneId, key);

        long requestStart = System.currentTimeMillis();
        ResponseInputStream<GetObjectResponse> s3Stream =
                backgroundImageService.downloadBackgroundImage(zoneId, key);

        GetObjectResponse s3Meta = s3Stream.response();
        String contentType = s3Meta.contentType() != null ? s3Meta.contentType() : "image/png";
        Long contentLength = s3Meta.contentLength();

        long ttfb = System.currentTimeMillis() - requestStart;
        logger.info("S3 TTFB: zone={}, key={}, ttfbMs={}", zoneId, key, ttfb);

        StreamingResponseBody body = outputStream -> {
            long transferStart = System.currentTimeMillis();
            long totalBytes = 0;
            try (s3Stream) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int read;
                while ((read = s3Stream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, read);
                    totalBytes += read;
                }
                outputStream.flush();
            } catch (IOException e) {
                logger.error("Error streaming image to client: zone={}, key={}", zoneId, key, e);
                throw e;
            }
            long transferMs = System.currentTimeMillis() - transferStart;
            double throughputKbps = transferMs > 0 ? (totalBytes / 1024.0) / (transferMs / 1000.0) : 0;
            logger.info("Stream complete: zone={}, key={}, totalBytes={}, transferMs={}, throughputKBps={:.1f}",
                    zoneId, key, totalBytes, transferMs, throughputKbps);
        };

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.CONTENT_TYPE, contentType);
        headers.set(HttpHeaders.CACHE_CONTROL, "public, max-age=86400");
        if (contentLength != null) {
            headers.setContentLength(contentLength);
        }

        return ResponseEntity.ok().headers(headers).body(body);
    }

    // -------------------------------------------------------------------------
    // GET /background_images/responsive
    // -------------------------------------------------------------------------

    /**
     * Stream a viewport-adapted version of the background image.
     *
     * <p>The image is fetched from S3, decoded with {@link ImageIO}, proportionally scaled
     * to the requested {@code width} (height is computed to preserve aspect ratio), and
     * re-encoded as PNG before streaming to the client.
     *
     * <p>This solves the problem of CSS {@code background-image} not responding to
     * {@code <picture>} / {@code srcset} media queries: the caller (typically the login
     * page JS or a {@code <img>} tag) decides which width to request and the server
     * delivers exactly that resolution.
     *
     * <p>Common usage:
     * <pre>
     *   /background_images/responsive?key=background_images/zone/xxx.png&amp;width=375   (mobile)
     *   /background_images/responsive?key=background_images/zone/xxx.png&amp;width=768   (tablet)
     *   /background_images/responsive?key=background_images/zone/xxx.png&amp;width=1280  (laptop)
     *   /background_images/responsive?key=background_images/zone/xxx.png&amp;width=1920  (desktop)
     * </pre>
     *
     * @param key   the S3 object key
     * @param width desired output width in pixels (default: 1920, clamped to [{@value #MIN_WIDTH_PX}, {@value #MAX_WIDTH_PX}])
     * @return streaming PNG response scaled to the requested width
     */
    @GetMapping(value = "/responsive", produces = MediaType.IMAGE_PNG_VALUE)
    public ResponseEntity<StreamingResponseBody> responsiveImage(
            @RequestParam("key") String key,
            @RequestParam(value = "width", defaultValue = "" + DEFAULT_WIDTH_PX) int width) {

        String zoneId = IdentityZoneHolder.get().getId();
        int targetWidth = Math.max(MIN_WIDTH_PX, Math.min(MAX_WIDTH_PX, width));
        logger.info("GET /background_images/responsive: zone={}, key={}, requestedWidth={}, targetWidth={}",
                zoneId, key, width, targetWidth);

        StreamingResponseBody body = outputStream -> {
            long start = System.currentTimeMillis();

            // 1. Fetch from S3
            try (ResponseInputStream<GetObjectResponse> s3Stream =
                         backgroundImageService.downloadBackgroundImage(zoneId, key)) {

                long s3Ms = System.currentTimeMillis() - start;
                logger.debug("S3 fetch complete: zone={}, key={}, s3Ms={}", zoneId, key, s3Ms);

                // 2. Decode original image
                BufferedImage original = ImageIO.read(s3Stream);
                if (original == null) {
                    logger.error("ImageIO could not decode image: zone={}, key={}", zoneId, key);
                    throw new IOException("Unsupported image format for key: " + key);
                }

                // 3. Scale proportionally
                int origWidth  = original.getWidth();
                int origHeight = original.getHeight();
                int targetHeight = (int) Math.round((double) origHeight / origWidth * targetWidth);

                logger.debug("Resizing: original={}x{}, target={}x{}, zone={}",
                        origWidth, origHeight, targetWidth, targetHeight, zoneId);

                BufferedImage resized = new BufferedImage(targetWidth, targetHeight, BufferedImage.TYPE_INT_ARGB);
                Graphics2D g2d = resized.createGraphics();
                try {
                    g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
                            RenderingHints.VALUE_INTERPOLATION_BILINEAR);
                    g2d.setRenderingHint(RenderingHints.KEY_RENDERING,
                            RenderingHints.VALUE_RENDER_QUALITY);
                    g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                            RenderingHints.VALUE_ANTIALIAS_ON);
                    g2d.drawImage(original, 0, 0, targetWidth, targetHeight, null);
                } finally {
                    g2d.dispose();
                }

                // 4. Encode as PNG and stream
                boolean written = ImageIO.write(resized, "png", outputStream);
                if (!written) {
                    throw new IOException("No suitable PNG ImageWriter found");
                }
                outputStream.flush();

                long totalMs = System.currentTimeMillis() - start;
                logger.info("Responsive image served: zone={}, key={}, width={}, totalMs={}",
                        zoneId, key, targetWidth, totalMs);

            } catch (IOException e) {
                logger.error("Failed to serve responsive image: zone={}, key={}, width={}",
                        zoneId, key, targetWidth, e);
                throw e;
            }
        };

        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.CONTENT_TYPE, MediaType.IMAGE_PNG_VALUE);
        headers.set(HttpHeaders.CACHE_CONTROL, "public, max-age=86400");
        // Inform CDN/browser of the actual rendered width for Vary caching
        headers.set("X-Image-Width", String.valueOf(targetWidth));

        return ResponseEntity.ok().headers(headers).body(body);
    }
}
