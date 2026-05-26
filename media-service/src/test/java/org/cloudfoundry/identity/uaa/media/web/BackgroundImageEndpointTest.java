package org.cloudfoundry.identity.uaa.media.web;

import org.cloudfoundry.identity.uaa.media.service.BackgroundImageService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.server.ResponseStatusException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class BackgroundImageEndpointTest {

    private static final String ZONE_ID = "test-zone";

    @Mock private BackgroundImageService backgroundImageService;
    @InjectMocks private BackgroundImageEndpoint endpoint;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(endpoint)
                .setControllerAdvice(new FallbackExceptionHandler())
                .build();
        IdentityZone zone = new IdentityZone();
        zone.setId(ZONE_ID);
        IdentityZoneHolder.set(zone);
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    @ControllerAdvice
    static class FallbackExceptionHandler {
        @ExceptionHandler(RuntimeException.class)
        public ResponseEntity<Void> handleRuntimeException(RuntimeException e) {
            if (e instanceof ResponseStatusException rse) {
                return ResponseEntity.status(rse.getStatusCode()).build();
            }
            return ResponseEntity.internalServerError().build();
        }
    }

    // -------------------------------------------------------------------------
    // POST /background_images/upload
    // -------------------------------------------------------------------------

    @Test
    void upload_validFile_returns200AndDelegatesToService() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "image.png", "image/png", "data".getBytes());

        mockMvc.perform(multipart("/background_images/upload").file(file))
                .andExpect(status().isOk());

        verify(backgroundImageService).uploadBackgroundImage(any(), eq(ZONE_ID));
    }

    @Test
    void upload_serviceThrowsUnsupportedMediaType_returns415() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "image.gif", "image/gif", "data".getBytes());
        doThrow(new ResponseStatusException(HttpStatus.UNSUPPORTED_MEDIA_TYPE, "Unsupported image type"))
                .when(backgroundImageService).uploadBackgroundImage(any(), any());

        mockMvc.perform(multipart("/background_images/upload").file(file))
                .andExpect(status().isUnsupportedMediaType());
    }

    @Test
    void upload_serviceThrowsPayloadTooLarge_returns413() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "image.png", "image/png", "data".getBytes());
        doThrow(new ResponseStatusException(HttpStatus.PAYLOAD_TOO_LARGE, "Image exceeds maximum allowed size"))
                .when(backgroundImageService).uploadBackgroundImage(any(), any());

        mockMvc.perform(multipart("/background_images/upload").file(file))
                .andExpect(status().isPayloadTooLarge());
    }

    @Test
    void upload_serviceThrowsRuntimeException_returns500() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "image.png", "image/png", "data".getBytes());
        doThrow(new RuntimeException("S3 upload failed"))
                .when(backgroundImageService).uploadBackgroundImage(any(), any());

        mockMvc.perform(multipart("/background_images/upload").file(file))
                .andExpect(status().isInternalServerError());
    }

    @Test
    void upload_passesCurrentZoneIdToService() throws Exception {
        MockMultipartFile file = new MockMultipartFile("file", "image.png", "image/png", "data".getBytes());

        mockMvc.perform(multipart("/background_images/upload").file(file));

        verify(backgroundImageService).uploadBackgroundImage(any(), eq(ZONE_ID));
    }

    // -------------------------------------------------------------------------
    // DELETE /background_images
    // -------------------------------------------------------------------------

    @Test
    void delete_imageExists_returns204NoContent() throws Exception {
        when(backgroundImageService.deleteBackgroundImage(ZONE_ID)).thenReturn(true);

        mockMvc.perform(delete("/background_images"))
                .andExpect(status().isNoContent());
    }

    @Test
    void delete_noImageInZone_returns404NotFound() throws Exception {
        when(backgroundImageService.deleteBackgroundImage(ZONE_ID)).thenReturn(false);

        mockMvc.perform(delete("/background_images"))
                .andExpect(status().isNotFound());
    }

    @Test
    void delete_passesCurrentZoneIdToService() throws Exception {
        when(backgroundImageService.deleteBackgroundImage(ZONE_ID)).thenReturn(true);

        mockMvc.perform(delete("/background_images"));

        verify(backgroundImageService).deleteBackgroundImage(eq(ZONE_ID));
    }

    @Test
    void delete_serviceThrowsRuntimeException_returns500() throws Exception {
        doThrow(new RuntimeException("S3 connection refused"))
                .when(backgroundImageService).deleteBackgroundImage(ZONE_ID);

        mockMvc.perform(delete("/background_images"))
                .andExpect(status().isInternalServerError());
    }
}
