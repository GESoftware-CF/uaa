package org.cloudfoundry.identity.uaa.provider.token;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

final class TestCodecUtils {
    private static final Base64.Encoder URL_ENCODER = Base64.getUrlEncoder().withoutPadding();

    private TestCodecUtils() {}

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    static String utf8Decode(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    static byte[] b64UrlEncode(byte[] data) {
        return URL_ENCODER.encode(data);
    }

    static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            len += p.length;
        }
        byte[] out = new byte[len];
        int pos = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }
}
