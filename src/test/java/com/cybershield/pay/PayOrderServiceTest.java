package com.cybershield.pay;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PayOrderServiceTest {

    private static final byte[] TEST_KEY = "unit-test-32-byte-signing-secret!".getBytes(StandardCharsets.UTF_8);
    private static final Instant START_TIME = Instant.parse("2026-11-26T00:00:00Z");

    private final ObjectMapper mapper = new ObjectMapper();

    private static final class MutableClock extends Clock {
        private Instant current;

        MutableClock(Instant initial) { this.current = initial; }
        void advanceSeconds(long secs) { this.current = this.current.plusSeconds(secs); }

        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return current; }
    }

    private String decodeQrToken(String qrPngBase64) throws Exception {
        byte[] png = Base64.getDecoder().decode(qrPngBase64);
        BufferedImage img = ImageIO.read(new ByteArrayInputStream(png));
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(new BufferedImageLuminanceSource(img)));
        return new MultiFormatReader().decode(bitmap).getText();
    }

    private String replacePayloadField(String cs1Token, String paOverride, String amOverride) throws Exception {
        String[] parts = cs1Token.split("\\.", -1);
        PayOrderService.OrderPayload orig = mapper.readValue(
                Base64.getUrlDecoder().decode(parts[1]),
                PayOrderService.OrderPayload.class
        );
        PayOrderService.OrderPayload modified = new PayOrderService.OrderPayload(
                paOverride != null ? paOverride : orig.pa(),
                orig.pn(),
                amOverride != null ? amOverride : orig.am(),
                orig.tr(),
                orig.tn(),
                orig.ts()
        );
        String b64u = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mapper.writeValueAsBytes(modified));
        return parts[0] + "." + b64u + "." + parts[2];
    }

    @Test
    @DisplayName("Valid CS1 token encoded in QR PNG verifies cleanly")
    void validTokenVerifies() throws Exception {
        PayOrderService service = new PayOrderService(TEST_KEY, Clock.fixed(START_TIME, ZoneOffset.UTC), mapper);
        PayOrderService.OrderResponse order = service.createOrder(
                new PayOrderService.CreateOrderRequest(
                        "demo-shop@csbank",
                        "Cyber Shield Demo Store",
                        new BigDecimal("250.5"),
                        "Order checkout",
                        "ORD-101"
                )
        );

        assertThat(order.canonical()).isEqualTo("demo-shop@csbank|Cyber Shield Demo Store|250.50|ORD-101|Order checkout|" + START_TIME.toEpochMilli());
        assertThat(order.payload().am()).isEqualTo("250.50");
        assertThat(order.signatureHex()).hasSize(64);

        String qrToken = decodeQrToken(order.qrPngBase64());
        assertThat(qrToken).startsWith("CS1.");

        PayOrderService.VerifyResponse res = service.verifyToken(qrToken);
        assertThat(res.valid()).isTrue();
        assertThat(res.reason()).isEqualTo("valid");
        assertThat(res.changedFields()).isEmpty();
        assertThat(res.payload()).isEqualTo(order.payload());
    }

    @Test
    @DisplayName("Tampered pa is detected with changedFields naming pa")
    void tamperedPaDetected() throws Exception {
        PayOrderService service = new PayOrderService(TEST_KEY, Clock.fixed(START_TIME, ZoneOffset.UTC), mapper);
        PayOrderService.OrderResponse order = service.createOrder(
                new PayOrderService.CreateOrderRequest("demo-shop@csbank", "Shop", new BigDecimal("500"), "Tea", "ORD-102")
        );
        String qrToken = decodeQrToken(order.qrPngBase64());
        String tampered = replacePayloadField(qrToken, "attacker@ybl", null);

        PayOrderService.VerifyResponse res = service.verifyToken(tampered);
        assertThat(res.valid()).isFalse();
        assertThat(res.changedFields()).hasSize(1);
        assertThat(res.changedFields().get(0).field()).isEqualTo("pa");
        assertThat(res.changedFields().get(0).original()).isEqualTo("demo-shop@csbank");
        assertThat(res.changedFields().get(0).received()).isEqualTo("attacker@ybl");
    }

    @Test
    @DisplayName("Tampered am is detected with changedFields naming am")
    void tamperedAmDetected() throws Exception {
        PayOrderService service = new PayOrderService(TEST_KEY, Clock.fixed(START_TIME, ZoneOffset.UTC), mapper);
        PayOrderService.OrderResponse order = service.createOrder(
                new PayOrderService.CreateOrderRequest("demo-shop@csbank", "Shop", new BigDecimal("500"), "Tea", "ORD-103")
        );
        String qrToken = decodeQrToken(order.qrPngBase64());
        String tampered = replacePayloadField(qrToken, null, "5000.00");

        PayOrderService.VerifyResponse res = service.verifyToken(tampered);
        assertThat(res.valid()).isFalse();
        assertThat(res.changedFields()).extracting(PayOrderService.ChangedField::field).containsExactly("am");
        assertThat(res.changedFields().get(0).original()).isEqualTo("500.00");
        assertThat(res.changedFields().get(0).received()).isEqualTo("5000.00");
    }

    @Test
    @DisplayName("Expired token (>300s) returns valid=false and reason='expired'")
    void expiredTokenRejected() throws Exception {
        MutableClock clock = new MutableClock(START_TIME);
        PayOrderService service = new PayOrderService(TEST_KEY, clock, mapper);
        PayOrderService.OrderResponse order = service.createOrder(
                new PayOrderService.CreateOrderRequest("demo-shop@csbank", "Shop", new BigDecimal("100"), "Pay", "ORD-104")
        );
        String qrToken = decodeQrToken(order.qrPngBase64());

        clock.advanceSeconds(301);

        PayOrderService.VerifyResponse res = service.verifyToken(qrToken);
        assertThat(res.valid()).isFalse();
        assertThat(res.reason()).isEqualTo("expired");
        assertThat(res.changedFields()).isEmpty();
    }

    @Test
    @DisplayName("Garbage token returns valid=false and reason='unsigned or unknown order'")
    void garbageTokenRejected() {
        PayOrderService service = new PayOrderService(TEST_KEY, Clock.fixed(START_TIME, ZoneOffset.UTC), mapper);
        for (String bad : new String[]{null, "", "not-a-token", "CS1.bad!!.sig", "CS2.abc.def"}) {
            PayOrderService.VerifyResponse res = service.verifyToken(bad);
            assertThat(res.valid()).isFalse();
            assertThat(res.reason()).isEqualTo("unsigned or unknown order");
            assertThat(res.changedFields()).isEmpty();
        }
    }

    @Test
    @DisplayName("Invalid order requests (amount <= 0, empty VPA, missing ref) are rejected")
    void invalidOrderInputsRejected() {
        PayOrderService service = new PayOrderService(TEST_KEY, Clock.fixed(START_TIME, ZoneOffset.UTC), mapper);
        assertThatThrownBy(() -> service.createOrder(
                new PayOrderService.CreateOrderRequest("", "Shop", new BigDecimal("10"), "N", "REF-1")
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.createOrder(
                new PayOrderService.CreateOrderRequest("a@b", "Shop", BigDecimal.ZERO, "N", "REF-1")
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.createOrder(
                new PayOrderService.CreateOrderRequest("a@b", "Shop", new BigDecimal("-5"), "N", "REF-1")
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.createOrder(
                new PayOrderService.CreateOrderRequest("a@b", "Shop", new BigDecimal("10"), "N", " ")
        )).isInstanceOf(IllegalArgumentException.class);
    }
}

