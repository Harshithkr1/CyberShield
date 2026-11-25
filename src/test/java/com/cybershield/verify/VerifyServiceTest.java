package com.cybershield.verify;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Verify backend unit tests — Registry, ReceiverVerifier, PaymentSigner, QR, Receipts")
class VerifyServiceTest {

    private static final byte[] TEST_KEY = "0123456789abcdef0123456789abcdef".getBytes(StandardCharsets.UTF_8);

    @Test
    @DisplayName("demo-merchants.json loads 5 fictional Demo Bank merchants")
    void merchantRegistryLoadsFiveDemoMerchants() {
        DemoMerchantRegistry registry = new DemoMerchantRegistry();
        List<DemoMerchant> all = registry.findAll();

        assertThat(all).hasSize(5);
        assertThat(all).allSatisfy(m -> {
            assertThat(m.id()).isNotBlank();
            assertThat(m.name()).isNotBlank();
            assertThat(m.upiId()).endsWith("@demobank");
            assertThat(m.bank()).isEqualTo("Demo Bank");
        });
    }

    @Test
    @DisplayName("ReceiverVerifier classifies VERIFIED_DEMO, NAME_MISMATCH, LOOKALIKE, and UNKNOWN")
    void receiverVerifierClassifications() {
        DemoMerchantRegistry registry = new DemoMerchantRegistry();
        ReceiverVerifier verifier = new ReceiverVerifier(registry);

        var verified = verifier.verify("ravi@demobank", "Ravi Stores");
        assertThat(verified.status()).isEqualTo(ReceiverVerifier.Status.VERIFIED_DEMO);
        assertThat(verified.merchant().id()).isEqualTo("ravi-stores");

        var mismatch = verifier.verify("ravi@demobank", "Other Shop");
        assertThat(mismatch.status()).isEqualTo(ReceiverVerifier.Status.NAME_MISMATCH);

        var lookalike = verifier.verify("ravl@demobank", null);
        assertThat(lookalike.status()).isEqualTo(ReceiverVerifier.Status.LOOKALIKE);
        assertThat(lookalike.closestMatch().upiId()).isEqualTo("ravi@demobank");

        var unknown = verifier.verify("nobody@unknownbank", null);
        assertThat(unknown.status()).isEqualTo(ReceiverVerifier.Status.UNKNOWN);
        assertThat(unknown.reason()).isEqualTo("cannot be verified here");

        // Distance <= 2 on DIFFERENT handle is UNKNOWN, not LOOKALIKE
        var differentHandle = verifier.verify("ravl@otherbank", null);
        assertThat(differentHandle.status()).isEqualTo(ReceiverVerifier.Status.UNKNOWN);
    }

    @Test
    @DisplayName("PaymentSigner: sign then check = VALID; tampered amount or merchant = TAMPERED")
    void signCheckAndTamperDetection() {
        Instant now = Instant.parse("2026-11-25T10:00:00Z");
        Clock fixedClock = Clock.fixed(now, ZoneOffset.UTC);
        PaymentSigner signer = new PaymentSigner(TEST_KEY, fixedClock);

        var signed = signer.sign("ravi-stores", "ravi@demobank", 50000L, "ORD-101");
        assertThat(signed.canonical()).isEqualTo(
                "v1|ravi-stores|ravi@demobank|50000|INR|ORD-101|" + (now.getEpochSecond() + 600));

        var validCheck = signer.check(signed.payload(), signed.signature());
        assertThat(validCheck.status()).isEqualTo(PaymentSigner.Status.VALID);
        assertThat(validCheck.amountPaise()).isEqualTo(50000L);
        assertThat(validCheck.amountRupees()).isEqualTo("500.00");

        // Change amount in payload
        String decoded = new String(Base64.getUrlDecoder().decode(signed.payload()), StandardCharsets.UTF_8);
        String tamperedAmount = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(decoded.replace("|50000|", "|500000|").getBytes(StandardCharsets.UTF_8));
        assertThat(signer.check(tamperedAmount, signed.signature()).status())
                .isEqualTo(PaymentSigner.Status.TAMPERED);

        // Change merchant in payload
        String tamperedMerchant = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(decoded.replace("ravi-stores", "evil-stores").getBytes(StandardCharsets.UTF_8));
        assertThat(signer.check(tamperedMerchant, signed.signature()).status())
                .isEqualTo(PaymentSigner.Status.TAMPERED);

        // Malformed payload
        assertThat(signer.check("not-base64!!!", signed.signature()).status())
                .isEqualTo(PaymentSigner.Status.MALFORMED);
    }

    @Test
    @DisplayName("PaymentSigner: expired token returns EXPIRED")
    void expiredTokenReturnsExpired() {
        Instant t0 = Instant.parse("2026-11-25T10:00:00Z");
        PaymentSigner issueSigner = new PaymentSigner(TEST_KEY, Clock.fixed(t0, ZoneOffset.UTC));
        var signed = issueSigner.sign("ravi-stores", "ravi@demobank", 10000L, "ORD-102");

        // Verify 10 minutes + 1 second later using the same key
        Clock expiredClock = Clock.fixed(t0.plusSeconds(601), ZoneOffset.UTC);
        PaymentSigner verifySigner = new PaymentSigner(TEST_KEY, expiredClock);

        var check = verifySigner.check(signed.payload(), signed.signature());
        assertThat(check.status()).isEqualTo(PaymentSigner.Status.EXPIRED);
    }

    @Test
    @DisplayName("QrCodeGenerator returns a valid 300x300 PNG data URI")
    void qrGeneratorCreates300pxPngDataUri() throws Exception {
        QrCodeGenerator gen = new QrCodeGenerator();
        String uri = gen.toPngDataUri("https://demo.example/pay-demo.html?p=abc&s=xyz");
        assertThat(uri).startsWith("data:image/png;base64,");

        byte[] pngBytes = Base64.getDecoder().decode(uri.substring("data:image/png;base64,".length()));
        BufferedImage img = ImageIO.read(new ByteArrayInputStream(pngBytes));
        assertThat(img).isNotNull();
        assertThat(img.getWidth()).isEqualTo(300);
        assertThat(img.getHeight()).isEqualTo(300);
    }

    @Test
    @DisplayName("ReceiptService: 3 chained receipts are valid; editing amount in entry 2 returns brokenAtIndex 1")
    void chainedReceiptsAndTamperIndexDetection() {
        Instant now = Instant.parse("2026-11-25T10:00:00Z");
        Clock fixedClock = Clock.fixed(now, ZoneOffset.UTC);
        PaymentSigner signer = new PaymentSigner(TEST_KEY, fixedClock);
        DemoMerchantRegistry registry = new DemoMerchantRegistry();
        ReceiptService receiptService = new ReceiptService(signer, registry, fixedClock);

        var p1 = signer.sign("ravi-stores", "ravi@demobank", 15000L, "ORD-1");
        var p2 = signer.sign("meera-tailors", "meera.tailor@demobank", 25000L, "ORD-2");
        var p3 = signer.sign("shanti-pharmacy", "shanti.meds@demobank", 45000L, "ORD-3");

        var r1 = receiptService.issueReceipt(p1.payload(), p1.signature(), null);
        var r2 = receiptService.issueReceipt(p2.payload(), p2.signature(), r1.hash());
        var r3 = receiptService.issueReceipt(p3.payload(), p3.signature(), r2.hash());

        assertThat(r1.receiptId()).startsWith("DEMO-");
        assertThat(receiptService.checkTrail(List.of(r1, r2, r3)).valid()).isTrue();

        // Tamper amount in entry 2 (index 1)
        var tamperedR2 = new ReceiptService.ReceiptEntry(
                r2.receiptId(), r2.merchant(), r2.upiId(), "999.00",
                r2.timestamp(), r2.prevHash(), r2.hash(), r2.signature()
        );
        var broken = receiptService.checkTrail(List.of(r1, tamperedR2, r3));
        assertThat(broken.valid()).isFalse();
        assertThat(broken.brokenAtIndex()).isEqualTo(1);

        // Tampered payment token cannot issue a receipt
        assertThatThrownBy(() -> receiptService.issueReceipt(p1.payload(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", null))
                .isInstanceOf(ReceiptService.InvalidPaymentTokenException.class);
    }
}

