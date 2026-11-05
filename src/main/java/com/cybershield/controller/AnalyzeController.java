package com.cybershield.controller;

import com.cybershield.model.AnalysisResult;
import com.cybershield.service.AnalyzerService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST controller for the single analysis endpoint.
 *
 * <p>POST /api/analyze accepts JSON with {@code text} and {@code useMl},
 * validates input, delegates to {@link AnalyzerService}, and returns the
 * full {@link AnalysisResult} as JSON.</p>
 *
 * <p>Validation errors produce HTTP 400 with a clear {@code error} message.</p>
 */
@RestController
@RequestMapping("/api")
public class AnalyzeController {

    private final AnalyzerService analyzerService;

    public AnalyzeController(AnalyzerService analyzerService) {
        this.analyzerService = analyzerService;
    }

    // ── Request DTO ──────────────────────────────────────────────────────────

    public record AnalyzeRequest(
            @NotBlank(message = "text must not be blank")
            @Size(max = 5000, message = "text must be at most 5000 characters")
            String text,
            boolean useMl
    ) {}

    // ── Endpoint ─────────────────────────────────────────────────────────────

    /**
     * Analyse the submitted text for cybersecurity threats.
     *
     * @param request validated request body
     * @return 200 with {@link AnalysisResult} or 400 on validation failure
     */
    @PostMapping("/analyze")
    public ResponseEntity<AnalysisResult> analyze(@Valid @RequestBody AnalyzeRequest request) {
        AnalysisResult result = analyzerService.analyse(request.text(), request.useMl());
        return ResponseEntity.ok(result);
    }

    // ── Error handlers (fail-safe, zero stack-trace leakage) ────────────────

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .findFirst()
                .orElse("Invalid request");
        return ResponseEntity.badRequest().body(Map.of("error", message));
    }

    @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, String>> handleNotReadable(org.springframework.http.converter.HttpMessageNotReadableException ex) {
        return ResponseEntity.badRequest().body(Map.of("error", "Malformed request payload"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleGenericException(Exception ex) {
        return ResponseEntity.internalServerError().body(Map.of("error", "An unexpected error occurred while processing the request"));
    }
}
