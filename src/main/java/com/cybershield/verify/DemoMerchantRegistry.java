package com.cybershield.verify;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

/**
 * Loads fictional merchants from {@code verify/demo-merchants.json} on the classpath.
 */
@Component
public class DemoMerchantRegistry {

    public static final String DEFAULT_MERCHANTS_PATH = "/verify/demo-merchants.json";

    private final List<DemoMerchant> merchants;
    private final Map<String, DemoMerchant> byId;
    private final Map<String, DemoMerchant> byUpiId;

    public DemoMerchantRegistry() {
        this(new ObjectMapper(), DEFAULT_MERCHANTS_PATH);
    }

    @Autowired
    public DemoMerchantRegistry(@Autowired(required = false) ObjectMapper mapper) {
        this(mapper != null ? mapper : new ObjectMapper(), DEFAULT_MERCHANTS_PATH);
    }

    public DemoMerchantRegistry(ObjectMapper mapper, String resourcePath) {
        try (InputStream is = DemoMerchantRegistry.class.getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IllegalStateException("Demo merchants file not found on classpath: " + resourcePath);
            }
            List<DemoMerchant> loaded = mapper.readValue(is, new TypeReference<>() {});
            if (loaded == null || loaded.isEmpty()) {
                throw new IllegalStateException("Demo merchants list cannot be empty");
            }
            this.merchants = List.copyOf(loaded);

            Map<String, DemoMerchant> idMap = new LinkedHashMap<>();
            Map<String, DemoMerchant> upiMap = new LinkedHashMap<>();
            for (DemoMerchant m : loaded) {
                idMap.put(m.id().toLowerCase(Locale.ROOT), m);
                upiMap.put(m.upiId().toLowerCase(Locale.ROOT), m);
            }
            this.byId = Map.copyOf(idMap);
            this.byUpiId = Map.copyOf(upiMap);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load demo merchants from " + resourcePath, e);
        }
    }

    public List<DemoMerchant> findAll() {
        return merchants;
    }

    public Optional<DemoMerchant> findById(String id) {
        if (id == null || id.isBlank()) return Optional.empty();
        return Optional.ofNullable(byId.get(id.trim().toLowerCase(Locale.ROOT)));
    }

    public Optional<DemoMerchant> findByUpiId(String upiId) {
        if (upiId == null || upiId.isBlank()) return Optional.empty();
        return Optional.ofNullable(byUpiId.get(upiId.trim().toLowerCase(Locale.ROOT)));
    }
}

