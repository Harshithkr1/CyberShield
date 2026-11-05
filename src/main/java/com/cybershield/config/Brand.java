package com.cybershield.config;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Represents a recognized brand and its official (canonical) domain names.
 *
 * @param name            human-readable brand name (e.g. "SBI", "Amazon")
 * @param officialDomains list of authorized domains for this brand (e.g. ["sbi.co.in", "onlinesbi.sbi"])
 */
public record Brand(
        @JsonProperty("name")
        String name,

        @JsonProperty("officialDomains")
        @JsonAlias({"canonicalDomains", "domains"})
        List<String> officialDomains
) {

    public Brand {
        if (officialDomains == null) {
            officialDomains = List.of();
        } else {
            officialDomains = List.copyOf(officialDomains);
        }
    }

    /**
     * Alias for {@link #officialDomains()} for compatibility with canonical domain naming.
     */
    public List<String> canonicalDomains() {
        return officialDomains;
    }

    /**
     * Checks whether a host name matches one of this brand's official domains.
     *
     * @param host domain or host name (e.g. "secure.sbi.co.in" or "sbi.co.in")
     * @return true if the host is or belongs to an official domain
     */
    public boolean isOfficialDomain(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String cleanHost = host.trim().toLowerCase();
        return officialDomains.stream()
                .map(String::toLowerCase)
                .anyMatch(domain -> cleanHost.equals(domain) || cleanHost.endsWith("." + domain));
    }
}

