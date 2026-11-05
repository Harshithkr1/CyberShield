package com.cybershield.detector;

import com.cybershield.model.Signal;

import java.util.List;

/**
 * Contract for all signal detectors.
 * Each implementation inspects the raw input text and returns zero or more
 * {@link Signal}s it detected.
 */
public interface Detector {

    /**
     * Analyse the given text and return all signals found.
     *
     * @param text the raw user-submitted text (never null, never empty)
     * @return immutable list of signals (may be empty, never null)
     */
    List<Signal> detect(String text);

    /**
     * A short, human-readable name used for logging and ordering.
     */
    String name();
}
