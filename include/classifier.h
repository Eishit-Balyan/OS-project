#ifndef WARDEN_CLASSIFIER_H
#define WARDEN_CLASSIFIER_H

/**
 * ============================================================================
 * Warden - Event Classifier Module
 * Module Purpose: Evaluates raw filesystem events against established baseline
 *                 records and sensitive paths to assign a security severity.
 * Owner: Ashutosh
 * ============================================================================
 */

#include "common.h"

// Evaluates an Event against baseline records and critical paths to return a ClassifiedEvent
ClassifiedEvent classify(const Event& ev, const Config& config);

#endif // WARDEN_CLASSIFIER_H
