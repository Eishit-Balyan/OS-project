#ifndef SENTINELFS_CLASSIFIER_H
#define SENTINELFS_CLASSIFIER_H

/**
 * ============================================================================
 * SentinelFS - Event Classifier Module
 * Module Purpose: Evaluates raw filesystem events against established baseline
 *                 records and sensitive paths to assign a security severity.
 * Owner: Ayaansh
 * ============================================================================
 */

#include "common.h"

// Evaluates an Event against baseline records and critical paths to return a ClassifiedEvent
ClassifiedEvent classify(const Event& ev, const Config& config);

#endif // SENTINELFS_CLASSIFIER_H
