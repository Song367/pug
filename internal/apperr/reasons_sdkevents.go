package apperr

// SDK events domain reasons.
var (
	ReasonInvalidEventBatch             = codes.add("INVALID_EVENT_BATCH")
	ReasonCookielessIdentityUnavailable = codes.add("COOKIELESS_IDENTITY_UNAVAILABLE")
	ReasonIngestRateLimited             = codes.add("INGEST_RATE_LIMITED")
	ReasonIngestConcurrencyLimited      = codes.add("INGEST_CONCURRENCY_LIMITED")
)
