CREATE TABLE public.webhook_endpoints (
    id TEXT PRIMARY KEY
        CHECK (id ~ '^we_[A-Za-z0-9]+$' AND length(id) <= 255),

    merchant_id TEXT NOT NULL
        CHECK (length(btrim(merchant_id)) BETWEEN 1 AND 255),

    url TEXT NOT NULL
        CHECK (url LIKE 'https://%'),

    secret TEXT NOT NULL
        CHECK (secret ~ '^whsec_[A-Za-z0-9_-]+$'),

    events TEXT[] NOT NULL
        CHECK (
            cardinality(events) > 0
            AND array_position(events, NULL) IS NULL
            AND events <@ ARRAY[
                'payment_intent.succeeded',
                'payment_intent.payment_failed',
                'refund.created'
            ]::TEXT[]
        ),

    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX webhook_endpoints_merchant_page_idx
    ON public.webhook_endpoints (
        merchant_id,
        created_at DESC,
        id DESC
    );
