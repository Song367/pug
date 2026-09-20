-- +goose Up

-- Keep the most recent non-empty browser/device/geo values from real web
-- events. Server-side domain events deliberately have url='', so they can
-- still advance last_seen and event totals without erasing client context.
-- Separate states keep migration additive and preserve the pre-012 columns
-- for rollback.
ALTER TABLE distinct_id_activity_states
    ADD COLUMN IF NOT EXISTS latest_web_browser_state AggregateFunction(argMaxIf, String, DateTime64(3), UInt8),
    ADD COLUMN IF NOT EXISTS latest_web_browser_version_state AggregateFunction(argMaxIf, String, DateTime64(3), UInt8),
    ADD COLUMN IF NOT EXISTS latest_web_os_state AggregateFunction(argMaxIf, String, DateTime64(3), UInt8),
    ADD COLUMN IF NOT EXISTS latest_web_os_version_state AggregateFunction(argMaxIf, String, DateTime64(3), UInt8),
    ADD COLUMN IF NOT EXISTS latest_web_device_state AggregateFunction(argMaxIf, String, DateTime64(3), UInt8),
    ADD COLUMN IF NOT EXISTS latest_web_country_state AggregateFunction(argMaxIf, String, DateTime64(3), UInt8),
    ADD COLUMN IF NOT EXISTS latest_web_region_state AggregateFunction(argMaxIf, String, DateTime64(3), UInt8),
    ADD COLUMN IF NOT EXISTS latest_web_city_state AggregateFunction(argMaxIf, String, DateTime64(3), UInt8);

ALTER TABLE distinct_id_activity_states_mv MODIFY QUERY
SELECT
    project_id,
    distinct_id,
    minState(occur_time)                     AS first_seen_state,
    maxState(occur_time)                     AS last_seen_state,
    countState()                             AS total_events_state,
    sumState(toUInt64(kind = 'page_view'))   AS pageviews_state,
    uniqState(session_id)                    AS sessions_state,
    argMaxState(browser, occur_time)         AS latest_browser_state,
    argMaxState(browser_version, occur_time) AS latest_browser_version_state,
    argMaxState(os, occur_time)              AS latest_os_state,
    argMaxState(os_version, occur_time)      AS latest_os_version_state,
    argMaxState(device, occur_time)          AS latest_device_state,
    argMaxState(country, occur_time)         AS latest_country_state,
    argMaxState(region, occur_time)          AS latest_region_state,
    argMaxState(city, occur_time)            AS latest_city_state,
    argMaxIfState(browser, occur_time, url != '' AND browser != '')                 AS latest_web_browser_state,
    argMaxIfState(browser_version, occur_time, url != '' AND browser_version != '') AS latest_web_browser_version_state,
    argMaxIfState(os, occur_time, url != '' AND os != '')                           AS latest_web_os_state,
    argMaxIfState(os_version, occur_time, url != '' AND os_version != '')           AS latest_web_os_version_state,
    argMaxIfState(device, occur_time, url != '' AND device != '')                   AS latest_web_device_state,
    argMaxIfState(country, occur_time, url != '' AND country != '')                 AS latest_web_country_state,
    argMaxIfState(region, occur_time, url != '' AND region != '')                   AS latest_web_region_state,
    argMaxIfState(city, occur_time, url != '' AND city != '')                       AS latest_web_city_state
FROM events
WHERE NOT startsWith(distinct_id, 'cookieless-')
GROUP BY project_id, distinct_id;

-- Recover only context that is already present in historical raw events. A
-- state with no matching value is neutral when merged with future states.
INSERT INTO distinct_id_activity_states (
    project_id,
    distinct_id,
    latest_web_browser_state,
    latest_web_browser_version_state,
    latest_web_os_state,
    latest_web_os_version_state,
    latest_web_device_state,
    latest_web_country_state,
    latest_web_region_state,
    latest_web_city_state
)
SELECT
    project_id,
    distinct_id,
    argMaxIfState(browser, occur_time, url != '' AND browser != ''),
    argMaxIfState(browser_version, occur_time, url != '' AND browser_version != ''),
    argMaxIfState(os, occur_time, url != '' AND os != ''),
    argMaxIfState(os_version, occur_time, url != '' AND os_version != ''),
    argMaxIfState(device, occur_time, url != '' AND device != ''),
    argMaxIfState(country, occur_time, url != '' AND country != ''),
    argMaxIfState(region, occur_time, url != '' AND region != ''),
    argMaxIfState(city, occur_time, url != '' AND city != '')
FROM events
WHERE NOT startsWith(distinct_id, 'cookieless-')
GROUP BY project_id, distinct_id;

-- +goose Down

ALTER TABLE distinct_id_activity_states_mv MODIFY QUERY
SELECT
    project_id,
    distinct_id,
    minState(occur_time)                     AS first_seen_state,
    maxState(occur_time)                     AS last_seen_state,
    countState()                             AS total_events_state,
    sumState(toUInt64(kind = 'page_view'))   AS pageviews_state,
    uniqState(session_id)                    AS sessions_state,
    argMaxState(browser, occur_time)         AS latest_browser_state,
    argMaxState(browser_version, occur_time) AS latest_browser_version_state,
    argMaxState(os, occur_time)              AS latest_os_state,
    argMaxState(os_version, occur_time)      AS latest_os_version_state,
    argMaxState(device, occur_time)          AS latest_device_state,
    argMaxState(country, occur_time)         AS latest_country_state,
    argMaxState(region, occur_time)          AS latest_region_state,
    argMaxState(city, occur_time)            AS latest_city_state
FROM events
WHERE NOT startsWith(distinct_id, 'cookieless-')
GROUP BY project_id, distinct_id;

ALTER TABLE distinct_id_activity_states
    DROP COLUMN IF EXISTS latest_web_browser_state,
    DROP COLUMN IF EXISTS latest_web_browser_version_state,
    DROP COLUMN IF EXISTS latest_web_os_state,
    DROP COLUMN IF EXISTS latest_web_os_version_state,
    DROP COLUMN IF EXISTS latest_web_device_state,
    DROP COLUMN IF EXISTS latest_web_country_state,
    DROP COLUMN IF EXISTS latest_web_region_state,
    DROP COLUMN IF EXISTS latest_web_city_state;
