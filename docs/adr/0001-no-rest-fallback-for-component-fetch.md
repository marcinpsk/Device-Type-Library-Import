# ADR 0001: No REST fallback for component fetch

## Status

Accepted

## Context

The component cache had an empty `REST_ONLY_ENDPOINTS` set. An endpoint in that set would use REST instead of
GraphQL. The REST count check would then skip the endpoint because comparing REST data with a REST count gives no
independent check.

The set was always empty, so the trigger condition never fired in production. The REST adapter was a hypothetical
seam. Tests could exercise the branches only by monkeypatching the module global.

## Decision

Delete `REST_ONLY_ENDPOINTS` and both guarded branches. Bulk component fetching uses GraphQL. The integrity check
compares each cached component count with REST. Targeted REST reads for a cold cache remain unchanged.

## Consequences

The component cache has one bulk fetch path and no inactive adapter branch. Tests no longer change a module global
to create a runtime state that production cannot reach.

This decision is reversible. If a NetBox version drops a required field from GraphQL but keeps it in REST, a REST
path can be restored with a few lines and tests against an actual trigger condition.
