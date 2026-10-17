"""Retry NetBox writes after a transient error, without repeating a write that committed."""

import time

import pynetbox
import requests

# Transient errors that warrant a retry: no reply, a cut-off reply, or a reply that is not JSON
RETRYABLE_EXCEPTIONS = (
    requests.exceptions.ConnectionError,
    requests.exceptions.Timeout,
    requests.exceptions.ChunkedEncodingError,
    pynetbox.core.query.ContentError,
)

MAX_RETRIES = 3
RETRY_BACKOFF = (2, 5, 10)  # seconds to wait before each retry attempt


def call_with_retry(func, *args, find_existing=None, **kwargs):
    """Call *func* with retries on transient connection errors.

    Retries up to ``MAX_RETRIES`` times with backoff for each error in ``RETRYABLE_EXCEPTIONS``.
    Non-retryable exceptions propagate immediately.

    A transient error can arrive after NetBox committed the write.  Before each retry,
    *find_existing* (when given) checks for that: a result other than None is returned
    in place of a second write.  A transient error in that check counts as a failed attempt.
    """
    for attempt in range(MAX_RETRIES + 1):
        try:
            if attempt and find_existing is not None:
                existing = find_existing()
                if existing is not None:
                    return existing
            return func(*args, **kwargs)
        except RETRYABLE_EXCEPTIONS:
            if attempt >= MAX_RETRIES:
                raise
            time.sleep(RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF) - 1)])
    raise AssertionError("unreachable: the last attempt returns or raises")


def create_with_retry(endpoint, payload, key, **scope):
    """Create *payload* on *endpoint*, retrying without creating a duplicate.

    *key* names the payload field that, with the *scope* filters, identifies one object
    (for example ``key="model", manufacturer=slug``).  Before a retry, the object is looked
    up by that natural key.  When it exists, it is returned as the create would return it:
    one Record for a dict payload, a list of Records in payload order for a list payload.

    A bulk create in NetBox is atomic, so a partial match means another writer.  It is not
    taken as the result; the create is sent again and NetBox rejects or accepts it.
    """
    if isinstance(payload, list):
        return call_with_retry(endpoint.create, payload, find_existing=lambda: _find_all(endpoint, payload, key, scope))
    return call_with_retry(endpoint.create, payload, find_existing=lambda: endpoint.get(**scope, **{key: payload[key]}))


def delete_with_retry(endpoint, object_id):
    """Delete one object by id, counting it as deleted when a lost reply hid the commit.

    Returns True.  Before a retry, the object is looked up by id; when it is gone, the
    earlier attempt committed and the delete is not sent again.
    """
    return call_with_retry(
        endpoint.delete, [object_id], find_existing=lambda: True if endpoint.get(id=object_id) is None else None
    )


def _find_all(endpoint, items, key, scope):
    """Return the record for each item in payload order, or None unless every item exists."""
    found = {getattr(record, key): record for record in endpoint.filter(**scope, **{key: [i[key] for i in items]})}
    if any(item[key] not in found for item in items):
        return None
    return [found[item[key]] for item in items]
