# OpenList WebDAV Ticket v3

OpenList generates a deterministic, path-bound Ticket for each browser direct
link. The payload contains the storage audience, OpenList user id, a SHA-256
digest of the current OpenList JWT, the public scope, the canonical public
path, and `auth_generation`. It contains no raw JWT, cookie, nonce, expiry or
random `jti`.

The signing key is derived from `webdav_auth_secret` and the storage's
`webdav_auth_nonce`. The nonce is read by the backend; the frontend never
stores or sends it. If the setting is absent, the protocol compatibility
default is used. An explicitly malformed nonce is rejected.

`Link()` only returns the Ticket URL. It does not create a grant. During the
first browser authorization, `/api/webdav/authorize` validates the logged-in
OpenList JWT and writes one signed v3 grant using an independent random
`grant_id`. The exchange URL contains that id:

```text
/webdav-auth/exchange?ticket=<T>&state=<S>&grant_id=<G>
```

Apache reads exactly `<G>`, verifies the grant, consumes it once, and creates
its own WebDAV session. A session authorizes the configured scope, not a list
of previously opened files. Every later OpenList URL still carries its own
path-bound Ticket, while the existing WebDAV cookie avoids a new grant flow.

The only runtime lifetime in v3 is the WebDAV session sliding TTL. A long
video may continue on an established connection; every new GET, HEAD or Range
request must carry the Ticket and pass the current session check.
