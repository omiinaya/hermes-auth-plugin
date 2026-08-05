## Summary

<!-- What does this change do, and why? One short paragraph. -->

## Related issues

<!-- Link any issues this closes, e.g. Closes #12. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Doc update
- [ ] Refactor / maintenance
- [ ] Dependency bump

## Security / correctness checklist

- [ ] I reviewed `docs/THREAT_MODEL.md` and updated it if this change alters
      the threat surface (crypto, handshake, or auth logic).
- [ ] No secrets, keys, or credentials are committed.
- [ ] I used timing-safe comparison (`hmac.compare_digest`) for any secret
      equality checks I added.

## Testing

- [ ] `make lint` passes
- [ ] `make test` passes
- [ ] `make coverage` passes the 85% gate (project is at 100% — keep it there)
- [ ] For crypto/auth changes: I reviewed the relevant `tests/` and added
      coverage for new branches.

## Deployment notes

<!-- Does this need a version bump + redeploy? New env vars? DB migration?
Server deployment is described in deploy/hermes-id-auth.service. -->