## Summary

Describe the change, why it is needed, and the owning repository boundary.

## Validation

- [ ] Repository-specific tests and validators pass.
- [ ] The diff and commit scope were reviewed.
- [ ] Generated files and private runtime artifacts remain outside Git.
- [ ] The commit is signed.

## Security and operations

- [ ] No secrets, credentials, customer data, raw evidence, state, plans,
      backups, databases, installers, exports, or logs are included.
- [ ] No validation step performs a live cloud, infrastructure, endpoint,
      customer-system, email, or runtime mutation.
- [ ] Required approval gates and rollback are documented.

## Rollback

Describe how to revert or disable the change safely.
