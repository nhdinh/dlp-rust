# M004: Policy Authoring (v0.4.0)

**Vision:** Give DLP administrators a complete policy authoring workflow in the TUI — from condition building to CRUD to cross-environment portability via import/export.

## Success Criteria

- Admin can create policies with compound conditions via TUI
- Admin can edit/delete existing policies
- Policies can be exported to JSON and imported in another environment
- Invalid policies are rejected with clear error messages

## Slices

- [x] **S01: Conditions builder** `risk:high` `depends:[]`
  > After this: Admin can compose policy conditions using the TUI builder
- [x] **S02: Policy CRUD** `risk:medium` `depends:[S01]`
  > After this: Admin can create, view, edit, and delete policies end-to-end
- [x] **S03: Import/export** `risk:low` `depends:[S02]`
  > After this: Policies can be exported as JSON and imported in different environments
