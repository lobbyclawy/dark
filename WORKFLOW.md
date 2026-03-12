# arkd-rs Development Workflow

## Rules (mandatory for every issue)

1. **Branch** — `git checkout main && git pull && git checkout -b feat/<issue-name>`
2. **Implement** — write the code for the issue
3. **Local checks** — `cargo fmt --all` + `cargo clippy -- -D warnings` + `cargo test --workspace` — all must pass before pushing
4. **Push** — `git push origin feat/<issue-name>`
5. **Open PR** — via GitHub API with clear title and body referencing the issue
6. **CI check loop:**
   - Poll CI every 2 minutes
   - If **red** → identify the failure, fix it, push again, repeat until green
   - Never merge while CI is red
7. **Review — MANDATORY before merge:**
   - Add a **PR-level summary review** (overall assessment, key decisions, concerns)
   - Add **inline comments on specific lines** for anything noteworthy: tricky logic, potential issues, placeholder code, future TODOs
   - Use GitHub's review API to post inline comments with `path`, `line`, and `body`
   - **All review comments must be addressed before merging** — either fix the code or explicitly resolve with a reply explaining why it's acceptable as-is
8. **Address review** — push fixes for any issues raised, then re-check CI
9. **Merge** — squash-merge ONLY when:
   - All CI checks are green ✅
   - All review comments are addressed ✅
10. **Close issue** — mark the GitHub issue as closed
11. **Update roadmap** — tick the issue in Issue #13, update progress percentages
12. **Update README** — tick any phase checkboxes if the issue completes a phase

## How to Add Inline Review Comments

```bash
GH_TOKEN=$GH_TOKEN
REPO=lobbyclawy/arkd-rs

# Get the latest commit SHA on the PR
SHA=$(curl -s -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/$REPO/pulls/PR_NUM" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['head']['sha'])")

# Create a review with inline comments
curl -s -X POST -H "Authorization: token $GH_TOKEN" -H "Content-Type: application/json" \
  "https://api.github.com/repos/$REPO/pulls/PR_NUM/reviews" \
  -d "{
    \"commit_id\": \"$SHA\",
    \"event\": \"COMMENT\",
    \"body\": \"## Review Summary\\n\\nOverall assessment here...\",
    \"comments\": [
      {
        \"path\": \"crates/arkd-bitcoin/src/tree.rs\",
        \"line\": 42,
        \"body\": \"Inline comment on this specific line\"
      },
      {
        \"path\": \"crates/arkd-bitcoin/src/tree.rs\",
        \"line\": 100,
        \"body\": \"Another inline comment\"
      }
    ]
  }"
```

## GitHub API Reference

```bash
GH_TOKEN=$GH_TOKEN
REPO=lobbyclawy/arkd-rs

# Create PR
curl -s -X POST -H "Authorization: token $GH_TOKEN" -H "Content-Type: application/json" \
  "https://api.github.com/repos/$REPO/pulls" \
  -d '{"title":"...","head":"feat/...","base":"main","body":"..."}'

# Get PR head SHA
curl -s -H "Authorization: token $GH_TOKEN" "https://api.github.com/repos/$REPO/pulls/PR_NUM" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['head']['sha'])"

# Check CI
curl -s -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/$REPO/commits/SHA/check-runs" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); [print(r['name'], r['status'], r.get('conclusion','')) for r in d.get('check_runs',[])]"

# Squash merge
curl -s -X PUT -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/$REPO/pulls/PR_NUM/merge" \
  -d '{"merge_method":"squash","commit_title":"✨ ...","commit_message":"..."}'

# Close issue
curl -s -X PATCH -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/$REPO/issues/N" -d '{"state":"closed"}'
```

## Commit Style
Use gitmoji: ✨ feature · 🐛 fix · 📝 docs · 🔧 config · ♻️ refactor · ✅ tests · 🏗️ architecture

## ⚠️ Never push directly to main
All changes go through feature branches and PRs. No exceptions.
