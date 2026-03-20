# dark Development Workflow

## Rules (mandatory for every issue)

1. **Branch** — `git checkout main && git pull && git checkout -b feat/<issue-name>`
2. **Assign the issue to yourself** — do this immediately when starting:
   ```bash
   curl -s -X POST -H "Authorization: token $GH_TOKEN" -H "Content-Type: application/json" \
     "https://api.github.com/repos/$REPO/issues/ISSUE_NUM/assignees" \
     -d '{"assignees":["lobbyclawy"]}'
   ```
3. **Implement** — write the code for the issue
4. **Local checks** — `cargo fmt --all` + `cargo clippy -- -D warnings` + `cargo test --workspace` — all must pass before pushing
5. **Push** — `git push origin feat/<issue-name>`
6. **Open PR** — via GitHub API with clear title and body referencing the issue
7. **CI check loop:**
   - Poll CI every 2 minutes
   - If **red** → identify the failure, fix it, push again, repeat until green
   - Never merge while CI is red
8. **Review — MANDATORY before merge:**
   - Add a **PR-level summary review** (overall assessment, key decisions, concerns)
   - Add **inline comments on specific lines** using the GitHub API `comments` array (with `path`, `line`, `body`) — mentioning line numbers in the summary text does NOT count as inline comments
   - Minimum: at least 3 inline comments per PR on meaningful lines (logic, edge cases, placeholders, TODOs)
9. **Address ALL review comments before merging — NO EXCEPTIONS:**
   - For each inline comment: either push a fix commit, or reply to the comment explaining why no change is needed
   - **"Deferred to future issue" does NOT count as addressing a comment** — if something is truly deferred, create a GitHub issue for it, link it in the reply, then resolve
   - Do NOT merge while any comment is unresolved
   - After pushing fixes: re-run CI, wait for green, then merge
10. **Merge** — squash-merge ONLY when:
    - All CI checks are green ✅
    - Every inline review comment has been replied to and resolved ✅
    - **NEVER bypass branch protection or force-push to merge** — if CI is red, fix the code first
11. **Close issue** — mark the GitHub issue as closed
12. **Update roadmap** — tick the issue in Issue #13, update progress percentages
13. **Update README** — tick any phase checkboxes if the issue completes a phase

## How to Reply to and Resolve Review Comments

```bash
# List all inline comments on a PR
curl -s -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/$REPO/pulls/PR_NUM/comments" \
  | python3 -c "import json,sys; [print(f'ID:{c[\"id\"]} {c[\"path\"]}:{c[\"line\"]} — {c[\"body\"][:60]}') for c in json.load(sys.stdin)]"

# Reply to a specific inline comment
curl -s -X POST -H "Authorization: token $GH_TOKEN" -H "Content-Type: application/json" \
  "https://api.github.com/repos/$REPO/pulls/PR_NUM/comments" \
  -d "{\"body\": \"Fixed in latest commit — changed X to Y.\", \"in_reply_to\": COMMENT_ID}"

# Resolve a comment thread (mark as resolved)
curl -s -X PUT -H "Authorization: token $GH_TOKEN" -H "Content-Type: application/json" \
  "https://api.github.com/repos/$REPO/pulls/PR_NUM/comments/COMMENT_ID/reactions" \
  -d '{"content": "+1"}'
```

## How to Add Inline Review Comments

```bash
GH_TOKEN=$GH_TOKEN
REPO=lobbyclawy/dark

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
        \"path\": \"crates/dark-bitcoin/src/tree.rs\",
        \"line\": 42,
        \"body\": \"Inline comment on this specific line\"
      },
      {
        \"path\": \"crates/dark-bitcoin/src/tree.rs\",
        \"line\": 100,
        \"body\": \"Another inline comment\"
      }
    ]
  }"
```

## GitHub API Reference

```bash
GH_TOKEN=$GH_TOKEN
REPO=lobbyclawy/dark

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
