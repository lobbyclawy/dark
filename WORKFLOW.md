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
7. **Review** — add inline review comments to the PR (what looks good, what was tricky, any concerns)
8. **Address review** — if comments raise issues, fix them and push
9. **Merge** — squash-merge ONLY when all CI checks are green and review is addressed
10. **Close issue** — mark the GitHub issue as closed
11. **Update roadmap** — tick the issue in Issue #13, update progress percentages
12. **Update README** — tick any phase checkboxes if the issue completes a phase

## Commit style
Use gitmoji: ✨ feature · 🐛 fix · 📝 docs · 🔧 config · ♻️ refactor · ✅ tests · 🏗️ architecture

## GitHub API reference
```bash
GH_TOKEN=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
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

# Add review comment
curl -s -X POST -H "Authorization: token $GH_TOKEN" -H "Content-Type: application/json" \
  "https://api.github.com/repos/$REPO/pulls/PR_NUM/reviews" \
  -d '{"event":"COMMENT","body":"..."}'

# Squash merge
curl -s -X PUT -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/$REPO/pulls/PR_NUM/merge" \
  -d '{"merge_method":"squash","commit_title":"✨ ...","commit_message":"..."}'

# Close issue
curl -s -X PATCH -H "Authorization: token $GH_TOKEN" \
  "https://api.github.com/repos/$REPO/issues/N" -d '{"state":"closed"}'
```
