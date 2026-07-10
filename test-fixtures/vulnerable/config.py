# Deliberately-committed fixture for pipelineguard-action's own test workflow.
# This is a randomly-generated fake token (not a real credential, never
# used anywhere) shaped to match gitleaks' github-pat rule, so the test
# workflow has something deterministic to detect. AWS's own well-known
# public EXAMPLE key was tried first and turned out to be allowlisted by
# gitleaks by default precisely because it's such a common false positive.
GITHUB_TOKEN = "ghp_DcZoy1y0aSmLzS4waoBBoJxKT7daqbtnqxWE"
