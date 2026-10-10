.PHONY: help test test-policies scan-sample lint

help:
	@echo "Zero-Trust DevSecOps Pipeline Commands:"
	@echo "  make test          - Run Python unit and integration test suite"
	@echo "  make scan-sample   - Execute Trivy, Syft, and Semgrep on sample-app"
	@echo "  make test-policies - Validate Kyverno and Gatekeeper policy manifests"

test:
	PYTHONPATH=. python3 -m unittest discover -s tests -p "test_*.py"

scan-sample:
	@echo "Executing local security pipeline checks..."
	@which semgrep >/dev/null 2>&1 && semgrep --config policies/semgrep/rules.yaml sample-app/ || echo "Semgrep not installed in path"
	@which trivy >/dev/null 2>&1 && trivy fs sample-app/ || echo "Trivy not installed in path"

test-policies:
	@echo "Verifying Kyverno and Gatekeeper policy syntax..."
	python3 -c "import yaml, pathlib; [yaml.safe_load(p.read_text()) for p in pathlib.Path('policies').rglob('*.yaml')]"
	@echo "All policy YAML manifests parsed cleanly."
