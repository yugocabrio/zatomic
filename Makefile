.PHONY: doctor setup demo two-party verify stop-node

doctor:
	python3 scripts/dev.py doctor

setup:
	python3 scripts/dev.py setup

demo:
	python3 scripts/dev.py demo

two-party:
	python3 scripts/dev.py two-party

verify:
	python3 scripts/dev.py verify

stop-node:
	python3 scripts/regtest_node.py stop
