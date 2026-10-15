.PHONY: doctor setup demo verify stop-node

doctor:
	python3 scripts/dev.py doctor

setup:
	python3 scripts/dev.py setup

demo:
	python3 scripts/dev.py demo

verify:
	python3 scripts/dev.py verify

stop-node:
	python3 scripts/regtest_node.py stop
