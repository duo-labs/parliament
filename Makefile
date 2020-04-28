setup:
	pip install -r requirements.txt
update-brew:
	pip install homebrew-pypi-poet parliament
	poet -f parliament > HomebrewFormula/parliament.rb
test:
	bash tests/scripts/unit_tests.sh