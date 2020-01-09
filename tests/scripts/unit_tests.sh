#! /bin/bash
if [ -f .coverage ]; then
  rm .coverage
fi

export PRIVATE_TESTS=""
echo "echo"
echo $PRIVATE_TESTS
if [ -d parliament/private_auditors/tests/ ]; then
  export PRIVATE_TESTS="parliament/private_auditors/tests/"
fi

python3 -m "nose" tests/unit $PRIVATE_TESTS \
--with-coverage \
--cover-package=parliament \
--cover-html \
--cover-min-percentage=75 \
--cover-html-dir=htmlcov

