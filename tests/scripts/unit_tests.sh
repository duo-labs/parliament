#! /bin/bash
if [ -f .coverage ]; then
  rm .coverage
fi

export PRIVATE_TESTS=""
if [ -d parliament/private_auditors/tests/ ]; then
  export PRIVATE_TESTS="parliament/private_auditors/tests/"
fi

export COMMUNITY_TESTS
if [ -d parliament/community_auditors/tests/ ]; then
  export COMMUNITY_TESTS="parliament/community_auditors/tests/"
fi

python3 -m "nose" tests/unit $PRIVATE_TESTS $COMMUNITY_TESTS \
--with-coverage \
--cover-package=parliament \
--cover-html \
--cover-min-percentage=75 \
--cover-html-dir=htmlcov

