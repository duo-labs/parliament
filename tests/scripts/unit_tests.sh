#! /bin/bash
if [ -f .coverage ]; then
  rm .coverage
fi

nosetests tests/unit \
--with-coverage \
--cover-package=parliament \
--cover-html \
--cover-html-dir=htmlcov

# --cover-min-percentage=60 \