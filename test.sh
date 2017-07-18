#!/usr/bin/env bash
set -e

coverage erase
coverage run setup.py test

# includes every python file so we can ensure nothing remains untested / unused
coverage_include='*.py'
coverage_omit='venv/*,.eggs/*'

# if we're running this from a tty (our laptop), make html (but don't fail)
if [ -t 1 ]; then
coverage html --include="$coverage_include" --omit="$coverage_omit" && \
  echo -e "\033[1;37m\nHtml test report generated at:\n$(readlink -f $(dirname "$0"))/htmlcov/index.html\n\033[0m" || \
  echo 'Could not make html coverage report.' >&2
fi

coverage report --include="$coverage_include" --omit="$coverage_omit" --show-missing --fail-under=95
