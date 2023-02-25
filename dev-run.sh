#!/bin/bash

# Check code
echo "Checking code package"

which mypy > /dev/null
if [ $? -eq 0 ]
then
    echo ""
    mypy  --strict --namespace-packages --ignore-missing-imports --cache-dir=/tmp src/python_cmc/*.py
else
    echo "mypy is not installed, skipping..."
    echo "Dont forget to install types-requests"
fi

which black > /dev/null
if [ $? -eq 0 ]
then
    black --line-length 120 src/python_cmc/*.py
else
    echo "black is not installed, skipping..."
fi

which pylint > /dev/null
if [ $? -eq 0 ]
then
    echo ""
    pylint --max-line-length 120 src/python_cmc/*.py
else
    echo "pylint is not installed, skipping..."
fi

which mypy > /dev/null
if [ $? -eq 0 ]
then
    echo ""
    mypy  --strict --namespace-packages --ignore-missing-imports --cache-dir=/tmp tests/*.py
fi

which black > /dev/null
if [ $? -eq 0 ]
then
    black --line-length 120 tests/*.py
fi

which pylint > /dev/null
if [ $? -eq 0 ]
then
    echo ""
    pylint --max-line-length 120 tests/*.py
fi

echo "Running tests"
python3 -m unittest || exit 1

