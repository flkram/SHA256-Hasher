#!/bin/bash
# This is a shell script to check your program(s) on test cases.
# It usese the same language you normally use to type commands in
# a terminal window.  You can write whole programs in shell.

# Assume we've succeeded until we see otherwise.
FAIL=0

# Print an error message and set the fail flag.
fail() {
    echo "**** $1"
    FAIL=1
}

# Check the exit status.  The actual exit status (ASTATUS) should match
# the expected status (ESTATUS)
checkStatus() {
  ESTATUS="$1"
  ASTATUS="$2"

  # Make sure the program exited with the right exit status.
  if [ "$ASTATUS" -ne "$ESTATUS" ]; then
      fail "FAILED - incorrect program exit status. (Expected: $ESTATUS, Got: $ASTATUS)"
      return 1
  fi

  return 0
}

# Check the contents of an a file.  If the expected file (EFILE)
# exists, then the actual file (AFILE) should exist and it should match.
checkFile() {
  NAME="$1"
  EFILE="$2"
  AFILE="$3"

  # Make sure we're really expecting this file.
  if [ ! -f "$EFILE" ]; then
      return 0
  fi

  # Make sure the output matches the expected output.
  echo "   diff $EFILE $AFILE"
  diff -q "$EFILE" "$AFILE" >/dev/null 2>&1
  if [ $? -ne 0 ]; then
      fail "FAILED - $NAME ($AFILE) doesn't match expected ($EFILE)"
      return 1
  fi

  return 0
}

# Same as checkFile, but if the expected file (EFILE) doesn't exist, the
# actual file (AFILE) should be empty.
checkFileOrEmpty() {
  NAME="$1"
  EFILE="$2"
  AFILE="$3"
  
  # if the expected output file doesn't exist, the actual file should be
  # empty.
  if [ ! -f "$EFILE" ]; then
      if [ -s "$AFILE" ]; then
	  fail "FAILED - $NAME ($AFILE) should be empty."
	  return 1
      fi
      return 0
  fi

  # Make sure the output matches the expected output.
  echo "   diff $EFILE $AFILE"
  diff -q "$EFILE" "$AFILE" >/dev/null 2>&1
  if [ $? -ne 0 ]; then
      fail "FAILED - $NAME ($AFILE) doesn't match expected ($EFILE)"
      return 1
  fi

  return 0
}

# Same as checkFile, but if the expected file (EFILE) doesn't exist, the
# actual file (AFILE) should not exist.
checkFileOrDNE() {
  NAME="$1"
  EFILE="$2"
  AFILE="$3"
  
  # if the expected output file doesn't exist, the actual file should not exist
  if [ ! -f "$EFILE" ]; then
      if [ -f "$AFILE" ]; then
	  fail "FAILED - $NAME ($AFILE) should not exist."
	  return 1
      fi
      return 0
  fi

  # Make sure the output matches the expected output.
  echo "   diff $EFILE $AFILE"
  diff -q "$EFILE" "$AFILE" >/dev/null 2>&1
  if [ $? -ne 0 ]; then
      fail "FAILED - $NAME ($AFILE) doesn't match expected ($EFILE)"
      return 1
  fi

  return 0
}

# The given file should exist but should be empty.
checkEmpty() {
  NAME="$1"
  AFILE="$2"
  
  if [ -s "$AFILE" ]; then
      fail "FAILED - $NAME ($AFILE) should be empty."
      return 1
  fi

  return 0
}

# Run a test case on the hash program.
testHash() {
    TESTNO="$1"
    ARGS="$2"
    ESTATUS="$3"

    rm -f output.txt

    # Prepare an executable command in a file
    echo "./hash $ARGS > stdout.txt 2>stderr.txt" > command.sh
    
    echo "Test $TESTNO"
    echo -n "   "
    cat command.sh
    source command.sh
    ASTATUS=$?

    if ! checkStatus "$ESTATUS" "$ASTATUS" ||
	    ! checkFile "Hash output" "expected-$TESTNO.txt" "stdout.txt" ||
	    ! checkFileOrEmpty "Stderr output" "error-$TESTNO.txt" "stderr.txt"
    then
	FAIL=1
	return 1
    fi

    echo "Test $TESTNO PASS"
    return 0
}

# Try the unit tests
make clean
make sha256test

if [ -x sha256test ]
then
    if ./sha256test
    then
       echo "Unit tests executed successfully"
    else
	fail "Unit tests didn't execute successfully";
    fi
else
    fail "Unit tests didn't build successfully";
fi

# make a fresh copy of the target programs
make

if [ $? -ne 0 ]; then
  fail "Make exited unsuccessfully"
fi

# Run test cases
if [ -x hash ]; then
    testHash 01 "input-01.txt" 0
    testHash 02 "input-02.txt" 0
    testHash 03 "input-03.txt" 0
    testHash 04 "input-04.txt" 0
    testHash 05 "input-05.txt" 0
    testHash 06 "input-06.txt" 0
    testHash 07 "< input-07.txt" 0
    testHash 08 "input-08.txt" 0
    testHash 09 "input-09.bin" 0
    testHash 10 "input-10.bin" 0
    testHash 11 "input-11.bin" 0
    testHash 12 "input-12.txt extra cmd line args" 1
    testHash 13 "missing-input-file.txt" 1
else
    fail "Since your hash program didn't compile, we couldn't test it"
fi

if [ $FAIL -ne 0 ]; then
  echo "FAILING TESTS!"
  exit 13
else 
  echo "TESTS SUCCESSFUL"
  exit 0
fi
