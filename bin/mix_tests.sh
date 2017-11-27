#!/bin/bash
cd $TRAVIS_BUILD_DIR
  # Run all tests except pending ones
  echo "- mix test --exclude pending --trace "
        mix test --exclude pending --trace

      if [ "$?" -eq 0 ]; then
            echo "mix test successfully completed"
          else
            echo "mix test Finished with errors, exited with 1"
            mix_test=1 ;
      fi;

if [ "${mix_test}" == "1" ]; then
  echo "finished with errors"
  exit 1;
fi;