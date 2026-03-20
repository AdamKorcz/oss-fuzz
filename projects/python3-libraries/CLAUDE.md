You are a fuzzer developer working on porting some new python3-library fuzzers from .cc files to a format where the fuzzers are implemented as python programs. The new fuzzers are placed in library-fuzzers/module-fuzzers, however, if you look in library-fuzzers, the project follows a format where the fuzzers are written as python files and then the Makefile compiles those python files into libFuzzer programs. 

Your job is to rewrite the fuzzers in library-fuzzers/module-fuzzers to follow the same format, ie. the fuzzers in library-fuzzers/module-fuzzers should be python programs that the Makefile builds as libFuzzer binaries like it does with the existing fuzzers.

You must make this work with library-fuzzers's OSS-Fuzz integration. You must ensure that OSS-Fuzz also builds the new python-based fuzzers in library-fuzzers/module-fuzzers. 

To test that the fuzzers build with OSS-Fuzz, you can use `python3 ../../infra/helper.py build_fuzzers library-fuzzers`, and you can try running a fuzzer with `python3 ../../infra/helper.py run_fuzzer library-fuzzers $fuzzer`.

You can generate a coverage report by running the fuzzers and storing the corpus and using it to generate a coverage report.

To store the fuzzer, do the following: `python3 ../../infra/helper.py run_fuzzer python-libraries $fuzzer --corpus-dir=$PWD/../../build/corpus/python-libraries/$fuzzer`. This stores the corpus in the place where OSS-Fuzz will read it when generating a coverage report.

Then, build the fuzzers with coverage sanitizer: `python3 ../../infra/helper.py build_fuzzers python-libraries --sanitizer=coverage` and generate the coverage report with `python3 ../../infra/helper.py coverage python-libraries --no-corpus-download --no-serve`. This creates the coverage report in ../../build/out/python-libraries. 

You can then use the coverage report to evaluate the overall coverage or the coverage of specific fuzzers or do branch blocker analysis. 
