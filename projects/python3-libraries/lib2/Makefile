all : fuzzer-html fuzzer-email fuzzer-httpclient fuzzer-json fuzzer-difflib fuzzer-csv fuzzer-decode fuzzer-ast fuzzer-tarfile fuzzer-tarfile-hypothesis fuzzer-zipfile fuzzer-zipfile-hypothesis fuzzer-re fuzzer-configparser fuzzer-tomllib fuzzer-plistlib fuzzer-xml fuzzer-array fuzzer-binascii fuzzer-codecs fuzzer-collections fuzzer-compression fuzzer-crypto fuzzer-csv-module fuzzer-ctypes fuzzer-datetime fuzzer-dbm fuzzer-dis fuzzer-expat fuzzer-ioops fuzzer-json-decode fuzzer-json-encode fuzzer-locale fuzzer-mmap fuzzer-operator fuzzer-pickle fuzzer-sqlite3 fuzzer-ssl fuzzer-time fuzzer-unicodedata

PYTHON_CONFIG_PATH=$(CPYTHON_INSTALL_PATH)/bin/python3-config
CXXFLAGS += $(shell $(PYTHON_CONFIG_PATH) --cflags)
LDFLAGS += -rdynamic $(shell $(PYTHON_CONFIG_PATH) --ldflags --embed) $(CPYTHON_MODLIBS) $(CPYTHON_HACL_LIBS) -Wl,--allow-multiple-definition

fuzzer-html:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"html.py\"" -ldl $(LDFLAGS) -o fuzzer-html
fuzzer-email:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"email.py\"" -ldl $(LDFLAGS) -o fuzzer-email
fuzzer-httpclient:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"httpclient.py\"" -ldl $(LDFLAGS) -o fuzzer-httpclient
fuzzer-json:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"json.py\"" -ldl $(LDFLAGS) -o fuzzer-json
fuzzer-difflib:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"difflib.py\"" -ldl $(LDFLAGS) -o fuzzer-difflib
fuzzer-csv:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"csv.py\"" -ldl $(LDFLAGS) -o fuzzer-csv
fuzzer-decode:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"decode.py\"" -ldl $(LDFLAGS) -o fuzzer-decode
fuzzer-ast:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"ast.py\"" -ldl $(LDFLAGS) -o fuzzer-ast
fuzzer-re:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"re.py\"" -ldl $(LDFLAGS) -o fuzzer-re
fuzzer-zipfile:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"zipfile.py\"" -ldl $(LDFLAGS) -o fuzzer-zipfile
fuzzer-zipfile-hypothesis:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"zipfile_hypothesis.py\"" -ldl $(LDFLAGS) -o fuzzer-zipfile-hypothesis
fuzzer-tarfile:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"tarfile.py\"" -ldl $(LDFLAGS) -o fuzzer-tarfile
fuzzer-tarfile-hypothesis:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"tarfile_hypothesis.py\"" -ldl $(LDFLAGS) -o fuzzer-tarfile-hypothesis
fuzzer-configparser:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"configparser.py\"" -ldl $(LDFLAGS) -o fuzzer-configparser
fuzzer-tomllib:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"tomllib.py\"" -ldl $(LDFLAGS) -o fuzzer-tomllib
fuzzer-plistlib:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"plist.py\"" -ldl $(LDFLAGS) -o fuzzer-plistlib
fuzzer-xml:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"xml.py\"" -ldl $(LDFLAGS) -o fuzzer-xml
fuzzer-array:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_array.py\"" -ldl $(LDFLAGS) -o fuzzer-array
fuzzer-binascii:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_binascii.py\"" -ldl $(LDFLAGS) -o fuzzer-binascii
fuzzer-codecs:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_codecs.py\"" -ldl $(LDFLAGS) -o fuzzer-codecs
fuzzer-collections:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_collections.py\"" -ldl $(LDFLAGS) -o fuzzer-collections
fuzzer-compression:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_compression.py\"" -ldl $(LDFLAGS) -o fuzzer-compression
fuzzer-crypto:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_crypto.py\"" -ldl $(LDFLAGS) -o fuzzer-crypto
fuzzer-csv-module:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_csv_module.py\"" -ldl $(LDFLAGS) -o fuzzer-csv-module
fuzzer-ctypes:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_ctypes.py\"" -ldl $(LDFLAGS) -o fuzzer-ctypes
fuzzer-datetime:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_datetime.py\"" -ldl $(LDFLAGS) -o fuzzer-datetime
fuzzer-dbm:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_dbm.py\"" -ldl $(LDFLAGS) -o fuzzer-dbm
fuzzer-dis:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_dis.py\"" -ldl $(LDFLAGS) -o fuzzer-dis
fuzzer-expat:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_expat.py\"" -ldl $(LDFLAGS) -o fuzzer-expat
fuzzer-ioops:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_ioops.py\"" -ldl $(LDFLAGS) -o fuzzer-ioops
fuzzer-json-decode:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_json_decode.py\"" -ldl $(LDFLAGS) -o fuzzer-json-decode
fuzzer-json-encode:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_json_encode.py\"" -ldl $(LDFLAGS) -o fuzzer-json-encode
fuzzer-locale:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_locale.py\"" -ldl $(LDFLAGS) -o fuzzer-locale
fuzzer-mmap:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_mmap.py\"" -ldl $(LDFLAGS) -o fuzzer-mmap
fuzzer-operator:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_operator.py\"" -ldl $(LDFLAGS) -o fuzzer-operator
fuzzer-pickle:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_pickle.py\"" -ldl $(LDFLAGS) -o fuzzer-pickle
fuzzer-sqlite3:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_sqlite3.py\"" -ldl $(LDFLAGS) -o fuzzer-sqlite3
fuzzer-ssl:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_ssl.py\"" -ldl $(LDFLAGS) -o fuzzer-ssl
fuzzer-time:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_time.py\"" -ldl $(LDFLAGS) -o fuzzer-time
fuzzer-unicodedata:
	clang++ $(CXXFLAGS) $(LIB_FUZZING_ENGINE) -std=c++17 fuzzer.cpp -DPYTHON_HARNESS_PATH="\"fuzz_unicodedata.py\"" -ldl $(LDFLAGS) -o fuzzer-unicodedata
