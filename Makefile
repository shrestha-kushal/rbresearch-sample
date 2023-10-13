SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

CC = gcc
CFLAGS =
LDFLAGS = -static -no-pie

BUILD_DIR = ./build
LIBS_DIR = ./lib
INCLUDE_DIR = ./include
UNITY_DIR = ./src/unity


LIB_ARCHIVES = libssh2.a libxml2.a liblzma.a libjansson.a libcurl.a \
               libbrotlienc.a libbrotlidec.a libbrotlicommon.a libssl.a \
               libcrypto.a libnghttp2.a libz.a libsqlite3.a
LIBS = $(addprefix $(LIBS_DIR)/, $(LIB_ARCHIVES))

LIBMYUTILS_DIR = ./src/libmyutils
LIBMYUTILS_DIR_OBJS = aws.o crypt_utils.o curl_utils.o
LIBMYUTILS_TEST_DIR = ./test/libmyutils
LIBMYUTILS_TEST_EXES = test_libmyutils.exe

RESEARCH_DIR = ./src/research
RESEARCH_TEST_DIR = ./test/research


all: libmyutils


# Begin libmyutils rules -->
$(LIBMYUTILS_DIR)/aws.o: $(LIBMYUTILS_DIR)/crypt_utils.h

$(LIBMYUTILS_DIR)/%.o: $(LIBMYUTILS_DIR)/%.c $(LIBMYUTILS_DIR)/%.h
	$(CC) -o $@ -c $< -I$(INCLUDE_DIR)

LIBMYUTILS_OBJS = $(addprefix $(LIBMYUTILS_DIR)/, $(LIBMYUTILS_DIR_OBJS))

$(BUILD_DIR)/lib/libmyutiils.a: $(LIBMYUTILS_OBJS)
	mkdir -p $(@D)
	ar rcs $@ $^

libmyutils: $(BUILD_DIR)/lib/libmyutils.a
	@echo "built libmyutils.a"
.PHONY: libmyutils
# <-- End libmyutils rules


# Begin transition printing script rules -->
$(BUILD_DIR)/bin/forbidden.exe: ./src/research/forbidden_main.c ./src/research/forbidden.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

forbidden_script: $(BUILD_DIR)/bin/forbidden.exe
	@echo "built forbidden transitions printing script."
.PHONY: forbidden_script
# <-- End transition printing script rules


# Begin transition printing tool testing rules -->
$(RESEARCH_DIR)/forbidden.o: $(RESEARCH_DIR)/forbidden.c
	$(CC) -o $@ -c $<

$(BUILD_DIR)/test/research/test_forbidden.exe: ./test/research/test_forbidden.c $(RESEARCH_DIR)/forbidden.o $(UNITY_DIR)/unity.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ -I$(UNITY_DIR)

test_forbidden_script: $(BUILD_DIR)/test/research/test_forbidden.exe
	$<
# <-- End transition printing tool testing rules


clean:
	@echo "cleaning artifacts"
	rm -fr $(BUILD_DIR)
	rm -fr $(LIBMYUTILS_DIR)/*.o
	rm -fr $(RESEARCH_DIR)/*.o
	rm -fr $(RESEARCH_TEST_DIR)/*.o
.PHONY: clean
