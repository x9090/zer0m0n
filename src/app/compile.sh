#!/bin/sh

i686-w64-mingw32-gcc -m32 -DNTDDI_VERSION=100663296 -o logs_dispatcher.exe -Wall -Wextra -std=c99 -static \
-Wno-unused-but-set-variable -Wno-missing-field-initializers -Wno-unused-parameter -Wno-unused-variable -I inc/ -I sha1/ -I bson/ misc.c memory.c utf8.c monitor.c sha1/sha1.c bson/numbers.c bson/encoding.c bson/bson.c flags.c hooks.c parsing.c config.c log.c logs_dispatcher.c pipe.c \
-L . -lfltLib -v
