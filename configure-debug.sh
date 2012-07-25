#!/bin/sh

GCC_HOME=${HOME}/app/gcc-4.7.0

top_dir=$(pwd)

DBG_FLAGS="-D DEBUG"
DBG_FLAGS="$DBG_FLAGS -D _GLIBCXX_DEBUG"
DBG_FLAGS="$DBG_FLAGS -D _GLIBCXX_DEBUG_PEDANTIC"
DBG_FLAGS="$DBG_FLAGS -fno-inline"
DBG_FLAGS="$DBG_FLAGS -fno-eliminate-unused-debug-types"
DBG_FLAGS="$DBG_FLAGS -g3"
DBG_FLAGS="$DBG_FLAGS -O0"

export CXX="${GCC_HOME}/bin/g++"
export CXXFLAGS="$DBG_FLAGS -std=gnu++11"

mkdir -p $top_dir/build
cd $top_dir/build

#$top_dir/configure --datadir=$top_dir/build/src/.libs --prefix=$top_dir/install
$top_dir/configure --prefix=$top_dir/install

