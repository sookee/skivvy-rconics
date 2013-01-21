#!/bin/sh

GCC_HOME=${HOME}/app/gcc-4.7.0

top_dir=$(pwd)

SKIVVY_INCLUDES="-I../../../skivvy/src/include/"

export CXX="${GCC_HOME}/bin/g++"
export CXXFLAGS="$SKIVVY_INCLUDES -g0 -O3 -std=gnu++11 -Wno-unused-parameter -Wno-unused-variable"

mkdir -p $top_dir/build-release
cd $top_dir/build-release
$top_dir/configure --prefix=$top_dir/install

