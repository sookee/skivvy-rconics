#!/bin/sh

GCC_HOME=${HOME}/app/gcc-4.7.0

top_dir=$(pwd)

export CXX="${GCC_HOME}/bin/g++"
export CXXFLAGS="-g0 -O3 -std=gnu++11 -Wno-unused-parameter -Wno-unused-variable"

mkdir -p $top_dir/build-release
cd $top_dir/build-release
$top_dir/configure --prefix=$top_dir/install

