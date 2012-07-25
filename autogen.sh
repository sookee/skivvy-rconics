#! /bin/sh
mkdir -p m4
autoreconf --force --install -I config -I m4

#libtoolize --force --copy \
#&& aclocal \
#&& autoheader \
#&& automake -c --gnu --add-missing --force-missing \
#&& autoconf
