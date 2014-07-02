ChronoSync: synchronization library for distributed realtime applications for NDN
=================================================================================

In supporting many distributed applications, such as group text messaging, file sharing,
and joint editing, a basic requirement is the efficient and robust synchronization of
knowledge about the dataset such as text messages, changes to the shared folder, or
document edits.  This library implements
[ChronoSync protocol](http://named-data.net/wp-content/uploads/2014/03/chronosync-icnp2013.pdf),
which exploits the features of the Named Data Networking architecture to efficiently
synchronize the state of a dataset among a distributed group of users.  Using appropriate
naming rules, ChronoSync summarizes the state of a dataset in a condensed cryptographic
digest form and exchange it among the distributed parties.  Differences of the dataset can
be inferred from the digests and disseminated efficiently to all parties.  With the
complete and up-to-date knowledge of the dataset changes, applications can decide whether
or when to fetch which pieces of the data.

ChronoSync uses [ndn-cxx](https://github.com/named-data/ndn-cxx) library as NDN
  development library.

ChronoSync is an open source project licensed under GPL 3.0 (see `COPYING.md` for more
detail).  We highly welcome all contributions to the ChronoSync code base, provided that
they can licensed under GPL 3.0+ or other compatible license.

Feedback
--------

Please submit any bugs or issues to the **ChronoSync** issue tracker:

* http://redmine.named-data.net/projects/chronosync

Installation instructions
-------------------------

### Prerequisites

Required:

* [ndn-cxx and its dependencies](http://named-data.net/doc/ndn-cxx/)
* Boost libraries
* `protobuf` library
* log4cxx (optional, if enabled with `--with-log4cxx` configure option)

### Build

To build ChronoSync from the source:

    ./waf configure
    ./waf
    sudo ./waf install

If configured with tests: `./waf configure --with-tests`), the above commands will also
generate unit tests in `./build/unit-tests`
