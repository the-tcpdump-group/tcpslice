# TCPSLICE 1.x by [The Tcpdump Group](https://www.tcpdump.org/)

**To report a security issue please send an e-mail to security@tcpdump.org.**

Anonymous git access is available via

	https://github.com/the-tcpdump-group/tcpslice

This directory contains source code for tcpslice, a tool for extracting
portions of packet trace files generated using tcpdump's `-w` flag.

Problems, bugs, questions, desirable enhancements, source code contributions,
etc., should be sent to the mailing list "tcpdump-workers@lists.tcpdump.org".

### Dependency on libpcap
Tcpslice uses libpcap, a system-independent interface for user-level
packet capture.  Before building tcpslice, you must first retrieve and
build libpcap.

Once libpcap is built (either install it or make sure it's in `../libpcap`),
you can build tcpslice using the procedure in the [installation guidelines](INSTALL).

### Origins of tcpslice

```text
formerly from   Lawrence Berkeley National Laboratory
                ftp://ftp.ee.lbl.gov/tcpslice-1.2a3.tar.gz
```
