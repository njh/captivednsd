captivednsd
===========

captivednsd, the Captive Domain Name Server, returns same authorative response 
to every query. The reponse to 'A' queries and 'PTR' records are passed as 
a parameter on the command line. The code is covered by the GNU license.

I wrote the daemon to direct people to a captive web portal, on a system that 
was not connected to the Internet. This meant that it was not possible to 
resolve the correct IP address for a host and then redirect the query using a 
firewall.

captivednsd is based on the source code of scdns and Busybox's dnsd:

* http://www.oao.no/filer/scdns-25.tgz
* http://www.busybox.net/cgi-bin/viewcvs.cgi/trunk/busybox/networking/dnsd.c


Usage
-----

    captivednsd [options] <ip> <host>
          -t <ttl>   Set the TTL for DNS responses (default 30).
          -p <port>  Port number to listen on (default 53).
          -b <addr>  Bind to an IP address (default 0.0.0.0).


Example
-------

    captivednsd 10.0.0.1 portal.local.

* All A requests will return IP address 10.0.0.1.
* All PTR requests will return portal.local.
