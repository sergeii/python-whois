python-whois
%%%%%%%%%%%%

:Version:           1.0.0
:Home page:         https://github.com/sergeii/python-whois
:Author:            Sergei Khoroshilov <kh.sergei@gmail.com>
:License:           The MIT License (http://opensource.org/licenses/MIT)


Description
===========
Python whois utility
Inspired by https://code.google.com/p/pywhois/


Command Line Usage
==================
Example 1::

    python whois.py github.com

    % IANA WHOIS server
    % for more information on IANA, visit http://www.iana.org
    % This query returned 1 object

    refer:        whois.verisign-grs.com

    domain:       COM

    organisation: VeriSign Global Registry Services
    address:      12061 Bluemont Way
    address:      Reston Virginia 20190
    address:      United States
    ...

Exmaple 2::

    python whois.py --pretty 192.30.252.130

    country: us
    orgname: GitHub, Inc.
    ipv4range: ('192.30.252.0', '192.30.255.255')
    ipv4_from: 192.30.252.0
    ipv4_to: 192.30.255.255


Application Usage
=================
::

    from whois import whois

    # output whois response without formatting
    print(whois('github.com', raw=True))

    # format whois response (most useful for obtaining IP address info)
    print(whois('192.30.252.130'))