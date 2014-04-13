# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import socket
import re
from functools import reduce


def ip2int(ip):
    return reduce(lambda a,b: a*256+b, map(int, ip.split('.')), 0)


def int2ip(ip):
    if not 0 <= ip <= 0xffffffff:
        raise ValueError('long ip must be between 0 and 0xffffffff inclusive')
    return '%d.%d.%d.%d' % (ip>>24 & 255, ip>>16 & 255, ip>>8 & 255, ip & 255)


class whois(object):
    # host list
    ANICHOST = 'whois.arin.net'
    RNICHOST = 'whois.ripe.net'
    PNICHOST = 'whois.apnic.net'
    IANAHOST = 'whois.iana.org'
    AFRINIC = 'whois.afrinic.net'

    # list of host specific whois queries
    QUERY = {
        ANICHOST: 'n + %s',
        RNICHOST: '-V Md5.0 %s',
        AFRINIC: '-V Md5.0 %s',
    }

    # use IANA as the default whois host
    DEFAULT_HOST = IANAHOST
    DEFAULT_PORT = 43

    TIMEOUT = 0.5

    # list of host referral fields
    FIELDS_REFER = {
        'hostname': (
            ('referralserver', 'refer', 'whois'), 
            (r'\S+://(?P<hostname>\w[-.a-z0-9]+)(?::(?P<port>\d{1,5}))?', r'\w[-.a-z0-9]+')
        )
    }

    # list of special whois fields
    FIELDS_WHOIS = {
        'country': (
            ('country', 'zip code', 'country-code'), 
            (r'[a-z]+',)
        ),
        'orgname': (
            (
                'descr', 'orgname', 'org-name', 
                'organization', 'netname', 'network-name', 
                'service name', 'owner', 'name', 'id', 'responsible'
            ),
            (r'[^\r\n]+',)
        ),
        'ipv4range': (
            (
                'ip-network-range', 'ip-network', 
                'inetnum', 'netrange', 'ipv4 address',
            ), 
            (
                r'(?P<ipv4_from>[\d.]+)\D*-\D*(?P<ipv4_to>[\d.]+)', 
                r'(?P<ipv4_addr>[\d.]+)/(?P<ipv4_mask>\d{1,2})'
            )
        ),
    }

    class BreakLoop(Exception): 
        pass

    @classmethod
    def query(cls, query, hostname=None, port=None):
        # set default hostname if None
        hostname = hostname or cls.DEFAULT_HOST
        port = port or cls.DEFAULT_PORT
        # open a tcp socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(cls.TIMEOUT)
        stack = []
        response = b''
        try:
            sock.connect((hostname, port))
            # send a query
            format = cls.QUERY.get(hostname, '%s') + '\r\n'
            sock.send((format % query).encode('ascii'))
            # read the response
            while True:
                buf = sock.recv(4096)
                response += buf
                if not buf:
                    break
        except socket.timeout:
            return ''
        finally:
            sock.close()
        response = response.decode('utf-8', errors='ignore')
        stack.append(response)
        # see if we are being redirected to another whois server
        referral = cls.parse_fields(cls.FIELDS_REFER, response)
        # do another query
        if referral.get('hostname', None):
            try:
                port = int(referral['port'])
            except (KeyError, ValueError, TypeError):
                pass
            stack.extend(cls.query(query, referral['hostname'], port))
        return stack

    @classmethod
    def parse(cls, response):
        """
        Parse a whois response.

        Return a dictionary mapping fields described with `FIELDS_WHOIS` 
        to their corresponding parsed values. 
        If provided response argument is a stack (i.e. an iterable containing 
        ordered response data receieved from referring whois sources), try the data
        in reversed order untill one of the described fields get a non-empty result.

        Args:
            response - plain text or stack-like response.
        """
        if not isinstance(response, (tuple, list)):
            response = [response]
        for text in reversed(response):
            parsed = cls.parse_fields(cls.FIELDS_WHOIS, text)
            # attempt to expand ipv4 range
            if parsed.get('ipv4_mask', None):
                try:
                    parsed['ipv4range'] = cls.expand_ipv4_address(parsed['ipv4_addr'], int(parsed['ipv4_mask']))
                except ValueError:
                    parsed['ipv4range'] = None
            elif parsed.get('ipv4_from', None):
                parsed['ipv4range'] = parsed['ipv4_from'], parsed['ipv4_to']
            # fix country
            if parsed.get('country'):
                # USA > us
                parsed['country'] = parsed['country'][:2].lower() if 1 < len(parsed['country']) <= 3 else None
            # if any of the above has been parsed, return the result as successful
            if [value for value in parsed.values() if value is not None]:
                return parsed
        # use the latest parsed value as the last resort
        try:
            return parsed
        # provided response stack is empty
        except NameError:
            return None

    @classmethod
    def whois(cls, address, hostname=None, port=None, raw=False):
        stack = cls.query(address, hostname, port)
        # do not parse/format the response
        if raw:
            return '\n'.join(stack)
        return cls.parse(stack)

    @classmethod
    def parse_fields(cls, fields, text):
        result = {}
        for alias, (fields, patterns) in fields.items():
            try:
                for field in fields:
                    for pattern in patterns:
                        matched = re.search(
                            r'^(?:[^:]+:)?{}[ \t]*:[ \t]*({})'.format(field, pattern), text, re.I | re.M
                        )
                        if matched:
                            result[alias] = matched.group(1)
                            # update the dict with named groups (if any)
                            result.update(matched.groupdict())
                            raise cls.BreakLoop()
            except cls.BreakLoop:
                pass
            else:
                result[alias] = None
        return result

    @staticmethod
    def expand_ipv4_address(address, mask=None):
        mask = mask or 32
        # replace missing ip parts with zeroes, e.g. 187.12 -> 187.12.0.0
        ipv4_from = '.'.join((address.split('.') + ['0']*4)[:4])
        ipv4_to = int2ip(ip2int(ipv4_from) + 2**(32-mask)-1)
        return (ipv4_from, ipv4_to)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument('addr')
    parser.add_argument('--pretty', action='store_true', default=False)
    args = parser.parse_args()

    result = whois.whois(args.addr, raw=not args.pretty)
    # display dict items
    if isinstance(result, dict):
        for item in result.items():
            print('%s: %s' % item)
    # display result as is
    else:
        print(result)