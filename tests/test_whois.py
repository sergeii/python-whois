# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import os
import unittest
from io import open

import six
from mock import patch, Mock

from whois import whois, ip2int, int2ip


class WhoisParseTestCase(unittest.TestCase):

    known_values = {
        '81.19.209.212.txt': {
            'orgname': 'KillerCreation Networks Ltd - www.killercreation.co.uk',
            'country': 'gb',
            'ipv4range': ('81.19.209.0', '81.19.209.255')
        },
        '123.123.123.123.txt': {
            'orgname': 'China Unicom Beijing province network',
            'country': 'cn',
            'ipv4range': ('123.112.0.0', '123.127.255.255')
        },
        '69.113.167.2.txt': {
            'orgname': 'Optimum Online',
            'country': 'us',
            'ipv4range': ('69.113.166.0', '69.113.167.255')
        },
        '145.47.32.18.txt': {
            'orgname': 'Heineken NV',
            'country': 'nl',
            'ipv4range': ('145.47.0.0', '145.47.255.255')
        },
        '77.222.40.171.txt': {
            'orgname': 'SpaceWeb.ru Hosting Provider',
            'country': 'ru',
            'ipv4range': ('77.222.40.0', '77.222.43.255')
        },
        '187.12.145.12.txt': {
            'orgname': 'Telemar Norte Leste S.A.',
            'country': 'br',
            'ipv4range': ('187.12.0.0', '187.15.255.255')
        },
        '24.27.12.147.txt': {
            'orgname': 'Road Runner',
            'country': 'us',
            'ipv4range': ('24.24.0.0', '24.27.255.255')
        },
        '201.51.57.102.txt': {
            'country': 'br',
            'orgname': 'Telemar Norte Leste S.A.',
            'ipv4range': ('201.50.0.0', '201.51.255.255')
        },
        '189.132.72.18.txt': {
            'country': 'mx',
            'orgname': 'Gestión de direccionamiento UniNet',
            'ipv4range': ('189.132.72.0', '189.132.72.255'),
        },
        '201.230.239.126.txt': {
            'country': 'pe',
            'orgname': 'PE-TDPERX9-LACNIC',
            'ipv4range': ('201.230.239.0', '201.230.239.127'),
        },
        '201.143.224.166.txt': {
            'country': 'mx',
            'orgname': 'Telefonos del Noroeste, S.A. de C.V.',
            'ipv4range': ('201.143.192.0', '201.143.255.255'),
        },
        '201.216.202.229.txt': {
            'country': 'ar',
            'orgname': 'NSS S.A.',
            'ipv4range': ('201.216.192.0', '201.216.223.255')
        },
        '82.174.20.225.txt': {
            'country': 'nl',
            'orgname': 'Tele 2 Nederland B.V.',
            'ipv4range': ('82.172.0.0', '82.175.255.255')
        },
        '62.166.17.241.txt': {
            'country': 'nl',
            'orgname': 'Tele 2 Nederland B.V.',
            'ipv4range': ('62.166.0.0', '62.166.255.255')
        },
        '201.22.187.198.txt': {
            'country': 'br',
            'orgname': 'Global Village Telecom', 
            'ipv4range': ('201.22.0.0', '201.22.255.255')
        },
        '200.46.198.3.txt': {
            'country': 'pa',
            'orgname': 'Redspan Corporation', 
            'ipv4range': ('200.46.198.0', '200.46.198.63')
        },
        '200.88.76.196.txt': {
            'country': 'do',
            'orgname': 'Compañía Dominicana de Teléfonos, C. por A. - CODETEL',
            'ipv4range': ('200.88.64.0', '200.88.127.255'),
        },
        '209.33.251.216.txt': {
            'country': 'us', 
            'orgname': 'InfoWest, Inc',
            'ipv4range': ('209.33.192.0', '209.33.255.255')
        },
        '74.72.23.22.txt': {
            'country': 'us',
            'orgname': 'Road Runner',
            'ipv4range': ('74.72.0.0', '74.73.255.255'),
        },
        '76.180.108.159.txt': {
            'country': 'us',
            'orgname': 'Road Runner',
            'ipv4range': ('76.180.0.0', '76.180.255.255')
        },
        '190.22.89.128.txt': {
            'country': 'cl',
            'orgname': 'TELEFÓNICA CHILE S.A.', 
            'ipv4range': ('190.22.0.0', '190.22.127.255'),
        },
        '84.173.251.133.txt': {
            'country': 'de',
            'orgname': 'Deutsche Telekom AG',
            'ipv4range': ('84.136.0.0', '84.191.255.255'),
        },
        '217.107.7.174.txt': {
            'country': 'ru',
            'orgname': 'OJSC RTComm.RU',
            'ipv4range': ('217.106.0.0', '217.107.255.255')
        },
        '88.147.190.142.txt': {
            'country': 'ru',
            'orgname': 'Network of Saratov branch of OJSC "Volgatelecom"',
            'ipv4range': ('88.147.176.0', '88.147.195.255'),
        },
        '41.245.19.131.txt': {
            'country': 'mu',
            'orgname': 'AfriNIC - www.afrinic.net',
            'ipv4range': ('41.0.0.0', '41.255.255.255'),
        },
        '59.49.78.131.txt': {
            'country': 'cn',
            'orgname': 'ShanXi Telecom TaiYuan Branch IP Node Links To Customer IP Address',
            'ipv4range': ('59.49.78.131', '59.49.78.131'),
        },
        '216.167.160.29.txt': {
            'country': 'us',
            'orgname': 'NTS Communications',
            'ipv4range': ('216.167.128.0', '216.167.191.255'),
        },
        '82.226.225.134.txt': {
            'country': 'fr',
            'orgname': 'Proxad / Free SAS',
            'ipv4range': ('82.226.224.0', '82.226.225.255'),
        },
        '89.187.232.13.txt': {
            'country': 'pl',
            'orgname': 'Internetia - Krakow, Wroclaw, Bielsko-Biala',
            'ipv4range': ('89.187.224.0', '89.187.239.255')
        },
        '92.113.218.205.txt': {
            'country': 'ua',
            'orgname': 'NCC#2011011865 Approved IP assignment',
            'ipv4range': ('92.113.0.0', '92.113.255.255')
        },
        '205.146.55.254.txt': {
            'country': 'us',
            'orgname': 'Robert Morris College',
            'ipv4range': ('205.146.52.0', '205.146.55.255'),
        },
        '84.78.12.118.txt': {
            'country': 'es',
            'orgname': 'Ya.com Internet Factory',
            'ipv4range': ('84.78.0.0', '84.79.255.255')
        },
        '78.29.128.115.txt': {
            'country': 'pt',
            'orgname': 'Cabo TV Acoreana',
            'ipv4range': ('78.29.128.0', '78.29.159.255')
        },
        '85.124.100.112.txt': {
            'country': 'at',
            'orgname': 'Inode Telekommunikationsdienstleitung GesmbH',
            'ipv4range': ('85.124.100.0', '85.124.100.255')
        },
    }

    def test_known_values(self):
        for filename, expected in self.known_values.items():
            with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), 'sample', filename), mode='rb') as f:
                parsed = whois.parse(f.read().decode('latin1'))
                for item_name, item_value in expected.items():
                    self.assertEqual(parsed[item_name], item_value)

    def test_parse_empty_list_returns_none(self):
        self.assertEqual(whois.parse([]), None)

    def test_parse_empty_text_returns_dict_with_none_values(self):
        parsed = whois.parse('')
        self.assertTrue(len(parsed))
        for k in parsed:
            self.assertIs(parsed[k], None)

    def test_parse_returns_the_nearest_non_none_match_in_reversed_order(self):
        parsed = whois.parse(['country:un', 'country:eu', 'foo:bar'])
        self.assertEqual(parsed['country'], 'eu')

        parsed = whois.parse('country:eu')
        self.assertEqual(parsed['country'], 'eu')


class IPv4NumericConversionTestCase(unittest.TestCase):

    known_values = (
        (0, '0.0.0.0'),
        (4294967295, '255.255.255.255'),
    )

    invalid_numeric_values = (
        -1,
        4294967296,
        -4294967296,
    )

    def test_invalid_numeric_number_raises_value_error(self):
        for invalid_value in self.invalid_numeric_values:
            self.assertRaises(ValueError, int2ip, invalid_value)

    def test_known_values(self):
        for numeric, dotted in self.known_values:
            self.assertEqual(int2ip(numeric), dotted)
            self.assertEqual(ip2int(dotted), numeric)

    def test_sanity_check(self):
        for numeric in six.moves.xrange(0, 0xffffffff, 256*256):
            self.assertEqual(ip2int(int2ip(numeric)), numeric)


class IPv4ExpansionTestCase(unittest.TestCase):

    known_values = (
        (('0', 32), ('0.0.0.0', '0.0.0.0')),
        (('0.0', None), ('0.0.0.0', '0.0.0.0')),
        (('187', None), ('187.0.0.0', '187.0.0.0')),
        (('187.0', 12), ('187.0.0.0', '187.15.255.255')),
        (('127.0.0.1', 32), ('127.0.0.1', '127.0.0.1')),
        (('127.0.0.1', None), ('127.0.0.1', '127.0.0.1')),
        (('127.0.0.0', 31), ('127.0.0.0', '127.0.0.1')),
        (('127.0.0.0', 8), ('127.0.0.0', '127.255.255.255')),
        (('192.168.0.0', 16), ('192.168.0.0', '192.168.255.255')),
        (('201.22.0.0', 16), ('201.22.0.0', '201.22.255.255')),
        (('24.30.96.0', 19), ('24.30.96.0', '24.30.127.255')),
        (('68.255.16.0', 20), ('68.255.16.0', '68.255.31.255')),
        (('83.174.240.0', 21), ('83.174.240.0', '83.174.247.255')),
    )

    def test_known_values(self):
        for ((addr, mask), ip_range) in self.known_values:
            self.assertEqual(whois.expand_ipv4_address(addr, mask), ip_range)


class WhoisReferrerTestCase(unittest.TestCase):

    known_values = (
        (b'ReferralServer: whois://whois.apnic.net\n', 'whois.apnic.net', 43),
        (b'whois: whois://ipmt.rr.com:4321\n', 'ipmt.rr.com', 4321),
        (b'ReferralServer: rwhois://rwhois.ptd.net:4321\n', 'rwhois.ptd.net', 4321),
    )

    def test_known_values(self):
        for text, hostname, port in self.known_values:
            with patch('whois.socket.socket') as mock:
                mock_inst = Mock()
                mock_inst.recv.side_effect = [text, b'', b'foo', b'']
                mock.return_value = mock_inst
                self.assertEqual(whois.query('127.0.0.1')[-1], 'foo')
                mock_inst.connect.assert_called_with((hostname, port))