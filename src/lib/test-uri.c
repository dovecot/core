/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "test-common.h"
#include "str.h"
#include "str-sanitize.h"
#include "uri-util.h"

/* Valid uri tests */
const char *valid_uri_tests[] = {
	"http://www.dovecot.org",
	"http://127.0.0.1",
	"http://www.dovecot.org/frop",
	"http://www.dovecot.org/frop%20frop",
	"http://www.dovecot.org/frop/frop",
	"http://www.dovecot.org/frop/frop?query",
	"http://www.dovecot.org?query",
	"http://www.dovecot.org?query&query",
	"mailto:frop@example.com",
};

unsigned int valid_uri_test_count = N_ELEMENTS(valid_uri_tests);

static void test_uri_valid(void)
{
	unsigned int i;

	test_begin("uri valid");
	for (i = 0; i < valid_uri_test_count; i++) T_BEGIN {
		const char *uri_in, *error = NULL;
		int ret;

		uri_in = valid_uri_tests[i];

		ret = uri_check(uri_in, 0, &error);
		test_out_quiet(
			t_strdup_printf("parse [%u] <%s>", i, str_sanitize(uri_in, 64)),
			ret >= 0);
	} T_END;
	test_end();
}

/* Invalid uri tests */
const char *invalid_uri_tests[] = {
	"http",
	"http$44",
	"/index.html",
	"imap:[",
	"imap://[",
	"frop://friep\"",
	"http://example.com/settings/%00/",
	"http://[]/index.html",
	"http://example.com:65536/index.html"
};

unsigned int invalid_uri_test_count = N_ELEMENTS(invalid_uri_tests);

static void test_uri_invalid(void)
{
	unsigned int i;

	test_begin("uri invalid");
	for (i = 0; i < invalid_uri_test_count; i++) T_BEGIN {
		const char *uri_in, *error = NULL;
		int ret;

		uri_in = invalid_uri_tests[i];

		ret = uri_check(uri_in, 0, &error);
		test_out_quiet(
			t_strdup_printf("parse [%u] <%s>", i, str_sanitize(uri_in, 64)),
			ret < 0);
	} T_END;
	test_end();
}

/* RFC uri tests */
const char *rfc_uri_tests[] = {
	/* from RFC 1738 */
	"http://www.acl.lanl.gov/URI/archive/uri-archive.index.html",
	"file://vms.host.edu/disk$user/my/notes/note12345.txt",
	"ftp://@host.com/",
	"ftp://host.com/",
	"ftp://foo:@host.com/",
	"ftp://myname@host.dom/%2Fetc/motd",
	"ftp://myname@host.dom/etc/motd",
	"ftp://myname@host.dom//etc/motd",
	"ftp://info.cern.ch/pub/www/doc;type=d",
	"http://ds.internic.net/instructions/overview.html#WARNING",
	/* from RFC 2056 */
	"z39.50s://melvyl.ucop.edu/cat",
	"z39.50r://melvyl.ucop.edu/mags?elecworld.v30.n19",
	"z39.50r://cnidr.org:2100/tmf?bkirch_rules__a1;esn=f;rs=marc",
	/* from RFC 2122 */
	"vemmi://zeus.mctel.fr/demo",
	"vemmi://zeus.mctel.fr",
	"vemmi://zeus.mctel.fr",
	"vemmi://mctel.fr/demo;$USERDATA=smith;account=1234",
	"vemmi://ares.mctel.fr/TEST",
	/* from RFC 2141 */
	"URN:foo:a123,456",
	"urn:foo:a123,456",
	"urn:FOO:a123,456",
	"urn:foo:A123,456",
	"urn:foo:a123%2C456",
	"URN:FOO:a123%2c456",
	/* from RFC 2224 */
	"nfs://server/d/e/f",
	"nfs://server//a/b/c/d/e/f",
	"nfs://server/a/b",
	/* from RFC 2229 */
	"dict://dict.org/d:shortcake:",
	"dict://dict.org/d:shortcake:*",
	"dict://dict.org/d:shortcake:wordnet:",
	"dict://dict.org/d:shortcake:wordnet:1",
	"dict://dict.org/d:abcdefgh",
	"dict://dict.org/d:sun",
	"dict://dict.org/d:sun::1",
	"dict://dict.org/m:sun",
	"dict://dict.org/m:sun::soundex",
	"dict://dict.org/m:sun:wordnet::1",
	"dict://dict.org/m:sun::soundex:1",
	"dict://dict.org/m:sun:::",
	/* from RFC 2326 */
	"rtsp://media.example.com:554/twister/audiotrack",
	"rtsp://media.example.com:554/twister",
	"rtsp://server.example.com/fizzle/foo",
	"rtsp://example.com/foo/bar/baz.rm",
	"rtsp://audio.example.com/audio",
	"rtsp://audio.example.com/twister.en",
	"rtsp://audio.example.com/meeting.en",
	"rtsp://example.com/fizzle/foo",
	"rtsp://bigserver.com:8001",
	"rtsp://example.com/meeting/audio.en",
	"rtsp://foo.com/bar.file",
	"rtsp://foo.com/bar.avi/streamid=0;seq=45102",
	"rtsp://foo.com/bar.avi/streamid=1;seq=30211",
	"rtsp://audio.example.com/twister/audio.en",
	"rtsp://video.example.com/twister/video",
	"rtsp://video.example.com/twister/video;seq=12312232;rtptime=78712811",
	"rtsp://audio.example.com/twister/audio.en;seq=876655;rtptime=1032181",
	"rtsp://foo/twister/video;seq=9810092;rtptime=3450012",
	"rtsp://foo.com/test.wav/streamid=0;seq=981888;rtptime=3781123",
	"rtsp://server.example.com/demo/548/sound",
	"rtsp://server.example.com/demo/548/sound",
	"rtsp://server.example.com/meeting",
	"rtsp://server.example.com/meeting/audiotrack",
	"rtsp://server.example.com/meeting/videotrack",
	"rtsp://server.example.com/meeting",
	"rtsp://example.com/movie/trackID=1",
	"rtsp://media.example.com:554/twister",
	/* from RFC 2371 */
	"tip://123.123.123.123/?urn:xopen:xid",
	"tip://123.123.123.123/?transid1",
	/* from RFC 2384 */
	"pop://rg@mailsrv.qualcomm.com",
	"pop://rg;AUTH=+APOP@mail.eudora.com:8110",
	"pop://baz;AUTH=SCRAM-MD5@foo.bar",
	/* from RFC 2392 */
	"mid:960830.1639@XIson.com/partA.960830.1639@XIson.com",
	"cid:foo4%25foo1@bar.net",
	"cid:foo4*foo1@bar.net",
	/* from RFC 2397 */
	"data:,A%20brief%20note",
	"data:image/gif;base64,R0lGODdhMAAwAPAAAAAAAP///ywAAAAAMAAw"
		"AAAC8IyPqcvt3wCcDkiLc7C0qwyGHhSWpjQu5yqmCYsapyuvUUlvONmOZtfzgFz"
		"ByTB10QgxOR0TqBQejhRNzOfkVJ+5YiUqrXF5Y5lKh/DeuNcP5yLWGsEbtLiOSp"
		"a/TPg7JpJHxyendzWTBfX0cxOnKPjgBzi4diinWGdkF8kjdfnycQZXZeYGejmJl"
		"ZeGl9i2icVqaNVailT6F5iJ90m6mvuTS4OK05M0vDk0Q4XUtwvKOzrcd3iq9uis"
		"F81M1OIcR7lEewwcLp7tuNNkM3uNna3F2JQFo97Vriy/Xl4/f1cf5VWzXyym7PH"
		"hhx4dbgYKAAA7",
#if 0 // this one doesn't comply with RFC 3986
	"data:text/plain;charset=iso-8859-7,%be%fg%be",
#endif
	"data:application/vnd-xxx-query,select_vcount,fcol_from_fieldtable/local",
	/* from RFC 2838 */
	"tv:wqed.org",
	"tv:nbc.com",
	"tv:",
	"tv:abc.com",
	"tv:abc.co.au",
	"tv:east.hbo.com",
	"tv:west.hbo.com",
	/* from RFC 3261 */
#if 0 // these don't comply with RFC 3986
	"sip:+1-212-555-1212:1234@gateway.com;user=phone",
	"sip:+12125551212@server.phone2net.com",
	"sip:+12125551212@server.phone2net.com;tag=887s",
	"sip:+358-555-1234567@foo.com;postd=pp22;user=phone",
	"sip:+358-555-1234567;isub=1411;postd=pp22@foo.com;user=phone",
	"sip:+358-555-1234567;phone-context=5;tsp=a.b@foo.com;user=phone",
	"sip:+358-555-1234567;postd=pp22@foo.com;user=phone",
	"sip:+358-555-1234567;POSTD=PP22@foo.com;user=phone",
	"sip:+358-555-1234567;postd=pp22;isub=1411@foo.com;user=phone",
	"sip:%61lice@atlanta.com;transport=TCPv",
	"sip:agb@bell-telephone.com",
	"sip:alice@192.0.2.4v",
	"sip:alice@atlanta.covm",
	"sip:alice@atlanta.com;maddr=239.255.255.1;ttl=15",
	"sip:alice@atlanta.com?priority=urgent&subject=project%20x",
	"sip:alice@atlanta.com?subject=project%20x&priority=urgent",
	"sip:alice@AtLanTa.CoM;Transport=tcp",
	"sip:alice@AtLanTa.CoM;Transport=UDP",
	"SIP:ALICE@AtLanTa.CoM;Transport=udp",
	"sip:alice;day=tuesday@atlanta.com",
	"sip:alice@pc33.atlanta.com",
	"sip:alice:secretword@atlanta.com;transport=tcp",
	"sip:anonymous@anonymizer.invalid",
	"sip:atlanta.com;method=REGISTER?to=alice%40atlanta.com",
	"sip:bigbox3.site3.atlanta.com;lr",
	"sip:biloxi.com;method=REGISTER;transport=tcp?to=sip:bob%40biloxi.com",
	"sip:biloxi.com;transport=tcp;method=REGISTER?to=sip:bob%40biloxi.com",
	"sip:bob@192.0.2.4",
	"sip:bob@biloxi.com",
	"sip:bob@biloxi.com:5060",
	"sip:bob@biloxi.com:6000;transport=tcp",
	"sip:bob@biloxi.com;transport=udp",
	"sip:bob@engineering.biloxi.com",
	"sip:bob@phone21.boxesbybob.com",
	"sip:c8oqz84zk7z@privacy.org>;tag=hyh8",
	"sip:callee@domain.com",
	"sip:callee@gateway.leftprivatespace.com",
	"sip:callee@u2.domain.com",
	"sip:callee@u2.rightprivatespace.com",
	"sip:caller@u1.example.com",
	"sip:carol@chicago.com",
	"sip:carol@chicago.com;security=off",
	"sip:carol@chicago.com;security=on",
	"sip:carol@chicago.com;newparam=5",
	"sip:carol@chicago.com;security=off",
	"sip:carol@chicago.com;security=on",
	"sip:carol@chicago.com?Subject=next%20meeting",
	"sip:carol@cube2214a.chicago.com",
	"sip:chicago.com",
	"sip:not-in-service-recording@atlanta.com",
	"sip:operator@cs.columbia.edu",
	"sip:p1.domain.com;lr",
	"sip:p1.example.com;lr",
	"sip:p2.domain.com;lr",
	"sips:1212@gateway.com",
	"sips:+358-555-1234567@foo.com;postd=pp22;user=phone",
	"sips:+358-555-1234567;postd=pp22@foo.com;user=phone",
	"sips:alice@atlanta.com?subject=project%20x&priority=urgent",
	"sip:server10.biloxi.com;lr",
	"sip:ss1.carrier.com",
	"sip:user@host?Subject=foo&Call-Info=<http://www.foo.com>",
	"sip:watson@bell-telephone.com",
	"sip:watson@worcester.bell-telephone.com",
#endif
	/* from RFC 3368 */
	"go:Mercedes%20Benz",
	"go://?Mercedes%20Benz",
	"go://cnrp.foo.com?Mercedes%20Benz;geography=US-ga",
	"go://cnrp.foo.org?Martin%20J.%20D%C3%BCrst",
	"go://cnrp.foo.com?id=5432345",
	/* from RFC 3507 */
	"icap://icap.example.net:2000/services/icap-service-1",
	"icap://icap.net/service?mode=translate&lang=french",
	"icap://icap.example.net/translate?mode=french",
	"icap://icap-server.net/server?arg=87",
	"icap://icap.example.org/satisf",
	"icap://icap.server.net/sample-service",
	/* from RFC 3510 */
	"ipp://example.com",
	"ipp://example.com/printer",
	"ipp://example.com/printer/tiger",
	"ipp://example.com/printer/fox",
	"ipp://example.com/printer/tiger/bob",
	"ipp://example.com/printer/tiger/ira",
	"ipp://example.com",
	"ipp://example.com/~smith/printer",
	"ipp://example.com:631/~smith/printer",
	"ipp://example.com/printer/123",
	"ipp://example.com/printer/tiger/job123",
	/* from RFC 3529 */
	"xmlrpc.beep://stateserver.example.com/NumberToName",
	"xmlrpc.beep://stateserver.example.com:1026",
	"xmlrpc.beep://stateserver.example.com",
	"xmlrpc.beep://10.0.0.2:1026",
	"xmlrpc.beeps://stateserver.example.com/NumberToName",
	/* from RFC 3617 */
	"tftp://example.com/myconfigurationfile;mode=netascii",
	"tftp://example.com/mystartupfile",
	/* from RFC 3859 */
	"pres:fred@example.com",
	/* from RFC 3860 */
	"im:fred@example.com",
	"im:pepp=example.com/fred@relay-domain",
	/* from RFC 3966 */
	"tel:+1-201-555-0123",
	"tel:7042;phone-context=example.com",
	"tel:863-1234;phone-context=+1-914-555",
	/* from RFC 3981 */
	"iris:dreg1//example.com/local/myhosts",
	"iris:dreg1//com",
	"iris:dreg1//com/iris/id",
	"iris:dreg1//example.com/domain/example.com",
	"iris:dreg1//example.com",
	"iris:dreg1//com/domain/example.com",
	"iris:dreg1//192.0.2.1:44/domain/example.com",
	"iris.lwz:dreg1//192.0.2.1:44/domain/example.com",
	"iris.beep:dreg1//com/domain/example.com",
	"iris:dreg1/bottom/example.com/domain/example.com",
	"iris.beep:dreg1/bottom/example.com/domain/example.com",
	/* from RFC 3986 */
	"ftp://ftp.is.co.za/rfc/rfc1808.txt",
	"http://www.ietf.org/rfc/rfc2396.txt",
	"ldap://[2001:db8::7]/c=GB?objectClass?one",
	"mailto:John.Doe@example.com",
	"news:comp.infosystems.www.servers.unix",
	"tel:+1-816-555-1212",
	"telnet://192.0.2.16:80/",
	"urn:oasis:names:specification:docbook:dtd:xml:4.1.2",
	/* from RFC 4078 */
	"crid://example.com/foobar",
	"crid://example.co.jp/%E3%82%A8%E3%82%A4%E3%82%AC",
	/* from RFC 4088 */
	"snmp://example.com",
	"snmp://tester5@example.com:8161",
	"snmp://example.com/bridge1",
	"snmp://example.com/bridge1;800002b804616263",
	"snmp://example.com//1.3.6.1.2.1.1.3.0",
	"snmp://example.com//1.3.6.1.2.1.1.3+",
	"snmp://example.com//1.3.6.1.2.1.1.3.*",
	"snmp://example.com/bridge1/1.3.6.1.2.1.2.2.1.8.*",
	"snmp://example.com//(1.3.6.1.2.1.2.2.1.7,1.3.6.1.2.1.2.2.1.8).*",
	/* from RFC 4151 */
	"tag:timothy@hpl.hp.com,2001:web/externalHome",
	"tag:sandro@w3.org,2004-05:Sandro",
	"tag:my-ids.com,2001-09-15:TimKindberg:presentations:UBath2004-05-19",
	"tag:blogger.com,1999:blog-555",
	"tag:yaml.org,2002:int",
	/* from RFC 4227 */
	"soap.beep://stockquoteserver.example.com/StockQuote",
	"soap.beep://stockquoteserver.example.com:1026",
	"soap.beep://stockquoteserver.example.com",
	"soap.beep://192.0.2.0:1026",
	/* from RFC 4324 */
	"cap://cal.example.com",
	"cap://cal.example.com/Company/Holidays",
	"cap://cal.example.com/abcd1234Usr",
	"cap://cal.example.com/abcd1234USR",
	"cap://host.com/joe",
	"cap:example.com/Doug",
	"cap://cal.example.com/sdfifgty4321",
	"cap://calendar.example.com",
	"cap://mycal.example.com",
	/* from RFC 4452 */
	"info:ddc/22/eng//004.678",
	"info:lccn/2002022641",
	"info:sici/0363-0277(19950315)120:5%3C%3E1.0.TX;2-V",
	"info:bibcode/2003Icar..163..263Z",
	"info:pmid/12376099",
	/* from RFC 4501 */
	"dns:www.example.org.?clAsS=IN;tYpE=A",
	"dns:www.example.org",
	"dns:simon.example.org?type=CERT",
	"dns://192.168.1.1/ftp.example.org?type=A",
	"dns:world%20wide%20web.example%5c.domain.org?TYPE=TXT",
#if 0 // contains %00 encoding, which is currently always rejected
	"dns://fw.example.org/*.%20%00.example?type=TXT",
#endif
	/* from RFC 4516 */
	"ldap:///o=University%20of%20Michigan,c=US",
	"ldap://ldap1.example.net/o=University%20of%20Michigan,c=US",
	"ldap://ldap1.example.net/o=University%20of%20Michigan,"
		"c=US?postalAddress",
	"ldap://ldap1.example.net:6666/o=University%20of%20Michigan,"
		"c=US?\?sub?(cn=Babs%20Jensen)",
	"LDAP://ldap1.example.com/c=GB?objectClass?ONE",
	"ldap://ldap2.example.com/o=Question%3f,c=US?mail",
	"ldap://ldap3.example.com/o=Babsco,c=US"
		"??\?(four-octet=%5c00%5c00%5c00%5c04)",
	"ldap://ldap.example.com/o=An%20Example%5C2C%20Inc.,c=US",
	"ldap://ldap.example.net",
	"ldap://ldap.example.net/",
	"ldap://ldap.example.net/?",
	"ldap:///?\?sub?\?e-bindname=cn=Manager%2cdc=example%2cdc=com",
	"ldap:///?\?sub?\?!e-bindname=cn=Manager%2cdc=example%2cdc=com"
	/* from RFC 4975 */
	"msrp://atlanta.example.com:7654/jshA7weztas;tcp",
	"msrp://biloxi.example.com:12763/kjhd37s2s20w2a;tcp",
	"msrp://host.example.com:8493/asfd34;tcp",
	"msrp://alice.example.com:7394/2s93i9ek2a;tcp",
	"msrp://bob.example.com:8493/si438dsaodes;tcp",
	"msrp://alicepc.example.com:7777/iau39soe2843z;tcp",
	"msrp://bob.example.com:8888/9di4eae923wzd;tcp",
	"msrp://alice.example.com:7777/iau39soe2843z;tcp",
	"msrp://bobpc.example.com:8888/9di4eae923wzd;tcp",
	"msrp://alicepc.example.com:7654/iau39soe2843z;tcp",
	"msrp://alicepc.example.com:8888/9di4eae923wzd;tcp",
	"msrp://example.com:7777/iau39soe2843z;tcp",
	"msrp://bob.example.com:8888/9di4eae923wzd;tcp",
	/* from RFC 5092 */
	"imap://michael@example.org/INBOX",
	"imap://bester@example.org/INBOX",
	"imap://joe@example.com/INBOX/;uid=20/;section=1.2;urlauth="
		"submit+fred:internal:91354a473744909de610943775f92038",
	"imap://minbari.example.org/gray-council;UIDVALIDITY=385759045/;"
		"UID=20/;PARTIAL=0.1024",
	"imap://psicorp.example.org/~peter/%E6%97%A5%E6%9C%AC%E8%AA%9E/"
		"%E5%8F%B0%E5%8C%97",
	"imap://;AUTH=GSSAPI@minbari.example.org/gray-council/;uid=20/"
		";section=1.2",
	"imap://;AUTH=*@minbari.example.org/gray%20council?"
		"SUBJECT%20shadows",
	"imap://john;AUTH=*@minbari.example.org/babylon5/personel?"
		"charset%20UTF-8%20SUBJECT%20%7B14+%7D%0D%0A%D0%98%D0%B2%"
		"D0%B0%D0%BD%D0%BE%D0%B2%D0%B0",
	/* from RFC 5122 */
	"xmpp:node@example.com",
	"xmpp://guest@example.com",
	"xmpp:guest@example.com",
	"xmpp://guest@example.com/support@example.com?message",
	"xmpp:support@example.com?message",
	"xmpp:example-node@example.com",
	"xmpp:example-node@example.com/some-resource",
	"xmpp:example.com",
	"xmpp:example-node@example.com?message",
	"xmpp:example-node@example.com?message;subject=Hello%20World",
	"xmpp:example-node@example.com",
	"xmpp:example-node@example.com?query",
	"xmpp:nasty!%23$%25()*+,-.;=%3F%5B%5C%5D%5E_%60%7B%7C%7D~node@example.com",
	"xmpp:node@example.com/repulsive%20!%23%22$%25&'()*+,-.%2F:;%3C="
		"%3E%3F%40%5B%5C%5D%5E_%60%7B%7C%7D~resource",
	"xmpp:ji%C5%99i@%C4%8Dechy.example/v%20Praze",
	/* from RFC 5456 */
#if 0 // these don't comply with RFC 3986
	"iax:example.com/alice",
	"iax:example.com:4569/alice",
	"iax:example.com:4570/alice?friends",
	"iax:192.0.2.4:4569/alice?friends",
	"iax:[2001:db8::1]:4569/alice?friends",
	"iax:example.com/12022561414",
	"iax:johnQ@example.com/12022561414",
	"iax:atlanta.com/alice",
	"iax:AtLaNtA.com/ALicE",
	"iax:atlanta.com:4569/alice",
	"iax:alice@atlanta.com/alice",
	"iax:alice@AtLaNtA.com:4569/ALicE",
	"iax:ALICE@atlanta.com/alice",
	"iax:alice@atlanta.com/alice",
#endif
	/* from RFC 5724 */
	"sms:+15105550101",
	"sms:+15105550101,+15105550102",
	"sms:+15105550101?body=hello%20there",
	/* from RFC 5804 */
	"sieve://example.com//script",
	"sieve://example.com/script",
	/* from RFC 5538 */
	"news://news.server.example/example.group.this",
	"news://news.server.example/*",
	"news://news.server.example/",
	"news://wild.server.example/example.group.th%3Fse",
	"news:example.group.*",
	"news:example.group.this",
	"news://news.gmane.org/gmane.ietf.tools",
	"news://news.gmane.org/p0624081dc30b8699bf9b@%5B10.20.30.108%5D",
	"nntp://wild.server.example/example.group.n%2Fa/12345",
	"nntp://news.server.example/example.group.this",
	"nntp://news.gmane.org/gmane.ietf.tools/742",
	"nntp://news.server.example/example.group.this/12345",
	/* from RFC 5870 */
	"geo:13.4125,103.8667",
	"geo:48.2010,16.3695,183",
	"geo:48.198634,16.371648;crs=wgs84;u=40",
	"geo:90,-22.43;crs=WGS84",
	"geo:90,46",
	"geo:22.300;-118.44",
	"geo:22.3;-118.4400",
	"geo:66,30;u=6.500;FOo=this%2dthat",
	"geo:66.0,30;u=6.5;foo=this-that",
	"geo:70,20;foo=1.00;bar=white",
	"geo:70,20;foo=1;bar=white",
	"geo:47,11;foo=blue;bar=white",
	"geo:47,11;bar=white;foo=blue",
	"geo:22,0;bar=Blue",
	"geo:22,0;BAR=blue",
	/* from RFC 6068 */
	"mailto:addr1@an.example,addr2@an.example",
	"mailto:?to=addr1@an.example,addr2@an.example",
	"mailto:addr1@an.example?to=addr2@an.example",
	"mailto:chris@example.com",
	"mailto:infobot@example.com?subject=current-issue",
	"mailto:infobot@example.com?body=send%20current-issue",
	"mailto:infobot@example.com?body=send%20current-issue%0D%0Asend%20index",
	"mailto:list@example.org?In-Reply-To=%3C3469A91.D10AF4C@example.com%3E",
	"mailto:majordomo@example.com?body=subscribe%20bamboo-l",
	"mailto:joe@example.com?cc=bob@example.com&body=hello",
	"mailto:gorby%25kremvax@example.com",
	"mailto:unlikely%3Faddress@example.com?blat=foop",
	"mailto:joe@an.example?cc=bob@an.example&amp;body=hello",
	"mailto:Mike%26family@example.org",
	"mailto:%22not%40me%22@example.org",
	"mailto:%22oh%5C%5Cno%22@example.org",
	"mailto:%22%5C%5C%5C%22it's%5C%20ugly%5C%5C%5C%22%22@example.org",
	"mailto:user@example.org?subject=caf%C3%A9",
	"mailto:user@example.org?subject=%3D%3Futf-8%3FQ%3Fcaf%3DC3%3DA9%3F%3D",
	"mailto:user@example.org?subject=%3D%3Fiso-8859-1%3FQ%3Fcaf%3DE9%3F%3D",
	"mailto:user@example.org?subject=caf%C3%A9&body=caf%C3%A9",
	"mailto:user@%E7%B4%8D%E8%B1%86.example.org?subject=Test&body=NATTO",
	/* from RFC 6455 */
	"ws://example.com/chat",
	/* from RFC 6694 */
	"about:blank",
	/* from RFC 6733 */
#if 0 // these don't comply with RFC 3986
	"aaa://host.example.com;transport=tcp",
	"aaa://host.example.com:6666;transport=tcp",
	"aaa://host.example.com;protocol=diameter",
	"aaa://host.example.com:6666;protocol=diameter",
	"aaa://host.example.com:6666;transport=tcp;protocol=diameter",
	"aaa://host.example.com:1813;transport=udp;protocol=radius",
#endif
	/* from RFC 6787 */
	"session:request1@form-level.store",
	"session:help@root-level.store",
	"session:menu1@menu-level.store",
	"session:request1@form-level.store",
	"session:request2@field-level.store",
	"session:helpgramar@root-level.store",
	"session:request1@form-level.store",
	"session:field3@form-level.store",
	/* from RFC 6920 */
	"ni:///sha-256;UyaQV-Ev4rdLoHyJJWCi11OHfrYv9E1aGQAlMO2X_-Q",
	"ni:///sha-256-32;f4OxZQ?ct=text/plain",
	"ni:///sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk",
	"ni://example.com/sha-256;f4OxZX_x_FO5LcGBSKHWXfwtSx-j1ncoSt3SABJtkGk",
	"nih:sha-256-120;5326-9057-e12f-e2b7-4ba0-7c89-2560-a2;f",
	"nih:sha-256-32;53269057;b",
	"nih:3;532690-57e12f-e2b74b-a07c89-2560a2;f",
	/* from RFC 7064 */
	"stun:example.org",
	"stuns:example.org",
	"stun:example.org:8000",
	/* from RFC 7065 */
	"turn:example.org",
	"turns:example.org",
	"turn:example.org:8000",
	"turn:example.org?transport=udp",
	"turn:example.org?transport=tcp",
	"turns:example.org?transport=tcp",
	/* from RFC 7230 */
	"http://www.example.com/hello.txt",
	"http://example.com:80/~smith/home.html",
	"http://EXAMPLE.com/%7Esmith/home.html",
	"http://EXAMPLE.com:/%7esmith/home.html",
	"http://www.example.org/where?q=now",
	"http://www.example.org/pub/WWW/TheProject.html",
	"http://www.example.org:8001",
	"http://www.example.org:8080/pub/WWW/TheProject.html",
	/* from RFC 7252 */
	"coap://example.com:5683/~sensors/temp.xml",
	"coap://EXAMPLE.com/%7Esensors/temp.xml",
	"coap://EXAMPLE.com:/%7esensors/temp.xml",
	"coap://server/temperature",
	"coap://[2001:db8::2:1]/",
	"coap://example.net/",
	"coap://example.net/.well-known/core",
	"coap://xn--18j4d.example/%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF",
	"coap://198.51.100.1:61616//%2F//?%2F%2F&?%26"
	/* from draft-ietf-appsawg-acct-uri-06 */
	"acct:foobar@status.example.net",
	"acct:user@example.com",
	"acct:bob@example.com",
	/* from draft-mcdonald-ipps-uri-scheme-18 */
	"ipps://example.com/",
	"ipps://example.com/ipp",
	"ipps://example.com/ipp/faxout",
	"ipps://example.com/ipp/print",
	"ipps://example.com/ipp/scan",
	"ipps://example.com/ipp/print/bob",
	"ipps://example.com/ipp/print/ira",
	"ipps://example.com/",
	"ipps://example.com/ipp/print",
	"ipps://example.com:631/ipp/print",
	/* from draft-pechanec-pkcs11uri-21 */
	"pkcs11:",
	"pkcs11:object=my-pubkey;type=public",
	"pkcs11:object=my-key;type=private?pin-source=file:/etc/token",
	"pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;"
		"manufacturer=Snake%20Oil,%20Inc.;model=1.0;"
		"object=my-certificate;type=cert;"
		"id=%69%95%3E%5C%F4%BD%EC%91;serial="
		"?pin-source=file:/etc/token_pin",
	"pkcs11:object=my-sign-key;type=private?module-name=mypkcs11",
	"pkcs11:object=my-sign-key;type=private"
		"?module-path=/mnt/libmypkcs11.so.1",
	"pkcs11:token=Software%20PKCS%2311%20softtoken;"
		"manufacturer=Snake%20Oil,%20Inc.?pin-value=the-pin",
	"pkcs11:slot-description=Sun%20Metaslot",
	"pkcs11:library-manufacturer=Snake%20Oil,%20Inc.;"
		"library-description=Soft%20Token%20Library;"
		"library-version=1.23",
	"pkcs11:token=My%20token%25%20created%20by%20Joe;"
		"library-version=3;id=%01%02%03%Ba%dd%Ca%fe%04%05%06",
	"pkcs11:token=A%20name%20with%20a%20substring%20%25%3B;"
		"object=my-certificate;type=cert",
	"pkcs11:token=Name%20with%20a%20small%20A%20with%20acute:%20%C3%A1;"
	"object=my-certificate;type=cert",
	"pkcs11:token=my-token;object=my-certificate;"
		"type=cert;vendor-aaa=value-a"
		"?pin-source=file:/etc/token_pin&vendor-bbb=value-b"
};

unsigned int rfc_uri_test_count = N_ELEMENTS(rfc_uri_tests);

static void test_uri_rfc(void)
{
	unsigned int i;

	test_begin("uri from rfcs");
	for (i = 0; i < rfc_uri_test_count; i++) T_BEGIN {
		const char *uri_in, *error = NULL;
		int ret;

		uri_in = rfc_uri_tests[i];

		ret = uri_check(uri_in, URI_PARSE_ALLOW_FRAGMENT_PART, &error);
		test_out_quiet(
			t_strdup_printf("parse [%d] <%s>", i, str_sanitize(uri_in, 64)),
			ret >= 0);
	} T_END;
	test_end();
}

static void test_uri_escape(void)
{
	string_t *str = t_str_new(256);

	test_begin("uri escape - userinfo");
	uri_append_user_data(str, NULL, "abcdefghijklmnopqrstuvwxyz");
	test_assert(strcmp(str_c(str), "abcdefghijklmnopqrstuvwxyz") == 0);
	str_truncate(str, 0);
	uri_append_user_data(str, NULL, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	test_assert(strcmp(str_c(str), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0);
	str_truncate(str, 0);
	uri_append_user_data(str, NULL, "0123456789");
	test_assert(strcmp(str_c(str), "0123456789") == 0);
	str_truncate(str, 0);
	uri_append_user_data(str, NULL, "-._~!$&'()*+,;=");
	test_assert(strcmp(str_c(str), "-._~!$&'()*+,;=") == 0);
	str_truncate(str, 0);
	uri_append_user_data(str, NULL, "a@b/c/d:e");
	test_assert(strcmp(str_c(str), "a%40b%2fc%2fd:e") == 0);
	str_truncate(str, 0);
	uri_append_user_data(str, NULL, "[yes]what?oh#13");
	test_assert(strcmp(str_c(str), "%5byes%5dwhat%3foh%2313") == 0);
	str_truncate(str, 0);
	uri_append_user_data(str, ":", "a@b/c/d:e");
	test_assert(strcmp(str_c(str), "a%40b%2fc%2fd%3ae") == 0);
	str_truncate(str, 0);
	test_end();

	test_begin("uri escape - path segment");
	uri_append_path_segment_data(str, NULL, "abcdefghijklmnopqrstuvwxyz");
	test_assert(strcmp(str_c(str), "abcdefghijklmnopqrstuvwxyz") == 0);
	str_truncate(str, 0);
	uri_append_path_segment_data(str, NULL, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	test_assert(strcmp(str_c(str), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0);
	str_truncate(str, 0);
	uri_append_path_segment_data(str, NULL, "0123456789");
	test_assert(strcmp(str_c(str), "0123456789") == 0);
	str_truncate(str, 0);
	uri_append_path_segment_data(str, NULL, "-._~!$&'()*+,;=");
	test_assert(strcmp(str_c(str), "-._~!$&'()*+,;=") == 0);
	str_truncate(str, 0);
	uri_append_path_segment_data(str, NULL, "a@b/c/d:e");
	test_assert(strcmp(str_c(str), "a@b%2fc%2fd:e") == 0);
	str_truncate(str, 0);
	uri_append_path_segment_data(str, NULL, "[yes]what?oh#13");
	test_assert(strcmp(str_c(str), "%5byes%5dwhat%3foh%2313") == 0);
	str_truncate(str, 0);
	uri_append_path_segment_data(str, "@", "a@b/c/d:e");
	test_assert(strcmp(str_c(str), "a%40b%2fc%2fd:e") == 0);
	str_truncate(str, 0);
	test_end();

	test_begin("uri escape - path");
	uri_append_path_data(str, NULL, "abcdefghijklmnopqrstuvwxyz");
	test_assert(strcmp(str_c(str), "abcdefghijklmnopqrstuvwxyz") == 0);
	str_truncate(str, 0);
	uri_append_path_data(str, NULL, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	test_assert(strcmp(str_c(str), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0);
	str_truncate(str, 0);
	uri_append_path_data(str, NULL, "0123456789");
	test_assert(strcmp(str_c(str), "0123456789") == 0);
	str_truncate(str, 0);
	uri_append_path_data(str, NULL, "-._~!$&'()*+,;=");
	test_assert(strcmp(str_c(str), "-._~!$&'()*+,;=") == 0);
	str_truncate(str, 0);
	uri_append_path_data(str, NULL, "a@b/c/d:e");
	test_assert(strcmp(str_c(str), "a@b/c/d:e") == 0);
	str_truncate(str, 0);
	uri_append_path_data(str, NULL, "[yes]what?oh#13");
	test_assert(strcmp(str_c(str), "%5byes%5dwhat%3foh%2313") == 0);
	str_truncate(str, 0);
	uri_append_path_data(str, "@", "a@b/c/d:e");
	test_assert(strcmp(str_c(str), "a%40b/c/d:e") == 0);
	str_truncate(str, 0);
	test_end();

	test_begin("uri escape - query");
	uri_append_query_data(str, NULL, "abcdefghijklmnopqrstuvwxyz");
	test_assert(strcmp(str_c(str), "abcdefghijklmnopqrstuvwxyz") == 0);
	str_truncate(str, 0);
	uri_append_query_data(str, NULL, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	test_assert(strcmp(str_c(str), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0);
	str_truncate(str, 0);
	uri_append_query_data(str, NULL, "0123456789");
	test_assert(strcmp(str_c(str), "0123456789") == 0);
	str_truncate(str, 0);
	uri_append_query_data(str, NULL, "-._~!$&'()*+,;=");
	test_assert(strcmp(str_c(str), "-._~!$&'()*+,;=") == 0);
	str_truncate(str, 0);
	uri_append_query_data(str, NULL, "a@b/c/d:e");
	test_assert(strcmp(str_c(str), "a@b/c/d:e") == 0);
	str_truncate(str, 0);
	uri_append_query_data(str, NULL, "[yes]what?oh#13");
	test_assert(strcmp(str_c(str), "%5byes%5dwhat?oh%2313") == 0);
	str_truncate(str, 0);
	uri_append_query_data(str, "@", "a@b/c/d:e");
	test_assert(strcmp(str_c(str), "a%40b/c/d:e") == 0);
	str_truncate(str, 0);
	test_end();

	test_begin("uri escape - fragment");
	uri_append_fragment_data(str, NULL, "abcdefghijklmnopqrstuvwxyz");
	test_assert(strcmp(str_c(str), "abcdefghijklmnopqrstuvwxyz") == 0);
	str_truncate(str, 0);
	uri_append_fragment_data(str, NULL, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	test_assert(strcmp(str_c(str), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0);
	str_truncate(str, 0);
	uri_append_fragment_data(str, NULL, "0123456789");
	test_assert(strcmp(str_c(str), "0123456789") == 0);
	str_truncate(str, 0);
	uri_append_fragment_data(str, NULL, "-._~!$&'()*+,;=");
	test_assert(strcmp(str_c(str), "-._~!$&'()*+,;=") == 0);
	str_truncate(str, 0);
	uri_append_fragment_data(str, NULL, "a@b/c/d:e");
	test_assert(strcmp(str_c(str), "a@b/c/d:e") == 0);
	str_truncate(str, 0);
	uri_append_fragment_data(str, NULL, "[yes]what?oh#13");
	test_assert(strcmp(str_c(str), "%5byes%5dwhat?oh%2313") == 0);
	str_truncate(str, 0);
	uri_append_fragment_data(str, "@", "a@b/c/d:e");
	test_assert(strcmp(str_c(str), "a%40b/c/d:e") == 0);
	str_truncate(str, 0);
	test_end();

	test_begin("uri escape - unreserved");
	uri_append_unreserved(str, "abcdefghijklmnopqrstuvwxyz");
	test_assert(strcmp(str_c(str), "abcdefghijklmnopqrstuvwxyz") == 0);
	str_truncate(str, 0);
	uri_append_unreserved(str, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	test_assert(strcmp(str_c(str), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0);
	str_truncate(str, 0);
	uri_append_unreserved(str, "0123456789");
	test_assert(strcmp(str_c(str), "0123456789") == 0);
	str_truncate(str, 0);
	uri_append_unreserved(str, "-._~");
	test_assert(strcmp(str_c(str), "-._~") == 0);
	str_truncate(str, 0);
	uri_append_unreserved(str, "!$&'()*+,;=");
	test_assert(strcmp(str_c(str), "%21%24%26%27%28%29%2a%2b%2c%3b%3d") == 0);
	str_truncate(str, 0);
	uri_append_unreserved(str, "a@b/c/d:e");
	test_assert(strcmp(str_c(str), "a%40b%2fc%2fd%3ae") == 0);
	str_truncate(str, 0);
	uri_append_unreserved(str, "[yes]what?oh#13");
	test_assert(strcmp(str_c(str), "%5byes%5dwhat%3foh%2313") == 0);
	str_truncate(str, 0);
	test_end();

	test_begin("uri escape - unreserved");
	uri_append_unreserved_path(str, "abcdefghijklmnopqrstuvwxyz");
	test_assert(strcmp(str_c(str), "abcdefghijklmnopqrstuvwxyz") == 0);
	str_truncate(str, 0);
	uri_append_unreserved_path(str, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	test_assert(strcmp(str_c(str), "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0);
	str_truncate(str, 0);
	uri_append_unreserved_path(str, "0123456789");
	test_assert(strcmp(str_c(str), "0123456789") == 0);
	str_truncate(str, 0);
	uri_append_unreserved_path(str, "-._~");
	test_assert(strcmp(str_c(str), "-._~") == 0);
	str_truncate(str, 0);
	uri_append_unreserved_path(str, "!$&'()*+,;=");
	test_assert(strcmp(str_c(str), "%21%24%26%27%28%29%2a%2b%2c%3b%3d") == 0);
	str_truncate(str, 0);
	uri_append_unreserved_path(str, "a@b/c/d:e");
	test_assert(strcmp(str_c(str), "a%40b/c/d%3ae") == 0);
	str_truncate(str, 0);
	uri_append_unreserved_path(str, "[yes]what?oh#13");
	test_assert(strcmp(str_c(str), "%5byes%5dwhat%3foh%2313") == 0);
	str_truncate(str, 0);
	test_end();
}

void test_uri(void)
{
	test_uri_valid();
	test_uri_invalid();
	test_uri_rfc();
	test_uri_escape();
}
