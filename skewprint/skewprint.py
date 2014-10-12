#!/usr/bin/env python

import datetime, threading, socket, sys, select, ssl, random, urlparse, argparse

# try to remove scapy because installing it on windows sucks and it's not python 3 compat.
import scapy.layers.inet
import scapy_http.http # https://github.com/invernizzi/scapy-http

''' 
	Feature Brainstorm:
	IP timestamps
	Collect TCP timestamps
	IPv6
	.csv logging
	Clock skew analysis
	Improved method by requesting timestamps on the clock edge
	Induce server load to raise temp to change clock skew
	TLS handshake timestamp
	Ricochet?
	More ways to log data (match masscan)
	Fancy real time data visualization stuff (for demonstrations)
	Code readability/make it easy to extend
	Release first stable version
	Possibly experiment with other methods of analyzing the clock skew,
		such as packets sent in regular intervals without timestamps
	Sequence numbers as timestamps
	Merge with some other tool (hping already has a clock skew estimator)
	Better cross platform support
	Rewrite in compiled language
'''

def send_loop(counter):
	global basetime, sock, running, wait, verbose, payload, max_count

	# Request timestamps every wait seconds. The extra random delay is to prevent sampling bias.
	tick_offset = counter*wait + random.uniform(0,1)*wait
	next_tick = basetime + datetime.timedelta(0, tick_offset)
	t = threading.Timer((next_tick - datetime.datetime.utcnow()).total_seconds(),
	                    lambda:send_loop(counter))
	if running:
		t.start()
		counter+=1
		if counter > max_count and max_count != 0:
			running = False
		try:
			sock.send(payload)
		except:
			#TODO: Handle writes to closed sockets
			if not running:
				return
			else:
				raise
		if verbose:
			print "%d\t%.6f\t%s" % (counter, tick_offset, datetime.datetime.utcnow())

# TODO: descend from urlparse?
class url():
	default_scheme = "http://"
	default_path = "/"
	# TODO: Make a scheme class instead of using a dict
	supported_schemes = dict(default={'port':80, 'tls':False,
	                                  'socktype':socket.SOCK_STREAM,
												 'proto':socket.IPPROTO_TCP},
	                         icmp={'port':0,'tls':False,
									       'socktype':socket.SOCK_RAW,
											 'proto':socket.IPPROTO_ICMP},
									 http={'port':80, 'tls':False,
									       'socktype':socket.SOCK_STREAM,
											 'proto':socket.IPPROTO_TCP},
									 https={'port':443, 'tls':True,
									        'socktype':socket.SOCK_STREAM,
											  'proto':socket.IPPROTO_TCP})
	bad_addresses = ("127.0.53.53", "0.0.0.0")

	def __init__(self, scheme, netloc, username, password, hostname, port,
	             path, query, fragment, address, tls, socktype, proto):
		# TODO: combine tls and scheme into a scheme class
		self.scheme=scheme
		self.netloc=netloc
		self.username=username
		self.password=password
		self.hostname=hostname
		self.port=port
		self.path=path
		self.query=query
		self.fragment=fragment
		self.address=address
		self.tls=tls
		self.socktype=socktype
		self.proto=proto

	def __str__(self):
		return ("scheme: " + str(self.scheme) + "\n"
		       "username: " + str(self.username) + "\n"
		       "password: " + str(self.password) + "\n"
		       "hostname: " + str(self.hostname) + "\n"
		       "address: " + str(self.address) + "\n"
		       "port: " + str(self.port) + "\n"
		       "tls: " + str(self.tls) + "\n"
		       "path: " + str(self.path) + "\n"
		       "query: " + str(self.query) + "\n"
		       "fragment: " + str(self.fragment) + "\n"
				 "socktype: " + str(self.socktype) + "\n"
				 "proto: " + str(self.proto))

	def resolve_host(self):
		#TODO: Hostname if given IP address: gethostbyaddr? (for HTTP Host: header)
		#TODO: IPv6 support: socket.getaddrinfo
		#TODO: Merge with socket connection
		self.address = socket.gethostbyname(self.hostname)
		if self.address in self.bad_addresses:
			msg = "Cannot resolve host: %s" % self.hostname
			raise argparse.ArgumentTypeError(msg)

	@classmethod
	def resolve(cls, url):
		'''
		Parses, validates, and resolves a url string.
		'''
		url_obj = cls.parse(url)
		url_obj.resolve_host()
		return url_obj

	@classmethod
	def parse(cls, url):
		'''
		 Splits url string into its components and validates results.
	    Does not validate or resolve hostname.

		 url should be of the form:
			[scheme://user:pass@]hostname[:port/path?query#fragment]
			Ex:  https://www.example.com/flavors.html#chocolate
			     example.co.uk
				  icmp://HOSTNAME
		 Where scheme is in supported_schemes, and all fields are
		 optional except for hostname.
		'''

		# Fill in missing scheme and reparse so netloc won't be confused with path
		splt = urlparse.urlsplit(url)
		if not splt.scheme:
			url = "%s%s" % (cls.default_scheme, url)
			splt = urlparse.urlsplit(url)

		scheme=splt.scheme
		netloc=splt.netloc
		username=splt.username
		password=splt.password
		hostname=splt.hostname
		port=splt.port
		path=splt.path
		query=splt.query
		fragment=splt.fragment
		address=""
		tls=False
		socktype=False
		proto=False

		if not path:
			path = cls.default_path
		if not port:
			port = cls.supported_schemes['default']['port']
			if cls.supported_schemes.has_key(scheme):
				port = cls.supported_schemes[scheme]['port']

		# Validate results
		if not cls.supported_schemes.has_key(scheme):
			msg = "%s is not a supported protocol." % scheme
			raise argparse.ArgumentTypeError(msg)
		if not hostname:
			msg = "No target host specified"
			raise argparse.ArgumentTypeError(msg)

		s = cls.supported_schemes[scheme]
		tls = s['tls']
		socktype = s['socktype']
		proto = s['proto']

		return cls(scheme, netloc, username, password, hostname,
		           port, path, query, fragment, address, tls, socktype, proto)

def parse_args(argv):
	parser = argparse.ArgumentParser(description="Gathers timestamps in order to perform clock skew-"
		                                          "based remote physical device fingerprinting.")
	parser.add_argument("url", type=url.resolve)
	parser.add_argument("-c", "--count", type=int, nargs="?", default=10)
	parser.add_argument("-w", "--wait", type=int, nargs="?", default=1)
	parser.add_argument("-i", "--iptimestamp", action="store_true")
#  parser.add_argument("-f", "--logfile", type=argparse.FileType("ab"), default=False)
	parser.add_argument("-q", "--quiet", action="store_true")
	return parser.parse_args()

def get_payload(url_obj):
	scheme = url_obj.scheme
	if scheme in ("http", "https"):
		payload = ("HEAD " + url_obj.path + " HTTP/1.1\r\nHost: " +
		           url_obj.hostname + "\r\nConnection: Keep-Alive\r\n\r\n")
	elif scheme in ("icmp"):
		# ICMP Timestamp Request
		# from str(scapy.layers.inet.ICMP(type=13, code=0, ts_ori=0, ts_rx=0, ts_tx=0))
		payload = '\r\x00\xf2\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	else:
		payload = ""
	return payload

def connect_sock(url_obj):
	global sock
	sock = socket.socket(socket.AF_INET, url_obj.socktype, url_obj.proto)
	if url_obj.tls:
		sock = ssl.wrap_socket(sock)
	sock.connect((url_obj.address, url_obj.port))

def main(argv):
	global basetime, sock, running, wait, verbose, payload, max_count

	args = parse_args(argv)
	counter = 1
	max_count = args.count
	running = True
	wait = args.wait
	verbose = not args.quiet
	payload = get_payload(args.url)

	connect_sock(args.url)

	print args.url

	basetime = datetime.datetime.utcnow()
	send_loop(counter)
	min_time = datetime.timedelta(0,20)

	while running:
		time_started = datetime.datetime.utcnow()
		recv_loop(args.url.scheme)
		sock.close()
		time_finished = datetime.datetime.utcnow()
		duration = time_finished - time_started
		if duration < min_time:
			running = False
		else:
			connect_sock(args.url)

	sock.close()

def extract_timestamp(response, scheme):
	timestamp = False
	if scheme in ("http", "https"):
		response = scapy_http.http.HTTPResponse(response)
		timestamp = response.Date
	elif scheme in ("icmp"):
		icmp_timestamp_reply = 14
		response = scapy.layers.inet.IP(response)
		if response.haslayer(scapy.layers.inet.ICMP):
			if response['ICMP'].type == icmp_timestamp_reply:
				timestamp = max(response.ts_tx, response.ts_rx)
	return timestamp

def recv_loop(scheme):
	global sock, verbose, running
	to_read = [sock, sys.stdin]
	while running:
		iread, iwrite, iexcept = select.select(to_read,[],[])
		for i in iread:
			if i == sys.stdin:
				sys.stdin.readline()
				running = 0
			elif i == sock:
				# Connection header:
				# Keep-Alive vs Close
				# max
				# timeout
				# connected -> half-open -> closed

				# Avoid getting problems with recv if prog just closed by keyboard
				if not running:
					return

				data = sock.recv(1024)
				if data:
					print extract_timestamp(data, scheme)
				else:
					if verbose:
						print "%s\tNo Response" % datetime.datetime.utcnow()
					return

if __name__ == "__main__":
	main(sys.argv)
