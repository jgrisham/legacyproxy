#!/usr/bin/env ruby

# To do - jhg
# - Fix "Error: undefined method `request_uri' for #<URI::Generic www.apple.com:443>"
# - Parse command-line arguments
# - Catch CTRL-C and other signals (e.g. 'status' signal)
# - Add optional counters (runtime, number of requests, number of bytes, etc...)
#
#  A proxy MUST NOT transform the payload (Section 3.3 of [RFC7231]) of
#   a message that contains a no-transform cache-control directive
#   (Section 5.2 of [RFC7234]).
	
require 'rubygems'
require 'socket'
require 'uri'
require 'net/http'
require 'net/https'
require 'openssl'
require 'nokogiri'
require 'htmlentities'
require 'rmagick'

$port = 8080
$bufferLength = 4096
# $verbose = false
$verbose = true
$userAgent = 'LegacyProxy/1.0'
$version = 'v1.0.1a1' # For debug / change management purposes only ... not normally seen by user

$entityCoder = HTMLEntities.new

# HTTP status code categories:
#  1xx (Informational): The request was received, continuing process
#  2xx (Successful):    The request was successfully received, understood, and accepted
#  3xx (Redirection):   Further action needs to be taken in order to complete the request
#  4xx (Client Error):  The request contains bad syntax or cannot be fulfilled
#  5xx (Server Error):  The server failed to fulfill an apparently valid request
# status codes that are defined as cacheable by default
#  (e.g., 200, 203, 204, 206, 300, 301, 404, 405, 410, 414, and 501 in RFC7231)

$statusCodes = {				# https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
	100 => "Continue",
	101 => "Switching Protocols",		# [RFC7231], removed in HTTP/2
	102 => "Processing",			# [RFC2518]
	103 => "Early Hints",			# [RFC8297]
	200 => "OK",
	201 => "Created",
	202 => "Accepted",
	203 => "Non-Authoritative Information",	# e.g. changed by proxy (Section 6.3.4 of [RFC7231]), HTTP/1.1 warn-code of 214 ("Transformation Applied") if one is not already in the message (see Section 5.5 of [RFC7234])
	204 => "No Content",
	205 => "Reset Content",
	206 => "Partial Content",
	207 => "Multi-Status",			# [RFC4918]
	208 => "Already Reported",		# [RFC5842]
	226 => "IM Used",			# [RFC3229] instance-manipulations applied to the current instance
	300 => "Multiple Choices",
	301 => "Moved Permanently",
	302 => "Found",
	303 => "See Other",
	304 => "Not Modified",
	305 => "Use Proxy",
	306 => "Switch Proxy",			# (reserved)
	307 => "Temporary Redirect",
	308 => "Permanent Redirect",
	400 => "Bad Request",
	401 => "Unauthorized",
	402 => "Payment Required",
	403 => "Forbidden",
	404 => "Not Found",
	405 => "Method Not Allowed",
	406 => "Not Acceptable",
	407 => "Proxy Authentication Required",
	408 => "Request Timeout",
	409 => "Conflict",
	410 => "Gone",
	411 => "Length Required",
	412 => "Precondition Failed",
	413 => "Payload Too Large",
	414 => "URI Too Long",
	415 => "Unsupported Media Type",
	416 => "Range Not Satisfiable",
	417 => "Expectation Failed",
	418 => "I'm a Teapot",
	421 => "Misdirected Request",
	422 => "Unprocessable Content",		# [RFC-ietf-httpbis-semantics, Section 15.5.21]
	423 => "Locked",			# [RFC4918]
	424 => "Failed Dependency",		# [RFC4918]
	425 => "Too Early",			# [RFC8470]
	426 => "Upgrade Required",
	428 => "Precondition Required",		# [RFC6585]
	429 => "Too Many Requests",		# [RFC6585]
	431 => "Request Header Fields Too Large",	# [RFC6585]
	451 => "Unavailable For Legal Reasons",
	500 => "Internal Server Error",
	501 => "Not Implemented",
	502 => "Bad Gateway",
	503 => "Service Unavailable",
	504 => "Gateway Timeout",
	505 => "HTTP Version Not Supported",
	506 => "Variant Also Negotiate",	# [RFC2295]
	507 => "Insufficient Storage",		# [RFC4918]
	508 => "Loop Detected",			# [RFC5842]
	510 => "Not Extended (OBSOLETED)",	# [RFC2774][status-change-http-experiments-to-historic]
	511 => "Network Authentication Required"	# [RFC6585]
}

# Parse command-line arguments - jhg
# References:	https://code-maven.com/argv-the-command-line-arguments-in-ruby
#		https://www.codecademy.com/article/ruby-command-line-argv
#		https://ruby-doc.org/core-1.9.3/ARGF.html#method-i-argv
#		https://ruby-doc.com/docs/ProgrammingRuby/html/rubyworld.html
#		https://www.thoughtco.com/command-line-arguments-2908191
# Alternative options
#	OptionParser class	https://ruby-doc.org/stdlib-2.4.2/libdoc/optparse/rdoc/OptionParser.html
#1						https://ruby-doc.org/stdlib-2.5.5/libdoc/optparse/rdoc/OptionParser.html
#	GetoptLong

# Also taken from:
# https://gist.github.com/Neurogami/c27443536227bdef8f84c923bdc24820
# https://bugs.ruby-lang.org/issues/12323
# This is based on code copied from https://bugs.ruby-lang.org/issues/12323
# to replace non-working example given in the rdocs for the OptionParser class

$programName = $0

puts "	Starting #{$version} of #{$programName} as User-Agent #{$userAgent}." if $verbose
puts "	Will attempt to listen on port #{$port}; buffer length set to: #{$bufferLength}." if $verbose
puts "	Running in verbose / debug mode." if $verbose

begin
	# Load OptionParser module
	require 'optparse'
	class ProcessScriptArguments
		ClassVersion = '1.0.0'

		class ScriptOptions

			# Not sure what this does - jhg
			# https://www.rubyguides.com/2018/11/attr_accessor/
			# Instance variables - start with '@'
			# Automatically creates 'getter' and 'setter' methods to read instance variables from instances of this object
			attr_accessor :port, :bufferLength, :verbose, :userAgent

			def initialize
				# Set initial variable values
				self.port = 8080
				self.verbose = true
				self.bufferLength = 4096
				self.userAgent = 'LegacyProxy/1.0'
			end # method def initialize
		end # class ScriptOptions

		def self.define_options(parser)
			@parser ||= OptionParser.new do |parser|
			parser.banner = "Usage: #{$programName} [options]"
			parser.seperator ""
			parser.seperator "Specific options:"

			# add additional options
			specify_listening_port(parser)
			boolean_verbose_option(parser)

			parser.separator ""
			parser.separator "Common options:"

			# No argument, shows at tail. This will print an options summary.
			parser.on_tail("-h", "--help", "Show this message") do
				puts parser
				exit
			end
			# Print current script version
			parser.on_tail("-V", "--version", "Show version") do
				puts Version
				exit
			end
		end # do
		end # method def define_options(parser)

		# parser.on("--type [TYPE]", [:text, :binary, :auto],
		def boolean_verbose_option(parser)
			# Boolean switch.
			parser.on("-v", "--[no-]verbose", "Run verbosely") do |v|
			  self.verbose = v
			end
		end # method def boolean_verbose_option(parser)

		def specify_listening_port(parser)
			# puts ARGV[x].to_i + ARGV[1].to_i
			parser.on("-p PORT", "--port=PORT", Integer, "Incoming TCP port") do |p|
				# self.port = p.to_i
				self.port = p
			end
		end # method def specify_listening_port(parser)

		#
		# Return a structure describing the options.
		#
		def parse(args)
			# The options specified on the command line will be collected in
			# *options*.
		
			@options = ScriptOptions.new
			# @args = OptionParser.new do |parser|
			# 	@options.define_options(parser)
			# 	parser.parse!(args) # self-modifying 'dangerous' method?
			#   end
			define_options.parse! args
			@options
		end

		attr_reader :parser, :options

	
	end # class ProcessScriptArguments

	# get list of instance variables
	# machine.instance_variables

	# Options = Struct.new(:name)
	class Parser
		# Defines 'parse' method of class 'Parser'?
	  def self.parse(options)
		# args = Options.new("world")

		  # new copy of 'OptionParser' for each ??
		opt_parser = OptionParser.new do |opts|
		  opts.banner = "Usage: #{$programName} [options]"

		  opts.on("-pPORT", "--port=PORT", Integer, "TCP port to monitor for incoming requests") do |n|
			args.name = n
		  end

		  opts.on("-h", "--help", "Prints this help") do
			puts opts
			exit
		  end
			
		  opts.on("-v", "--[no-]verbose", "Run verbosely") do |v|
	 	   options[:verbose] = v
		  end
			
		end #opt_parser

		opt_parser.parse!(ARGV)
		return args
	  end # def self.parse
	end # class Parser
	# options1 = Parser.parse %w[--help]
	# options1 = Parser.parse ARGV
	options2 = ProcessScriptArguments.parse ARGV
rescue LoadError
	# The 'optparse' gem is not installed
	puts "	OptionParser gem is not available - ignoring command-line arguments." if $verbose
end

if ARGV.length > 0
	input_array = ARGV
	first_arg, *the_rest = ARGV
	puts input_array.length if $verbose
	puts input_array.to_s if $verbose
	puts first_arg if $verbose
	puts the_rest if $verbose
	# puts "--> Response code: #{response.code}" if $verbose
	if $verbose
		for i in 0 ... ARGV.length
   			puts "#{i} #{ARGV[i]}"
		end
		ARGV.each do|a|
		  puts "Argument: #{a}"
		end
	end
	
	# If a number, convert to a number
	# puts ARGV[x].to_i + ARGV[1].to_i
end

server = TCPServer.open($port)
puts "Listening on #{$port}, press ^C to exit..."

def sanitizeHtml(doc, requestHeaders)
	parsedDoc = Nokogiri::HTML(doc)

	# rewrite https urls to http
	parsedDoc.css("img").each do |image|
		image['src'] = image['src'].sub(/^https:/, 'http:') if image['src'].nil? == false
	end
	parsedDoc.css("a").each do |link|
		link['href'] = link['href'].sub(/^https:/, 'http:') if link['href'].nil? == false
	end

	if requestHeaders.nil? == false && requestHeaders['user-agent'] == 'Mozilla/1.0N (Macintosh)' then
		parsedDoc.css("tr").each do |tr|
			br = Nokogiri::XML::Node.new("br", parsedDoc)
			tr.add_next_sibling(br)
		end
	end
	parsedDoc.css("script").each { |s| s.remove }
	parsedDoc.css("noscript").each { |s| s.remove }
	parsedDoc.css("style").each { |s| s.remove }

	html = parsedDoc.to_html(encoding: 'US-ASCII') # force entity encoding so they survive transit, otherwise nokogiri will output the real characters which get lost
	html = html.gsub(/&#\d+;/) { |s| $entityCoder.encode($entityCoder.decode(s), :decimal) } # repair entities

	if requestHeaders.nil? == false && requestHeaders['user-agent'] == 'Mozilla/1.0N (Macintosh)' then
		# replace some fancy characters with simple versions
		html = html.gsub('&#160;', " ")
		html = html.gsub('&#8211;', "-")
		html = html.gsub('&#8212;', "-")
		html = html.gsub('&#8216;', "'")
		html = html.gsub('&#8217;', "'")
		html = html.gsub('&#8220;', "\"")
		html = html.gsub('&#8221;', "\"")
		html = html.gsub('&#8230;', "...")
		html = html.gsub('&#188;', "1/4")
		html = html.gsub('&#189;', "1/2")
		html = html.gsub('&#190;', "3/4")
	end

	html
end

def sendResponse(client, code, headers = {}, body = nil, requestHeaders = nil)
	message = '-'
	message = $statusCodes[code.to_i] if $statusCodes.has_key?(code.to_i)

	headers['cache-control'] = 'no-cache'
	headers['connection'] = 'close'
	headers['date'] = Time.now.utc.strftime '%a, %d %b %Y %H:%M:%S GMT'
	headers['server'] = $userAgent

	headers['content-type'] = 'text/plain' if headers.has_key?('content-type') == false # ensure content type

	# tweak html content type
	if headers['content-type'] =~ /^text\/html/ then
 		body.force_encoding($1) if body.nil? == false && headers['content-type'] =~ /; charset=(.*)$/
		headers['content-type'] = 'text/html'
 	end

	if headers['content-type'] =~ /^image\/svg/ || headers['content-type'] =~ /^image\/png/ then
		# pre-render unsupported images, rewrite to gif (it's small and preserves transparency)
		headers['content-type'] = 'image/gif'
		img = Magick::Image.from_blob(body).first
		img.format = 'gif'
		body = img.to_blob
	else
		body = sanitizeHtml(body, requestHeaders) if headers['content-type'] == 'text/html' && body.nil? == false
	end

	headers['content-length'] = body.bytesize.to_s if body.nil? == false # update content length

	client.print "HTTP/1.0 #{code} #{message}\r\n"
	headers.each do |k, v|
		key = k.to_s.split(/-/).map { |s| s.capitalize }.join('-')
		client.print "#{key}: #{v}\r\n"
	end
	client.print "\r\n"
	client.write body if body.nil? == false
	client.close
end

def sendError(client, message)
	response = "<html>\n<head>\n<title>Proxy Error</title>\n</head>\n\n<body>\n#{message}\n</body>"
	sendResponse(client, 503, { "Content-Type" => "text/html" }, response)
end

def sendProxyContent(client, url, verb, headers, body)
	begin
		# TODO: try https first, fall back to http?
		uri = URI.parse(url.strip)
		puts "<-- #{uri.to_s}" if $verbose
		http = Net::HTTP.new(uri.host, uri.port)
		if uri.scheme == 'https' then
			http.use_ssl = true
			http.verify_mode = OpenSSL::SSL::VERIFY_NONE
		end
		http.open_timeout = 30
		http.read_timeout = 45

		response = http.send_request(verb, uri.request_uri, body, headers)

		puts "--> Response code: #{response.code}" if $verbose

		responseHeaders = {}
		response.header.each do |key, value|
			next if value.nil?
			key = key.downcase
			if responseHeaders.has_key?(key) then
				responseHeaders[key] += ", #{value}"
			else
				responseHeaders[key] = value
			end
		end
		puts "--> Response Headers: #{responseHeaders}" if $verbose

		case response
		when Net::HTTPRedirection then
			sendProxyContent(client, response.header['location'], verb, headers, body)
		else
			sendResponse(client, response.code, responseHeaders, response.body, headers)
		end
	rescue Interrupt
		sendError(client, "Interrupt")
	rescue => e
		sendError(client, "#{e}")
		$stderr.puts "Error: #{e}"
	end
end

loop {
	Thread.start(server.accept) do |client|
		clientAddress = client.peeraddr
		request = ""

		while client.closed? == false do
			read_ready = IO.select([client])[0]
			if read_ready.include?(client)
				data = client.recv_nonblock($bufferLength)
				request += data
				break if data.bytesize < $bufferLength
			end
		end

		requestHeaders, body = request.split("\r\n\r\n", 2)
		body = nil if body.length == 0
		headers = {}
		urlRequest = nil
		requestHeaders.split("\r\n").each do |h|
			# first line is the GET <url> HTTP/<version> request:
			if urlRequest.nil? then
				urlRequest = h.split(/\s+/)
				next
			end
			key, value = h.split(/:\s*/)
			next if value.nil?
			key = key.downcase
			if headers.has_key?(key) then
				headers[key] += ", #{value}"
			else
				headers[key] = value
			end
		end

		headers['x-forwarded-for'] = clientAddress[3]
		headers['via'] = "HTTP/1.1 #{$userAgent}"

		if urlRequest.length != 3 then
			sendError(client, "Invalid request")
			return
		end
		verb = urlRequest[0]
		url = urlRequest[1]

		puts "--> #{clientAddress[2]}:#{clientAddress[1]} #{verb} #{url}"

 		puts "Request Headers: '#{headers}'" if $verbose
 		puts "Request Body: '#{body}'" if $verbose && body.nil? == false
		sendProxyContent(client, url, verb, headers, body)
	end
}
