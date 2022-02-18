#!/usr/bin/env ruby

{ # To do - jhg
	# - Fix "Error: undefined method `request_uri' for #<URI::Generic www.apple.com:443>"
	# - Parse command-line arguments
	# - Catch CTRL-C and other signals (e.g. 'status' signal)
	# - Add optional counters (runtime, number of requests, number of bytes, etc...)
	#
	#  A proxy MUST NOT transform the payload (Section 3.3 of [RFC7231]) of
	#   a message that contains a no-transform cache-control directive
	#   (Section 5.2 of [RFC7234]).
}
	
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
$version = 'v1.0.1a19'	# For debug / change management purposes only ... not normally seen by user
$programName = $0		# Mostly to help me remember the syntax - jhg

$entityCoder = HTMLEntities.new

{ # HTTP status code categories:
	#  1xx (Informational): The request was received, continuing process
	#  2xx (Successful):    The request was successfully received, understood, and accepted
	#  3xx (Redirection):   Further action needs to be taken in order to complete the request
	#  4xx (Client Error):  The request contains bad syntax or cannot be fulfilled
	#  5xx (Server Error):  The server failed to fulfill an apparently valid request
	# status codes that are defined as cacheable by default
	#  (e.g., 200, 203, 204, 206, 300, 301, 404, 405, 410, 414, and 501 in RFC7231)
}

$statusCodes = {				# https://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
	100 => "Continue",
	101 => "Switching Protocols",		# [RFC7231], removed in HTTP/2
	102 => "Processing",				# [RFC2518]
	103 => "Early Hints",				# [RFC8297]
	200 => "OK",
	201 => "Created",
	202 => "Accepted",
	203 => "Non-Authoritative Information",	# e.g. changed by proxy (Section 6.3.4 of [RFC7231]), HTTP/1.1 warn-code of 214 ("Transformation Applied") if one is not already in the message (see Section 5.5 of [RFC7234])
	204 => "No Content",
	205 => "Reset Content",
	206 => "Partial Content",
	207 => "Multi-Status",				# [RFC4918]
	208 => "Already Reported",			# [RFC5842]
	226 => "IM Used",			# [RFC3229] instance-manipulations applied to the current instance
	300 => "Multiple Choices",
	301 => "Moved Permanently",
	302 => "Found",
	303 => "See Other",
	304 => "Not Modified",
	305 => "Use Proxy",
	306 => "Switch Proxy",				# (reserved)
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
	423 => "Locked",					# [RFC4918]
	424 => "Failed Dependency",			# [RFC4918]
	425 => "Too Early",					# [RFC8470]
	426 => "Upgrade Required",
	428 => "Precondition Required",		# [RFC6585]
	429 => "Too Many Requests",			# [RFC6585]
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
	508 => "Loop Detected",				# [RFC5842]
	510 => "Not Extended (OBSOLETED)",	# [RFC2774][status-change-http-experiments-to-historic]
	511 => "Network Authentication Required"	# [RFC6585]
}

{ # Parse command-line arguments - jhg
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
}

$programName = $0


if ARGV.length > 0 # Don't bother with any of this if there are no command-line arguments!

	begin # Parse command-line options using 'OptionParser' module
		# Load OptionParser module
		require 'optparse'				
		class ProcessScriptArguments	# Wrap ScriptOptions class with methods
			ClassVersion = '1.0.0'

			class ScriptOptions			# Data object
				# Instance variables - start with '@'
				# Automatically creates 'getter' and 'setter' methods to read instance variables from instances of this object
				attr_accessor :port, :bufferLength, :verbose, :userAgent

				def initialize
					# Set initial variable values
					self.port = $port
					self.verbose = $verbose
					self.bufferLength = $bufferLength
					self.userAgent = $userAgent
				end # method def initialize
			end # class ScriptOptions

			def self.define_options #(parser)	# main class method
				@parser ||= OptionParser.new do |parser|
					parser.banner = "Usage: #{$programName} [options]"
					parser.separator ""
					parser.separator "Specific options:"

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
						puts $version
						exit
					end
				end # do
			end # method def define_options(parser)

			# parser.on("--type [TYPE]", [:text, :binary, :auto],
			def self.boolean_verbose_option(parser)					# option: --verbose
				# Boolean switch.
				parser.on("-v", "--[no-]verbose", "Run verbosely") do |v|
					@options.verbose = v
				end
			end # method def boolean_verbose_option(parser)

			def self.specify_listening_port(parser)					# option: --port PORTNUM
				# puts ARGV[x].to_i + ARGV[1].to_i
				# # TODO: Need beter error catching in case this is not providded as a number
				# (just ignore if not a number??)
				parser.on("-p PORTNUM", "--port=PORTNUM", Integer, "Incoming TCP port") do |p|
					# self.port = p.to_i
					@options.port = p
				rescue
				end
			end # method def specify_listening_port(parser)

			def self.parse(args)					# Return a structure describing the options.
				# The options specified on the command line will be collected in
				# *options*.
			
				@options = ScriptOptions.new
				#@args = OptionParser.new do |parser|
				# 	@options.define_options(parser)
				# 	parser.parse!(args) # self-modifying 'dangerous' method?
				#end
				define_options.parse! args
				@options
			end

			attr_reader :parser, :options			# Allow external access to properties
		
		end # class ProcessScriptArguments

		# Options = Struct.new(:name)
		class Parser					# Alternative implemention - not in use 2022-02-17
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

		# options1 = Parser.parse %w[--help]			# Test with dummy data
		# options1 = Parser.parse ARGV
		$options2 = ProcessScriptArguments.parse ARGV	# Actually parse command-line options

		# Need to actually set global variables based on options now
		$port = $options2.port
		$verbose = $options2.verbose
		$bufferLength = $options2.bufferLength
		$userAgent = $options2.userAgent
		# Because I did that, does 'options2' actually need to be global? (i.e. '$options2')
	#rescue LoadError
	rescue # let's just ignore _all_ errors from the above 'begin' block
		# The 'optparse' gem is not installed
		puts "	OptionParser gem is not available - ignoring command-line arguments." if $verbose
	end

	#{ # show verbose debugging info
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
	#}	
	# If a number, convert to a number
	# puts ARGV[x].to_i + ARGV[1].to_i

end	# end if ARGV.length > 0



puts "	Starting #{$version} of #{$programName} as User-Agent #{$userAgent}." if $verbose
puts "	Will attempt to listen on port #{$port}; buffer length set to: #{$bufferLength}." if $verbose
puts "	Running in verbose / debug mode." if $verbose
begin
	puts "   Options2 verbose status: #{$options2.verbose}"
	puts "   Options2 port: #{$options2.port}"
rescue
end
puts "   Global port:   #{$port}"


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

def sendError(client, message, statusCode=503)
	response = "<html>\n<head>\n<title>Proxy Error</title>\n</head>\n\n<body>\n#{message}\n</body>"
	sendResponse(client, statusCode, { "Content-Type" => "text/html" }, response)
end

def sendProxyContent(client, url, verb, headers, body)
	begin
		# TODO: try https first, fall back to http?
		uri = URI.parse(url.strip)
		#if object.is_a?(ClassName)
		# URI::HTTPS.build(host: 'www.example.com', port: 80, path: '/foo/bar')
		if uri.respond_to?(:request_uri) == false	# if resolved to URI::Generic, force https
			uri = URI.parse("https://#{url.strip}")
		end
		puts "<-- #{uri.to_s}" if $verbose
		http = Net::HTTP.new(uri.host, uri.port)
		if uri.scheme == 'https' then
			http.use_ssl = true
			http.verify_mode = OpenSSL::SSL::VERIFY_NONE
		end
		http.open_timeout = 30
		http.read_timeout = 45

		if $verbose
			puts ""
			puts "    --> URL: #{url}"
			puts "    --> URI: #{uri}"
			puts "    -->            client: #{client}"
			puts "    --> HTTP    send verb: #{verb}"
			# puts "    --> URI instance   methods: #{uri.instance_methods}"
			puts "    --> URI instance variables: #{uri.instance_variables}"
			puts "    --> URI        scheme: #{uri.scheme}"
			puts "    --> URI     relative?: #{uri.relative?()}"
			puts "    --> URI hierarchical?: #{uri.hierarchical?()}"
			puts "    --> URI      userinfo: #{uri.userinfo}"
			puts "    --> URI          user: #{uri.user}"
			puts "    --> URI      password: #{uri.password}"
			puts "    --> URI          host: #{uri.host}"
			puts "    --> URI          port: #{uri.port}"
			puts "    --> URI      registry: #{uri.registry}"
			puts "    --> URI          path: #{uri.path}"
			puts "    --> URI         query: #{uri.query}"
			puts "    --> URI        opaque: #{uri.opaque}"
			puts "    --> URI      fragment: #{uri.fragment}"	# e.g. page anchor
			# puts "    --> URI        parser: #{uri.parser}"		# internal use
			# puts "    --> URI     arg_check: #{uri.arg_check}"
			puts "    --> URI   request_uri: #{uri.request_uri}"
			puts "    --> HTTP send headers: #{headers}"
			puts "    --> HTTP    send body: #{body}"
			puts ""
		end
		response = http.send_request(verb, uri.request_uri, body, headers) # removed .request_uri

		puts "--> Response code: #{response.code}" if $verbose

		responseHeaders = {}
		response.to_s if $verbose # Full text of response to HTTP request
		response.header.each do |key, value|
			next if value.nil?
			puts " |__ resp key: #{key}; value: #{value}" if $verbose
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
		puts "Request: #{request.to_s}" if $verbose

		requestHeaders, body = request.split("\r\n\r\n", 2)
		body = nil if body.length == 0
		headers = {}
		urlRequest = nil
		# puts " ---> requestHeaders: #{requestHeaders.to_s}" if $verbose
		requestHeaders.split("\r\n").each do |h|
			# first line is the GET <url> HTTP/<version> request:
			if urlRequest.nil? then
				urlRequest = h.split(/\s+/)
				next
			end
			key, value = h.split(/:\s*/)
			next if value.nil?
			next if key == "Upgrade-Insecure-Requests"
			puts " |__ req key: #{key}; value: #{value}" if $verbose
			key = key.downcase
			if headers.has_key?(key) then
				headers[key] += ", #{value}"
			else
				headers[key] = value
			end
		end

		# puts " ---> urlRequest: #{urlRequest.to_s}"

		# headers['x-forwarded-for'] = clientAddress[3]
		# headers['via'] = "HTTP/1.1 #{$userAgent}"

		if urlRequest.length != 3 then
			sendError(client, "Invalid request")
			puts "--> Invalid request (client)"
			return
		end
		verb = urlRequest[0]
		url = urlRequest[1]

		if verb == "CONNECT" then
			#sendError(client, "Invalid request")
			sendError(client, "HTTP Version Not Supported", 505)
			# puts "--> Invalid verb (client / CONNECT)" if $verbose
			# return
		else
			
			puts " ---> requestHeaders: #{requestHeaders.to_s}" if $verbose

			puts " ---> urlRequest: #{urlRequest.to_s}"


			puts "--> #{clientAddress[2]}:#{clientAddress[1]} #{verb} #{url}"

			puts "Request Headers: '#{headers}'" if $verbose
			puts "Request Body: '#{body}'" if $verbose && body.nil? == false
			sendProxyContent(client, url, verb, headers, body)
		end


	end
}
