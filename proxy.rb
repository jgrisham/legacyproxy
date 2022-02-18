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

	# 2022-02-18 Stopping work on this for now.
	#	- does not work with Edge on Windows due to 'proxy' mode
	#		invoking the HTTP/1.1 'CONNECT' verb to try to
	#		bypass/tunnel through the proxy for TLS connection
	#		Since this is fundamental to the TLS anti-MITM
	#		protections, this appears to require deviating
	#		from the standards, or using this in a transparent
	#		mode (e.g. redirection by a router so this looks like
	#		a normal web server and not a proxy)
	#	- in the code below, I temporarly disabled the 'upgrade-require'
	#		header from incoming requests, but not sure if that made a difference
	#	- I was able, with this exact version (v1.0.1a20) of `proxy.rb`
	#		to use Classilla 9.2.3 on the TAM to successfully download
	#		a `.sit` file from a HTTP site
	#	- Earlier browsers (especially HTTP/1.0 ones that don't know about
	#		the `CONNECT` verb) may work just fine with HTTPS connections?
	#		I should test that
	#		- Use `respond.to?` to test against Generic URI objects, so it least
	#			we don't flood the zone with error messages
	#		- Can we respond with a specific error page, something like
	#			"This browser is too new for the proxy you are trying to use
	#			to access this secure (HTTPS) website."
	#	- Some recent attempts at viewing HTTPS sites resulted in a loop of
	#		response code `302` requests)
	#	- To do
	#		- Figure out how to color debug console entries
	#			e.g. green for `200`, yellow for `3xx`, red for `4xx`/`5xx`
	#		- Can I have a custom method for those debug messages, that includes
	#			things like the `verbose` toggle, maybe a line number, etc.?
	#		- Can we store all headers in a database for future use?
	#			- e.g. (datetime) (uri) (verb) (content-type) (content-length) (last-modified) (client_ip) (server_ip) ...
	#	- Edited using VSCode & Github
	#	- Testing was done on RPi, using the following bash aliases
	#		- `alias run='./proxy.rb'`
	#		- `alias gfc='clear && date && echo && git stash && git pull && chmod a+x proxy.rb && echo && grep -e "For debug" proxy.rb'`
	#	- Tl;dr: there seems a purpose to this, but for more modern systems
	#		(i.e. those with proxy support but not current TLS / certs)
	#		other solutions may more sense.
	#	- References and further reading:
	#	- https://stackoverflow.com/questions/26381558/sending-http-requests-with-specific-http-version-protocol-in-ruby
	#	- HTTP `CONNECT` verb
	#		- https://www.rfc-editor.org/rfc/rfc2817#section-5.2
	#		- https://www.rfc-editor.org/rfc/rfc2616#page-57
	#		- https://stackoverflow.com/questions/6594604/connect-request-to-a-forward-http-proxy-over-an-ssl-connection
	#			- https://bz.apache.org/bugzilla/show_bug.cgi?id=29744
	#		- https://httpwg.org/specs/rfc7231.html#CONNECT
	#		- https://reqbin.com/Article/HttpConnect
	#		- https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/CONNECT
	#	- https://medium.com/rubycademy/the-return-keyword-in-ruby-df0a7f578fcb
	#	- https://docs.ruby-lang.org/en/master/URI/RFC2396_Parser.html
	#	- Ruby general
	#		- http://rubykoans.com/ http://github.com/edgecase/ruby_koans
	#		- http://ruby-lang.org/
	#		- https://ruby.github.io/TryRuby/ https://try.ruby-lang.org/ https://try.ruby-lang.org/playground/
	#		- https://pragprog.com/book/ruby4/programming-ruby-1-9-2-0
	#		- http://pragmaticstudio.com/ruby
	#		- http://pragprog.com/titles/bmsft/everyday-scripting-with-ruby
	#		- https://poignant.guide/ Welcome to the pirate radio of technical manuals.
	#		- https://pine.fm/LearnToProgram/
	#		- https://ruby-doc.org/docs/ruby-doc-bundle/ProgrammingRuby/index.html
	#		- https://web.archive.org/web/20190714182258/http://www.rubyist.net:80/~slagell/ruby/
	#		- https://web.archive.org/web/20190601212008/http://www.rubyist.net/~slagell/
	#		- Blocks
	#			- https://medium.com/@noordean/understanding-ruby-blocks-3a45d16891f1
	#
	#	- Ruby `Object` https://ruby-doc.org/core/Object.html
	#		- "The Ruby Object Model"
	#		- https://stackoverflow.com/questions/15769739/determining-type-of-an-object-in-ruby
	#			`object.is_a?(ClassName)` or `object.class`, or 'duck typing', e.g. `object.respond_to?(:to_s)`
	#			`p object.instance_of? String`. See also `Object.ancestors`
	#		- https://www.youtube.com/watch?v=1l3U1X3z0CE
	#	- Ruby `OpenURI`
	#		- https://ruby-doc.org/stdlib-2.6.3/libdoc/open-uri/rdoc/OpenURI.html
	#		- https://stackoverflow.com/questions/5786779/using-nethttp-get-for-an-https-url
	#	- Ruby `nokogiri` Gem
	#		- https://www.railscarma.com/blog/technical-articles/learning-the-fundamentals-of-nokogiri-gem/
	#		- https://discuss.rubyonrails.org/t/nokogiri-as-a-default-dependency/74369
	#		- https://rdoc.info/github/sparklemotion/nokogiri/Nokogiri/HTML/Document
	#		- https://medium.com/@allegranzia/basic-webscraping-with-nokogiri-c9e9a4efc942
	#	- Ruby class `IPSocket`
	#		- https://docs.ruby-lang.org/en/master/IPSocket.html
	#	- Requirements for Internet Hosts
	#		- RFC 1123 https://datatracker.ietf.org/doc/html/rfc1123
	#	- Internet Message Format (including HTTP messages)
	#		- RFC 5322 https://datatracker.ietf.org/doc/html/rfc5322 
	#		- Replaced RFC 2822 https://datatracker.ietf.org/doc/html/rfc2822
	#		- Replaced RFC 822 https://datatracker.ietf.org/doc/html/rfc822
	#	- HTTP https://developer.mozilla.org/en-US/docs/Web/HTTP/Resources_and_specifications
	#		- HTTP/1.0 (c. 1996)
	#			- RFC 1945 https://datatracker.ietf.org/doc/html/rfc1945
	#		- HTTP/1.1 (c. 1997)
	#			- RFC 7230 Hypertext Transfer Protocol (HTTP/1.1): Message Syntax and Routing
	#				https://datatracker.ietf.org/doc/html/rfc7230
	#				- Replaced RFC 2145 Use and Interpretation of HTTP Version Numbers https://datatracker.ietf.org/doc/html/rfc2145 
	#				- RFC 2818 HTTP Over TLS https://datatracker.ietf.org/doc/html/rfc2818
	#				- RFC 8615 Well-Known Uniform Resource Identifiers (URIs) https://datatracker.ietf.org/doc/html/rfc8615
	#			- RFC 7231 Hypertext Transfer Protocol (HTTP/1.1): Semantics and Content
	#				https://datatracker.ietf.org/doc/html/rfc7231
	#				- Replaced RFC 2616 https://www.w3.org/Protocols/rfc2616/rfc2616.html
	#				- RFC 2817 Upgrading to TLS Within HTTP/1.1 https://datatracker.ietf.org/doc/html/rfc2817
	#					- Replaced RFC 2068 https://www.w3.org/Protocols/rfc2068/rfc2068.txt
	#		- HTTP/1.2 proposal (c. 1996)
	#			- https://www.w3.org/TR/WD-http-pep-960820
	#			- RFC 822
	#		- HTTP/2.0 (c. 2015)
	#			- RFC 7540 https://datatracker.ietf.org/doc/html/rfc7540
	#			- RFC 8740 Using TLS 1.3 with HTTP/2 https://datatracker.ietf.org/doc/html/rfc8740
	#		- HTTP/2.1 (does not yet exist)
	#		- HTTP/3.0 (does not yet exist)
	#		- Forwarded HTTP Extension
	#			- RFC 7239 https://datatracker.ietf.org/doc/html/rfc7239
	#		- HTTP Immutable Responses
	#			- RFC 8246 https://datatracker.ietf.org/doc/html/rfc8246
	#		- SSL and TLS
	#			- https://en.wikipedia.org/wiki/Transport_Layer_Security
	#			- SSL 2.0 (c. 1995-2011)
	#				- RFC 6176 Prohibiting Secure Sockets Layer (SSL) Version 2.0 https://datatracker.ietf.org/doc/html/rfc6176
	#			- SSL 3.0 (c. 1996-2015)
	#				- RFC 6101 https://datatracker.ietf.org/doc/html/rfc6101
	#				- RFC 7568 Deprecating Secure Sockets Layer Version 3.0 https://datatracker.ietf.org/doc/html/rfc7568
	#			- TLS 1.0 (c. 1999)
	#				- RFC 2246 https://datatracker.ietf.org/doc/html/rfc2246
	#			- TLS 1.1 (c. 2006)
	#				- RFC 4346 https://datatracker.ietf.org/doc/html/rfc4346
	#				- RFC 8996 Deprecating TLS 1.0 and TLS 1.1 https://datatracker.ietf.org/doc/html/rfc8996
	#			- TLS 1.2 (c. 2008)
	#				- RFC 5246 https://datatracker.ietf.org/doc/html/rfc5246
	#			- TLS 1.3 (c. 2019 May)
	#				- RFC 8446 https://datatracker.ietf.org/doc/html/rfc8446
	#			- TLS 1.4 (does not yet exist)
	#			- TLS 2.0 (does not yet exist)
}
	
require 'rubygems'		# https://stackoverflow.com/questions/2711779/require-rubygems
require 'socket'		# https://docs.ruby-lang.org/en/master/Socket.html
require 'uri'			# https://docs.ruby-lang.org/en/master/URI.html https://docs.ruby-lang.org/en/master/URI/HTTP.html
require 'net/http'		# https://docs.ruby-lang.org/en/master/Net/HTTP.html https://ruby-doc.org/stdlib-3.1.0/libdoc/net/http/rdoc/Net/HTTP.html
require 'net/https'		# https://ruby-doc.org/stdlib-2.6.5/libdoc/net/http/rdoc/Net/HTTP.html#class-Net::HTTP-label-HTTPS
require 'openssl'		# https://docs.ruby-lang.org/en/master/OpenSSL.html
require 'nokogiri'		# https://nokogiri.org/
require 'htmlentities'	# https://www.rubydoc.info/gems/htmlentities/HTMLEntities
require 'rmagick'		# https://rmagick.github.io/

# Force HTTP/1.0
# https://stackoverflow.com/questions/26381558/sending-http-requests-with-specific-http-version-protocol-in-ruby
Net::HTTP.send(:remove_const, :HTTPVersion) # avoid warning
Net::HTTP::HTTPVersion = '1.0'

$port = 8080
$bufferLength = 4096
# $verbose = false
$verbose = true
$userAgent = 'LegacyProxy/1.0'
$version = 'v1.0.1a21'	# For debug / change management purposes only ... not normally seen by user
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
