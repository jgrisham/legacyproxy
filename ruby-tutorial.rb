#!/usr/bin/env ruby
#
# Ruby tutorial - jhg 2022-02-17
#
# Inspired by https://www.ruby-lang.org/en/documentation/quickstart/3/

def methodName(parameterName = "DefaultValue")
	# ..
end

class ClassName
	attr_accessor :key
	def initialize(parameterName = "DefaultValue")
		@key = parameterName
	end
	def methodName1(parameterName = "DefaultValue")
	end
	def methodName2(parameterName = "DefaultValue")
		if @key.nil?
			# ...
		elsif @key.respond_to?("each")			# signifies @key is an array compatible with '.each'
			@key.each do |lambdaParamaterName|	# do...end is an anonymous function ('lambda') block
				# ...
			end
		elsif @key.respond_to?("join")			# signifies @key is an array compatible with '.join'
			puts "#{@key.join(", ")}"
		else
			# ...
		end
	end
	puts "Class definition complete."			# class definitions are executable
end

{	
	# A block
}

do
	# another block
	# alternative string syntax: `%Q(...)`, e.g. `%Q("That's it", she said.)`
	# multi-line string, including line breaks: `<<END...END`
	# 	str = <<END
	#	......
	#	END
end


if __FILE__ == $0	# Is this being run directly, rather than being included elsewhere
	
	objectName = ClassName.new("paramaterValue")

	objectName.methodName1()

	# Show methods for object instance
	ClassName.instance_methods

	# Show only explicitly defined methods
	ClassName.instance_methods(false)

	# Show instance variables
	ClassName.instance_variables

	# Test object for a method
	objectName.respond_to?("name")	# Can I get the value of 'name'?
	objectName.respond_to?("name=")	# Can I set the value of 'name'?

	# Set the key to an array
	objectName.key = ["Full", "Half", "Empty"]

	# Set the key to nil
	objectName.key = nil
end

