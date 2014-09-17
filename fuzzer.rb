require "mechanize"
require 'set'

fuzzy = Mechanize.new

#puts ARGV.to_s



# @param args [Array]
def main(args)
  if args.count >= 1
    url = args[0]

    if args[0] == "discover"
    	puts "discovering"

    end

    if args[0] == "test"
    	puts "testing"
    end


  end
  url ||= "http://google.com"
  puts url
end

def discover()
	url_set = Set.new([])
	page.links.each do |url|
		url_set.add(url.url)
	end
end


#puts ARGV.count
main(ARGV)

