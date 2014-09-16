require "mechanize"

fuzzy = Mechanize.new

#puts ARGV.to_s


# @param args [Array]
def main(args)
  if args.count >= 1
    url = args[0]
  end
  url ||= "http://google.com"
  puts url
end



#puts ARGV.count
main(ARGV)

