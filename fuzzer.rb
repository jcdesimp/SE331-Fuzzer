require "mechanize"
require 'set'

#puts ARGV.to_s



# @param args [Array]
def main(args)

  #mechanize instance to do the fuzzing
  fuzzy = Mechanize.new

  if args.count >= 2

    #get the url
    url = args[1]
    #puts url

    flags = parse_flags(args)


    if args[0] == "discover"
    	discover(url, fuzzy)

    elsif args[0] == "test"
    	puts "testing"
    else
      puts "Unknown Command!"
      display_help
    end
  else
    puts "Not enough arguments given!"
    display_help
  end

end

# @param [Array] args
# @return [Hash]
def parse_flags(args)
  #flag parsing
  flags = Hash.new(nil)
  args.each do
    # @type arg [String]
  |arg|
    if arg.start_with?("--")
      arg_data = arg.split("=")

      flags[arg_data[0]] = arg_data[1]
    end
  end
  flags
end


# @param [Mechanize] fuzzer
# @param [String] url
def discover(url, fuzzer)
  page = fuzzer.get(url)
	url_set = Set.new([])
  visited_set = Set.new([url])
end


def display_help
  print(
      "

ruby fuzzer.rb [discover | test] url OPTIONS

COMMANDS:
  discover  Output a comprehensive, human-readable list of all discovered inputs to the system. Techniques include both crawling and guessing.
  test      Discover all inputs, then attempt a list of exploit vectors on those inputs. Report potential vulnerabilities.

OPTIONS:
  --custom-auth=string     Signal that the fuzzer should use hard-coded authentication for a specific application (e.g. dvwa). Optional.

  Discover options:
    --common-words=file    Newline-delimited file of common words to be used in page guessing and input guessing. Required.

  Test options:
    --vectors=file         Newline-delimited file of common exploits to vulnerabilities. Required.
    --sensitive=file       Newline-delimited file data that should never be leaked. It's assumed that this data is in the application's database (e.g. test data), but is not reported in any response. Required.
    --random=[true|false]  When off, try each input to each page systematically.  When on, choose a random page, then a random input field and test all vectors. Default: false.
    --slow=500             Number of milliseconds considered when a response is considered \"slow\". Default is 500 milliseconds

Examples:
  # Discover inputs
  fuzz discover http://localhost:8080 --common-words=mywords.txt

  # Discover inputs to DVWA using our hard-coded authentication
  fuzz discover http://localhost:8080 --common-words=mywords.txt

  # Discover and Test DVWA without randomness
  fuzz test http://localhost:8080 --custom-auth=dvwa --common-words=words.txt --vectors=vectors.txt --sensitive=creditcards.txt --random=false\n"
  )
  exit
end

#puts ARGV.count
main(ARGV)

