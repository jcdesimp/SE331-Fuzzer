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

    elsif args[0] == "test"
    	puts "testing"
    end


  end
end

def discover(url)
  page = agent.get(url)
	url_set = Set.new([])
  visited_set = Set.new([url])
end

def display_help
  print(
      "

fuzz [discover | test] url OPTIONS

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
end

#puts ARGV.count
main(ARGV)

