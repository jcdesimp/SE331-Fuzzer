require 'mechanize'
require 'set'


ACCEPTABLE_FLAGS = %w(custom-auth common-words)
AUTHENTICATIONS = {
    :dvwa => %w(admin password),

    # more authentication can be added
}

# @param args [Array]
# Parses arguments and calls the appropriate functions
def main(args)

  #mechanize instance to do the fuzzing
  fuzzy = Mechanize.new

  # Check argument count
  if args.count >= 2

    #get the url
    url = args[1]
    #puts url

    fuzzy.get(url)

    # get the flag data in a hash
    flags = parse_flags(args)

    # authenticate if auth flag is given
    auth_flag = flags['custom-auth']
    # check if flag exists
    if auth_flag != nil

      auth_data = AUTHENTICATIONS[auth_flag.to_s.to_sym]
      # check if given auth option is in
      # hard coded auth hash
      if auth_data == nil
        puts "\nNo authentication data for '#{auth_flag}'"
        display_help
      end

      # If it isnt 'nil' then feed it to authenticate and get the
      # post-authetication url to continue on
      fuzzy = authenticate(fuzzy, auth_data[0], auth_data[1])
    end


    # discovering or testing?
    # otherwise print "Unknown command"


    if args[0] == 'discover'
      # discovering
    	discover(fuzzy)

    elsif args[0] == 'test'
      # testing
    	puts 'testing'
    elsif args[0] == 'help'
      display_help
    else
      # invalid option
      puts 'Unknown Command!'
      display_help
    end
  else
    puts 'Not enough arguments given!'
    display_help
  end
end

# @param [Array] args
# @return [Hash]
# Parses the arguments and returns
# a hash of flags and their asspciated values
def parse_flags(args)

  #flag parsing
  flags = Hash.new(nil)

  args.each do
    # @type arg [String]
  |arg|
    # if it starts with '--' then it's a flag
    if arg.start_with?('--')

      # @type arg_data [Array]
      arg_data = arg.split('=')

      # construct the individual flag data
      flag = arg_data[0].to_s.sub('--','')

      # make sure the flag actually was given a value
      if arg_data.count != 2
        puts "\nflag #{flag} not set!"
        display_help
      end
      unless ACCEPTABLE_FLAGS.include? (flag)
        puts "\nUnknown Flag '#{flag}'"
        display_help
      end
      flags[flag] = arg_data[1]
    end
  end
  flags
end


# @param [Mechanize] fuzzer
def discover(fuzzer)
  page = fuzzer.current_page
  link_array = []


  visited = []

  page.links.each do |link|
    if link.uri.to_s != "logout.php"
      link_array.push(link)
    end
  end

  while link_array.length() != 0 do
    to_visit = link_array.pop()
    puts to_visit.uri
    if to_visit.uri.to_s != "logout.php"
      visited.push(to_visit.uri.to_s)
    end
    page = to_visit.click
    
    puts "-------------------------------"
    puts page.uri
    puts "-------------------------------"

    page.links.each do |url|
      unless visited.include? url.uri
        link_array.push(url)
      end
    end
    link_array.uniq!
  end
  visited.uniq!

end

# @param [Mechanize] fuzzer
# @param [String] username
# @param [String] password
# @return [String]
def authenticate(fuzzer, username, password)
  page = fuzzer.current_page
  login_form = page.forms.first
  login_form['username'] = username
  login_form['password'] = password
  page = login_form.click_button
  return fuzzer
end

# displays the help information and ends the program
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

