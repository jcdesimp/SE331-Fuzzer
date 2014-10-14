require 'mechanize'
require 'set'
require 'uri'


ACCEPTABLE_FLAGS = %w(custom-auth common-words vectors sensitive random slow)
AUTHENTICATIONS = {
    :dvwa => %w(admin password),

    # more authentication can be added
}

# @param args [Array]
# Parses arguments and calls the appropriate functions
def main(args)

  #mechanize instance to do the fuzzing
  # @type fuzzy [Mechanize]
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
      # @type fuzzy [Mechanize]
      fuzzy = authenticate(fuzzy, auth_data[0], auth_data[1])
    end


    # discovering or testing?
    # otherwise print "Unknown command"
    if args[0] == 'discover' || args[0] == 'test'

      #get the guessed results
      if flags['common-words'] != nil
        #puts fuzzy.current_page.uri
        guesses = guess_initialize(fuzzy.current_page, flags['common-words'])
      else
        guesses = []
      end


      # discovering
    	#discover(fuzzy, guesses)
      discovered = discover_rec(fuzzy, guesses)
      if args[0] == 'discover'
        print_results(fuzzy, discovered)

      elsif args[0] == 'test'
        # testing
        #puts 'testing'
        #todo make call to test function
        # should we just pass the flag array to the function??

        test_exploits(fuzzy, discovered, parse_file(flags['vectors']), nil, nil, 0)

      end


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



# @param filepath [String]
# @return [Array]
def parse_file(filepath)
  words = []
  f = File.open(filepath, 'r')
  f.each_line do |line|
    line.delete!("\n")
    words.push(line)
  end
  words
end



# @param filepath [String]
# @return [Array]
def guess_initialize(start_page, filepath)
  guesser = Mechanize.new

  extensions = %w(.php .html .jsp .asp .js .rb .py)

  uri_lst = []

  found = []

  words = parse_file(filepath)

  words.each do |word|
    uri_lst.push(word)
    extensions.each do |ext|
      new_uri = word + ext
      uri_lst.push(new_uri)
    end
  end

    uri_lst.each {
      # @type g [String]
        |g|
      begin

        guesser.get(start_page.uri + '/'+ g)
        found.push(guesser.current_page)
      rescue Mechanize::ResponseCodeError, Net::HTTPNotFound
        next
      end
    }
  found

end


# @param fuzzer [Mechanize]
# @param guesses [Array]
# @return [Array]
def discover_rec(fuzzer, guesses=[])
  # @type current_page [Page]
  current_page = fuzzer.current_page
  #puts current_page.uri
  visited = crawl(current_page, [])

  guesses.each {
    # @type p [Page]
      |p|
    visited = crawl(p, visited)
  }

  visited
  #print_results(fuzzer, visited)
end

# @param visited [Array]
# @return [Array]
def crawl(page, visited)
  host = page.uri.host
  visited.push(page.uri)
  #puts page.uri
  if page.class != Mechanize::Page
    return visited
  end
  page.links.each {
    # @type l [Link]
      |l|
    #puts l
    # @type new_page [Page]
    #puts l.text

    if l.text.include?('Logout') || l == nil
      next
    end
    begin
      new_page = l.click
    rescue Mechanize::ResponseCodeError, Net::HTTPNotFound

      next
    rescue Mechanize::ResponseReadError => e
      new_page = e.force_parse
    end

    #### make sure we haven't visited this page yet AND it is within our domain
    ## RECURSIVE BASE CASE
    unless visited.include?(new_page.uri) || new_page.uri.host != host
      #puts new_page.uri
      #puts l.text
      visited = crawl(new_page, visited)
    end


  }
  #puts visited
  visited
end


# @param fuzzer [Mechanize]
# @param discovered_pages [Array]
# @param vectors [Array]
# @param sensitive [Array]
# @param random [Boolean]
def test_exploits(fuzzer, discovered_pages, vectors, sensitive, random, time_limit)
  unless random
    discovered_pages.each do # @type p [URI]
      |p|
      fuzzer.get(p)
      # @type currpage [Page]
      currpage = fuzzer.current_page
      #puts currpage.title
    puts currpage.uri
      currpage.forms.each do
        # @type f [Form]
        |f|
        f.fields.each do
          # @type fi [Field]
          |fi|
          vectors.each do
            |v|
            fi.value = v
            puts '    submitted - ' + f.submit.uri.to_s

          end
          #fi.value = 'test'
          #puts '    submitted - ' + f.submit.uri.to_s

        end
      end

    end
  end
end

=begin
  
fuzzy.read_timeout=4
rescue Mechanize::Timeout::Error => e
  puts "There is a delay."
  new_page = e.force_parse
end
  
=end

=begin
  
rescue Mechanize::ResponseCodeError => ex
  puts "There is a #{ex.class} when opening the page."
  new_page = ex.force_parse
end
  
end
  
=end


# @param fuzzer [Mechanize]
# @param visited [Array]
def print_results(fuzzer, visited)
  puts 'Pages and Forms'
  puts '----------------'

  visited.each {
    # @type u [String]
      |u|
    fuzzer.get(u)
    p = fuzzer.current_page
    puts "PAGE: #{p.uri}"
    p.forms.each {
      # @type f [Form]
        |f|
      puts "  FORM: #{f.name}"
      puts "    SUBMIT: #{f.submit(f.submits[0]).uri}"
      puts '    Fields:'
      f.fields.each {
        # @type fi [Field]
          |fi|
        puts "       #{fi.name}"
      }

    }


  }


  puts "\nCookies"
  puts '--------'
  fuzzer.cookies.each {
    # @type co [HTTP:Cookie]
      |co|
    puts "  #{co.to_s}"

  }
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
  fuzzer
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

