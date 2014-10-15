require 'rubygems'
require 'mechanize'


# @param [Mechanize] fuzzer
# @param [String] url
# @param [String] username
# @param [String] password
# @return Page
def authenticate(url, fuzzer, username, password)
  page = fuzzer.
  login_form = page.forms.first
  login_form['username'] = username
  login_form['password'] = password
  page = login_form.click_button
end
=begin
fuzzy = Mechanize.new
url = 'http://127.0.0.1/dvwa/login.php'
pw = 'password'
un = 'admin'
url = authenticate(url, fuzzy, un, pw)
pp url

p = "fuck"
puts p
s = "shit"
puts s
v = "nothing"
puts v
v = s
s.concat(p)
puts s
puts v
=end


# @param [Page] post_page
# @param [String] info
def parse_HTML(post_page, info)
  puts  post_page.body.include?(info)
end

shittyFuzzer = Mechanize.new
page = shittyFuzzer.get('http://store.channelfireball.com/landing')
parse_HTML(page, 'store')
