require 'rubygems'
require 'mechanize'


# @param [Mechanize] fuzzer
# @param [String] url
# @param [String] username
# @param [String] password
# @return Page
def authenticate(url, fuzzer, username, password)
  page = fuzzer.get(url)
  login_form = page.forms.first
  login_form['username'] = username
  login_form['password'] = password
  page = login_form.click_button
  return page
end

fuzzy = Mechanize.new
url = 'http://127.0.0.1/dvwa/login.php'
pw = 'password'
un = 'admin'
url = authenticate(url, fuzzy, un, pw)
pp url