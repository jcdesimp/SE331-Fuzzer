require 'mechanize'

def guess_initialize(filepath)
	extensions = [
		".php",
		".html",
		".jsp",
		".asp",
		".js",
		".rb",
		".py"
	]

	words = []

	uri_lst = []

	f = File.open(filepath ,"r")
	f.each_line do |line|
		line.delete!("\n")
		words.push(line)
	end

	words.each do |word|
		uri_lst.push(word)
		extensions.each do |ext|
			new_uri = word + ext
			uri_lst.push(new_uri)
		end
	end

	puts uri_lst
	return uri_lst

end

def discover(url)
  agent = Mechanize.new do | agent |
      agent.user_agent_alias = "Windows Chrome"
  end
  page = agent.get(url)

  link_array = []
  visited = []
  page.links.each do |link|
  	link_array.push(link)
  end

  while link_array.length() != 0 do
  	to_visit = link_array.pop()
  	visited.push(to_visit)
  	page = to_visit.click

  	page.links.each do |url|
  	  link_array.push(url)
  	end
  	link_array.uniq!
  end
  visited.uniq!


end