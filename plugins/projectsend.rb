Plugin.define do
  name "ProjectSend"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "ProjectSend is a free, open-source file sharing platform for organizations and teams."
  website "https://www.projectsend.org/"

  matches [
    {
      :search => "body",
      :regexp => /<div id="footer">\s*Provided by <a href="https:\/\/www\.projectsend\.org\/" target="_blank">ProjectSend<\/a>.*?<\/div>/,
      :name => "ProjectSend footer Tag"
    },
  ]
end
