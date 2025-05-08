Plugin.define do
  name "FastCGI"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "This plugin detects FastCGI instances based on the default test page or common headers."
  website "https://fastcgi-archives.github.io/FastCGI_A_High-Performance_Web_Server_Interface_FastCGI.html/"

  matches [
    {
      :search => "body",
      :regexp => /<title>TurnKey NGINX PHP FastCGI Server<\/title>/i,
      :name => "FastCGI Default Test Page Title"
    },
    {
      :search => "headers",
      :regexp => /fastcgi/i,
      :name => "FastCGI Header Detected"
    }
  ]
end
