Plugin.define do
  name "FastCGI"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "This plugin detects FastCGI instances based on the default test page or common headers."
  website "https://www.fastcgi.com/"

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
