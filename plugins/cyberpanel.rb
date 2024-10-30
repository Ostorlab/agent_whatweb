Plugin.define do
  name "CyberPanel"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "CyberPanel is a web hosting control panel powered by OpenLiteSpeed with features for managing websites, DNS, and email."
  website "https://cyberpanel.net/"

  matches [
    {
      :search => "body",
      :regexp => /<h4 class="text-muted text-center mb-10">Web Hosting Control Panel<\/h4>/i,
      :name => "CyberPanel Web Hosting Control Panel Text"
    },
  ]
end
