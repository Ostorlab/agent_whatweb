Plugin.define do
  name "SolarWinds Web Help Desk"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "SolarWinds Web Help Desk is a ticketing and IT asset management solution designed for handling help desk requests and automating IT services."
  website "https://www.solarwinds.com/web-help-desk"

  matches [
    {
      :search => "body",
      :regexp => /You are being redirected to the help desk\.<br>If you are not taken there immediately,\s*<a href="\/helpdesk\/WebObjects\/Helpdesk\.woa">click here<\/a>/i,
      :name => "SolarWinds Web Help Desk Redirection Text"
    },
  ]
end
