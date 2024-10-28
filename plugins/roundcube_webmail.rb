Plugin.define do
  name "Roundcube Webmail"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Roundcube Webmail is a browser-based IMAP client with a user-friendly interface, providing features for email management."
  website "https://roundcube.net/"

  matches [
    {
      :search => "title",
      :regexp => /<title>.*?Roundcube Webmail<\/title>/,
      :name => "Roundcube Webmail Title Tag"
    },
  ]
end
