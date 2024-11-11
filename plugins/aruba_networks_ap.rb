Plugin.define do
  name "Aruba Networks Access Points"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Aruba Networks Access Points provide secure Wi-Fi solutions for enterprises, and this fingerprint matches the login page for Aruba Access Points."
  website "https://www.arubanetworks.com"

  matches [
    {
      :search => "body",
      :regexp => /<img id="aruba-logo" src="\/images\/aruba-hpe-logo.png" width="175" alt="Aruba Networks" title="Aruba Networks"/,
      :name => "Aruba Networks Login Page Logo"
    },
  ]
end
