Plugin.define do
  name "Fortinet FortiMail"
  authors [
    "Ostorlab"
  ]
  version "0.1"
  description "FortiMail is a top-rated secure email gateway that stops volume-based and targeted cyber threats to help secure the dynamic enterprise attack surface."
  website "https://www.fortinet.com/products/email-security"

  matches [
    {
      :regexp => /<title>FortiMail<\/title>/,
      :name => "FortiMail Title"
    }
  ]
end