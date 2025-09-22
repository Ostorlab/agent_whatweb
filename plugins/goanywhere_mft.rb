Plugin.define do
  name "GoAnywhere MFT"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "GoAnywhere Managed File Transfer (MFT) is a secure file transfer solution that automates and encrypts data."
  website "https://www.goanywhere.com/"

  matches [
    {
      :search => "body",
      :text => "GoAnywhere Managed File Transfer",
      :name => "Title Match"
    },
    {
      :search => "body",
      :regexp => /GoAnywhere\s+([0-9]+\.[0-9]+\.[0-9]+)/,
      :name => "Version Match"
    }
  ]
end
