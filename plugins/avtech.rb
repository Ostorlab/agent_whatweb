Plugin.define do
  name "AVTECH DVR"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "AVTECH DVRs provide web management interfaces for monitoring and controlling DVR functions."
  website "https://www.avtech.com.tw/"

  matches [
    {
      :search => "headers[server]",
      :regexp => /Avtech/i,
      :name => "AVTECH DVR Server Header"
    },
    {
      :search => "body",
      :regexp => /This machine is not supported, please visit 'www.avtech.com.tw' for more details./i,
      :name => "AVTECH Unsupported Machine Message"
    },
  ]
end
