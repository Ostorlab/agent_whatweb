Plugin.define do
  name "Array Networks"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Array Networks provides secure application delivery solutions."
  website "https://www.arraynetworks.com/"

  matches [
    {
      :search => "headers[set-cookie]",
      :regexp => /ANsession/,
      :name => "Set-Cookie header with ANsession"
    },
    {
      :search => "ssl.cert.issuer",
      :regexp => /AG Product/,
      :name => "SSL Certificate Issuer Organizational Unit"
    },
    {
      :search => "body",
      :regexp => /AG_PROXY_ID/,
      :name => "HTML tags containing AG_PROXY_ID"
    },
  ]
end
