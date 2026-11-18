Plugin.define do
  name "Flagr"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Flagr is an open-source feature flagging, A/B testing and dynamic configuration microservice."
  website "https://openflagr.github.io/flagr/"

  matches [
    {
      :search => "body",
      :regexp => /<title>\s*Flagr\s*<\/title>/i,
      :name => "Flagr UI title"
    },
    {
      :search => "headers[www-authenticate]",
      :regexp => /Basic realm="you shall not pass"/i,
      :name => "Flagr basic-auth challenge realm"
    },
  ]
end
