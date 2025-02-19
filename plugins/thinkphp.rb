Plugin.define do
  name "ThinkPHP"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "ThinkPHP is an open source, fast, simple, lightweight, and object-oriented PHP development framework distributed under the Apache2 open source license."
  website "https://github.com/top-think"

  matches [
    {
      :search => "body",
      :regexp => /<title>.*ThinkPHP.*<\/title>/i,
      :name => "ThinkPHP Title Tag"
    },
  ]
end
