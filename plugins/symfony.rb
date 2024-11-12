Plugin.define do
  name "Symfony"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Symfony is a PHP framework for web applications and a set of reusable PHP components."
  website "https://symfony.com/"

  matches [
    {
      :search => "headers[set-cookie]",
      :regexp => /symfony/i,
      :name => "Symfony Set-Cookie Header"
    },
  ]
end
