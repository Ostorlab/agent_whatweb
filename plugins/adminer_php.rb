Plugin.define do
  name "Adminer"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Adminer is a full-featured database management tool (single PHP file). Fingerprints login fields, version, and common paths."
  website "https://www.adminer.org/"

  matches [
    {
      :search => "body",
      :regexp => /<title>Login - Adminer<\/title>/i,
      :name => "Adminer Login Page Title"
    },
    {
      :search => "body",
      :regexp => /<link rel="stylesheet" href="adminer\.php\?file=default\.css&amp;version=\d+\.\d+\.\d+"/i,
      :name => "Adminer Default CSS Reference"
    },
    {
      :search => "body",
      :regexp => /<h1><a href='https:\/\/www\.adminer\.org\/'[^>]*>.*?Adminer<\/a> <span class='version'>/i,
      :name => "Adminer Footer Branding with Version"
    }
  ]
end
