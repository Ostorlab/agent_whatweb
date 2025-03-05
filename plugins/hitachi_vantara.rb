Plugin.define do
  name "Hitachi Vantara"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Hitachi Vantara provides enterprise storage solutions, cloud infrastructure, and IoT platforms."
  website "https://www.hitachivantara.com/"

  matches [
    {
      :search => "body",
      :regexp => /<div id="login-footer-company">\s*Hitachi Vantara\s*<\/div>/i,
      :name => "Hitachi Vantara Login Footer Match"
    },
  ]
end
