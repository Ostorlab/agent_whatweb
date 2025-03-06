Plugin.define do
  name "Ivanti Endpoint Manager"
  authors [
    "ostorlab",
  ]
  version "0.1"
  description "Ivanti® Endpoint Manager and Endpoint Security for Endpoint Manager consists of a wide variety of powerful and easy-to-use tools you can use to help manage and protect your Windows, Macintosh, mobile, and Linux devices."
  website "https://www.ivanti.com/en-gb/products/endpoint-manager"

  matches [
    {
      :search => "body",
      :regexp => /<title>Ivanti®Web\sConsole\s2.0<\/title>/i,
      :name => "Ivanti EPM Title Tag"
    }
  ]
end
