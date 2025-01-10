Plugin.define do
  name "Calibre"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Calibre is an e-book manager. It can view, convert, edit and catalog e-books in all of the major e-book formats."
  website "https://calibre-ebook.com/"

  matches [
    {
      :search => "headers[server]",
      :regexp => /calibre/i,
      :name => "Calibre Server Header"
    }
  ]
end
