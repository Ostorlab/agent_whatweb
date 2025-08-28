Plugin.define do
  name "Plex Media Server"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Plex Media Server is a digital media player and organizational tool that allows you to access the music, pictures, and videos stored on one computer with any other computer or compatible device."
  website "https://www.plex.tv/"

  matches [
    {
      :search => "headers[x-plex-protocol]",
      :regexp => /\d+\.\d+/,
      :name => "X-Plex-Protocol Header"
    },
    {
      :search => "headers[server]",
      :regexp => /Plex/i,
      :name => "Plex Server Header"
    },
    {
      :search => "headers[access-control-allow-origin]",
      :regexp => /app\.plex\.tv/,
      :name => "Plex CORS Origin Header"
    },
    {
      :search => "body",
      :regexp => /Plex Media Server/i,
      :name => "Plex Media Server in Body"
    },
    {
      :search => "head",
      :regexp => /<title>Plex<\/title>/i,
      :name => "Plex Title Tag"
    },
  ]
end
