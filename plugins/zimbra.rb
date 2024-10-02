Plugin.define do
  name "Zimbra"
  authors [
    "Ostorlab"
  ]
  version "0.1"
  description "Zimbra is an open platform solution that lets you manage and control your data the way you want it, while keeping it secure and private. With a modern user interface, Zimbra is easy to use and accessible anytime, anywhere."
  website "https://www.zimbra.com/"

  matches [
    {
      :search => "body",
      :regexp => /<title>Zimbra/,
      :name => "Zimbra Web Client Sign-in"
    },
  ]

end
