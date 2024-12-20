Plugin.define do
  name "Next.js"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Next.js is an open-source web development framework created by the private company Vercel providing React-based web applications with server-side rendering and static rendering. "
  website "https://nextjs.org/"

  matches [
    {
      :search => "headers[x-powered-by]",
      :regexp => /Next\.js/,
      :name => "x-powered-by header with Next.js"
    },
    {
      :search => "body",
      :regexp => /\/_next\/static/,
      :name => "HTML tags containing AG_PROXY_ID"
    },
  ]
end
