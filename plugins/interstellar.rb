Plugin.define do
  name "Interstellar"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Interstellar, an open-source web proxy front end, from the anonymous landing shell it serves: a data-shell marker, the /assets/js/main.js application script and the thesaurus decoy favicon. The shell is served by both the static and the built deployment, but it carries no release, so version extraction is a gap."
  website "https://github.com/UseInterstellar/Interstellar"

  matches [
    {
      :search => "body",
      :regexp => /(?=[\s\S]{0,65536}?data-shell=["']true["'])(?=[\s\S]{0,65536}?src=["']\/assets\/js\/main\.js["'])(?=[\s\S]{0,65536}?href=["']\/assets\/media\/favicon\/thesaurus\.png["'])/i,
      :name => "Interstellar landing shell (data-shell, application script, decoy favicon)",
    },
  ]
end
