Plugin.define do
  name "MyMangaDB"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies MyMangaDB, a self-hosted manga collection manager with a React frontend and a FastAPI backend."
  website "https://github.com/FabianRolfMatthiasNoll/MyMangaDB"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*MyMangaDB\s*<\/title>/i,
      :name => "MyMangaDB landing title",
    },
    {
      :search => "body",
      :regexp => /Application to organize and manage your mangas/i,
      :name => "MyMangaDB landing description",
    },
  ]
end
