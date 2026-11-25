# Behavioral check for the Gitea Mirror plugin's product-specific markers.
#
# Usage: ruby plugin_gitea_mirror_check.rb <plugins directory>
# Exits 1 if a genuine Gitea Mirror page does not match or a lookalike matches.

class Plugin
  @plugins = []
  ALLOWED = %i[name authors version description website dorks matches passive aggressive].freeze

  class << self
    attr_reader :plugins

    def define(&block)
      plugin = new
      plugin.instance_eval(&block)
      @plugins << plugin
    end
  end

  ALLOWED.each do |attribute|
    define_method(attribute) do |value = nil|
      instance_variable_set("@#{attribute}", value) unless value.nil?
      instance_variable_get("@#{attribute}")
    end
  end

  def matches(value = nil)
    @matches = value unless value.nil?
    @matches || []
  end

  def method_missing(name, *_args, &_block)
    raise NoMethodError, "unknown WhatWeb Plugin DSL attribute: #{name}"
  end

  def respond_to_missing?(_name, _include_private = false)
    ALLOWED.include?(_name)
  end
end

SIGNUP_PAGE = <<~HTML
  <!doctype html>
  <html lang="en"><head>
  <title>Setup Admin Account - Gitea Mirror</title>
  </head><body>
  <img alt="Gitea Mirror Logo" src="/logo.svg">
  <h1>Welcome to Gitea Mirror</h1>
  <script>const BASE_PATH_WINDOW_KEY = "__GITEA_MIRROR_BASE_PATH__";</script>
  </body></html>
HTML

LOGIN_PAGE = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Login - Gitea Mirror</title></head>
  <body>
  <img alt="Gitea Mirror Logo" src="/logo.svg">
  <script>const BASE_PATH_WINDOW_KEY = "__GITEA_MIRROR_BASE_PATH__";</script>
  </body></html>
HTML

DASHBOARD_PAGE = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Dashboard - Gitea Mirror</title></head>
  <body>
  <script>const BASE_PATH_WINDOW_KEY = "__GITEA_MIRROR_BASE_PATH__";</script>
  </body></html>
HTML

NOT_FOUND_PAGE = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Page Not Found - Gitea Mirror</title></head>
  <body>
  <p>Error Code: <code>404_NOT_FOUND</code></p>
  <script>const BASE_PATH_WINDOW_KEY = "__GITEA_MIRROR_BASE_PATH__";</script>
  </body></html>
HTML

TITLE_ONLY_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>Gitea Mirror review</title></head>
  <body>A blog post about mirroring repositories.</body></html>
HTML

TITLE_WITHOUT_SHELL_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>Login - Gitea Mirror</title></head>
  <body><p>Sign in to an unrelated wiki.</p></body></html>
HTML

SHELL_WITHOUT_TITLE_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>Internal tooling</title></head>
  <body><script>const BASE_PATH_WINDOW_KEY = "__GITEA_MIRROR_BASE_PATH__";</script></body></html>
HTML

GITEA_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>Gitea: Git with a cup of tea</title></head>
  <body><p>Gitea is a painless self-hosted Git service.</p></body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "gitea_mirror.rb")
plugin = Plugin.plugins.last

def page_matched?(plugin, page)
  plugin.matches.any? do |match|
    next false if match[:url]

    hit = false
    hit ||= page.match?(match[:regexp]) if match[:regexp].is_a?(Regexp)
    hit ||= page.include?(match[:text]) if match[:text].is_a?(String)
    hit
  end
end

failures = []
failures << "signup page did not match" unless page_matched?(plugin, SIGNUP_PAGE)
failures << "login page did not match" unless page_matched?(plugin, LOGIN_PAGE)
failures << "dashboard page did not match" unless page_matched?(plugin, DASHBOARD_PAGE)
failures << "404 page did not match" unless page_matched?(plugin, NOT_FOUND_PAGE)
failures << "title-only lookalike matched" if page_matched?(plugin, TITLE_ONLY_LOOKALIKE)
failures << "title-without-shell lookalike matched" if page_matched?(plugin, TITLE_WITHOUT_SHELL_LOOKALIKE)
failures << "shell-without-title lookalike matched" if page_matched?(plugin, SHELL_WITHOUT_TITLE_LOOKALIKE)
failures << "Gitea lookalike matched" if page_matched?(plugin, GITEA_LOOKALIKE)

begin
  Plugin.new.instance_eval { websit "https://example.test" }
  failures << "misspelled DSL attribute was accepted"
rescue NoMethodError
  # expected: the stand-in rejects an unknown DSL attribute
end

puts failures
exit(failures.empty? ? 0 : 1)
