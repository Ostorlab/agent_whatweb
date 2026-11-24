# Behavioral check for the Pangolin plugin's product-specific markers.
#
# Usage: ruby plugin_pangolin_check.rb <plugins directory>
# Exits 1 if a genuine Pangolin auth page does not match or a lookalike does.

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

  def respond_to_missing?(name, _include_private = false)
    ALLOWED.include?(name)
  end
end

LOGIN_PAGE = <<~HTML
  <!doctype html>
  <html lang="en"><head>
  <title>Log In - Pangolin</title>
  </head><body>
  <a href="https://pangolin.net/tos">Terms of Service</a>
  <a href="https://pangolin.net/privacy">Privacy Policy</a>
  </body></html>
HTML

RESOURCE_AUTH_PAGE = <<~HTML
  <!doctype html>
  <html lang="en"><head>
  <title>Resource Access - Pangolin</title>
  </head><body>
  <p>powered by <a href="https://pangolin.net/">Pangolin</a></p>
  </body></html>
HTML

TITLE_ONLY_LOOKALIKE = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Pangolin</title></head>
  <body>Pangolin documentation and a mention of the project.</body></html>
HTML

LINK_ONLY_LOOKALIKE = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Dashboard</title></head>
  <body><a href="https://pangolin.net/">A link to Pangolin</a></body></html>
HTML

UNRELATED_LOOKALIKE = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Log In - Example</title></head>
  <body><a href="https://example.test/tos">Terms</a></body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "pangolin.rb")
plugin = Plugin.plugins.last
body_patterns = plugin.matches
                       .select { |match| match[:search] == "body" }
                       .flat_map { |match| match.values.grep(Regexp) }

def body_matched?(patterns, page)
  patterns.any? { |pattern| page.match?(pattern) }
end

failures = []
failures << "Pangolin login page did not match" unless body_matched?(body_patterns, LOGIN_PAGE)
failures << "Pangolin resource auth page did not match" unless body_matched?(body_patterns, RESOURCE_AUTH_PAGE)
failures << "title-only lookalike matched" if body_matched?(body_patterns, TITLE_ONLY_LOOKALIKE)
failures << "link-only lookalike matched" if body_matched?(body_patterns, LINK_ONLY_LOOKALIKE)
failures << "unrelated page matched" if body_matched?(body_patterns, UNRELATED_LOOKALIKE)

begin
  Plugin.new.instance_eval { websit "https://example.test" }
  failures << "misspelled DSL attribute was accepted"
rescue NoMethodError
  # expected: the stand-in rejects an unknown DSL attribute
end

puts failures
exit(failures.empty? ? 0 : 1)
