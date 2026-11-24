# Behavioral check for the Donetick plugin's product-specific markers.
#
# Usage: ruby plugin_donetick_check.rb <plugins directory>
# Exits 1 if a genuine Donetick landing does not match or a lookalike does.

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

DONETICK_LANDING = <<~HTML
  <!doctype html>
  <html lang="en"><head>
  <title>Donetick</title>
  <script>localStorage.getItem('donetick-theme-skin')</script>
  </head><body><div id="root"></div></body></html>
HTML

TITLE_ONLY = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Donetick</title></head>
  <body>Donetick documentation and a mention of the project</body></html>
HTML

SKIN_ONLY = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Chores</title></head>
  <body><script>localStorage.getItem('donetick-theme-skin')</script></body></html>
HTML

UNRELATED = <<~HTML
  <!doctype html>
  <html lang="en"><head><title>Dashboard</title></head>
  <body>hello</body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "donetick.rb")
plugin = Plugin.plugins.last
body_patterns = plugin.matches
                       .select { |match| match[:search] == "body" }
                       .flat_map { |match| match.values.grep(Regexp) }

def body_matched?(patterns, page)
  patterns.any? { |pattern| page.match?(pattern) }
end

failures = []
failures << "Donetick landing body did not match" unless body_matched?(body_patterns, DONETICK_LANDING)
failures << "title-only lookalike matched" if body_matched?(body_patterns, TITLE_ONLY)
failures << "skin-only lookalike matched" if body_matched?(body_patterns, SKIN_ONLY)
failures << "unrelated page matched" if body_matched?(body_patterns, UNRELATED)

begin
  Plugin.new.instance_eval { websit "https://example.test" }
  failures << "misspelled DSL attribute was accepted"
rescue NoMethodError
  # expected: the stand-in rejects an unknown DSL attribute
end

puts failures
exit(failures.empty? ? 0 : 1)
