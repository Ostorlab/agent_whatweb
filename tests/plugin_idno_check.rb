# Behavioral check for the Idno plugin's product-specific markers.
#
# Usage: ruby plugin_idno_check.rb <plugins directory>
# Exits 1 if a genuine Idno landing does not match or a lookalike does.

class Plugin
  @plugins = []

  class << self
    attr_reader :plugins

    def define(&block)
      plugin = new
      plugin.instance_eval(&block)
      @plugins << plugin
    end
  end

  def name(value = nil)
    @name = value unless value.nil?
    @name
  end

  def matches(value = nil)
    @matches = value unless value.nil?
    @matches || []
  end

  def method_missing(*_args, &_block)
    nil
  end

  def respond_to_missing?(*_args)
    true
  end
end

IDNO_LANDING = <<~HTML
  <!doctype html>
  <html><head>
  <meta name="generator" content="Idno https://idno.co">
  <title>Idno</title></head>
  <body>hello</body></html>
HTML

GENERATOR_ONLY = <<~HTML
  <!doctype html>
  <html><head>
  <meta name="generator" content="Idno https://idno.co">
  <title>Site</title></head>
  <body>hello</body></html>
HTML

LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>Idno</title></head>
  <body>Idno documentation and a mention of idno.co</body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "idno.rb")
plugin = Plugin.plugins.last
body_patterns = plugin.matches
                       .select { |match| match[:search] == "body" }
                       .flat_map { |match| match.values.grep(Regexp) }
header_patterns = plugin.matches
                        .select { |match| match[:search].to_s.start_with?("headers[") }
                        .flat_map { |match| match.values.grep(Regexp) }

def body_matched?(patterns, page)
  patterns.any? { |pattern| page.match?(pattern) }
end

def header_matched?(patterns, value)
  patterns.any? { |pattern| value.match?(pattern) }
end

failures = []
failures << "Idno landing body did not match" unless body_matched?(body_patterns, IDNO_LANDING)
failures << "generator-only body did not match" unless body_matched?(body_patterns, GENERATOR_ONLY)
failures << "Idno powered-by header did not match" unless header_matched?(header_patterns, "https://idno.co")
failures << "unrelated lookalike matched" if body_matched?(body_patterns, LOOKALIKE)
failures << "unrelated header matched" if header_matched?(header_patterns, "PHP/8.4")

puts failures
exit(failures.empty? ? 0 : 1)
