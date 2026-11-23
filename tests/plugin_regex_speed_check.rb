# Checks that no plugin regex is too slow on a large page with non-ASCII text.
#
# Ruby's regex engine can backtrack for hours on some patterns, for example `[\s\S]` with the case-insensitive
# flag inside a lookahead, once the page contains a single non-ASCII character. WhatWeb runs every plugin on every
# page it downloads, so one such regex makes every scan hang.
#
# Usage: ruby plugin_regex_speed_check.rb <plugins directory> <time limit in seconds>
# Prints one line per slow or failing regex and exits with 1 if there is any.

# Minimal stand-in for WhatWeb's plugin DSL: it only keeps each plugin's name and match list.
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

PAGE = "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Example – Home</title></head>\n<body>\n" +
       ("<div class=\"section\"><p>Plan, model and forecast – café résumé “quoted”.</p><a href=\"/page\">Link</a></div>\n" * 2000) +
       "</body></html>\n"

plugins_directory, time_limit = ARGV
failures = []
checked = 0
Dir.glob(File.join(plugins_directory, "*.rb")).sort.each do |file|
  before = Plugin.plugins.size
  load file
  Plugin.plugins[before..].each do |plugin|
    plugin.matches.each do |match|
      match.each_value do |pattern|
        next unless pattern.is_a?(Regexp)

        checked += 1
        regex = Regexp.new(pattern.source, pattern.options, timeout: time_limit.to_f)
        begin
          PAGE.scan(regex)
        rescue Regexp::TimeoutError
          failures << "#{File.basename(file)} (#{plugin.name}): slower than #{time_limit}s: /#{pattern.source}/"
        rescue RegexpError => e
          failures << "#{File.basename(file)} (#{plugin.name}): #{e.message.split(':').first}: /#{pattern.source}/"
        end
      end
    end
  end
end

STDERR.puts "checked #{checked} regexes in #{Plugin.plugins.size} plugins"
puts failures
exit(failures.empty? ? 0 : 1)
