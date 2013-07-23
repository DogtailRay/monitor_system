#!/usr/bin/ruby

require "flow_rule"
require "yaml"

class RuleSet
  def initialize(conf_file)
    @rules = []
    File.open(conf_file,"r") do |is|
      data = YAML.load(is)
      data.each do |key,value|
        @rules.push FlowRule.new key,value
      end
      @rules.sort! { |r1,r2| r1.name <=> r2.name }
      if data.has_key? "default"
        @default = FlowRule.new "default",data["default"]
      else
        @default = @rules.first
      end
    end
  end

  # Return the rule matching the given parameters
  def matching_rule(params)
    @rules.each do |rule|
      if rule.match? params
        return rule
      end
    end
    return nil
  end

  def default_rule
    @default
  end
end
